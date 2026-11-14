//! `thadam-collector`: records what AI tools do on this Mac (ADR-003 Decision 10).
//!
//! Exit codes: 0 finished or stopped cleanly, 1 runtime failure (including the OS logger
//! exiting on its own, so a service manager restarts the collector), 2 usage or setup error.
//! Diagnostics hold counts only, never paths, arguments or values.

use std::fs::{self, DirBuilder};
use std::io::BufReader;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use thadam_collector::diag;
use thadam_collector::pipeline::{Pipeline, Settings};
use thadam_collector::registry::Registry;
use thadam_collector::run::{Ended, run, spawn_logger};
use thadam_collector::service;
use thadam_collector::snapshot::{self, SystemProcessTable};
use thadam_collector::source::eslogger::EsloggerSource;
use thadam_collector::source::network::{DEFAULT_SOCKET, FlowListener};
use thadam_store::{SegmentWriter, SystemDisk};

const USAGE: &str = "usage:
  thadam-collector run --registry <file> --store <folder> [--source eslogger|stdin] [--window-secs <n>]
                       [--flow-socket <path>|off]   (default: the system path with eslogger, off with stdin)
                       [--log <file>]               (default: stderr; the file rotates at 1 MB, 5 kept)
  thadam-collector check-registry <file>
  thadam-collector snapshot --registry <file>
  thadam-collector install [--registry <file>] [--store <folder>]   (as root; the system paths by default)
  thadam-collector uninstall                                        (as root; keeps the store, registry and logs)";

/// Longest accepted window (estimate: an hour bounds memory and crash loss).
const MAX_WINDOW_SECS: i64 = 3600;
const REPORT_EVERY: Duration = Duration::from_secs(60);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => cmd_run(&args[1..]),
        Some("check-registry") => cmd_check(&args[1..]),
        Some("snapshot") => cmd_snapshot(&args[1..]),
        Some("install") => cmd_install(&args[1..]),
        Some("uninstall") if args.len() == 1 => cmd_uninstall(),
        _ => Err(Failure::Usage(USAGE.to_string())),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(msg)) => {
            diag!("{msg}");
            ExitCode::from(2)
        }
        Err(Failure::Runtime(msg)) => {
            diag!("thadam-collector: {msg}");
            ExitCode::from(1)
        }
    }
}

enum Failure {
    Usage(String),
    Runtime(String),
}

#[derive(Default)]
struct Options {
    registry: Option<String>,
    store: Option<String>,
    source: Option<String>,
    window_secs: Option<String>,
    flow_socket: Option<String>,
    log: Option<String>,
}

fn parse_options(args: &[String]) -> Result<Options, Failure> {
    let mut o = Options::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let slot = match flag.as_str() {
            "--registry" => &mut o.registry,
            "--store" => &mut o.store,
            "--source" => &mut o.source,
            "--window-secs" => &mut o.window_secs,
            "--flow-socket" => &mut o.flow_socket,
            "--log" => &mut o.log,
            _ => return Err(Failure::Usage(USAGE.to_string())),
        };
        *slot = Some(
            it.next()
                .cloned()
                .ok_or_else(|| Failure::Usage(USAGE.to_string()))?,
        );
    }
    Ok(o)
}

fn load_registry(path: Option<&str>) -> Result<Registry, Failure> {
    let path = path.ok_or_else(|| Failure::Usage(USAGE.to_string()))?;
    let registry = Registry::load(path).map_err(|e| Failure::Usage(e.to_string()))?;
    for tool in registry.tools().filter(|t| t.has_path_matcher()) {
        diag!(
            "warning: tool '{}' is matched by path, which is weaker than code-signing identity",
            tool.key
        );
    }
    Ok(registry)
}

fn cmd_check(args: &[String]) -> Result<(), Failure> {
    let [path] = args else {
        return Err(Failure::Usage(USAGE.to_string()));
    };
    let registry = load_registry(Some(path))?;
    println!("OK    {} tools", registry.tools().count());
    for tool in registry.tools() {
        println!("      {}", tool.key);
    }
    Ok(())
}

fn cmd_snapshot(args: &[String]) -> Result<(), Failure> {
    let o = parse_options(args)?;
    let registry = load_registry(o.registry.as_deref())?;
    let snap = snapshot::take(&SystemProcessTable, &registry)
        .map_err(|e| Failure::Runtime(e.to_string()))?;
    println!(
        "{} session roots, {} member processes",
        snap.roots.len(),
        snap.members.len()
    );
    for root in &snap.roots {
        let key = registry.tool(root.tool).map_or("?", |t| t.key.as_str());
        let members = snap.members.values().filter(|r| **r == root.pid).count();
        println!("  {key}  pid {}  {members} processes", root.pid);
    }
    Ok(())
}

fn cmd_run(args: &[String]) -> Result<(), Failure> {
    let o = parse_options(args)?;
    let registry = load_registry(o.registry.as_deref())?;
    let store_path = o
        .store
        .as_deref()
        .ok_or_else(|| Failure::Usage(USAGE.to_string()))?;
    let mut settings = Settings::default();
    if let Some(w) = o.window_secs.as_deref() {
        let secs: i64 = w
            .parse()
            .ok()
            .filter(|s| (1..=MAX_WINDOW_SECS).contains(s))
            .ok_or_else(|| {
                Failure::Usage(format!("--window-secs must be 1 to {MAX_WINDOW_SECS}"))
            })?;
        settings.window = time::Duration::seconds(secs);
    }
    // The store is a folder of weekly segments with a catalog (ADR-009 Decision 1).
    let store = SegmentWriter::open(
        store_path,
        registry.retention().clone(),
        Box::new(SystemDisk),
    )
    .map_err(|e| Failure::Usage(e.to_string()))?;
    // After the writer lock: a refused second collector never touches the log (diag.rs).
    if let Some(log) = o.log.as_deref() {
        diag::to_file(Path::new(log))
            .map_err(|e| Failure::Usage(format!("cannot open the log: {e}")))?;
    }
    for warning in store.warnings() {
        diag!("thadam-collector: store warning: {warning}");
    }
    let source = o.source.as_deref().unwrap_or("eslogger");
    let flows = open_flow_socket(o.flow_socket.as_deref(), source)?;

    let stop = Arc::new(AtomicBool::new(false));
    let mut signals =
        Signals::new([SIGTERM, SIGINT]).map_err(|e| Failure::Runtime(e.to_string()))?;
    {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            if signals.forever().next().is_some() {
                stop.store(true, Ordering::SeqCst);
            }
        });
    }

    let mut pipeline =
        Pipeline::new(registry, settings).map_err(|e| Failure::Runtime(e.to_string()))?;
    let (ended, stats) = match source {
        "eslogger" => {
            let (child, stdout) = spawn_logger()
                .map_err(|e| Failure::Runtime(format!("cannot start the OS logger: {e}")))?;
            let child = Arc::new(std::sync::Mutex::new(child));
            let killer = Arc::clone(&child);
            let result = run(
                EsloggerSource::new(stdout),
                flows,
                &mut pipeline,
                store,
                &stop,
                seed_from_snapshot,
                move || {
                    if let Ok(mut c) = killer.lock() {
                        let _ = c.kill();
                    }
                },
                REPORT_EVERY,
            );
            if let Ok(mut c) = child.lock() {
                let _ = c.kill();
                let _ = c.wait();
            }
            result
        }
        "stdin" => run(
            EsloggerSource::new(BufReader::new(std::io::stdin())),
            flows,
            &mut pipeline,
            store,
            &stop,
            |_| {},
            || {},
            REPORT_EVERY,
        ),
        _ => return Err(Failure::Usage(USAGE.to_string())),
    }
    .map_err(|e| Failure::Runtime(e.to_string()))?;

    diag!("thadam-collector: final {stats}");
    // A stop request that raced the logger's own exit is still a clean stop.
    let stopped = stop.load(Ordering::SeqCst);
    match (ended, source) {
        (Ended::EndOfInput, "eslogger") if !stopped => Err(Failure::Runtime(
            "the OS logger exited; stopping so the service manager can restart".into(),
        )),
        _ => Ok(()),
    }
}

/// Installs this binary as the launch daemon (ADR-010 Decision 5). Run with sudo; without
/// root the first write fails.
fn cmd_install(args: &[String]) -> Result<(), Failure> {
    let o = parse_options(args)?;
    if o.source.is_some() || o.window_secs.is_some() || o.flow_socket.is_some() || o.log.is_some() {
        return Err(Failure::Usage(USAGE.to_string()));
    }
    let registry = o.registry.as_deref().unwrap_or(service::DEFAULT_REGISTRY);
    let store = o.store.as_deref().unwrap_or(service::DEFAULT_STORE);
    load_registry(Some(registry))?;
    let root = |e: std::io::Error| match e.kind() {
        std::io::ErrorKind::PermissionDenied => Failure::Usage("run install with sudo".into()),
        _ => Failure::Runtime(e.to_string()),
    };
    let bin_dir = Path::new(service::BIN_DIR);
    DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(bin_dir)
        .map_err(root)?;
    if let Some(folder) = service::unsafe_folder(bin_dir, 0).map_err(root)? {
        return Err(Failure::Usage(format!(
            "not installed: {folder} must be owned by root and writable only by root"
        )));
    }
    let me = std::env::current_exe().map_err(root)?;
    if me != Path::new(service::BIN) {
        let tmp = bin_dir.join("thadam-collector.tmp");
        fs::copy(&me, &tmp).map_err(root)?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).map_err(root)?;
        fs::rename(&tmp, service::BIN).map_err(root)?;
    }
    if let Some(dir) = Path::new(service::LOG).parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(dir)
            .map_err(root)?;
    }
    let tmp = format!("{}.tmp", service::PLIST);
    fs::write(
        &tmp,
        service::plist(service::BIN, registry, store, service::LOG),
    )
    .map_err(root)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).map_err(root)?;
    fs::rename(&tmp, service::PLIST).map_err(root)?;

    // A reinstall replaces the running job; "not loaded" is not an error here.
    launchctl(&["bootout", &format!("system/{}", service::LABEL)]);
    if !launchctl(&["bootstrap", "system", service::PLIST]) {
        return Err(Failure::Runtime("launchctl did not load the job".into()));
    }
    println!("Installed: the collector runs from boot and restarts if it stops.");
    println!(
        "First install: allow Full Disk Access for {} in System Settings,",
        service::BIN
    );
    println!(
        "then: sudo launchctl kickstart -k system/{}",
        service::LABEL
    );
    Ok(())
}

fn cmd_uninstall() -> Result<(), Failure> {
    launchctl(&["bootout", &format!("system/{}", service::LABEL)]);
    for path in [service::PLIST, service::BIN] {
        match fs::remove_file(path) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(Failure::Usage("run uninstall with sudo".into()));
            }
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(Failure::Runtime(e.to_string()));
            }
            _ => {}
        }
    }
    println!("Removed the collector daemon. The store, registry and logs are kept.");
    Ok(())
}

/// Runs launchctl; true when it succeeded. Its own messages are not passed on.
fn launchctl(args: &[&str]) -> bool {
    std::process::Command::new("/bin/launchctl")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The network source's socket. A path given explicitly must work; the default is best
/// effort, and the stats line then says `network=off`.
fn open_flow_socket(arg: Option<&str>, source: &str) -> Result<Option<FlowListener>, Failure> {
    match (arg, source) {
        (Some("off"), _) | (None, "stdin") => Ok(None),
        (Some(path), _) => FlowListener::bind(path)
            .map(Some)
            .map_err(|e| Failure::Usage(format!("cannot listen for network flows: {e}"))),
        (None, _) => match FlowListener::bind(DEFAULT_SOCKET) {
            Ok(l) => Ok(Some(l)),
            Err(e) => {
                diag!("thadam-collector: network flows not recorded, cannot listen: {e}");
                Ok(None)
            }
        },
    }
}

fn seed_from_snapshot(pipeline: &mut Pipeline) {
    match snapshot::take(&SystemProcessTable, pipeline.registry()) {
        Ok(snap) => {
            diag!(
                "thadam-collector: snapshot found {} session roots, {} member processes",
                snap.roots.len(),
                snap.members.len()
            );
            pipeline.seed(&snap);
        }
        // Not fatal: processes started from now on are still attributed.
        Err(e) => diag!("thadam-collector: snapshot failed, continuing without it: {e}"),
    }
}
