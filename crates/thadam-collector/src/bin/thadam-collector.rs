//! `thadam-collector`: records what AI tools do on this Mac (ADR-003 Decision 10).
//!
//! Exit codes: 0 finished or stopped cleanly, 1 runtime failure (including the OS logger
//! exiting on its own, so a service manager restarts the collector), 2 usage or setup error.
//! Diagnostics hold counts only, never paths, arguments or values.

use std::io::BufReader;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use thadam_collector::pipeline::{Pipeline, Settings};
use thadam_collector::registry::Registry;
use thadam_collector::run::{Ended, run, spawn_logger};
use thadam_collector::snapshot::{self, SystemProcessTable};
use thadam_collector::source::eslogger::EsloggerSource;
use thadam_collector::source::network::{DEFAULT_SOCKET, FlowListener};
use thadam_store::{SegmentWriter, SystemDisk};

const USAGE: &str = "usage:
  thadam-collector run --registry <file> --store <folder> [--source eslogger|stdin] [--window-secs <n>]
                       [--flow-socket <path>|off]   (default: the system path with eslogger, off with stdin)
  thadam-collector check-registry <file>
  thadam-collector snapshot --registry <file>";

/// Longest accepted window (estimate: an hour bounds memory and crash loss).
const MAX_WINDOW_SECS: i64 = 3600;
const REPORT_EVERY: Duration = Duration::from_secs(60);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => cmd_run(&args[1..]),
        Some("check-registry") => cmd_check(&args[1..]),
        Some("snapshot") => cmd_snapshot(&args[1..]),
        _ => Err(Failure::Usage(USAGE.to_string())),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(msg)) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
        Err(Failure::Runtime(msg)) => {
            eprintln!("thadam-collector: {msg}");
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
        eprintln!(
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
    for warning in store.warnings() {
        eprintln!("thadam-collector: store warning: {warning}");
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

    eprintln!("thadam-collector: final {stats}");
    // A stop request that raced the logger's own exit is still a clean stop.
    let stopped = stop.load(Ordering::SeqCst);
    match (ended, source) {
        (Ended::EndOfInput, "eslogger") if !stopped => Err(Failure::Runtime(
            "the OS logger exited; stopping so the service manager can restart".into(),
        )),
        _ => Ok(()),
    }
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
                eprintln!("thadam-collector: network flows not recorded, cannot listen: {e}");
                Ok(None)
            }
        },
    }
}

fn seed_from_snapshot(pipeline: &mut Pipeline) {
    match snapshot::take(&SystemProcessTable, pipeline.registry()) {
        Ok(snap) => {
            eprintln!(
                "thadam-collector: snapshot found {} session roots, {} member processes",
                snap.roots.len(),
                snap.members.len()
            );
            pipeline.seed(&snap);
        }
        // Not fatal: processes started from now on are still attributed.
        Err(e) => eprintln!("thadam-collector: snapshot failed, continuing without it: {e}"),
    }
}
