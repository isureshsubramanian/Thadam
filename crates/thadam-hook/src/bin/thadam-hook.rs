//! `thadam-hook --tool <key>`: see the library docs. `install-hooks` and `uninstall-hooks`
//! (run with sudo) write and remove the tools' hook configuration.

use std::path::Path;
use std::process::ExitCode;

use std::io::Write;

use thadam_core::AGENT_SOCKET;
use thadam_core::guard::REGISTRY;
use thadam_hook::guard::{MAX_LSTATS, Registry, resolve_links};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--tool") => {
            if let Some(tool) = args.get(1)
                && let Some(payload) = thadam_hook::read_payload(std::io::stdin().lock())
            {
                // `HOME` comes from the tool's own process, which the agent's commands can't
                // change; it only expands `~/` in the paths the call names.
                let home = std::env::var("HOME").ok();
                let mut budget = MAX_LSTATS;
                let mut resolve = |p: &str| resolve_links(p, &mut budget);
                let reply = thadam_hook::run(
                    tool,
                    &payload,
                    &|| Registry::read(Path::new(REGISTRY)),
                    home.as_deref(),
                    &mut resolve,
                );
                // The refusal goes out first: the tool waits for this process to exit.
                if let Some(out) = reply.stdout {
                    let mut stdout = std::io::stdout().lock();
                    let _ = stdout
                        .write_all(out.as_bytes())
                        .and_then(|()| stdout.flush());
                }
                if let Some(line) = reply.line {
                    let _ = thadam_hook::send(Path::new(AGENT_SOCKET), &line);
                }
            }
            // Whatever happened, the tool must see success; any output is the guard's refusal.
            ExitCode::SUCCESS
        }
        Some("install-hooks") => thadam_hook::install::cli_install(&args[1..]),
        Some("uninstall-hooks") => thadam_hook::install::cli_uninstall(&args[1..]),
        _ => ExitCode::SUCCESS,
    }
}
