//! `thadam-hook --tool <key>`: see the library docs. `install-hooks` and `uninstall-hooks`
//! (run with sudo) write and remove the tools' hook configuration.

use std::path::Path;
use std::process::ExitCode;

use thadam_core::AGENT_SOCKET;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--tool") => {
            if let Some(tool) = args.get(1)
                && let Some(payload) = thadam_hook::read_payload(std::io::stdin().lock())
                && let Some(line) = thadam_hook::handle(tool, &payload)
            {
                let _ = thadam_hook::send(Path::new(AGENT_SOCKET), &line);
            }
            // Whatever happened, the tool must see success and no output.
            ExitCode::SUCCESS
        }
        Some("install-hooks") => thadam_hook::install::cli_install(&args[1..]),
        Some("uninstall-hooks") => thadam_hook::install::cli_uninstall(&args[1..]),
        _ => ExitCode::SUCCESS,
    }
}
