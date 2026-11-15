//! Root-managed hook requirements, encoded without a TOML dependency.

use std::fmt::Write as _;

pub const PATH: &str = "/etc/codex/requirements.toml";
const MARKER: &str = "# managed by thadam-hook; do not edit";

pub fn render(hook_bin: &str) -> String {
    let command = thadam_core::hook_command(hook_bin, super::KEY);
    let mut encoded = String::new();
    for c in command.chars() {
        match c {
            '\\' => encoded.push_str("\\\\"),
            '"' => encoded.push_str("\\\""),
            '\u{0}'..='\u{1f}' | '\u{7f}' => {
                let _ = write!(encoded, "\\u{:04X}", u32::from(c));
            }
            _ => encoded.push(c),
        }
    }
    let mut out = format!("{MARKER}\n[features]\nhooks = true\n");
    for event in super::EVENTS {
        let _ = write!(
            out,
            "\n[[hooks.{event}]]\n[[hooks.{event}.hooks]]\ntype = \"command\"\ncommand = \"{encoded}\"\n"
        );
        if *event == "SessionEnd" {
            out.push_str("timeout = 2\n");
        } else {
            out.push_str("async = true\ntimeout = 5\n");
        }
    }
    out
}

pub fn is_ours(existing: &str) -> bool {
    existing.split('\n').next() == Some(MARKER)
}
