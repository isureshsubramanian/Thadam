//! Codex hooks (payload shapes from the ADR-011 probe, 15 Nov 2026).
//!
//! Join key (amendment 1): `turn_id`; a permission request's `tool_input` holds the command
//! and a description while the call's holds the command only, so the input hash covers
//! `tool_input.command` alone. A helper session has a null `transcript_path`; it is sent
//! without one and the collector marks its rows internal.

mod config;

use serde_json::Value;
use thadam_core::{AgentKind, AgentMessage, CallKind, Reason};

use super::{Adapter, HookConfig, sha256_hex, text};

pub const KEY: &str = "codex";

/// HIDDEN COUPLING: `config::render` subscribes to exactly these events. SessionEnd is
/// configured although the probe never saw it fire (the collector also closes a session
/// when the tool's process exits).
pub const EVENTS: &[&str] = &[
    "SessionStart",
    "UserPromptSubmit",
    "PermissionRequest",
    "PreToolUse",
    "PostToolUse",
    "Stop",
    "SessionEnd",
];

pub const ADAPTER: Adapter = Adapter {
    key: KEY,
    events: EVENTS,
    parse,
    // Not confirmed that a managed Codex hook can refuse a call (ADR-018 probe).
    deny: None,
    config: HookConfig {
        path: config::PATH,
        render: config::render,
        is_ours: config::is_ours,
    },
};

fn parse(p: &Value) -> Option<AgentMessage> {
    let kind = match p.get("hook_event_name")?.as_str()? {
        "SessionStart" => AgentKind::SessionStart,
        "UserPromptSubmit" => AgentKind::Prompt,
        "PermissionRequest" => AgentKind::PermissionRequest,
        "PreToolUse" => AgentKind::CallStart,
        "PostToolUse" => AgentKind::CallDone,
        "Stop" => AgentKind::TurnEnd,
        "SessionEnd" => AgentKind::SessionEnd,
        _ => return None,
    };
    let mut m = AgentMessage::new(KEY, kind, &text(p, "session_id")?);
    m.transcript = text(p, "transcript_path");
    m.turn = text(p, "turn_id");
    match kind {
        AgentKind::SessionStart => {
            m.reason = Some(match p.get("source").and_then(Value::as_str) {
                Some("startup") => Reason::Startup,
                Some("resume") => Reason::Resume,
                _ => Reason::Other,
            });
        }
        AgentKind::SessionEnd => m.reason = Some(Reason::Other),
        AgentKind::Prompt => m.text = Some(text(p, "prompt").unwrap_or_default()),
        AgentKind::TurnEnd => {}
        _ => {
            let name = text(p, "tool_name")?;
            let input = p.get("tool_input").unwrap_or(&Value::Null);
            let command = text(input, "command");
            m.input_hash = command.as_deref().map(|c| sha256_hex(c.as_bytes()));
            m.call_kind = Some(match name.as_str() {
                "Bash" => CallKind::Shell,
                // A patch names its files inside its text, which is never kept.
                "apply_patch" => CallKind::FileWrite,
                _ => CallKind::Other,
            });
            if m.call_kind == Some(CallKind::Shell) {
                m.text = command;
            }
            m.tool_name = Some(name);
            m.call = text(p, "tool_use_id");
        }
    }
    Some(m)
}

#[cfg(test)]
mod tests;
