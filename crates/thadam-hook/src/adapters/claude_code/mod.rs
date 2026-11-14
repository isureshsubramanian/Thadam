//! Claude Code hooks (payload shapes from the ADR-011 probe, 14-15 Nov 2026).
//!
//! Join key (amendment 1): every event of a turn carries `prompt_id`; a permission request
//! has no `tool_use_id` but the same `tool_input` as the call that follows, so the input
//! hash covers the whole `tool_input`.

mod config;

use serde_json::Value;
use thadam_core::{AgentKind, AgentMessage, CallKind, Reason};

use super::{Adapter, HookConfig, sha256_hex, text};

pub const KEY: &str = "claude_code";

/// HIDDEN COUPLING: `config::render` subscribes to exactly these events.
pub const EVENTS: &[&str] = &[
    "SessionStart",
    "UserPromptSubmit",
    "PermissionRequest",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PermissionDenied",
    "Stop",
    "SessionEnd",
];

pub const ADAPTER: Adapter = Adapter {
    key: KEY,
    events: EVENTS,
    parse,
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
        "PostToolUseFailure" => AgentKind::CallFailed,
        "PermissionDenied" => AgentKind::Denied,
        "Stop" => AgentKind::TurnEnd,
        "SessionEnd" => AgentKind::SessionEnd,
        _ => return None,
    };
    let mut m = AgentMessage::new(KEY, kind, &text(p, "session_id")?);
    m.transcript = text(p, "transcript_path");
    m.turn = text(p, "prompt_id");
    match kind {
        AgentKind::SessionStart => m.reason = Some(start_reason(p)),
        AgentKind::SessionEnd => m.reason = Some(end_reason(p)),
        AgentKind::Prompt => m.text = Some(text(p, "prompt").unwrap_or_default()),
        AgentKind::TurnEnd => {}
        AgentKind::PermissionRequest
        | AgentKind::CallStart
        | AgentKind::CallDone
        | AgentKind::CallFailed
        | AgentKind::Denied => {
            let name = text(p, "tool_name")?;
            let input = p.get("tool_input").unwrap_or(&Value::Null);
            // serde_json's map is sorted by key, so equal inputs hash equally.
            m.input_hash = Some(sha256_hex(input.to_string().as_bytes()));
            let (call_kind, call_text) = classify(&name, input);
            m.call_kind = Some(call_kind);
            m.text = call_text;
            m.tool_name = Some(name);
            m.call = text(p, "tool_use_id");
            m.subagent = text(p, "agent_type");
            if kind == AgentKind::CallFailed {
                m.interrupted = p.get("is_interrupt").and_then(Value::as_bool);
            }
        }
    }
    Some(m)
}

/// Keeps the command line or the path; drops everything else in the input (file text,
/// replacement strings, prompts to subagents).
fn classify(name: &str, input: &Value) -> (CallKind, Option<String>) {
    match name {
        "Bash" => (CallKind::Shell, text(input, "command")),
        "Read" => (CallKind::FileRead, text(input, "file_path")),
        "Write" | "Edit" | "MultiEdit" => (CallKind::FileWrite, text(input, "file_path")),
        "NotebookEdit" => (CallKind::FileWrite, text(input, "notebook_path")),
        _ => (CallKind::Other, None),
    }
}

fn start_reason(p: &Value) -> Reason {
    match p.get("source").and_then(Value::as_str) {
        Some("startup") => Reason::Startup,
        Some("resume") => Reason::Resume,
        Some("clear") => Reason::Clear,
        Some("compact") => Reason::Compact,
        _ => Reason::Other,
    }
}

fn end_reason(p: &Value) -> Reason {
    match p.get("reason").and_then(Value::as_str) {
        Some("prompt_input_exit") => Reason::Exit,
        Some("clear") => Reason::Clear,
        Some("logout") => Reason::Logout,
        _ => Reason::Other,
    }
}

#[cfg(test)]
mod tests;
