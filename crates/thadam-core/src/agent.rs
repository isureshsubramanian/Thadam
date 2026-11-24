//! Wire format `thadam.agent.v1` (ADR-011 Decision 3): one JSON line per hook event, sent
//! by `thadam-hook` to the collector's agent socket.
//!
//! CONTRACT: written by `thadam-hook` (adapters), read by the collector. Only the fields
//! ADR-011 Decision 4 allows are here; there is no field that could carry a file's text, a
//! tool's response or an assistant reply. Unknown fields are refused on arrival.
//!
//! The `tool` and session fields are what the tool claims. The collector attributes a
//! message by its sender's process, never by these (Decision 3).

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::guard::GuardResult;
use crate::model::{MAX_PATH, MAX_SESSION_ID, MAX_TARGET_INPUT, MAX_TOOL_KEY};

pub const AGENT_WIRE: &str = "thadam.agent.v1";
/// Where `thadam-hook install-hooks` puts the hook program, beside the collector. The
/// collector accepts agent messages only from a process running this file.
pub const HOOK_BIN: &str = "/Library/Application Support/Thadam/bin/thadam-hook";
/// The collector's agent socket (folder 0755, socket 0666, both root-owned).
pub const AGENT_SOCKET: &str = "/var/run/thadam-agent/agent.sock";
/// The shell command a tool's hook configuration runs: the hook path single-quoted (it
/// contains a space), then `--tool <key>`. The adapters render it and the collector recognises
/// the hook's own runs by it, so both sides use this one function.
pub fn hook_command(hook_bin: &str, tool_key: &str) -> String {
    format!("'{}' --tool {tool_key}", hook_bin.replace('\'', "'\\''"))
}

/// Longest accepted tool-side name (a tool or subagent name), in bytes. An estimate.
pub const MAX_NAME: usize = 128;

/// What happened, in the tool's own terms. Mapped from each tool's hook events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    SessionStart,
    /// The user submitted a prompt (`text` is the prompt).
    Prompt,
    /// The tool is about to ask the user to approve a call. Carries no call ID in either
    /// tool; joined to its call by `input_hash` within the turn (amendment 1).
    PermissionRequest,
    /// A call is about to run (before any approval).
    CallStart,
    CallDone,
    CallFailed,
    /// The tool's own rule or classifier refused a call.
    Denied,
    /// The tool finished answering a prompt.
    TurnEnd,
    SessionEnd,
}

/// What a call does, from the tool name and its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    /// `text` is the command line.
    Shell,
    /// `text` is the file path.
    FileRead,
    /// `text` is the file path, when the tool gave one.
    FileWrite,
    /// A file search or listing; `text` is the folder (or file) it searches (ADR-018).
    Search,
    /// Anything else (search, web, subagents, other tools): name only, no `text`.
    Other,
}

/// Why a session started or ended, from a fixed set (never the tool's free text).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Startup,
    Resume,
    Clear,
    Compact,
    Exit,
    Logout,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct AgentMessage {
    /// Always `AGENT_WIRE`.
    #[garde(custom(is_wire))]
    pub v: String,
    /// Registry key of the tool the hook was configured for.
    #[garde(length(min = 1, max = MAX_TOOL_KEY))]
    pub tool: String,
    #[garde(skip)]
    pub kind: AgentKind,
    /// The tool's own session ID.
    #[garde(length(min = 1, max = MAX_SESSION_ID))]
    pub agent_session_id: String,
    /// The tool's transcript file. `None` for a tool's helper session (amendment 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(inner(length(min = 1, max = MAX_PATH)))]
    pub transcript: Option<String>,
    /// The prompt (turn) this event belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(inner(length(min = 1, max = MAX_SESSION_ID)))]
    pub turn: Option<String>,
    /// The tool's call ID, when the event has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(inner(length(min = 1, max = MAX_SESSION_ID)))]
    pub call: Option<String>,
    /// SHA-256 (hex) of the call's input as the adapter defines it, for joining a
    /// permission request to its call. Never the input itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(inner(length(min = 64, max = 64), custom(is_hex)))]
    pub input_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(inner(length(min = 1, max = MAX_NAME)))]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub call_kind: Option<CallKind>,
    /// The prompt, the command line or the file path, unredacted: the collector redacts it
    /// before it is stored, as it does for OS events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(inner(length(max = MAX_TARGET_INPUT)))]
    pub text: Option<String>,
    /// The subagent that made the call, by its type name (amendment 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(inner(length(min = 1, max = MAX_NAME)))]
    pub subagent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub reason: Option<Reason>,
    /// The user stopped the call while it ran (a failure event's flag).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub interrupted: Option<bool>,
    /// What Thadam's guard did to this call (ADR-018), on a call start only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub guard: Option<GuardResult>,
}

impl AgentMessage {
    /// A message of `kind` with only the required fields set.
    pub fn new(tool: &str, kind: AgentKind, agent_session_id: &str) -> Self {
        Self {
            v: AGENT_WIRE.to_string(),
            tool: tool.to_string(),
            kind,
            agent_session_id: agent_session_id.to_string(),
            transcript: None,
            turn: None,
            call: None,
            input_hash: None,
            tool_name: None,
            call_kind: None,
            text: None,
            subagent: None,
            reason: None,
            interrupted: None,
            guard: None,
        }
    }
}

fn is_wire(value: &str, _ctx: &()) -> garde::Result {
    if value == AGENT_WIRE {
        Ok(())
    } else {
        Err(garde::Error::new("unknown wire version"))
    }
}

fn is_hex(value: &str, _ctx: &()) -> garde::Result {
    if value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(garde::Error::new("not lower-case hex"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_unknown_fields() {
        let mut m = AgentMessage::new("tool-a", AgentKind::CallStart, "a-51c2");
        m.call_kind = Some(CallKind::Shell);
        m.text = Some("ls".into());
        let line = serde_json::to_string(&m).unwrap();
        assert_eq!(
            line,
            r#"{"v":"thadam.agent.v1","tool":"tool-a","kind":"call_start","agent_session_id":"a-51c2","call_kind":"shell","text":"ls"}"#
        );
        let back: AgentMessage = serde_json::from_str(&line).unwrap();
        assert_eq!(back, m);
        assert!(back.validate().is_ok());
        let extra = line.replace(r#""text":"ls""#, r#""text":"ls","tool_response":"x""#);
        assert!(serde_json::from_str::<AgentMessage>(&extra).is_err());
    }

    #[test]
    fn validation_checks_meaning() {
        let mut m = AgentMessage::new("tool-a", AgentKind::Prompt, "a-51c2");
        assert!(m.validate().is_ok());
        m.v = "thadam.agent.v0".into();
        assert!(m.validate().is_err());
        let mut m = AgentMessage::new("tool-a", AgentKind::Prompt, "");
        assert!(m.validate().is_err());
        m.agent_session_id = "a".into();
        m.input_hash = Some("A".repeat(64));
        assert!(m.validate().is_err());
        m.input_hash = Some("a".repeat(64));
        assert!(m.validate().is_ok());
    }
}
