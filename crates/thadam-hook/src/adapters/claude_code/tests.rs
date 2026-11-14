// Payloads rebuilt from the probe's recorded shapes (field names and types), with made-up
// values. Unit tests: unwrap is allowed here.
#![allow(clippy::unwrap_used)]

use serde_json::{Value, json};
use thadam_core::{AgentKind, CallKind, Reason};

use super::parse;

fn base(event: &str) -> Value {
    json!({
        "session_id": "a-51c2e9d0-0000-4000-8000-000000000001",
        "transcript_path": "/Users/dev/.tool-a/projects/sample-app/a-51c2.jsonl",
        "cwd": "/Users/dev/projects/sample-app",
        "scratchpad_dir": "/tmp/tool-a/sample",
        "prompt_id": "p-0001",
        "permission_mode": "default",
        "effort": { "level": "medium" },
        "hook_event_name": event,
    })
}

fn with(mut v: Value, extra: Value) -> Value {
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    v
}

#[test]
fn a_prompt_keeps_its_text_turn_and_transcript() {
    let m = parse(&with(
        base("UserPromptSubmit"),
        json!({ "prompt": "fix the test for dev@example.test" }),
    ))
    .unwrap();
    assert_eq!(m.kind, AgentKind::Prompt);
    assert_eq!(m.text.as_deref(), Some("fix the test for dev@example.test"));
    assert_eq!(m.turn.as_deref(), Some("p-0001"));
    assert_eq!(
        m.transcript.as_deref(),
        Some("/Users/dev/.tool-a/projects/sample-app/a-51c2.jsonl")
    );
}

#[test]
fn a_permission_request_joins_its_call_by_input_hash() {
    let input = json!({ "command": "touch probe-x", "description": "Create a file" });
    let ask = parse(&with(
        base("PermissionRequest"),
        json!({ "tool_name": "Bash", "tool_input": input,
                "permission_suggestions": [{ "type": "addDirectories", "directories": ["/Users/dev"] }] }),
    ))
    .unwrap();
    let call = parse(&with(
        base("PreToolUse"),
        json!({ "tool_name": "Bash", "tool_input": input, "tool_use_id": "toolu_0001" }),
    ))
    .unwrap();
    assert_eq!(ask.kind, AgentKind::PermissionRequest);
    assert_eq!(ask.call, None);
    assert_eq!(call.call.as_deref(), Some("toolu_0001"));
    assert_eq!(ask.input_hash, call.input_hash);
    assert_eq!(ask.input_hash.as_ref().map(String::len), Some(64));
    assert_eq!(call.call_kind, Some(CallKind::Shell));
    assert_eq!(call.text.as_deref(), Some("touch probe-x"));
}

#[test]
fn file_text_responses_and_replies_never_reach_the_message() {
    let edit = with(
        base("PostToolUse"),
        json!({
            "tool_name": "Edit",
            "tool_input": { "file_path": "/Users/dev/projects/sample-app/a.txt",
                            "old_string": "SECRET-OLD", "new_string": "SECRET-NEW", "replace_all": false },
            "tool_response": { "originalFile": "SECRET-FILE", "structuredPatch": [] },
            "tool_use_id": "toolu_0002",
            "duration_ms": 12,
        }),
    );
    let m = parse(&edit).unwrap();
    assert_eq!(m.call_kind, Some(CallKind::FileWrite));
    assert_eq!(
        m.text.as_deref(),
        Some("/Users/dev/projects/sample-app/a.txt")
    );
    let line = serde_json::to_string(&m).unwrap();
    assert!(!line.contains("SECRET"), "{line}");

    let stop = with(
        base("Stop"),
        json!({ "stop_hook_active": false, "last_assistant_message": "SECRET-REPLY",
                "background_tasks": [], "session_crons": [] }),
    );
    let line = serde_json::to_string(&parse(&stop).unwrap()).unwrap();
    assert!(!line.contains("SECRET"), "{line}");

    // A subagent prompt and a message to another tool keep the tool name only.
    let agent = with(
        base("PreToolUse"),
        json!({ "tool_name": "Agent", "tool_use_id": "toolu_0003",
                "tool_input": { "description": "x", "subagent_type": "general", "prompt": "SECRET-TASK" } }),
    );
    let m = parse(&agent).unwrap();
    assert_eq!(m.call_kind, Some(CallKind::Other));
    assert!(!serde_json::to_string(&m).unwrap().contains("SECRET"));
}

#[test]
fn a_failure_keeps_the_interrupt_flag_and_subagent_calls_are_labelled() {
    let m = parse(&with(
        base("PostToolUseFailure"),
        json!({ "tool_name": "Bash", "tool_input": { "command": "false" }, "tool_use_id": "toolu_0004",
                "error": "Exit code 1", "is_interrupt": false, "duration_ms": 3,
                "agent_id": "ag-1", "agent_type": "general" }),
    ))
    .unwrap();
    assert_eq!(m.kind, AgentKind::CallFailed);
    assert_eq!(m.interrupted, Some(false));
    assert_eq!(m.subagent.as_deref(), Some("general"));
    assert!(!serde_json::to_string(&m).unwrap().contains("Exit code"));
}

#[test]
fn session_reasons_come_from_a_fixed_set() {
    let start = parse(&with(
        base("SessionStart"),
        json!({ "source": "startup", "model": "m" }),
    ))
    .unwrap();
    assert_eq!(start.reason, Some(Reason::Startup));
    let end = parse(&with(
        base("SessionEnd"),
        json!({ "reason": "prompt_input_exit" }),
    ))
    .unwrap();
    assert_eq!(end.reason, Some(Reason::Exit));
    let odd = parse(&with(
        base("SessionEnd"),
        json!({ "reason": "free text from the tool" }),
    ))
    .unwrap();
    assert_eq!(odd.reason, Some(Reason::Other));
}

#[test]
fn unknown_events_and_payloads_without_a_session_are_dropped() {
    assert!(parse(&base("Notification")).is_none());
    assert!(parse(&base("SubagentStop")).is_none());
    let mut v = base("UserPromptSubmit");
    v["session_id"] = Value::Null;
    assert!(parse(&v).is_none());
    assert!(parse(&json!([1, 2])).is_none());
}

#[test]
fn every_configured_event_is_parsed() {
    for e in super::EVENTS {
        let v = with(
            base(e),
            json!({ "tool_name": "Bash", "tool_input": { "command": "ls" } }),
        );
        assert!(parse(&v).is_some(), "{e}");
    }
}
