// Payloads rebuilt from the probe's recorded shapes, with made-up values. Unit tests:
// unwrap is allowed here.
#![allow(clippy::unwrap_used)]

use serde_json::{Value, json};
use thadam_core::{AgentKind, CallKind, Reason};

use super::parse;

fn base(event: &str, transcript: Value) -> Value {
    json!({
        "session_id": "b-77aa0000-0000-4000-8000-000000000001",
        "turn_id": "t-0001",
        "transcript_path": transcript,
        "cwd": "/Users/dev/projects/sample-app",
        "hook_event_name": event,
        "model": "model-a",
        "permission_mode": "default",
    })
}

fn main_session(event: &str) -> Value {
    base(event, json!("/Users/dev/.tool-b/sessions/b-77aa.jsonl"))
}

fn with(mut v: Value, extra: Value) -> Value {
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    v
}

#[test]
fn a_permission_request_joins_its_call_by_the_command_alone() {
    let ask = parse(&with(
        main_session("PermissionRequest"),
        json!({ "tool_name": "Bash",
                "tool_input": { "command": "touch probe-y", "description": "Create a file" } }),
    ))
    .unwrap();
    let call = parse(&with(
        main_session("PreToolUse"),
        json!({ "tool_name": "Bash", "tool_input": { "command": "touch probe-y" },
                "tool_use_id": "call_0001" }),
    ))
    .unwrap();
    assert_eq!(ask.kind, AgentKind::PermissionRequest);
    assert_eq!(ask.input_hash, call.input_hash);
    assert!(ask.input_hash.is_some());
    assert_eq!(ask.turn.as_deref(), Some("t-0001"));
    assert_eq!(call.text.as_deref(), Some("touch probe-y"));
    assert_eq!(call.call.as_deref(), Some("call_0001"));
}

#[test]
fn a_helper_session_has_no_transcript() {
    let m = parse(&with(
        base("UserPromptSubmit", Value::Null),
        json!({ "prompt": "summarise the conversation" }),
    ))
    .unwrap();
    assert_eq!(m.transcript, None);
    assert_eq!(m.kind, AgentKind::Prompt);
}

#[test]
fn responses_replies_and_patches_are_dropped() {
    let done = with(
        main_session("PostToolUse"),
        json!({ "tool_name": "Bash", "tool_input": { "command": "ls" },
                "tool_response": "SECRET-OUTPUT", "tool_use_id": "call_0002" }),
    );
    assert!(
        !serde_json::to_string(&parse(&done).unwrap())
            .unwrap()
            .contains("SECRET")
    );
    let stop = with(
        main_session("Stop"),
        json!({ "stop_hook_active": false, "last_assistant_message": "SECRET-REPLY" }),
    );
    assert!(
        !serde_json::to_string(&parse(&stop).unwrap())
            .unwrap()
            .contains("SECRET")
    );
    let patch = with(
        main_session("PreToolUse"),
        json!({ "tool_name": "apply_patch", "tool_input": { "command": "*** SECRET-PATCH" },
                "tool_use_id": "call_0003" }),
    );
    let m = parse(&patch).unwrap();
    assert_eq!(m.call_kind, Some(CallKind::FileWrite));
    assert_eq!(m.text, None);
}

#[test]
fn every_configured_event_is_parsed() {
    for e in super::EVENTS {
        let v = with(
            main_session(e),
            json!({ "tool_name": "Bash", "tool_input": { "command": "ls" },
                                              "source": "startup" }),
        );
        assert!(parse(&v).is_some(), "{e}");
    }
    let start = parse(&with(
        main_session("SessionStart"),
        json!({ "source": "startup" }),
    ))
    .unwrap();
    assert_eq!(start.reason, Some(Reason::Startup));
    assert!(parse(&main_session("PostToolUseFailure")).is_none());
}
