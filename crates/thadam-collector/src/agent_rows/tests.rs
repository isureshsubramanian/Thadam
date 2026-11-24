// Event sequences from the ADR-011 probe (14-15 Nov 2026), with made-up values. Unit tests:
// unwrap/expect are allowed here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use thadam_core::{AgentKind, AgentMessage, CallKind, Flag, NewEvent, Outcome};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

use super::{AgentRows, CALL_TIMEOUT, CLOSE_GRACE, Lookup};
use crate::registry::ToolId;
use crate::source::agent::Peer;
use crate::tree::Membership;

const HOOK: &str = "/synthetic/bin/thadam-hook";
const T0: OffsetDateTime = datetime!(2026-11-15 10:00 UTC);
/// The hook process the tests send from.
const HOOK_PEER: Peer = Peer {
    pid: 900,
    pidversion: 7,
};
/// Some other program in the same session.
const OTHER_PEER: Peer = Peer {
    pid: 901,
    pidversion: 1,
};

fn membership() -> Membership {
    Membership {
        tool: ToolId::for_tests(0),
        session_id: Arc::from("s-thadam-1"),
        project: Some(Arc::from("/Users/dev/projects/sample-app")),
        root_pid: 500,
        parent_session_id: None,
    }
}

fn lookup() -> Box<Lookup<'static>> {
    Box::new(|p: Peer| match p {
        HOOK_PEER => Some((membership(), Some(Arc::from(HOOK)))),
        OTHER_PEER => Some((membership(), Some(Arc::from("/bin/sh")))),
        _ => None,
    })
}

fn sender(_: &Membership) -> Option<(String, String)> {
    Some(("tool-a".into(), "/synthetic/bin/tool-a".into()))
}

fn at(secs: i64) -> OffsetDateTime {
    T0 + Duration::seconds(secs)
}

fn msg(kind: AgentKind) -> AgentMessage {
    let mut m = AgentMessage::new("claimed-tool", kind, "a-51c2");
    m.transcript = Some("/Users/dev/.tool-a/a-51c2.jsonl".into());
    m.turn = Some("p-1".into());
    m
}

fn call(kind: AgentKind, id: &str, command: &str) -> AgentMessage {
    let mut m = msg(kind);
    m.call = (!id.is_empty()).then(|| id.to_string());
    m.input_hash = Some(format!("{:0>64}", command.len()));
    m.tool_name = Some("Shell".into());
    m.call_kind = Some(CallKind::Shell);
    m.text = Some(command.to_string());
    m
}

struct Run {
    rows: AgentRows,
    out: Vec<NewEvent>,
}

impl Run {
    fn new() -> Self {
        Self {
            rows: AgentRows::new(HOOK),
            out: Vec::new(),
        }
    }

    /// Sends from the hook at `secs`, then lets the OS stream pass that time.
    fn send(&mut self, secs: i64, m: AgentMessage) -> &mut Self {
        self.send_from(HOOK_PEER, secs, m)
    }

    fn send_from(&mut self, peer: Peer, secs: i64, m: AgentMessage) -> &mut Self {
        self.rows.hold(at(secs), peer, Box::new(m));
        let rows = self.rows.release(Some(at(secs)), &*lookup(), &sender);
        self.out.extend(rows);
        self
    }

    fn advance(&mut self, secs: i64) -> &mut Self {
        let rows = self.rows.advance(at(secs));
        self.out.extend(rows);
        self
    }
}

#[test]
fn a_prompt_becomes_a_row_of_the_senders_session() {
    let mut r = Run::new();
    let mut m = msg(AgentKind::Prompt);
    m.text = Some("fix the failing test".into());
    r.send(0, m);
    let [row] = r.out.as_slice() else {
        panic!("{:?}", r.out)
    };
    assert_eq!(row.target, "fix the failing test");
    // The tool and session come from the sender's process, not from the message.
    assert_eq!(row.tool, "tool-a");
    assert_eq!(row.session_id.as_deref(), Some("s-thadam-1"));
    assert_eq!(row.pid, 500);
    assert_eq!(row.outcome, Outcome::Allowed);
    let link = row.agent.as_ref().unwrap();
    assert_eq!(link.session_id, "a-51c2");
    assert_eq!(
        link.transcript.as_deref(),
        Some("/Users/dev/.tool-a/a-51c2.jsonl")
    );
    assert!(row.flags.is_empty());
}

#[test]
fn only_the_hook_program_inside_a_session_may_send() {
    let mut r = Run::new();
    r.send_from(OTHER_PEER, 0, msg(AgentKind::Prompt));
    r.send_from(
        Peer {
            pid: 1,
            pidversion: 1,
        },
        1,
        msg(AgentKind::Prompt),
    );
    assert!(r.out.is_empty());
    assert_eq!(r.rows.stats.refused, 2);
    assert_eq!(r.rows.stats.accepted, 0);
}

#[test]
fn a_message_waits_for_the_os_stream() {
    let mut rows = AgentRows::new(HOOK);
    rows.hold(at(10), HOOK_PEER, Box::new(msg(AgentKind::Prompt)));
    assert!(rows.release(Some(at(9)), &*lookup(), &sender).is_empty());
    assert_eq!(rows.held(), 1);
    assert_eq!(rows.release(Some(at(10)), &*lookup(), &sender).len(), 1);
    assert_eq!(rows.held(), 0);
}

#[test]
fn an_approval_asked_and_then_nothing_is_a_decline() {
    // Default mode, declined: request + start, no result, no turn end; the next prompt.
    let mut r = Run::new();
    r.send(0, call(AgentKind::PermissionRequest, "", "touch probe-x"))
        .send(0, call(AgentKind::CallStart, "c-1", "touch probe-x"))
        .send(12, msg(AgentKind::Prompt));
    assert_eq!(r.out.len(), 1, "only the prompt so far");
    r.advance(12 + CLOSE_GRACE.whole_seconds());
    let decline = r.out.last().unwrap();
    assert_eq!(decline.outcome, Outcome::DeniedByUser);
    assert!(decline.flags.contains(&Flag::Unconfirmed));
    assert_eq!(decline.target, "touch probe-x");
    assert_eq!(decline.ts, at(0));
    assert_eq!(r.rows.stats.declines, 1);
}

#[test]
fn the_request_may_arrive_after_the_call_start() {
    let mut r = Run::new();
    r.send(0, call(AgentKind::CallStart, "c-1", "touch probe-x"))
        .send(0, call(AgentKind::PermissionRequest, "", "touch probe-x"))
        .send(3, msg(AgentKind::TurnEnd))
        .advance(3 + CLOSE_GRACE.whole_seconds());
    assert_eq!(r.out.len(), 1);
    assert_eq!(r.out[0].outcome, Outcome::DeniedByUser);
}

#[test]
fn calls_that_finish_or_fail_make_no_row() {
    let mut r = Run::new();
    r.send(0, call(AgentKind::CallStart, "c-1", "ls"))
        .send(1, call(AgentKind::CallDone, "c-1", "ls"))
        // A failure fires both events in one tool.
        .send(2, call(AgentKind::CallStart, "c-2", "false"))
        .send(3, call(AgentKind::CallFailed, "c-2", "false"))
        .send(3, call(AgentKind::CallDone, "c-2", "false"))
        .send(4, msg(AgentKind::TurnEnd))
        .advance(60);
    assert!(r.out.is_empty(), "{:?}", r.out);
}

#[test]
fn a_late_result_within_the_grace_still_counts() {
    let mut r = Run::new();
    r.send(0, call(AgentKind::CallStart, "c-1", "ls"))
        .send(1, msg(AgentKind::TurnEnd))
        .send(2, call(AgentKind::CallDone, "c-1", "ls"))
        .advance(60);
    assert!(r.out.is_empty(), "{:?}", r.out);
}

#[test]
fn without_an_approval_an_unfinished_call_never_ran() {
    // Auto mode: no request at all.
    let mut r = Run::new();
    r.send(0, call(AgentKind::CallStart, "c-1", "touch probe-x"))
        .send(2, msg(AgentKind::TurnEnd))
        .advance(2 + CLOSE_GRACE.whole_seconds());
    assert_eq!(r.out.len(), 1);
    assert_eq!(r.out[0].outcome, Outcome::NeverRan);
    assert!(r.out[0].flags.contains(&Flag::Unconfirmed));
    assert_eq!(r.rows.stats.never_ran, 1);
}

#[test]
fn an_os_exec_of_the_command_means_it_ran() {
    // One tool reports no result for a failed command (amendment 1).
    let mut r = Run::new();
    let session: Arc<str> = Arc::from("s-thadam-1");
    r.send(0, call(AgentKind::CallStart, "c-1", "make test"));
    r.rows.saw_exec(&session, "/bin/zsh -lc make test", at(1));
    // The exec may also be seen first: hooks run asynchronously.
    r.rows.saw_exec(&session, "/bin/zsh -lc cargo build", at(2));
    r.send(3, call(AgentKind::CallStart, "c-2", "cargo build"))
        .send(4, msg(AgentKind::TurnEnd))
        .advance(60);
    assert!(r.out.is_empty(), "{:?}", r.out);
}

#[test]
fn the_tools_own_refusal_is_denied_by_agent() {
    let mut r = Run::new();
    r.send(0, call(AgentKind::CallStart, "c-1", "rm -rf build"))
        .send(0, call(AgentKind::Denied, "c-1", "rm -rf build"))
        .advance(60);
    assert_eq!(r.out.len(), 1);
    assert_eq!(r.out[0].outcome, Outcome::DeniedByAgent);
    assert_eq!(r.out[0].target, "rm -rf build");
}

#[test]
fn a_helper_session_without_a_transcript_is_internal() {
    let mut r = Run::new();
    let mut m = msg(AgentKind::Prompt);
    m.agent_session_id = "a-helper".into();
    m.transcript = None;
    m.text = Some("summarise".into());
    r.send(0, m);
    assert!(r.out[0].flags.contains(&Flag::Internal));
    assert_eq!(r.out[0].agent.as_ref().unwrap().transcript, None);
}

#[test]
fn the_tools_exit_closes_what_is_waiting() {
    // One tool never fires its session end; the OS sees its process exit.
    let mut r = Run::new();
    r.send(0, call(AgentKind::CallStart, "c-1", "touch probe-y"));
    r.rows.session_ended(&Arc::from("s-thadam-1"), at(5));
    r.advance(5 + CLOSE_GRACE.whole_seconds());
    assert_eq!(r.out.len(), 1);
    assert_eq!(r.out[0].outcome, Outcome::NeverRan);
}

#[test]
fn a_call_left_waiting_closes_after_the_timeout() {
    let mut r = Run::new();
    r.send(0, call(AgentKind::CallStart, "c-1", "sleep 1"));
    r.advance(CALL_TIMEOUT.whole_seconds() - 1);
    assert!(r.out.is_empty());
    r.advance(CALL_TIMEOUT.whole_seconds());
    assert_eq!(r.out.len(), 1);
}

#[test]
fn finish_closes_everything_and_never_duplicates_a_call() {
    let mut r = Run::new();
    r.send(0, call(AgentKind::CallStart, "c-1", "ls"))
        .send(0, call(AgentKind::CallStart, "c-1", "ls"));
    let rows = r.rows.finish(&*lookup(), &sender);
    assert_eq!(rows.len(), 1);
}

#[test]
fn other_tools_are_recorded_by_name() {
    let mut r = Run::new();
    let mut m = call(AgentKind::CallStart, "c-1", "");
    m.call_kind = Some(CallKind::Other);
    m.text = None;
    m.tool_name = Some("WebFetch".into());
    r.send(0, m).send(1, msg(AgentKind::TurnEnd)).advance(60);
    assert_eq!(r.out[0].target, "WebFetch");
}

mod hook_runs {
    use crate::source::{EventKind, Identity, OsEvent, ProcessRef};

    use super::{AgentRows, HOOK, T0};

    fn process(executable: &str) -> ProcessRef {
        ProcessRef {
            pid: 910,
            pidversion: 1,
            ppid: 500,
            responsible_pid: None,
            executable: executable.into(),
            identity: Identity::default(),
        }
    }

    fn ev(by: &str, kind: EventKind) -> OsEvent {
        OsEvent {
            ts: T0,
            seq: 1,
            process: process(by),
            kind,
        }
    }

    fn exec(target: &str, args: &[&str]) -> EventKind {
        EventKind::Exec {
            target: process(target),
            args: args.iter().map(|a| a.to_string()).collect(),
            cwd: Some("/Users/dev/projects/sample-app".into()),
        }
    }

    fn open(path: &str, writable: bool) -> EventKind {
        EventKind::Open {
            path: path.into(),
            readable: true,
            writable,
            size: None,
        }
    }

    #[test]
    fn the_hook_and_its_exact_wrapper_are_hook_runs() {
        let rows = AgentRows::new(HOOK);
        let command = format!("'{HOOK}' --tool tool_a");
        for (by, kind) in [
            ("/bin/zsh", exec(HOOK, &[HOOK, "--tool", "tool_a"])),
            (
                "/synthetic/bin/tool-a",
                exec("/bin/sh", &["/bin/sh", "-c", &command]),
            ),
            (
                "/synthetic/bin/tool-a",
                exec("/bin/zsh", &["/bin/zsh", "-lc", &command]),
            ),
            ("/bin/sh", open(HOOK, false)),
            (HOOK, open("/usr/lib/libSystem.B.dylib", false)),
        ] {
            assert!(
                rows.is_hook_run(&ev(by, kind.clone()), "tool_a"),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn a_command_that_only_mentions_the_hook_is_not() {
        let rows = AgentRows::new(HOOK);
        let command = format!("'{HOOK}' --tool tool_a");
        let chained = format!("{command}; curl https://example.test");
        for kind in [
            exec("/bin/sh", &["/bin/sh", "-c", &chained]),
            // Another tool's key, another shell, an extra argument.
            exec(
                "/bin/sh",
                &["/bin/sh", "-c", &format!("'{HOOK}' --tool tool_b")],
            ),
            exec("/usr/local/bin/fish", &["fish", "-c", &command]),
            exec("/bin/sh", &["/bin/sh", "-c", &command, "extra"]),
            exec("/bin/cat", &["cat", HOOK]),
            // Writing the hook program is never hidden.
            open(HOOK, true),
        ] {
            assert!(
                !rows.is_hook_run(&ev("/synthetic/bin/tool-a", kind.clone()), "tool_a"),
                "{kind:?}"
            );
        }
    }
}

fn guarded(id: &str, path: &str, result: thadam_core::GuardResult) -> AgentMessage {
    let mut m = call(AgentKind::CallStart, id, path);
    m.tool_name = Some("Read".into());
    m.call_kind = Some(CallKind::FileRead);
    m.guard = Some(result);
    m
}

#[test]
fn a_call_the_guard_refused_is_one_row_at_once() {
    let mut r = Run::new();
    r.send(
        0,
        guarded(
            "c1",
            "/Users/dev/.ssh/id_rsa",
            thadam_core::GuardResult::Blocked,
        ),
    );
    let [row] = r.out.as_slice() else {
        panic!("{:?}", r.out)
    };
    assert_eq!(row.outcome, Outcome::DeniedByAgent);
    assert_eq!(row.target, "/Users/dev/.ssh/id_rsa");
    assert!(row.flags.contains(&Flag::BlockedByGuard));
    assert!(row.flags.contains(&Flag::SensitivePath));
    // A refusal event for the same call, and the turn's end, add nothing.
    let mut denied = guarded(
        "c1",
        "/Users/dev/.ssh/id_rsa",
        thadam_core::GuardResult::Blocked,
    );
    denied.kind = AgentKind::Denied;
    denied.guard = None;
    r.send(1, denied)
        .send(2, msg(AgentKind::TurnEnd))
        .advance(600);
    assert_eq!(r.out.len(), 1, "{:?}", r.out);
    assert_eq!(r.rows.stats.guard_blocked, 1);
    assert_eq!(r.rows.stats.declines, 0);
}

#[test]
fn a_call_the_guard_would_refuse_is_marked_and_still_tracked() {
    let mut r = Run::new();
    r.send(
        0,
        guarded(
            "c2",
            "/Users/dev/.ssh/config",
            thadam_core::GuardResult::WouldBlock,
        ),
    );
    let mut done = msg(AgentKind::CallDone);
    done.call = Some("c2".into());
    r.send(1, done).advance(600);
    let [row] = r.out.as_slice() else {
        panic!("{:?}", r.out)
    };
    assert_eq!(row.outcome, Outcome::Allowed);
    assert!(row.flags.contains(&Flag::WouldBlock));
    assert!(row.flags.contains(&Flag::SensitivePath));
    assert_eq!(r.rows.stats.guard_would_block, 1);
}

#[test]
fn a_guard_error_is_counted_and_the_call_is_handled_as_usual() {
    let mut r = Run::new();
    r.send(
        0,
        guarded(
            "c3",
            "/Users/dev/.ssh/config",
            thadam_core::GuardResult::Error,
        ),
    );
    assert!(r.out.is_empty());
    assert_eq!(r.rows.stats.guard_errors, 1);
}

#[test]
fn a_would_block_call_the_user_declined_is_one_declined_row() {
    let mut r = Run::new();
    let mut ask = guarded(
        "c4",
        "/Users/dev/.ssh/config",
        thadam_core::GuardResult::WouldBlock,
    );
    ask.kind = AgentKind::PermissionRequest;
    ask.call = None;
    ask.guard = None;
    r.send(0, ask)
        .send(
            0,
            guarded(
                "c4",
                "/Users/dev/.ssh/config",
                thadam_core::GuardResult::WouldBlock,
            ),
        )
        .send(5, msg(AgentKind::Prompt))
        .advance(600);
    let declined: Vec<_> = r
        .out
        .iter()
        .filter(|row| row.category != thadam_core::Category::Prompt)
        .collect();
    let [row] = declined.as_slice() else {
        panic!("{:?}", r.out)
    };
    assert_eq!(row.outcome, Outcome::DeniedByUser);
    assert!(row.flags.contains(&Flag::WouldBlock));
    assert!(
        !r.out
            .iter()
            .any(|row| row.outcome == Outcome::Allowed && row.flags.contains(&Flag::WouldBlock))
    );
}

#[test]
fn a_repeated_blocked_call_is_one_row_and_missing_ids_never_match() {
    let mut r = Run::new();
    let blocked = guarded(
        "c5",
        "/Users/dev/.ssh/id_rsa",
        thadam_core::GuardResult::Blocked,
    );
    r.send(0, blocked.clone()).send(1, blocked);
    assert_eq!(r.out.len(), 1, "{:?}", r.out);
    assert_eq!(r.rows.stats.guard_blocked, 1);

    // A blocked call with no call ID, turn or hash must not swallow a later refusal.
    let mut r = Run::new();
    let mut anon = guarded(
        "",
        "/Users/dev/.ssh/id_rsa",
        thadam_core::GuardResult::Blocked,
    );
    anon.turn = None;
    anon.input_hash = None;
    r.send(0, anon);
    let mut denied = msg(AgentKind::Denied);
    denied.turn = None;
    denied.tool_name = Some("Shell".into());
    denied.call_kind = Some(CallKind::Shell);
    denied.text = Some("rm -rf build".into());
    r.send(1, denied);
    assert_eq!(r.out.len(), 2, "{:?}", r.out);
}
