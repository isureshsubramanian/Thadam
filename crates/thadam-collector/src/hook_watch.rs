//! Hooks that go quiet (ADR-017 Decision 4): a tool session with OS rows but no hook
//! message for `SILENT` becomes a `hooks_silent` coverage gap. No I/O here; `pipeline.rs`
//! feeds it and `run.rs` records the gaps.
//!
//! - Only tools registered with `"hooks": true`, and only sessions that started while the
//!   collector ran: a session seeded from the start-up snapshot sent its start message
//!   before anyone listened.
//! - Delegated sessions are skipped: the delegating tool's hooks speak for the work.
//! - The gap runs from the session's first OS row to its first hook message, or to the
//!   session's end (or the collector's stop) when none came.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use thadam_store::{Gap, GapReason};
use time::{Duration, OffsetDateTime};

/// How long a session may run with no hook message before it counts as a gap. An
/// estimate: long enough for any tool's session-start hook.
pub const SILENT: Duration = Duration::minutes(2);

#[derive(Debug, Default)]
pub struct HookWatch {
    /// Sessions not heard from yet: (first OS row, tool key).
    waiting: HashMap<Arc<str>, (OffsetDateTime, String)>,
    /// Sessions heard from, or not watched (seeded, delegated, or a tool without hooks).
    settled: HashSet<Arc<str>>,
    gaps: Vec<Gap>,
}

impl HookWatch {
    /// Sessions already running at start-up are not watched.
    pub fn skip(&mut self, sessions: impl IntoIterator<Item = Arc<str>>) {
        self.settled.extend(sessions);
    }

    /// An OS row of `session`. `watched` is false for delegated sessions and tools without
    /// hooks.
    pub fn os_row(&mut self, session: &Arc<str>, tool: &str, watched: bool, ts: OffsetDateTime) {
        if self.settled.contains(session) || self.waiting.contains_key(session) {
            return;
        }
        if watched {
            self.waiting
                .insert(Arc::clone(session), (ts, tool.to_string()));
        } else {
            self.settled.insert(Arc::clone(session));
        }
    }

    /// A hook message from `session`, received at `at`.
    pub fn heard(&mut self, session: &Arc<str>, at: OffsetDateTime) {
        if let Some(first) = self.waiting.remove(session) {
            self.close(first, at);
        }
        self.settled.insert(Arc::clone(session));
    }

    /// The session's root exited: it is forgotten either way.
    pub fn session_ended(&mut self, session: &Arc<str>, ts: OffsetDateTime) {
        if let Some(first) = self.waiting.remove(session) {
            self.close(first, ts);
        }
        self.settled.remove(session);
    }

    /// The collector is stopping: every session still waiting ends here.
    pub fn finish(&mut self, now: OffsetDateTime) {
        for (_, first) in std::mem::take(&mut self.waiting) {
            self.close(first, now);
        }
    }

    /// The gaps found since the last call, for the store.
    pub fn take_gaps(&mut self) -> Vec<Gap> {
        std::mem::take(&mut self.gaps)
    }

    fn close(&mut self, (from, tool): (OffsetDateTime, String), to: OffsetDateTime) {
        if to - from >= SILENT {
            self.gaps.push(Gap {
                from_us: micros(from),
                to_us: micros(to),
                reason: GapReason::HooksSilent,
                detail: Some(tool),
                missed: None,
            });
        }
    }
}

fn micros(t: OffsetDateTime) -> i64 {
    i64::try_from(t.unix_timestamp_nanos() / 1_000).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000 + secs).unwrap()
    }

    fn s(id: &str) -> Arc<str> {
        Arc::from(id)
    }

    #[test]
    fn a_session_with_no_hook_message_for_two_minutes_is_a_gap() {
        let mut w = HookWatch::default();
        w.os_row(&s("a"), "cli-agent", true, at(0));
        w.os_row(&s("a"), "cli-agent", true, at(30));
        w.heard(&s("a"), at(150));
        let gaps = w.take_gaps();
        assert_eq!(gaps.len(), 1);
        let g = &gaps[0];
        assert_eq!(g.reason, GapReason::HooksSilent);
        assert_eq!(g.detail.as_deref(), Some("cli-agent"));
        assert_eq!((g.from_us, g.to_us), (micros(at(0)), micros(at(150))));
        // Heard once: later rows and messages add nothing.
        w.os_row(&s("a"), "cli-agent", true, at(400));
        w.heard(&s("a"), at(900));
        assert!(w.take_gaps().is_empty());
    }

    #[test]
    fn a_hook_message_in_time_means_no_gap() {
        let mut w = HookWatch::default();
        w.os_row(&s("a"), "cli-agent", true, at(0));
        w.heard(&s("a"), at(5));
        w.session_ended(&s("a"), at(600));
        assert!(w.take_gaps().is_empty());
    }

    #[test]
    fn a_silent_session_ends_its_gap_at_exit_or_stop() {
        let mut w = HookWatch::default();
        w.os_row(&s("a"), "cli-agent", true, at(0));
        w.os_row(&s("b"), "cli-agent", true, at(10));
        w.session_ended(&s("a"), at(300));
        w.finish(at(500));
        let gaps = w.take_gaps();
        assert_eq!(
            gaps.iter()
                .map(|g| (g.from_us, g.to_us))
                .collect::<Vec<_>>(),
            vec![
                (micros(at(0)), micros(at(300))),
                (micros(at(10)), micros(at(500)))
            ]
        );
    }

    #[test]
    fn a_short_silent_session_is_not_a_gap() {
        let mut w = HookWatch::default();
        w.os_row(&s("a"), "cli-agent", true, at(0));
        w.session_ended(&s("a"), at(119));
        assert!(w.take_gaps().is_empty());
    }

    #[test]
    fn unwatched_and_seeded_sessions_write_none() {
        let mut w = HookWatch::default();
        w.skip([s("seeded")]);
        w.os_row(&s("seeded"), "cli-agent", true, at(0));
        w.os_row(&s("no-hooks"), "editor-agent", false, at(0));
        w.finish(at(3600));
        assert!(w.take_gaps().is_empty());
    }
}
