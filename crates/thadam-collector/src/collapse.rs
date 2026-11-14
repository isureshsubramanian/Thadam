//! Collapsing repeated reads and writes (ADR-002 Decision 3, ADR-003 Decision 6).
//!
//! Rows can't be updated once written, so repeats are counted here in memory and the
//! record is written when its window closes. Windows are timed by event time, not the
//! wall clock, so replaying a capture gives the same records as the live run.

use std::collections::{HashMap, VecDeque};

use thadam_core::{Action, NewEvent};
use time::{Duration, OffsetDateTime};

/// Window length. 30 s is an estimate, not measured (ADR-002 Decision 3).
pub const DEFAULT_WINDOW: Duration = Duration::seconds(30);
/// Most windows open at once before the oldest is flushed early. An estimate: Phase 0 saw
/// 393 distinct paths per session in 3 minutes.
pub const DEFAULT_CAP: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    session_id: Option<String>,
    action: Action,
    process_path: String,
    target: String,
}

#[derive(Debug)]
struct Pending {
    first: NewEvent,
    generation: u64,
}

/// Holds open windows. Every method returns the records that are now complete, oldest first.
#[derive(Debug)]
pub struct Collapser {
    window: Duration,
    cap: usize,
    open: HashMap<Key, Pending>,
    /// Keys in the order their windows opened; entries whose generation no longer matches
    /// were flushed early and are skipped.
    order: VecDeque<(OffsetDateTime, Key, u64)>,
    next_generation: u64,
}

impl Collapser {
    pub fn new(window: Duration, cap: usize) -> Self {
        Self {
            window,
            cap: cap.max(1),
            open: HashMap::new(),
            order: VecDeque::new(),
            next_generation: 0,
        }
    }

    /// Number of open windows.
    pub fn len(&self) -> usize {
        self.open.len()
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// Closes every window that has run its length by `now`. Call with the time of every
    /// OS event, including unrelated ones, so windows close while a tool is idle.
    pub fn advance(&mut self, now: OffsetDateTime) -> Vec<NewEvent> {
        let mut done = Vec::new();
        while let Some((opened, _, _)) = self.order.front() {
            if *opened + self.window > now {
                break;
            }
            if let Some(ev) = self.pop_front() {
                done.push(ev);
            }
        }
        done
    }

    /// Adds a record. Reads and writes are held for collapsing; anything else passes
    /// straight through.
    pub fn push(&mut self, event: NewEvent) -> Vec<NewEvent> {
        let mut done = self.advance(event.ts);
        if !matches!(event.action, Action::Read | Action::Write) {
            done.push(event);
            return done;
        }
        let key = Key {
            session_id: event.session_id.clone(),
            action: event.action,
            process_path: event.process_path.clone(),
            target: event.target.clone(),
        };
        if let Some(pending) = self.open.get_mut(&key) {
            pending.first.count = pending.first.count.saturating_add(event.count);
            if event.size_bytes.is_some() {
                pending.first.size_bytes = event.size_bytes;
            }
            pending.first.flags.extend(event.flags);
            return done;
        }
        while self.open.len() >= self.cap {
            match self.pop_front() {
                Some(ev) => done.push(ev),
                None => break,
            }
        }
        let generation = self.next_generation;
        self.next_generation += 1;
        self.order.push_back((event.ts, key.clone(), generation));
        self.open.insert(
            key,
            Pending {
                first: event,
                generation,
            },
        );
        done
    }

    /// Closes every window of a session (its root exited).
    pub fn flush_session(&mut self, session_id: &str) -> Vec<NewEvent> {
        let keys: Vec<Key> = self
            .open
            .keys()
            .filter(|k| k.session_id.as_deref() == Some(session_id))
            .cloned()
            .collect();
        let mut done: Vec<NewEvent> = keys
            .iter()
            .filter_map(|k| self.open.remove(k))
            .map(|p| p.first)
            .collect();
        done.sort_by_key(|e| e.ts);
        done
    }

    /// Closes every window (shutdown).
    pub fn flush_all(&mut self) -> Vec<NewEvent> {
        let mut done = Vec::with_capacity(self.open.len());
        while let Some(ev) = self.pop_front() {
            done.push(ev);
        }
        done
    }

    /// Removes the oldest window still open.
    fn pop_front(&mut self) -> Option<NewEvent> {
        while let Some((_, key, generation)) = self.order.pop_front() {
            if self
                .open
                .get(&key)
                .is_some_and(|p| p.generation == generation)
            {
                return self.open.remove(&key).map(|p| p.first);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use thadam_core::{Category, Outcome, Source};
    use time::macros::datetime;

    fn read(path: &str, secs: i64) -> NewEvent {
        NewEvent {
            ts: datetime!(2026-11-14 09:33:00 UTC) + Duration::seconds(secs),
            tool: "cli_agent".into(),
            session_id: Some("s1".into()),
            pid: 4300,
            process_path: "/usr/bin/cat".into(),
            category: Category::File,
            action: Action::Read,
            target: path.into(),
            outcome: Outcome::Allowed,
            size_bytes: Some(secs),
            bytes_out: None,
            bytes_in: None,
            project: None,
            flags: BTreeSet::new(),
            count: 1,
            sources: BTreeSet::from([Source::Os]),
        }
    }

    fn c() -> Collapser {
        Collapser::new(DEFAULT_WINDOW, DEFAULT_CAP)
    }

    #[test]
    fn repeats_in_a_window_become_one_record_with_first_time_and_last_size() {
        let mut c = c();
        for s in 0..47 {
            assert!(c.push(read("/p/main.rs", s % 29)).is_empty());
        }
        let out = c.flush_all();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].count, 47);
        assert_eq!(out[0].ts, read("x", 0).ts);
    }

    #[test]
    fn window_closes_by_event_time() {
        let mut c = c();
        c.push(read("/p/a", 0));
        c.push(read("/p/a", 10));
        assert!(c.advance(read("x", 29).ts).is_empty());
        let out = c.advance(read("x", 30).ts);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].count, 2);
        // A read after the window opens a new record.
        c.push(read("/p/a", 31));
        assert_eq!(c.flush_all()[0].count, 1);
    }

    #[test]
    fn different_programs_and_sessions_do_not_merge() {
        let mut c = c();
        c.push(read("/p/a", 0));
        let mut other_program = read("/p/a", 1);
        other_program.process_path = "/usr/bin/grep".into();
        c.push(other_program);
        let mut other_session = read("/p/a", 2);
        other_session.session_id = Some("s2".into());
        c.push(other_session);
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn non_collapsing_actions_pass_through() {
        let mut c = c();
        let mut exec = read("git status", 0);
        exec.action = Action::Exec;
        assert_eq!(c.push(exec).len(), 1);
        assert!(c.is_empty());
    }

    #[test]
    fn session_flush_leaves_other_sessions_open() {
        let mut c = c();
        c.push(read("/p/a", 0));
        let mut other = read("/p/b", 0);
        other.session_id = Some("s2".into());
        c.push(other);
        assert_eq!(c.flush_session("s1").len(), 1);
        assert_eq!(c.len(), 1);
        // The stale order entry for s1 is skipped later.
        assert_eq!(c.flush_all().len(), 1);
    }

    #[test]
    fn cap_flushes_the_oldest_window() {
        let mut c = Collapser::new(DEFAULT_WINDOW, 2);
        c.push(read("/p/a", 0));
        c.push(read("/p/b", 1));
        let out = c.push(read("/p/c", 2));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].target, "/p/a");
        assert_eq!(c.len(), 2);
    }
}
