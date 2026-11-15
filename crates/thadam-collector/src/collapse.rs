//! Collapsing repeated reads and writes (ADR-002 Decision 3, ADR-003 Decision 6) and
//! rolling up build output and bulk scans (ADR-005).
//!
//! Rows can't be updated once written, so repeats are counted here in memory and the
//! record is written when its window closes. Windows are timed by event time, not the
//! wall clock, so replaying a capture gives the same records as the live run.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};

use thadam_core::{Action, Flag, NewEvent, Outcome};
use time::{Duration, OffsetDateTime};

use crate::registry::DEFAULT_READ_BUDGET;
use crate::rollup::Rollup;

/// Window length. 30 s is an estimate, not measured (ADR-002 Decision 3).
pub const DEFAULT_WINDOW: Duration = Duration::seconds(30);
/// Most windows open at once before the oldest is flushed early. An estimate: Phase 0 saw
/// 393 distinct paths per session in 3 minutes.
pub const DEFAULT_CAP: usize = 10_000;
/// Most distinct paths counted per roll-up row (estimate, ADR-005 Decision 4). Beyond it
/// the row says `>100000 files`.
const MAX_DISTINCT: usize = 100_000;
/// Read-budget entries kept before expired ones are pruned (estimate; one per process).
const BUDGET_PRUNE_AT: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    session_id: Option<String>,
    action: Action,
    /// Allowed and refused attempts on one path never merge (ADR-006 Decision 4).
    outcome: Outcome,
    process_path: String,
    /// The path, or the folder for a roll-up row.
    target: String,
    rollup: bool,
}

/// Distinct paths behind a roll-up row, as hashes so the paths themselves aren't kept.
#[derive(Debug, Default)]
struct Paths {
    hashes: HashSet<u64>,
    saturated: bool,
}

#[derive(Debug)]
struct Pending {
    first: NewEvent,
    generation: u64,
    paths: Option<Paths>,
}

/// One process's individual reads in its current window (ADR-005 Rule 2).
#[derive(Debug)]
struct Budget {
    opened: OffsetDateTime,
    seen: HashSet<u64>,
}

/// Holds open windows. Every method returns the records that are now complete, oldest first.
#[derive(Debug)]
pub struct Collapser {
    window: Duration,
    cap: usize,
    read_budget: usize,
    open: HashMap<Key, Pending>,
    /// Keys in the order their windows opened; entries whose generation no longer matches
    /// were flushed early and are skipped.
    order: VecDeque<(OffsetDateTime, Key, u64)>,
    next_generation: u64,
    budgets: HashMap<(Option<String>, u32), Budget>,
    /// No prune before this time: when every budget is still live, pruning on each event
    /// would walk them all and remove nothing.
    next_prune: Option<OffsetDateTime>,
}

fn path_hash(path: &str) -> u64 {
    // DefaultHasher::new() uses fixed keys, so counts are the same on every run.
    let mut h = DefaultHasher::new();
    path.hash(&mut h);
    h.finish()
}

impl Collapser {
    pub fn new(window: Duration, cap: usize) -> Self {
        Self::with_read_budget(window, cap, DEFAULT_READ_BUDGET)
    }

    pub fn with_read_budget(window: Duration, cap: usize, read_budget: usize) -> Self {
        Self {
            window,
            cap: cap.max(1),
            read_budget,
            open: HashMap::new(),
            order: VecDeque::new(),
            next_generation: 0,
            budgets: HashMap::new(),
            next_prune: None,
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
        if self.budgets.len() > BUDGET_PRUNE_AT && self.next_prune.is_none_or(|t| now >= t) {
            let window = self.window;
            self.budgets.retain(|_, b| b.opened + window > now);
            // At most once a window: a budget can only expire a window after it opened.
            self.next_prune = Some(now + window);
        }
        done
    }

    /// Adds a record that is never rolled up. Reads and writes are held for collapsing;
    /// anything else passes straight through.
    pub fn push(&mut self, event: NewEvent) -> Vec<NewEvent> {
        self.push_with(event, Rollup::Never)
    }

    /// Adds a record with its roll-up eligibility (see `rollup::hint`).
    pub fn push_with(&mut self, event: NewEvent, rollup: Rollup) -> Vec<NewEvent> {
        let mut done = self.advance(event.ts);
        let folder = match rollup {
            Rollup::Folder(folder) => Some(folder),
            Rollup::Budget(group) if self.over_budget(&event) => Some(group),
            Rollup::Budget(_) | Rollup::Never => None,
        };
        if folder.is_none() && !matches!(event.action, Action::Read | Action::Write) {
            done.push(event);
            return done;
        }
        let rollup = folder.is_some();
        let path = (rollup).then(|| path_hash(&event.target));
        let key = Key {
            session_id: event.session_id.clone(),
            action: event.action,
            outcome: event.outcome,
            process_path: event.process_path.clone(),
            target: folder.unwrap_or_else(|| event.target.clone()),
            rollup,
        };
        if let Some(pending) = self.open.get_mut(&key) {
            pending.first.count = pending.first.count.saturating_add(event.count);
            if event.size_bytes.is_some() {
                pending.first.size_bytes = event.size_bytes;
            }
            pending.first.flags.extend(event.flags);
            if let (Some(paths), Some(h)) = (pending.paths.as_mut(), path) {
                if paths.hashes.len() < MAX_DISTINCT {
                    paths.hashes.insert(h);
                } else if !paths.hashes.contains(&h) {
                    paths.saturated = true;
                }
            }
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
        let mut first = event;
        let paths = path.map(|h| {
            first.target = key.target.clone();
            Paths {
                hashes: HashSet::from([h]),
                saturated: false,
            }
        });
        self.order.push_back((first.ts, key.clone(), generation));
        self.open.insert(
            key,
            Pending {
                first,
                generation,
                paths,
            },
        );
        done
    }

    /// Spends one unit of the process's read budget for a new path. True when the budget
    /// is already spent and the read must be rolled up instead (ADR-005 Rule 2).
    fn over_budget(&mut self, event: &NewEvent) -> bool {
        let budget = self
            .budgets
            .entry((event.session_id.clone(), event.pid))
            .or_insert_with(|| Budget {
                opened: event.ts,
                seen: HashSet::new(),
            });
        if event.ts >= budget.opened + self.window {
            budget.opened = event.ts;
            budget.seen.clear();
        }
        let h = path_hash(&event.target);
        if budget.seen.contains(&h) || budget.seen.len() < self.read_budget {
            budget.seen.insert(h);
            false
        } else {
            true
        }
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
            .map(finish)
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
                return self.open.remove(&key).map(finish);
            }
        }
        None
    }
}

/// The finished record. A roll-up row names its folder and how many files it stands for
/// (ADR-005 Decision 2).
fn finish(pending: Pending) -> NewEvent {
    let mut event = pending.first;
    if let Some(paths) = pending.paths {
        let files = if paths.saturated {
            format!(">{MAX_DISTINCT}")
        } else {
            paths.hashes.len().to_string()
        };
        event.target = format!("{}/** ({files} files)", event.target.trim_end_matches('/'));
        event.size_bytes = None;
        event.flags.insert(Flag::RolledUp);
    }
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rollup::Rollup;
    use std::collections::BTreeSet;
    use thadam_core::{Category, Source};
    use time::macros::datetime;

    fn read(path: &str, secs: i64) -> NewEvent {
        NewEvent {
            ts: datetime!(2026-11-14 09:33:00 UTC) + Duration::seconds(secs),
            tool: "cli_agent".into(),
            session_id: Some("s1".into()),
            parent_session_id: None,
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
            agent: None,
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

    fn with(action: Action, path: &str, secs: i64, pid: u32) -> NewEvent {
        let mut e = read(path, secs);
        e.action = action;
        e.pid = pid;
        e
    }

    const TARGET: &str = "/Users/test/projects/demo/target";

    #[test]
    fn folder_rollup_merges_many_paths_into_one_row_per_window() {
        let mut c = c();
        for i in 0..5_000 {
            let path = format!("{TARGET}/debug/deps/f{i}.o");
            let out = c.push_with(
                with(Action::Create, &path, i % 20, 4400),
                Rollup::Folder(TARGET.into()),
            );
            assert!(out.is_empty());
        }
        // The next window opens a second row; the first closes as it does.
        let mut out = c.push_with(
            with(Action::Create, &format!("{TARGET}/x.o"), 40, 4400),
            Rollup::Folder(TARGET.into()),
        );
        out.extend(c.flush_all());
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].target, format!("{TARGET}/** (5000 files)"));
        assert_eq!(out[0].count, 5_000);
        assert_eq!(out[0].size_bytes, None);
        assert!(out[0].flags.contains(&Flag::RolledUp));
        assert_eq!(out[1].target, format!("{TARGET}/** (1 files)"));
    }

    #[test]
    fn distinct_count_ignores_repeats() {
        let mut c = c();
        for i in 0..500 {
            let path = format!("{TARGET}/f{}.o", i % 10);
            c.push_with(
                with(Action::Read, &path, 0, 1),
                Rollup::Folder(TARGET.into()),
            );
        }
        let out = c.flush_all();
        assert_eq!(out[0].target, format!("{TARGET}/** (10 files)"));
        assert_eq!(out[0].count, 500);
    }

    #[test]
    fn read_budget_keeps_the_first_reads_and_rolls_up_the_rest_per_process() {
        let src = "/Users/test/projects/demo/src";
        let mut c = Collapser::with_read_budget(DEFAULT_WINDOW, DEFAULT_CAP, 100);
        for i in 0..250 {
            let path = format!("{src}/f{i}.rs");
            c.push_with(
                with(Action::Read, &path, 0, 7000),
                Rollup::Budget(src.into()),
            );
        }
        // A second process has its own budget; a re-read of a kept path stays individual.
        for i in 0..50 {
            let path = format!("{src}/g{i}.rs");
            c.push_with(
                with(Action::Read, &path, 1, 7001),
                Rollup::Budget(src.into()),
            );
        }
        c.push_with(
            with(Action::Read, &format!("{src}/f0.rs"), 2, 7000),
            Rollup::Budget(src.into()),
        );
        let out = c.flush_all();
        let rolled: Vec<&NewEvent> = out
            .iter()
            .filter(|e| e.flags.contains(&Flag::RolledUp))
            .collect();
        assert_eq!(rolled.len(), 1);
        assert_eq!(rolled[0].target, format!("{src}/** (150 files)"));
        assert_eq!(rolled[0].count, 150);
        assert_eq!(out.len() - rolled.len(), 100 + 50);
        let f0 = out.iter().find(|e| e.target.ends_with("/f0.rs")).unwrap();
        assert_eq!(f0.count, 2);
    }

    #[test]
    fn read_budget_resets_after_a_window() {
        let src = "/Users/test/projects/demo/src";
        let mut c = Collapser::with_read_budget(DEFAULT_WINDOW, DEFAULT_CAP, 2);
        let mut out = Vec::new();
        for (i, secs) in [(0, 0), (1, 1), (2, 2), (3, 31), (4, 32)] {
            let path = format!("{src}/f{i}.rs");
            out.extend(c.push_with(
                with(Action::Read, &path, secs, 1),
                Rollup::Budget(src.into()),
            ));
        }
        out.extend(c.flush_all());
        let individual = out
            .iter()
            .filter(|e| !e.flags.contains(&Flag::RolledUp))
            .count();
        assert_eq!(individual, 4, "2 per window");
    }

    #[test]
    fn rollup_rows_flush_with_their_session_and_replay_identically() {
        let run = || {
            let mut c = c();
            for i in 0..30 {
                let path = format!("{TARGET}/f{i}.o");
                c.push_with(
                    with(Action::Write, &path, i, 1),
                    Rollup::Folder(TARGET.into()),
                );
            }
            let mut out = c.flush_session("s1");
            out.extend(c.flush_all());
            out.into_iter()
                .map(|e| (e.target, e.count, e.ts))
                .collect::<Vec<_>>()
        };
        let first = run();
        assert_eq!(first.len(), 1);
        assert_eq!(first, run());
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
