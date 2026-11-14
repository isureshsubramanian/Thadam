//! Pairing opens with closes, so refused opens are recorded as refused (ADR-006).
//!
//! The OS logger reports an open before the file's permission bits are checked, and a
//! refused open is never followed by a close. So an open is held here until its close
//! (it succeeded) or its process's exit (it was refused). Where neither proves the result,
//! the row says so with the `unconfirmed` flag instead of guessing.
//!
//! Processes are keyed by pid alone: open descriptors survive exec, which changes the
//! pidversion. A pid reused after a missed exit can only follow a logger gap, and every open
//! pending across a gap is already unconfirmed.

use std::collections::{HashMap, HashSet, VecDeque};

use thadam_core::{Flag, NewEvent, Outcome};
use time::{Duration, OffsetDateTime};

use crate::rollup::Rollup;

/// Most opens held at once before the oldest is released as unconfirmed. An estimate:
/// Phase 0 saw 393 distinct paths per session in 3 minutes, and entries live only until
/// their close.
pub const DEFAULT_PENDING_CAP: usize = 50_000;
/// A read-only open still unclosed after this long, by a process that has closed other
/// files since, was refused (ADR-006 Decision 3). An estimate: twice the collapse window.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::seconds(60);
/// How often, in event time, held opens are checked against the timeout.
const SWEEP_EVERY: Duration = Duration::seconds(5);
/// Open times kept per path; further unclosed opens are only counted.
const MAX_TIMES: usize = 1_024;
/// Children tracked per held path; beyond this its result is unconfirmed.
const MAX_HEIRS: usize = 64;

/// A record whose result is now known, with its roll-up eligibility.
#[derive(Debug)]
pub struct Released {
    pub record: NewEvent,
    pub rollup: Rollup,
}

#[derive(Debug)]
struct Pending {
    /// As classified at the first open.
    record: NewEvent,
    rollup: Rollup,
    readable: bool,
    writable: bool,
    /// Times of opens not yet closed, oldest first.
    times: VecDeque<OffsetDateTime>,
    /// Unclosed opens beyond `MAX_TIMES`.
    extra: u32,
    /// Children forked after an open here and still alive. They may hold the descriptor,
    /// and the OS then reports its close under the child's pid.
    heirs: HashSet<u32>,
    /// More children than `MAX_HEIRS`: which may hold the file is no longer known.
    heirs_lost: bool,
    /// A logger gap happened while this was held, so its close may have been lost.
    gap: bool,
    generation: u64,
}

impl Pending {
    /// No close can still arrive from elsewhere, so an unclosed open here was refused.
    fn settled(&self) -> bool {
        self.heirs.is_empty() && !self.heirs_lost && !self.gap
    }

    fn unclosed(&self) -> u32 {
        u32::try_from(self.times.len())
            .unwrap_or(u32::MAX)
            .saturating_add(self.extra)
    }
}

#[derive(Debug, Default)]
struct Proc {
    last_close: Option<OffsetDateTime>,
    paths: HashMap<String, Pending>,
}

/// How a held open ends.
enum Verdict {
    Denied,
    Unconfirmed,
}

#[derive(Debug)]
pub struct Pairing {
    cap: usize,
    timeout: Duration,
    procs: HashMap<u32, Proc>,
    held: usize,
    /// Paths in the order they were first held; stale entries are skipped.
    order: VecDeque<(u32, String, u64)>,
    next_generation: u64,
    next_sweep: Option<OffsetDateTime>,
}

impl Default for Pairing {
    fn default() -> Self {
        Self::new(DEFAULT_PENDING_CAP, DEFAULT_READ_TIMEOUT)
    }
}

impl Pairing {
    pub fn new(cap: usize, timeout: Duration) -> Self {
        Self {
            cap: cap.max(1),
            timeout,
            procs: HashMap::new(),
            held: 0,
            order: VecDeque::new(),
            next_generation: 0,
            next_sweep: None,
        }
    }

    /// Number of paths held.
    pub fn len(&self) -> usize {
        self.held
    }

    pub fn is_empty(&self) -> bool {
        self.held == 0
    }

    /// Holds an open until its result is known. `record` is the row it becomes.
    pub fn open(
        &mut self,
        pid: u32,
        path: &str,
        record: NewEvent,
        rollup: Rollup,
        readable: bool,
        writable: bool,
    ) -> Vec<Released> {
        let ts = record.ts;
        if let Some(pending) = self.procs.get_mut(&pid).and_then(|p| p.paths.get_mut(path)) {
            pending.readable |= readable;
            pending.writable |= writable;
            if pending.times.len() < MAX_TIMES {
                pending.times.push_back(ts);
            } else {
                pending.extra = pending.extra.saturating_add(1);
            }
            return Vec::new();
        }
        let mut done = Vec::new();
        while self.held >= self.cap {
            match self.pop_oldest() {
                Some(r) => done.push(r),
                None => break,
            }
        }
        let generation = self.next_generation;
        self.next_generation += 1;
        self.procs.entry(pid).or_default().paths.insert(
            path.to_string(),
            Pending {
                record,
                rollup,
                readable,
                writable,
                times: VecDeque::from([ts]),
                extra: 0,
                heirs: HashSet::new(),
                heirs_lost: false,
                gap: false,
                generation,
            },
        );
        self.held += 1;
        self.order.push_back((pid, path.to_string(), generation));
        self.compact();
        done
    }

    /// A close: the oldest unclosed open of this path succeeded. It is matched to the
    /// closing process's own open, else to its parent's open that it inherited. A read
    /// becomes an `allowed` row; a write-only open needs none (its close records the write).
    pub fn close(&mut self, pid: u32, ppid: u32, path: &str, ts: OffsetDateTime) -> Vec<Released> {
        if let Some(proc) = self.procs.get_mut(&pid) {
            proc.last_close = Some(ts);
        }
        let own = self
            .procs
            .get(&pid)
            .is_some_and(|p| p.paths.contains_key(path));
        let inherited = !own
            && self
                .procs
                .get(&ppid)
                .and_then(|p| p.paths.get(path))
                .is_some_and(|p| p.heirs.contains(&pid));
        let owner = match (own, inherited) {
            (true, _) => pid,
            (false, true) => ppid,
            (false, false) => return Vec::new(),
        };
        let Some(proc) = self.procs.get_mut(&owner) else {
            return Vec::new();
        };
        let Some(pending) = proc.paths.get_mut(path) else {
            return Vec::new();
        };
        let opened = if pending.extra > 0 {
            pending.extra -= 1;
            pending.times.front().copied()
        } else {
            pending.times.pop_front()
        };
        let mut done = Vec::new();
        if pending.readable {
            let mut record = pending.record.clone();
            record.ts = opened.unwrap_or(record.ts);
            record.count = 1;
            done.push(Released {
                record,
                rollup: pending.rollup.clone(),
            });
        }
        if pending.unclosed() == 0 {
            proc.paths.remove(path);
            self.held -= 1;
        }
        done
    }

    /// A fork: descriptors held by the parent may now be closed by the child instead.
    /// Only direct children are tracked; a grandchild's close of an inherited file isn't
    /// matched (ADR-006 risks).
    pub fn fork(&mut self, pid: u32, child: u32) {
        if let Some(proc) = self.procs.get_mut(&pid) {
            for pending in proc.paths.values_mut() {
                if pending.heirs.len() < MAX_HEIRS {
                    pending.heirs.insert(child);
                } else {
                    pending.heirs_lost = true;
                }
            }
        }
    }

    /// A logger gap: any close may have been lost, so nothing held now can be called refused.
    pub fn gap(&mut self) {
        for pending in self.procs.values_mut().flat_map(|p| p.paths.values_mut()) {
            pending.gap = true;
        }
    }

    /// The process exited: what it never closed was refused, unless a living child or a
    /// gap leaves that uncertain. It also stops being a possible holder of its parent's files.
    pub fn exit(&mut self, pid: u32, ppid: u32) -> Vec<Released> {
        if let Some(parent) = self.procs.get_mut(&ppid) {
            for pending in parent.paths.values_mut() {
                pending.heirs.remove(&pid);
            }
        }
        let Some(proc) = self.procs.remove(&pid) else {
            return Vec::new();
        };
        self.held -= proc.paths.len();
        let mut done: Vec<Released> = proc
            .paths
            .into_values()
            .map(|p| {
                let verdict = if p.settled() {
                    Verdict::Denied
                } else {
                    Verdict::Unconfirmed
                };
                decide(p, verdict)
            })
            .collect();
        done.sort_by_key(|r| r.record.ts);
        done
    }

    /// Applies the read timeout (ADR-006 Decision 3). Call with the time of every event.
    pub fn advance(&mut self, now: OffsetDateTime) -> Vec<Released> {
        let next = *self.next_sweep.get_or_insert(now + SWEEP_EVERY);
        if now < next {
            return Vec::new();
        }
        self.next_sweep = Some(now + SWEEP_EVERY);
        let timeout = self.timeout;
        let mut done = Vec::new();
        for proc in self.procs.values_mut() {
            let Some(last_close) = proc.last_close else {
                continue;
            };
            let expired: Vec<String> = proc
                .paths
                .iter()
                .filter(|(_, p)| {
                    p.readable
                        && !p.writable
                        && p.settled()
                        && p.times
                            .front()
                            .is_some_and(|&t| t + timeout <= now && last_close > t)
                })
                .map(|(path, _)| path.clone())
                .collect();
            for path in expired {
                if let Some(p) = proc.paths.remove(&path) {
                    self.held -= 1;
                    done.push(decide(p, Verdict::Denied));
                }
            }
        }
        done.sort_by_key(|r| r.record.ts);
        done
    }

    /// Shutdown: nothing held can be confirmed either way.
    pub fn drain(&mut self) -> Vec<Released> {
        let mut done = Vec::with_capacity(self.held);
        while let Some(r) = self.pop_oldest() {
            done.push(r);
        }
        self.procs.clear();
        self.held = 0;
        done
    }

    /// Releases the oldest held path as unconfirmed.
    fn pop_oldest(&mut self) -> Option<Released> {
        while let Some((pid, path, generation)) = self.order.pop_front() {
            let Some(proc) = self.procs.get_mut(&pid) else {
                continue;
            };
            if proc
                .paths
                .get(&path)
                .is_some_and(|p| p.generation == generation)
            {
                let pending = proc.paths.remove(&path)?;
                self.held -= 1;
                return Some(decide(pending, Verdict::Unconfirmed));
            }
        }
        None
    }

    /// Drops stale order entries once they outnumber live ones.
    fn compact(&mut self) {
        if self.order.len() <= 2 * self.held + 1_024 {
            return;
        }
        let procs = &self.procs;
        self.order.retain(|(pid, path, generation)| {
            procs
                .get(pid)
                .and_then(|p| p.paths.get(path))
                .is_some_and(|p| p.generation == *generation)
        });
    }
}

/// The row for opens that were never closed.
fn decide(pending: Pending, verdict: Verdict) -> Released {
    let count = pending.unclosed();
    let mut record = pending.record;
    record.ts = pending.times.front().copied().unwrap_or(record.ts);
    record.count = count.max(1);
    match verdict {
        Verdict::Denied => {
            record.outcome = Outcome::DeniedByOs;
            // Nothing was read or written, so no size is claimed.
            record.size_bytes = None;
        }
        Verdict::Unconfirmed => {
            record.flags.insert(Flag::Unconfirmed);
        }
    }
    Released {
        record,
        rollup: Rollup::Never,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use thadam_core::{Action, Category, Source};
    use time::macros::datetime;

    const PATH: &str = "/Users/test/outside/locked.txt";

    fn at(secs: i64) -> OffsetDateTime {
        datetime!(2026-11-14 09:33:00 UTC) + Duration::seconds(secs)
    }

    fn record(action: Action, secs: i64) -> NewEvent {
        NewEvent {
            ts: at(secs),
            tool: "cli_agent".into(),
            session_id: Some("s1".into()),
            parent_session_id: None,
            pid: 4300,
            process_path: "/bin/cat".into(),
            category: Category::File,
            action,
            target: PATH.into(),
            outcome: Outcome::Allowed,
            size_bytes: Some(22),
            bytes_out: None,
            bytes_in: None,
            project: None,
            flags: BTreeSet::new(),
            count: 1,
            sources: BTreeSet::from([Source::Os]),
        }
    }

    fn read(p: &mut Pairing, secs: i64) -> Vec<Released> {
        p.open(
            4300,
            PATH,
            record(Action::Read, secs),
            Rollup::Never,
            true,
            false,
        )
    }

    #[test]
    fn closed_open_is_an_allowed_read_at_the_open_time() {
        let mut p = Pairing::default();
        assert!(read(&mut p, 0).is_empty());
        let out = p.close(4300, 4211, PATH, at(1));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].record.outcome, Outcome::Allowed);
        assert_eq!(out[0].record.ts, at(0));
        assert!(p.is_empty());
        assert!(p.exit(4300, 4211).is_empty());
    }

    #[test]
    fn unclosed_opens_at_exit_are_one_denied_row_with_their_count() {
        let mut p = Pairing::default();
        for i in 0..12 {
            read(&mut p, i);
        }
        let out = p.exit(4300, 4211);
        assert_eq!(out.len(), 1);
        let r = &out[0].record;
        assert_eq!(r.outcome, Outcome::DeniedByOs);
        assert_eq!(r.count, 12);
        assert_eq!(r.ts, at(0));
        assert_eq!(r.size_bytes, None);
        assert_eq!(out[0].rollup, Rollup::Never);
        assert!(p.is_empty());
    }

    #[test]
    fn mixed_attempts_pair_closes_first_and_refuse_the_rest() {
        let mut p = Pairing::default();
        read(&mut p, 0);
        read(&mut p, 1);
        read(&mut p, 2);
        assert_eq!(p.close(4300, 4211, PATH, at(3)).len(), 1);
        let out = p.exit(4300, 4211);
        assert_eq!(out[0].record.outcome, Outcome::DeniedByOs);
        assert_eq!(out[0].record.count, 2);
        assert_eq!(out[0].record.ts, at(1));
    }

    #[test]
    fn refused_write_open_is_a_denied_write_and_a_closed_one_adds_nothing() {
        let mut p = Pairing::default();
        p.open(
            4300,
            PATH,
            record(Action::Write, 0),
            Rollup::Never,
            false,
            true,
        );
        assert!(p.close(4300, 4211, PATH, at(1)).is_empty());
        p.open(
            4300,
            PATH,
            record(Action::Write, 2),
            Rollup::Never,
            false,
            true,
        );
        let out = p.exit(4300, 4211);
        assert_eq!(out[0].record.action, Action::Write);
        assert_eq!(out[0].record.outcome, Outcome::DeniedByOs);
    }

    #[test]
    fn fork_gap_shutdown_and_overflow_are_unconfirmed() {
        let unconfirmed = |r: &Released| {
            r.record.outcome == Outcome::Allowed && r.record.flags.contains(&Flag::Unconfirmed)
        };
        let mut p = Pairing::default();
        read(&mut p, 0);
        p.fork(4300, 4301);
        assert!(
            unconfirmed(&p.exit(4300, 4211)[0]),
            "a child that may hold it is alive"
        );

        read(&mut p, 0);
        p.gap();
        assert!(unconfirmed(&p.exit(4300, 4211)[0]));

        read(&mut p, 0);
        let out = p.drain();
        assert!(unconfirmed(&out[0]));
        assert!(p.is_empty());

        let mut p = Pairing::new(2, DEFAULT_READ_TIMEOUT);
        p.open(1, "/a", record(Action::Read, 0), Rollup::Never, true, false);
        p.open(2, "/b", record(Action::Read, 1), Rollup::Never, true, false);
        let out = p.open(3, "/c", record(Action::Read, 2), Rollup::Never, true, false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].record.ts, at(0));
        assert!(unconfirmed(&out[0]));
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn read_timeout_needs_later_closes_and_spares_write_opens() {
        let mut p = Pairing::default();
        read(&mut p, 0);
        p.open(
            4300,
            "/log",
            record(Action::Write, 0),
            Rollup::Never,
            false,
            true,
        );
        p.open(
            4300,
            "/other",
            record(Action::Read, 1),
            Rollup::Never,
            true,
            false,
        );
        // No close yet from this process: nothing is decided, however long it waits.
        assert!(p.advance(at(0)).is_empty());
        assert!(p.advance(at(120)).is_empty());
        p.close(4300, 4211, "/other", at(121));
        let out = p.advance(at(130));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].record.target, PATH);
        assert_eq!(out[0].record.outcome, Outcome::DeniedByOs);
        // The write open waits for its close, even after 10 minutes.
        assert!(p.advance(at(600)).is_empty());
        assert!(p.close(4300, 4211, "/log", at(601)).is_empty());
        assert!(p.is_empty());
    }

    #[test]
    fn children_inherit_opens_until_they_exit() {
        let mut p = Pairing::default();
        // Refused, then a shell is forked for the next command and exits: still refused.
        read(&mut p, 0);
        p.fork(4300, 4301);
        assert!(p.exit(4301, 4300).is_empty());
        assert_eq!(p.exit(4300, 4211)[0].record.outcome, Outcome::DeniedByOs);
        // Opened, then the child closes the inherited descriptor: an allowed read.
        read(&mut p, 1);
        p.fork(4300, 4302);
        let out = p.close(4302, 4300, PATH, at(2));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].record.outcome, Outcome::Allowed);
        assert!(p.is_empty());
        // An unrelated process's close of the same path pairs nothing.
        read(&mut p, 3);
        assert!(p.close(9999, 1, PATH, at(4)).is_empty());
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn descriptors_survive_exec_so_pairing_is_by_pid() {
        let mut p = Pairing::default();
        read(&mut p, 0);
        // An exec in between changes nothing here; the close arrives under the same pid.
        assert_eq!(p.close(4300, 4211, PATH, at(1)).len(), 1);
    }
}
