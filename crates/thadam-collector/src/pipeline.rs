//! Source item in, finished records out: tree, classify, pairing, collapse (ADR-003
//! Decisions 3, 6, 7; ADR-006).
//!
//! No I/O here; `run.rs` feeds items in and writes records out.

use std::collections::BTreeMap;
use std::fmt;

use thadam_core::{CoreError, DetectorKind, NewEvent, Redactor};
use time::Duration;

use crate::classify::classify;
use crate::collapse::Collapser;
use crate::pairing::{Pairing, Released};
use crate::registry::Registry;
use crate::rollup::{self, Rollup};
use crate::snapshot::Snapshot;
use crate::source::{EventKind, OsEvent, SkipReason, SourceItem};
use crate::tree::ProcessTree;

/// Counters for diagnostics. Counts only: never paths, arguments or values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub events: u64,
    pub member_events: u64,
    pub skipped: BTreeMap<SkipReason, u64>,
    pub gaps: u64,
    pub missed: u64,
    pub records: u64,
    pub invalid: u64,
    pub written: u64,
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "events={} kept={} records={} written={} invalid={} gaps={} missed={}",
            self.events,
            self.member_events,
            self.records,
            self.written,
            self.invalid,
            self.gaps,
            self.missed
        )?;
        for (reason, n) in &self.skipped {
            write!(f, " skipped_{}={n}", reason.name())?;
        }
        Ok(())
    }
}

/// Collector settings that are not in the registry file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub window: Duration,
    pub cap: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            window: crate::collapse::DEFAULT_WINDOW,
            cap: crate::collapse::DEFAULT_CAP,
        }
    }
}

pub struct Pipeline {
    registry: Registry,
    tree: ProcessTree,
    /// Holds opens until their close or exit shows whether the OS allowed them.
    pairing: Pairing,
    collapser: Collapser,
    /// Finds secrets in roll-up candidates' paths, which must stay individual (ADR-005).
    redactor: Redactor,
    pub stats: Stats,
}

impl Pipeline {
    pub fn new(registry: Registry, settings: Settings) -> Result<Self, CoreError> {
        let tree = ProcessTree::new(registry.responsible_attribution());
        let collapser =
            Collapser::with_read_budget(settings.window, settings.cap, registry.read_budget());
        Ok(Self {
            registry,
            tree,
            pairing: Pairing::default(),
            collapser,
            redactor: Redactor::with_default_detectors()?,
            stats: Stats::default(),
        })
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn seed(&mut self, snapshot: &Snapshot) {
        self.tree.seed(snapshot);
    }

    /// Processes one item and returns the records it completed, in completion order.
    pub fn handle(&mut self, item: SourceItem) -> Vec<NewEvent> {
        let event = match item {
            SourceItem::Event(e) => e,
            SourceItem::Gap { missed } => {
                self.pairing.gap();
                self.stats.gaps += 1;
                self.stats.missed = self.stats.missed.saturating_add(missed);
                return Vec::new();
            }
            SourceItem::Skipped(reason) => {
                *self.stats.skipped.entry(reason).or_insert(0) += 1;
                return Vec::new();
            }
        };
        self.stats.events += 1;

        let observation = self.tree.observe(&event, &self.registry);
        let pid = event.process.pid;
        let mut released = match &event.kind {
            EventKind::Close { path, .. } => {
                self.pairing.close(pid, event.process.ppid, path, event.ts)
            }
            EventKind::Fork { child } => {
                self.pairing.fork(pid, child.pid);
                Vec::new()
            }
            _ => Vec::new(),
        };
        released.extend(self.pairing.advance(event.ts));
        let record = observation
            .actor
            .as_ref()
            .and_then(|m| classify(&event, m, &self.registry));
        let mut done = match (record, &event.kind) {
            (
                Some(record),
                EventKind::Open {
                    path,
                    readable,
                    writable,
                    ..
                },
            ) => {
                let rollup = self.rollup_hint(&event, &record);
                released.extend(
                    self.pairing
                        .open(pid, path, record, rollup, *readable, *writable),
                );
                self.collapser.advance(event.ts)
            }
            (Some(record), _) => {
                let rollup = self.rollup_hint(&event, &record);
                self.collapser.push_with(record, rollup)
            }
            (None, _) => self.collapser.advance(event.ts),
        };
        if matches!(event.kind, EventKind::Exit) {
            released.extend(self.pairing.exit(pid, event.process.ppid));
        }
        self.push_released(released, &mut done);
        if observation.member.is_some() {
            self.stats.member_events += 1;
        }
        // Hidden ordering: the exit's held opens are pushed above, before the session's
        // windows are flushed here, so its refused opens are written with the session.
        if let Some(session) = observation.session_ended {
            done.extend(self.collapser.flush_session(&session));
        }
        self.stats.records += done.len() as u64;
        done
    }

    /// Closes every open window (shutdown or end of input).
    pub fn finish(&mut self) -> Vec<NewEvent> {
        let released = self.pairing.drain();
        let mut done = Vec::new();
        self.push_released(released, &mut done);
        done.extend(self.collapser.flush_all());
        self.stats.records += done.len() as u64;
        done
    }

    /// Roll-up eligibility; a path containing a secret always stays its own row (ADR-005).
    fn rollup_hint(&self, event: &OsEvent, record: &NewEvent) -> Rollup {
        let rollup = rollup::hint(event, record, &self.registry);
        if rollup != Rollup::Never
            && self.redactor.scan(&record.target).get(DetectorKind::Secret) > 0
        {
            return Rollup::Never;
        }
        rollup
    }

    fn push_released(&mut self, released: Vec<Released>, done: &mut Vec<NewEvent>) {
        for r in released {
            done.extend(self.collapser.push_with(r.record, r.rollup));
        }
    }
}
