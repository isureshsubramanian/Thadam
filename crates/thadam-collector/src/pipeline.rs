//! Source item in, finished records out: tree, classify, collapse (ADR-003 Decisions 3, 6, 7).
//!
//! No I/O here; `run.rs` feeds items in and writes records out.

use std::collections::BTreeMap;
use std::fmt;

use thadam_core::NewEvent;
use time::Duration;

use crate::classify::classify;
use crate::collapse::Collapser;
use crate::registry::Registry;
use crate::snapshot::Snapshot;
use crate::source::{SkipReason, SourceItem};
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
    collapser: Collapser,
    pub stats: Stats,
}

impl Pipeline {
    pub fn new(registry: Registry, settings: Settings) -> Self {
        let tree = ProcessTree::new(registry.responsible_attribution());
        Self {
            registry,
            tree,
            collapser: Collapser::new(settings.window, settings.cap),
            stats: Stats::default(),
        }
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
        let mut done = match observation
            .member
            .as_ref()
            .and_then(|m| classify(&event, m, &self.registry))
        {
            Some(record) => self.collapser.push(record),
            None => self.collapser.advance(event.ts),
        };
        if observation.member.is_some() {
            self.stats.member_events += 1;
        }
        if let Some(session) = observation.session_ended {
            done.extend(self.collapser.flush_session(&session));
        }
        self.stats.records += done.len() as u64;
        done
    }

    /// Closes every open window (shutdown or end of input).
    pub fn finish(&mut self) -> Vec<NewEvent> {
        let done = self.collapser.flush_all();
        self.stats.records += done.len() as u64;
        done
    }
}
