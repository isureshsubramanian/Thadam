//! Source item in, finished records out: tree, classify, pairing, collapse (ADR-003
//! Decisions 3, 6, 7; ADR-006), and network flows (ADR-007).
//!
//! No I/O here; `run.rs` feeds items in and writes records out.

use std::collections::BTreeMap;
use std::fmt;

use thadam_core::{Action, Category, CoreError, DetectorKind, HOOK_BIN, NewEvent, Redactor};
use thadam_store::SegmentStatus;
use time::Duration;

use crate::agent_rows::{AgentRows, AgentStats};
use crate::classify::classify;
use crate::collapse::Collapser;
use crate::netflow::{Attribution, NetFlows};
use crate::pairing::{Pairing, Released};
use crate::registry::Registry;
use crate::rollup::{self, Rollup};
use crate::snapshot::Snapshot;
use crate::source::agent::{AgentItem, AgentReject};
use crate::source::network::{FlowItem, FlowOpen, RejectReason};
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
    /// Network source: `None` when off, else the extensions connected now. Shown, so
    /// silence is never mistaken for "no traffic" (ADR-007 Risks).
    pub network: Option<u64>,
    pub flows: u64,
    pub flows_kept: u64,
    pub flows_rejected: BTreeMap<RejectReason, u64>,
    pub net_gaps: u64,
    pub net_missed: u64,
    /// The store folder, as the writer last saw it (ADR-009 Risks: tune limits from this).
    pub store: Option<SegmentStatus>,
    /// Agent socket (ADR-011): `None` when off.
    pub agent: Option<AgentStats>,
    pub agent_rejected: BTreeMap<AgentReject, u64>,
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
        match self.network {
            None => write!(f, " network=off")?,
            Some(connected) => {
                let state = if connected > 0 {
                    "connected"
                } else {
                    "not_connected"
                };
                write!(
                    f,
                    " network={state} flows={} flows_kept={} net_gaps={} net_missed={}",
                    self.flows, self.flows_kept, self.net_gaps, self.net_missed
                )?;
                for (reason, n) in &self.flows_rejected {
                    write!(f, " flows_rejected_{}={n}", reason.name())?;
                }
            }
        }
        if let Some(a) = &self.agent {
            write!(
                f,
                " agent_msgs={} agent_kept={} agent_refused={} agent_prompts={} agent_declines={} agent_never_ran={}",
                a.messages, a.accepted, a.refused, a.prompts, a.declines, a.never_ran
            )?;
            if a.overflow > 0 {
                write!(f, " agent_overflow={}", a.overflow)?;
            }
            for (reason, n) in &self.agent_rejected {
                write!(f, " agent_rejected_{}={n}", reason.name())?;
            }
        }
        if let Some(st) = &self.store {
            write!(
                f,
                " store_mb={} free_gb={} segments={} retired={}",
                st.store_bytes / 1_000_000,
                st.free_bytes / 1_000_000_000,
                st.segments,
                st.retired
            )?;
            if st.paused || st.missed > 0 {
                let state = if st.paused { "paused" } else { "resumed" };
                write!(f, " writing={state} not_written={}", st.missed)?;
            }
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
    /// Holds network flows until the OS stream catches up, then collapses them (ADR-007).
    net: NetFlows,
    /// Holds what the tools report about themselves until the OS stream catches up
    /// (ADR-011).
    agent: AgentRows,
    /// Time of the latest OS event handled.
    watermark: Option<time::OffsetDateTime>,
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
            net: NetFlows::new(settings.window),
            agent: AgentRows::new(HOOK_BIN),
            watermark: None,
            redactor: Redactor::with_default_detectors()?,
            stats: Stats::default(),
        })
    }

    /// Accepts agent messages from a hook program at `path` instead of the installed one
    /// (tests and local runs).
    pub fn set_hook_bin(&mut self, path: &str) {
        self.agent = AgentRows::new(path);
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

        // HIDDEN COUPLING (ADR-007 Decision 4, see netflow.rs): flows older than this event
        // are attributed before the tree applies it, so an exit here can't hide their process.
        let mut net_rows = self.release_flows(Some(event.ts));
        // HIDDEN COUPLING (ADR-011 Decision 3, see agent_rows.rs): the same for agent
        // messages. The hook process sends, then exits; its exit must not be applied before
        // its message is joined to its session.
        net_rows.extend(self.release_agent(Some(event.ts)));
        self.watermark = Some(self.watermark.map_or(event.ts, |w| w.max(event.ts)));

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
        if let (Some(r), Some(m)) = (&record, &observation.actor)
            && r.category == Category::Command
            && r.action == Action::Exec
        {
            self.agent.saw_exec(&m.session_id, &r.target, event.ts);
        }
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
            self.agent.session_ended(&session, event.ts);
        }
        done.append(&mut net_rows);
        self.stats.records += done.len() as u64;
        done
    }

    /// Processes one item from the network source and returns the rows it completed.
    pub fn handle_flow(&mut self, item: FlowItem) -> Vec<NewEvent> {
        match item {
            FlowItem::Flow { flow, ts, event } => {
                self.stats.flows += 1;
                self.net.hold(ts, flow, event);
            }
            FlowItem::Gap { missed } => {
                self.stats.net_gaps += 1;
                self.stats.net_missed = self.stats.net_missed.saturating_add(missed);
            }
            FlowItem::Rejected(reason) => {
                *self.stats.flows_rejected.entry(reason).or_insert(0) += 1;
            }
            FlowItem::Connected => {
                self.stats.network = Some(self.stats.network.unwrap_or(0) + 1);
            }
            FlowItem::Disconnected => {
                self.stats.network = Some(self.stats.network.unwrap_or(0).saturating_sub(1));
            }
        }
        let done = self.release_flows(self.watermark);
        self.stats.records += done.len() as u64;
        done
    }

    /// Processes one item from the agent socket and returns the rows it completed.
    pub fn handle_agent(&mut self, item: AgentItem) -> Vec<NewEvent> {
        match item {
            AgentItem::Message {
                peer,
                received,
                message,
            } => self.agent.hold(received, peer, message),
            AgentItem::Rejected(reason) => {
                *self.agent_rejected_mut().entry(reason).or_insert(0) += 1;
            }
        }
        // Before the first OS event the tree knows no one: wait for it, rather than refuse.
        let done = match self.watermark {
            Some(w) => self.release_agent(Some(w)),
            None => Vec::new(),
        };
        self.stats.records += done.len() as u64;
        done
    }

    /// Marks the agent socket as listening.
    pub fn enable_agent(&mut self) {
        self.stats.agent.get_or_insert_with(AgentStats::default);
    }

    fn agent_rejected_mut(&mut self) -> &mut BTreeMap<AgentReject, u64> {
        &mut self.stats.agent_rejected
    }

    fn release_agent(&mut self, before: Option<time::OffsetDateTime>) -> Vec<NewEvent> {
        let (tree, registry) = (&self.tree, &self.registry);
        let lookup = |p: crate::source::agent::Peer| tree.lookup(p.pid, p.pidversion, &[]);
        let sender = |m: &crate::tree::Membership| sender(tree, registry, m);
        let rows = match before {
            Some(_) => self.agent.release(before, &lookup, &sender),
            None => self.agent.finish(&lookup, &sender),
        };
        if let Some(a) = &mut self.stats.agent {
            *a = self.agent.stats.clone();
        }
        rows
    }

    /// Marks the network source as listening (no extension connected yet).
    pub fn enable_network(&mut self) {
        self.stats.network.get_or_insert(0);
    }

    fn release_flows(&mut self, before: Option<time::OffsetDateTime>) -> Vec<NewEvent> {
        let tree = &self.tree;
        let rows = self
            .net
            .release(before, |o| lookup(tree, o), &self.registry);
        self.stats.flows_kept = self.net.stats.attributed;
        rows
    }

    /// Closes every open window (shutdown or end of input).
    pub fn finish(&mut self) -> Vec<NewEvent> {
        let released = self.pairing.drain();
        let mut done = Vec::new();
        self.push_released(released, &mut done);
        done.extend(self.collapser.flush_all());
        let tree = &self.tree;
        done.extend(self.net.finish(|o| lookup(tree, o), &self.registry));
        done.extend(self.release_agent(None));
        self.stats.flows_kept = self.net.stats.attributed;
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

/// The tool key and the session root's image for an agent row (the key when the image is
/// not known yet, e.g. a root seeded from the start-up snapshot).
fn sender(
    tree: &ProcessTree,
    registry: &Registry,
    m: &crate::tree::Membership,
) -> Option<(String, String)> {
    let tool = registry.tool(m.tool)?;
    let image = tree
        .executable(m.root_pid)
        .map_or_else(|| tool.key.clone(), |e| e.to_string());
    Some((tool.key.clone(), image))
}

fn lookup(tree: &ProcessTree, open: &FlowOpen) -> Option<Attribution> {
    tree.lookup(open.pid, open.pidversion, &open.ppids)
        .map(|(member, executable)| Attribution { member, executable })
}
