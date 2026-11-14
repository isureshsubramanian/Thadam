//! Network flows into `connect` rows (ADR-007 Decisions 4 and 5).
//!
//! Flow records arrive by a faster path than OS events, so each is held until the OS stream
//! has caught up to its time (the watermark), then attributed through the process tree.
//! Flows of one session to one `host:port` are collapsed per window, like file events.
//! Bytes a flow moves after its `connect` row get rows of their own, flagged `continued`,
//! so every byte is counted in exactly one row.
//!
//! HIDDEN COUPLING (ADR-007 Decision 4): attribution is only right if the caller releases
//! flows with the time of each OS event *before* the tree applies that event (see
//! `Pipeline::handle`). Released later, a flow from a process that has just exited would
//! no longer find it in the tree.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

use thadam_core::{Action, Category, Flag, NewEvent, Outcome, Source};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::registry::Registry;
use crate::source::network::{FlowEvent, FlowOpen, Proto};
use crate::tree::Membership;

/// Longest a flow waits for the OS stream. An estimate, from Phase 0's measured lag of about
/// 4 minutes under load.
pub const MAX_HOLD: Duration = Duration::minutes(10);
/// Held records before the oldest are attributed early (estimate; the spike measured about
/// 35 flows a minute across the machine in a light session).
pub const DEFAULT_QUEUE_CAP: usize = 100_000;
/// Attributed flows tracked at once (estimate). Above it, idle flows with nothing left to
/// report are forgotten, oldest first.
pub const DEFAULT_FLOW_CAP: usize = 100_000;
/// File-sharing ports: SMB (445, and 139 over NetBIOS), AFP (548), NFS (2049).
const VOLUME_PORTS: &[u16] = &[139, 445, 548, 2049];
/// Period over which a session's uploads to one host are summed (ADR-007 Decision 5).
const UPLOAD_PERIOD: Duration = Duration::hours(1);
/// Upload sums kept before expired ones are pruned (estimate; one per session and host).
const UPLOAD_PRUNE_AT: usize = 4_096;
/// The process path when the flow's own process was not in the tree (resolved through its
/// ancestors).
pub const UNKNOWN_PROCESS: &str = "(unknown)";

/// The session a flow belongs to, and its executable if the tree knows it.
#[derive(Debug, Clone)]
pub struct Attribution {
    pub member: Membership,
    pub executable: Option<Arc<str>>,
}

/// Counts only, never hosts or addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetStats {
    /// Flows attributed to a session.
    pub attributed: u64,
    /// Flows of processes outside every session, dropped in memory.
    pub unrelated: u64,
    /// Idle flows forgotten because `DEFAULT_FLOW_CAP` was reached.
    pub evicted: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GroupKey {
    session: Arc<str>,
    process_path: Arc<str>,
    proto: Proto,
    target: Arc<str>,
    continued: bool,
}

#[derive(Debug)]
struct Group {
    ts: OffsetDateTime,
    flows: Vec<Uuid>,
}

/// What every row of a flow shares, fixed when it is attributed.
#[derive(Debug)]
struct Base {
    tool: String,
    member: Membership,
    pid: u32,
    category: Category,
    unknown_host: bool,
    large_upload: i64,
    large_upload_session: i64,
}

#[derive(Debug)]
struct Flow {
    key: GroupKey,
    base: Arc<Base>,
    last: OffsetDateTime,
    total_out: u64,
    total_in: u64,
    reported_out: u64,
    reported_in: u64,
    closed: bool,
    /// In a window that has not been written yet.
    queued: bool,
}

impl Flow {
    fn outcome(&self) -> (Outcome, bool) {
        match (self.total_in > 0, self.key.proto, self.closed) {
            (true, _, _) => (Outcome::Allowed, false),
            (false, Proto::Tcp, true) => (Outcome::Failed, false),
            // Nothing back yet, or UDP with no reply: seen, not confirmed.
            (false, _, _) => (Outcome::Allowed, true),
        }
    }
}

/// Holds flow records until they can be attributed, and open windows until they close.
/// Every method returns the rows that are now complete, oldest window first.
#[derive(Debug)]
pub struct NetFlows {
    window: Duration,
    queue_cap: usize,
    flow_cap: usize,
    held: VecDeque<(OffsetDateTime, Uuid, FlowEvent)>,
    newest: Option<OffsetDateTime>,
    flows: HashMap<Uuid, Flow>,
    groups: HashMap<GroupKey, Group>,
    /// Keys in the order their windows opened. A key is in here at most once: groups are
    /// only removed from the front.
    order: VecDeque<GroupKey>,
    uploads: HashMap<(Arc<str>, Arc<str>), (OffsetDateTime, i64)>,
    pub stats: NetStats,
}

impl NetFlows {
    pub fn new(window: Duration) -> Self {
        Self::with_caps(window, DEFAULT_QUEUE_CAP, DEFAULT_FLOW_CAP)
    }

    pub fn with_caps(window: Duration, queue_cap: usize, flow_cap: usize) -> Self {
        Self {
            window,
            queue_cap: queue_cap.max(1),
            flow_cap: flow_cap.max(1),
            held: VecDeque::new(),
            newest: None,
            flows: HashMap::new(),
            groups: HashMap::new(),
            order: VecDeque::new(),
            uploads: HashMap::new(),
            stats: NetStats::default(),
        }
    }

    /// Records held for attribution.
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Queues a record until `release` can attribute it.
    pub fn hold(&mut self, ts: OffsetDateTime, flow: Uuid, event: FlowEvent) {
        self.newest = Some(self.newest.map_or(ts, |n| n.max(ts)));
        self.held.push_back((ts, flow, event));
    }

    /// Attributes every held record older than `before` (the OS watermark), or held longer
    /// than `MAX_HOLD`, or beyond the queue cap; then closes windows that ended by `before`.
    pub fn release(
        &mut self,
        before: Option<OffsetDateTime>,
        resolve: impl Fn(&FlowOpen) -> Option<Attribution>,
        registry: &Registry,
    ) -> Vec<NewEvent> {
        let mut done = Vec::new();
        while let Some((ts, _, _)) = self.held.front() {
            let caught_up = before.is_some_and(|b| *ts < b);
            let expired = self.newest.is_some_and(|n| n - *ts > MAX_HOLD);
            if !(caught_up || expired || self.held.len() > self.queue_cap) {
                break;
            }
            if let Some((ts, flow, event)) = self.held.pop_front() {
                done.extend(self.apply(ts, flow, event, &resolve, registry));
            }
        }
        if let Some(now) = before {
            done.extend(self.advance(now));
        }
        done
    }

    /// Attributes everything still held and writes every open window (shutdown).
    pub fn finish(
        &mut self,
        resolve: impl Fn(&FlowOpen) -> Option<Attribution>,
        registry: &Registry,
    ) -> Vec<NewEvent> {
        let mut done = Vec::new();
        while let Some((ts, flow, event)) = self.held.pop_front() {
            done.extend(self.apply(ts, flow, event, &resolve, registry));
        }
        while let Some(key) = self.order.pop_front() {
            done.extend(self.emit(key));
        }
        done
    }

    fn apply(
        &mut self,
        ts: OffsetDateTime,
        id: Uuid,
        event: FlowEvent,
        resolve: &impl Fn(&FlowOpen) -> Option<Attribution>,
        registry: &Registry,
    ) -> Vec<NewEvent> {
        let mut done = self.advance(ts);
        match event {
            FlowEvent::Open(open) => {
                let Some(flow) = resolve(&open).and_then(|a| new_flow(&open, a, ts, registry))
                else {
                    self.stats.unrelated += 1;
                    return done;
                };
                self.stats.attributed += 1;
                let key = flow.key.clone();
                self.flows.insert(id, flow);
                self.enqueue(key, id, ts);
                self.evict_idle();
            }
            FlowEvent::Bytes {
                closed,
                bytes_out,
                bytes_in,
            } => {
                // Unknown id: an unrelated flow, already dropped.
                let Some(flow) = self.flows.get_mut(&id) else {
                    return done;
                };
                flow.last = ts;
                flow.closed |= closed;
                // Running totals only grow; a report without a count keeps the last one.
                flow.total_out = flow.total_out.max(bytes_out.unwrap_or(0));
                flow.total_in = flow.total_in.max(bytes_in.unwrap_or(0));
                let unreported =
                    flow.total_out > flow.reported_out || flow.total_in > flow.reported_in;
                match (flow.queued, unreported) {
                    // Counted when its window closes.
                    (true, _) => {}
                    (false, true) => {
                        let key = GroupKey {
                            continued: true,
                            ..flow.key.clone()
                        };
                        self.enqueue(key, id, ts);
                    }
                    (false, false) if flow.closed => {
                        self.flows.remove(&id);
                    }
                    (false, false) => {}
                }
            }
        }
        done.extend(self.advance(ts));
        done
    }

    fn enqueue(&mut self, key: GroupKey, id: Uuid, ts: OffsetDateTime) {
        if let Some(flow) = self.flows.get_mut(&id) {
            flow.queued = true;
        }
        match self.groups.get_mut(&key) {
            Some(group) => group.flows.push(id),
            None => {
                self.groups.insert(
                    key.clone(),
                    Group {
                        ts,
                        flows: vec![id],
                    },
                );
                self.order.push_back(key);
            }
        }
    }

    /// Writes every window that has run its length by `now`.
    fn advance(&mut self, now: OffsetDateTime) -> Vec<NewEvent> {
        let mut done = Vec::new();
        while let Some(key) = self.order.front() {
            match self.groups.get(key) {
                Some(g) if g.ts + self.window > now => break,
                _ => {}
            }
            if let Some(key) = self.order.pop_front() {
                done.extend(self.emit(key));
            }
        }
        done
    }

    /// Rows for one window: per outcome for `connect`, one row for `continued`.
    fn emit(&mut self, key: GroupKey) -> Vec<NewEvent> {
        let Some(group) = self.groups.remove(&key) else {
            return Vec::new();
        };
        // (outcome, unconfirmed) -> flows, in a fixed order so output is repeatable.
        let mut buckets: Vec<((Outcome, bool), Vec<Uuid>)> = Vec::new();
        for id in group.flows {
            let Some(flow) = self.flows.get(&id) else {
                continue;
            };
            let outcome = if key.continued {
                (Outcome::Allowed, false)
            } else {
                flow.outcome()
            };
            match buckets.iter_mut().find(|(o, _)| *o == outcome) {
                Some((_, ids)) => ids.push(id),
                None => buckets.push((outcome, vec![id])),
            }
        }
        buckets.sort_by_key(|((o, u), _)| (*o, *u));

        let mut done = Vec::new();
        for ((outcome, unconfirmed), ids) in buckets {
            let (mut out, mut inn, mut base) = (0u64, 0u64, None);
            for id in &ids {
                if let Some(flow) = self.flows.get_mut(id) {
                    out = out.saturating_add(flow.total_out - flow.reported_out);
                    inn = inn.saturating_add(flow.total_in - flow.reported_in);
                    flow.reported_out = flow.total_out;
                    flow.reported_in = flow.total_in;
                    flow.queued = false;
                    base.get_or_insert_with(|| Arc::clone(&flow.base));
                    if flow.closed {
                        self.flows.remove(id);
                    }
                }
            }
            let Some(base) = base else { continue };
            let bytes_out = i64::try_from(out).unwrap_or(i64::MAX);
            let mut flags = BTreeSet::new();
            if base.unknown_host {
                flags.insert(Flag::UnknownHost);
            }
            if unconfirmed {
                flags.insert(Flag::Unconfirmed);
            }
            if key.continued {
                flags.insert(Flag::Continued);
            }
            if self.large_upload(&key, &base, group.ts, bytes_out) {
                flags.insert(Flag::LargeUpload);
            }
            done.push(NewEvent {
                ts: group.ts,
                tool: base.tool.clone(),
                session_id: Some(base.member.session_id.to_string()),
                parent_session_id: base.member.parent_session_id.as_deref().map(str::to_string),
                pid: base.pid,
                process_path: key.process_path.to_string(),
                category: base.category,
                action: Action::Connect,
                target: key.target.to_string(),
                outcome,
                size_bytes: None,
                bytes_out: Some(bytes_out),
                bytes_in: Some(i64::try_from(inn).unwrap_or(i64::MAX)),
                project: base.member.project.as_deref().map(str::to_string),
                flags,
                count: u32::try_from(ids.len()).unwrap_or(u32::MAX),
                sources: BTreeSet::from([Source::Network]),
            });
        }
        done
    }

    /// A row is a large upload if it alone reaches the row threshold, or if it takes the
    /// session's uploads to this host in the current hour across the session threshold.
    fn large_upload(&mut self, key: &GroupKey, base: &Base, ts: OffsetDateTime, out: i64) -> bool {
        if self.uploads.len() > UPLOAD_PRUNE_AT {
            self.uploads
                .retain(|_, (start, _)| *start + UPLOAD_PERIOD > ts);
        }
        let entry = self
            .uploads
            .entry((Arc::clone(&key.session), Arc::clone(&key.target)))
            .or_insert((ts, 0));
        if entry.0 + UPLOAD_PERIOD <= ts {
            *entry = (ts, 0);
        }
        let before = entry.1;
        entry.1 = before.saturating_add(out);
        out >= base.large_upload
            || (before < base.large_upload_session && entry.1 >= base.large_upload_session)
    }

    /// Forgets the longest-idle flows with nothing left to report once over the cap. Rare,
    /// so the sort is acceptable: it only happens when flows are never closed.
    fn evict_idle(&mut self) {
        if self.flows.len() <= self.flow_cap {
            return;
        }
        let mut idle: Vec<(OffsetDateTime, Uuid)> = self
            .flows
            .iter()
            .filter(|(_, f)| !f.queued)
            .map(|(id, f)| (f.last, *id))
            .collect();
        idle.sort_unstable();
        let excess = self.flows.len() - self.flow_cap * 9 / 10;
        for (_, id) in idle.into_iter().take(excess) {
            self.flows.remove(&id);
            self.stats.evicted += 1;
        }
    }
}

fn new_flow(
    open: &FlowOpen,
    attribution: Attribution,
    ts: OffsetDateTime,
    registry: &Registry,
) -> Option<Flow> {
    let tool = registry.tool(attribution.member.tool)?;
    let category = category(open.remote_ip, open.remote_port, open.host.as_deref());
    let unknown_host = match open.host.as_deref() {
        Some(host) => !tool.network.is_known_host(host),
        // An address alone says nothing about who is behind it, unless it is local.
        None => !is_internal(open.remote_ip),
    };
    // The tree's executable, else the one the extension read, else a placeholder
    // (ADR-007 amendment 2).
    let process_path = attribution
        .executable
        .or_else(|| open.exe.as_deref().map(Arc::from))
        .unwrap_or_else(|| Arc::from(UNKNOWN_PROCESS));
    let key = GroupKey {
        session: Arc::clone(&attribution.member.session_id),
        process_path,
        proto: open.proto,
        target: Arc::from(target(
            open.remote_ip,
            open.remote_port,
            open.host.as_deref(),
        )),
        continued: false,
    };
    Some(Flow {
        key,
        base: Arc::new(Base {
            tool: tool.key.clone(),
            member: attribution.member,
            pid: open.pid,
            category,
            unknown_host,
            large_upload: tool.network.large_upload_bytes,
            large_upload_session: tool.network.large_upload_session_bytes,
        }),
        last: ts,
        total_out: 0,
        total_in: 0,
        reported_out: 0,
        reported_in: 0,
        closed: false,
        queued: false,
    })
}

/// `host:port`, or the address and port when there is no name (IPv6 in brackets).
pub fn target(ip: IpAddr, port: u16, host: Option<&str>) -> String {
    match (host, ip) {
        (Some(h), _) => format!("{h}:{port}"),
        (None, IpAddr::V4(v4)) => format!("{v4}:{port}"),
        (None, IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
    }
}

/// ADR-007 Decision 5: file-sharing ports first, then local addresses and `.local` names.
pub fn category(ip: IpAddr, port: u16, host: Option<&str>) -> Category {
    if VOLUME_PORTS.contains(&port) {
        Category::NetworkVolume
    } else if is_internal(ip) || host.is_some_and(|h| h.ends_with(".local")) {
        Category::NetworkInternal
    } else {
        Category::NetworkExternal
    }
}

/// Private, link-local, loopback and unique-local addresses.
pub fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_internal(IpAddr::V4(v4)),
            None => {
                let first = v6.segments()[0];
                v6.is_loopback() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ToolId;
    use crate::source::network::{Direction, HostFrom};
    use time::macros::datetime;

    const T0: OffsetDateTime = datetime!(2026-11-14 09:33:00 UTC);

    fn registry() -> Registry {
        Registry::parse(
            r#"{"version":1,"tools":[{"key":"cli_agent","match":[{"path":"/x"}],
                "network":{"known_hosts":["*.example-agent.test"],
                           "large_upload_bytes":1000,"large_upload_session_bytes":5000}}]}"#,
        )
        .unwrap()
    }

    fn tool() -> ToolId {
        registry()
            .match_identity("/x", &crate::source::Identity::default())
            .unwrap()
    }

    fn member(session: &str) -> Membership {
        Membership {
            tool: tool(),
            session_id: Arc::from(session),
            project: Some(Arc::from("/Users/test/p")),
            root_pid: 300,
            parent_session_id: None,
        }
    }

    /// Process 300 and its children are in session "s1"; nothing else is.
    fn resolve(open: &FlowOpen) -> Option<Attribution> {
        let known = open.pid == 300 || open.ppids.contains(&300);
        known.then(|| Attribution {
            member: member("s1"),
            executable: (open.pid == 300).then(|| Arc::from("/Users/test/.local/bin/agent")),
        })
    }

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn open(pid: u32, ip: &str, port: u16, host: Option<&str>, proto: Proto) -> FlowEvent {
        FlowEvent::Open(FlowOpen {
            pid,
            pidversion: 1,
            ppids: vec![300, 1],
            proto,
            direction: Direction::Out,
            remote_ip: ip.parse().unwrap(),
            remote_port: port,
            host: host.map(str::to_string),
            host_from: if host.is_some() {
                HostFrom::Api
            } else {
                HostFrom::None
            },
            exe: None,
        })
    }

    fn bytes(closed: bool, out: u64, inn: u64) -> FlowEvent {
        FlowEvent::Bytes {
            closed,
            bytes_out: Some(out),
            bytes_in: Some(inn),
        }
    }

    fn api(pid: u32) -> FlowEvent {
        open(
            pid,
            "203.0.113.7",
            443,
            Some("api.example-agent.test"),
            Proto::Tcp,
        )
    }

    struct Run {
        n: NetFlows,
        r: Registry,
        rows: Vec<NewEvent>,
    }

    impl Run {
        fn new() -> Self {
            Self {
                n: NetFlows::new(Duration::seconds(30)),
                r: registry(),
                rows: Vec::new(),
            }
        }
        /// Holds a record at `secs` and moves the OS watermark just past it.
        fn at(&mut self, secs: i64, flow: u128, event: FlowEvent) {
            let ts = T0 + Duration::seconds(secs);
            self.n.hold(ts, id(flow), event);
            self.os(secs);
        }
        fn os(&mut self, secs: i64) {
            let before = T0 + Duration::seconds(secs) + Duration::milliseconds(1);
            self.rows
                .extend(self.n.release(Some(before), resolve, &self.r));
        }
        fn finish(mut self) -> Vec<NewEvent> {
            self.rows.extend(self.n.finish(resolve, &self.r));
            self.rows
        }
    }

    #[test]
    fn flows_wait_for_the_os_stream_then_attribute() {
        let mut n = NetFlows::new(Duration::seconds(30));
        let r = registry();
        n.hold(T0, id(1), api(300));
        // The OS stream is behind the flow: nothing happens yet.
        assert!(
            n.release(Some(T0 - Duration::seconds(5)), resolve, &r)
                .is_empty()
        );
        assert_eq!(n.held(), 1);
        assert!(n.release(None, resolve, &r).is_empty());
        // Caught up: attributed, and the window closes 30 s later.
        assert!(
            n.release(Some(T0 + Duration::seconds(1)), resolve, &r)
                .is_empty()
        );
        assert_eq!(n.held(), 0);
        assert_eq!(n.stats.attributed, 1);
        let rows = n.release(Some(T0 + Duration::seconds(31)), resolve, &r);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].session_id.as_deref(), Some("s1"));
    }

    #[test]
    fn a_flow_is_released_after_the_longest_hold_even_without_os_events() {
        let mut n = NetFlows::new(Duration::seconds(30));
        let r = registry();
        n.hold(T0, id(1), api(300));
        n.hold(T0 + Duration::minutes(11), id(2), api(300));
        assert!(n.release(None, resolve, &r).is_empty());
        assert_eq!(n.held(), 1);
        assert_eq!(n.stats.attributed, 1);
    }

    #[test]
    fn unrelated_flows_write_nothing() {
        let mut run = Run::new();
        let mut other = open(
            999,
            "198.51.100.1",
            443,
            Some("www.example.test"),
            Proto::Tcp,
        );
        if let FlowEvent::Open(o) = &mut other {
            o.ppids = vec![1];
        }
        run.at(0, 1, other);
        run.at(1, 1, bytes(true, 10, 10));
        let s = run.n.stats.clone();
        assert!(run.finish().is_empty());
        assert_eq!(s.unrelated, 1);
    }

    #[test]
    fn many_flows_in_a_window_collapse_into_one_row() {
        let mut run = Run::new();
        for i in 0..40 {
            run.at(i / 2, 100 + i as u128, api(300));
            run.at(i / 2, 100 + i as u128, bytes(true, 10, 1000));
        }
        let rows = run.finish();
        assert_eq!(rows.len(), 1, "{rows:#?}");
        let r = &rows[0];
        assert_eq!(r.action, Action::Connect);
        assert_eq!(r.target, "api.example-agent.test:443");
        assert_eq!(r.count, 40);
        assert_eq!(r.bytes_out, Some(400));
        assert_eq!(r.bytes_in, Some(40_000));
        assert_eq!(r.outcome, Outcome::Allowed);
        assert_eq!(r.category, Category::NetworkExternal);
        assert_eq!(r.process_path, "/Users/test/.local/bin/agent");
        assert_eq!(r.sources, BTreeSet::from([Source::Network]));
        assert!(r.flags.is_empty(), "{:?}", r.flags);
    }

    #[test]
    fn a_long_flow_counts_every_byte_once() {
        let mut run = Run::new();
        run.at(0, 1, api(300));
        run.at(10, 1, bytes(false, 100, 500));
        // First window closes at 30 s: connect row with what moved so far.
        run.at(40, 1, bytes(false, 300, 900));
        run.at(75, 1, bytes(false, 300, 1500));
        run.at(110, 1, bytes(true, 350, 1500));
        let rows = std::mem::take(&mut run.rows);
        let mut run = Run { rows, ..run };
        run.rows.extend(run.n.finish(resolve, &run.r));
        let rows = run.rows;
        let summary: Vec<_> = rows
            .iter()
            .map(|r| (r.flags.contains(&Flag::Continued), r.bytes_out, r.bytes_in))
            .collect();
        assert_eq!(
            summary,
            vec![
                (false, Some(100), Some(500)),
                (true, Some(200), Some(400)),
                (true, Some(0), Some(600)),
                (true, Some(50), Some(0)),
            ]
        );
        assert_eq!(rows.iter().filter_map(|r| r.bytes_out).sum::<i64>(), 350);
        assert_eq!(rows.iter().filter_map(|r| r.bytes_in).sum::<i64>(), 1500);
        assert!(
            rows.iter()
                .all(|r| r.action == Action::Connect && r.count == 1)
        );
        // Closed and fully reported: forgotten.
        assert!(run.n.flows.is_empty());
    }

    #[test]
    fn outcomes_follow_what_came_back() {
        let mut run = Run::new();
        run.at(0, 1, api(300));
        run.at(1, 1, bytes(true, 50, 0)); // refused: TCP closed, nothing back
        run.at(0, 2, api(300));
        run.at(1, 2, bytes(false, 50, 10)); // answered
        run.at(0, 3, api(300)); // nothing yet
        run.at(0, 4, open(300, "198.51.100.9", 53, None, Proto::Udp));
        run.at(1, 4, bytes(true, 40, 0)); // UDP, no reply
        let rows = run.finish();
        let got: Vec<_> = rows
            .iter()
            .map(|r| {
                (
                    r.target.as_str(),
                    r.outcome,
                    r.flags.contains(&Flag::Unconfirmed),
                    r.count,
                )
            })
            .collect();
        assert!(
            got.contains(&("api.example-agent.test:443", Outcome::Failed, false, 1)),
            "{got:?}"
        );
        assert!(
            got.contains(&("api.example-agent.test:443", Outcome::Allowed, false, 1)),
            "{got:?}"
        );
        assert!(
            got.contains(&("api.example-agent.test:443", Outcome::Allowed, true, 1)),
            "{got:?}"
        );
        assert!(
            got.contains(&("198.51.100.9:53", Outcome::Allowed, true, 1)),
            "{got:?}"
        );
        assert_eq!(rows.len(), 4);
    }

    #[test]
    fn categories() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(
            category(ip("10.0.0.5"), 443, None),
            Category::NetworkInternal
        );
        assert_eq!(
            category(ip("192.168.1.2"), 80, None),
            Category::NetworkInternal
        );
        assert_eq!(
            category(ip("169.254.1.1"), 80, None),
            Category::NetworkInternal
        );
        assert_eq!(category(ip("fd00::1"), 80, None), Category::NetworkInternal);
        assert_eq!(category(ip("fe80::1"), 80, None), Category::NetworkInternal);
        assert_eq!(
            category(ip("::ffff:10.1.2.3"), 80, None),
            Category::NetworkInternal
        );
        assert_eq!(
            category(ip("203.0.113.7"), 443, Some("nas.local")),
            Category::NetworkInternal
        );
        assert_eq!(
            category(ip("203.0.113.7"), 443, None),
            Category::NetworkExternal
        );
        assert_eq!(
            category(ip("2001:db8::1"), 443, None),
            Category::NetworkExternal
        );
        assert_eq!(category(ip("10.0.0.5"), 445, None), Category::NetworkVolume);
        assert_eq!(
            category(ip("203.0.113.7"), 2049, None),
            Category::NetworkVolume
        );
        assert_eq!(target(ip("2001:db8::1"), 443, None), "[2001:db8::1]:443");
    }

    #[test]
    fn unknown_host_flags() {
        let mut run = Run::new();
        run.at(0, 1, api(300));
        run.at(
            0,
            2,
            open(
                300,
                "203.0.113.8",
                443,
                Some("other.example.test"),
                Proto::Tcp,
            ),
        );
        run.at(0, 3, open(300, "203.0.113.9", 443, None, Proto::Tcp));
        run.at(0, 4, open(300, "10.0.0.9", 8080, None, Proto::Tcp));
        let rows = run.finish();
        let flagged: Vec<_> = rows
            .iter()
            .map(|r| (r.target.as_str(), r.flags.contains(&Flag::UnknownHost)))
            .collect();
        assert!(flagged.contains(&("api.example-agent.test:443", false)));
        assert!(flagged.contains(&("other.example.test:443", true)));
        assert!(flagged.contains(&("203.0.113.9:443", true)));
        assert!(flagged.contains(&("10.0.0.9:8080", false)));
    }

    #[test]
    fn large_uploads_per_row_and_per_session_hour() {
        let mut run = Run::new();
        // One row at the 1,000-byte row threshold.
        run.at(0, 1, api(300));
        run.at(1, 1, bytes(true, 1000, 10));
        // Then 900 bytes per window: the session total crosses 5,000 in the fifth window
        // after the first (1000 + 4*900 = 4600, + 900 = 5500), and only that row is flagged.
        for w in 1..=6 {
            let f = 10 + w as u128;
            run.at(w * 40, f, api(300));
            run.at(w * 40 + 1, f, bytes(true, 900, 10));
        }
        let rows = run.finish();
        let flags: Vec<bool> = rows
            .iter()
            .map(|r| r.flags.contains(&Flag::LargeUpload))
            .collect();
        assert_eq!(
            flags,
            vec![true, false, false, false, false, true, false],
            "{rows:#?}"
        );
    }

    #[test]
    fn a_flow_from_a_process_the_tree_never_saw_is_unknown_process() {
        let mut run = Run::new();
        run.at(0, 1, api(301));
        let rows = run.finish();
        assert_eq!(rows[0].process_path, UNKNOWN_PROCESS);
        assert_eq!(rows[0].pid, 301);
    }

    #[test]
    fn the_extensions_exe_is_used_only_when_the_tree_has_none() {
        let with_exe = |pid| match api(pid) {
            FlowEvent::Open(o) => FlowEvent::Open(FlowOpen {
                exe: Some("/Users/test/.local/bin/helper".to_string()),
                ..o
            }),
            other => other,
        };
        let mut run = Run::new();
        // 301 is unknown to the tree: the extension's path is used.
        run.at(0, 1, with_exe(301));
        // 300 is known to the tree: the tree's path wins.
        run.at(0, 2, with_exe(300));
        let mut paths: Vec<String> = run.finish().into_iter().map(|r| r.process_path).collect();
        paths.sort();
        assert_eq!(
            paths,
            [
                "/Users/test/.local/bin/agent",
                "/Users/test/.local/bin/helper"
            ]
        );
    }

    #[test]
    fn idle_flows_are_forgotten_over_the_cap_but_queued_ones_never() {
        let mut n = NetFlows::with_caps(Duration::seconds(30), 100, 10);
        let r = registry();
        for i in 0..10u128 {
            n.hold(T0, id(i), api(300));
        }
        n.release(Some(T0 + Duration::seconds(31)), resolve, &r);
        // All ten written and idle, still open. Two more push over the cap.
        n.hold(T0 + Duration::seconds(32), id(20), api(300));
        n.hold(T0 + Duration::seconds(32), id(21), api(300));
        n.release(Some(T0 + Duration::seconds(33)), resolve, &r);
        assert!(n.stats.evicted > 0);
        assert!(n.flows.contains_key(&id(20)) && n.flows.contains_key(&id(21)));
    }
}
