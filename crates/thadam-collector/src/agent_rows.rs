//! Agent records (ADR-011 Decisions 3 and 4, amendment 1): what the tool reported about
//! itself, turned into rows. No I/O here; `pipeline.rs` feeds messages in.
//!
//! - A message is held until the OS stream has passed the time it was received, then joined
//!   to the session of the process that sent it (from the socket, never from the message).
//!   The sender must be the installed hook program, inside a registered tool's session.
//! - Prompts become rows. Calls that ran are not stored again (the OS rows have them).
//! - A call that never finished becomes a row when its turn ends: `denied_by_user` if the
//!   tool asked the user to approve it, else `never_ran`. Neither tool reports the user's
//!   answer, so both carry `unconfirmed`.
//! - A call Thadam's guard refused becomes a row at once: `denied_by_agent` with
//!   `blocked_by_guard` (ADR-018; the outcome list is fixed per segment, flags are not). A
//!   call it would have refused (monitor) becomes a row with `would_block` once its outcome is
//!   known: ran, failed, declined or never ran. Both carry `sensitive_path`: that is what the
//!   guard matches.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;

use thadam_core::{
    Action, AgentKind, AgentLink, AgentMessage, CallKind, Category, Flag, GuardResult, NewEvent,
    Outcome, Source,
};
use time::{Duration, OffsetDateTime};

use crate::source::agent::Peer;
use crate::source::{EventKind, OsEvent};
use crate::tree::Membership;

/// Shells a tool may start the hook command with.
const HOOK_SHELLS: &[&str] = &["/bin/sh", "/bin/zsh", "/bin/bash"];

/// After a turn ends, how long a call's late result may still arrive: each hook event is
/// its own process, so a result sent just before the turn's end can be read just after it.
/// An estimate.
pub const CLOSE_GRACE: Duration = Duration::seconds(5);
/// A call with no result and no end of its turn is closed after this (ADR-011 Decision 4,
/// an estimate).
pub const CALL_TIMEOUT: Duration = Duration::minutes(10);
/// Messages held for the OS stream to catch up; beyond this the oldest is dropped and
/// counted. An estimate: about 100 s of hook events at a busy 100 events/s.
pub const HELD_CAP: usize = 10_000;
/// Open calls and approval requests kept per tool session (estimates). Beyond them the
/// oldest is closed early.
const CALLS_CAP: usize = 256;
const ASKS_CAP: usize = 64;
/// Refused calls remembered per tool session, so a later refusal event for the same call
/// does not add a second row (estimate, like `ASKS_CAP`).
const BLOCKED_CAP: usize = 64;
/// Recent command lines kept per session, to tell a call that ran from one that did not
/// when the tool reports no result for failures (amendment 1).
const EXECS_CAP: usize = 64;

/// Who sent a message, as the process tree knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sender {
    pub membership: Membership,
    /// Registry key of the session's tool.
    pub tool: String,
    /// The tool process the rows are about: the session root.
    pub pid: u32,
    pub process_path: String,
}

/// The tree's answer for a peer: its session and running image, if it is a member.
pub type Lookup<'a> = dyn Fn(Peer) -> Option<(Membership, Option<Arc<str>>)> + 'a;

/// Counters for diagnostics. Counts only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentStats {
    pub messages: u64,
    pub accepted: u64,
    /// The sender was not a member of any session, or not the hook program.
    pub refused: u64,
    /// Dropped because too many were waiting for the OS stream.
    pub overflow: u64,
    pub prompts: u64,
    pub declines: u64,
    pub never_ran: u64,
    /// Calls the guard refused, or would have refused (ADR-018).
    pub guard_blocked: u64,
    pub guard_would_block: u64,
    /// Calls the guard could not check (registry unreadable); they ran.
    pub guard_errors: u64,
}

struct Held {
    received: OffsetDateTime,
    peer: Peer,
    message: Box<AgentMessage>,
}

#[derive(Debug, Clone)]
struct Call {
    started: OffsetDateTime,
    id: Option<String>,
    turn: Option<String>,
    input_hash: Option<String>,
    kind: CallKind,
    text: Option<String>,
    tool_name: Option<String>,
    asked: bool,
    /// The guard would have refused it (monitor): its row, written once the outcome is
    /// known, carries `would_block`.
    would_block: bool,
    close_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
struct Ask {
    turn: Option<String>,
    input_hash: Option<String>,
}

/// One tool session inside one Thadam session.
struct State {
    sender: Sender,
    /// The tool's own session ID (every row carries it, with the transcript).
    agent_session_id: String,
    transcript: Option<String>,
    calls: Vec<Call>,
    asks: VecDeque<Ask>,
    /// Calls the guard refused: (call ID, turn, input hash).
    blocked: VecDeque<(Option<String>, Option<String>, Option<String>)>,
    ended: bool,
}

type Key = (Arc<str>, String);

pub struct AgentRows {
    hook_bin: Arc<str>,
    held: VecDeque<Held>,
    sessions: HashMap<Key, State>,
    /// Recent command lines per Thadam session: (time, raw target).
    execs: HashMap<Arc<str>, VecDeque<(OffsetDateTime, String)>>,
    /// Nothing waiting closes before this time; `None` after any change, so the next
    /// `advance` looks. Lets the per-event call skip the walk over every session.
    quiet_until: Option<Quiet>,
    /// Sessions that sent an accepted message, with its time, until `take_heard`.
    heard: Vec<(Arc<str>, OffsetDateTime)>,
    pub stats: AgentStats,
}

#[derive(Debug, Clone, Copy)]
enum Quiet {
    Until(OffsetDateTime),
    /// No call waits and no ended session is left to forget.
    Always,
}

impl AgentRows {
    /// `hook_bin` is the installed hook's path; only that program may send.
    pub fn new(hook_bin: impl Into<Arc<str>>) -> Self {
        Self {
            hook_bin: hook_bin.into(),
            held: VecDeque::new(),
            sessions: HashMap::new(),
            execs: HashMap::new(),
            quiet_until: None,
            heard: Vec::new(),
            stats: AgentStats::default(),
        }
    }

    /// Whether an OS event is part of a run of the installed hook in a `tool_key` session:
    /// the hook process itself, the shell that runs exactly the configured hook command,
    /// or a read of the hook program. Its rows are marked tool-internal, not dropped.
    ///
    /// The shell must run that command and nothing else, so a command line that only
    /// mentions the hook (`'<hook>' --tool x; other`) is never hidden.
    pub fn is_hook_run(&self, event: &OsEvent, tool_key: &str) -> bool {
        let hook = &*self.hook_bin;
        if event.process.executable == hook {
            return true;
        }
        match &event.kind {
            EventKind::Exec { target, args, .. } => {
                target.executable == hook
                    || (HOOK_SHELLS.contains(&target.executable.as_str())
                        && matches!(args.as_slice(),
                            [_, flag, command]
                                if (flag == "-c" || flag == "-lc")
                                    && *command == thadam_core::hook_command(hook, tool_key)))
            }
            EventKind::Open {
                path,
                readable: true,
                writable: false,
                ..
            } => path == hook,
            _ => false,
        }
    }

    pub fn held(&self) -> usize {
        self.held.len()
    }

    pub fn hold(&mut self, received: OffsetDateTime, peer: Peer, message: Box<AgentMessage>) {
        self.stats.messages += 1;
        if self.held.len() >= HELD_CAP {
            self.held.pop_front();
            self.stats.overflow += 1;
        }
        // Kept in received order; lines from parallel connections can be read out of order.
        let at = self.held.partition_point(|h| h.received <= received);
        self.held.insert(
            at,
            Held {
                received,
                peer,
                message,
            },
        );
    }

    /// Joins every held message received up to `before` (all of them when `None`) to its
    /// sender and returns the rows completed, then closes the calls that are due.
    ///
    /// HIDDEN COUPLING (see `Pipeline::handle`): must run before the tree applies an OS
    /// event later than the messages, so the hook process's own exit cannot hide it.
    pub fn release(
        &mut self,
        before: Option<OffsetDateTime>,
        lookup: &Lookup<'_>,
        sender: &dyn Fn(&Membership) -> Option<(String, String)>,
    ) -> Vec<NewEvent> {
        let mut rows = Vec::new();
        while let Some(h) = self.held.front() {
            if before.is_some_and(|b| h.received > b) {
                break;
            }
            let Some(h) = self.held.pop_front() else {
                break;
            };
            let found = lookup(h.peer).filter(|(_, exe)| exe.as_deref() == Some(&*self.hook_bin));
            let Some((membership, _)) = found else {
                self.stats.refused += 1;
                continue;
            };
            let Some((tool, process_path)) = sender(&membership) else {
                self.stats.refused += 1;
                continue;
            };
            self.stats.accepted += 1;
            self.heard
                .push((Arc::clone(&membership.session_id), h.received));
            let s = Sender {
                pid: membership.root_pid,
                membership,
                tool,
                process_path,
            };
            rows.extend(self.apply(h.received, s, &h.message));
        }
        if let Some(now) = before {
            rows.extend(self.advance(now));
        }
        rows
    }

    /// The sessions heard from since the last call, with each message's time (ADR-017
    /// Decision 4).
    pub fn take_heard(&mut self) -> Vec<(Arc<str>, OffsetDateTime)> {
        std::mem::take(&mut self.heard)
    }

    /// A command line run in `session` (an OS exec row): a waiting call whose command it
    /// contains ran, even if the tool never reports a result.
    pub fn saw_exec(&mut self, session: &Arc<str>, target: &str, ts: OffsetDateTime) {
        let execs = self.execs.entry(Arc::clone(session)).or_default();
        if execs.len() >= EXECS_CAP {
            execs.pop_front();
        }
        execs.push_back((ts, target.to_string()));
        for ((s, _), state) in &mut self.sessions {
            if s == session {
                state.calls.retain(|c| !ran(c, ts, target));
            }
        }
    }

    /// The session's root process exited: whatever is still waiting closes after the grace.
    pub fn session_ended(&mut self, session: &Arc<str>, ts: OffsetDateTime) {
        self.quiet_until = None;
        for ((s, _), state) in &mut self.sessions {
            if s == session {
                state.ended = true;
                close_all(&mut state.calls, ts + CLOSE_GRACE);
            }
        }
        self.execs.remove(session);
    }

    /// True when nothing is held and nothing closes by `now`: a call would change nothing.
    pub fn is_quiet(&self, now: OffsetDateTime) -> bool {
        self.held.is_empty()
            && match self.quiet_until {
                Some(Quiet::Always) => true,
                Some(Quiet::Until(t)) => now < t,
                None => false,
            }
    }

    /// Closes the calls whose time has come and forgets sessions that have ended.
    pub fn advance(&mut self, now: OffsetDateTime) -> Vec<NewEvent> {
        if self.is_quiet(now) {
            return Vec::new();
        }
        let mut rows = Vec::new();
        for state in self.sessions.values_mut() {
            let mut i = 0;
            while i < state.calls.len() {
                if state.calls[i].close_at <= now {
                    let call = state.calls.remove(i);
                    rows.push(closed_row(&mut self.stats, state, &call));
                } else {
                    i += 1;
                }
            }
        }
        self.sessions
            .retain(|_, s| !(s.ended && s.calls.is_empty()));
        self.quiet_until = Some(
            self.sessions
                .values()
                .flat_map(|s| s.calls.iter().map(|c| c.close_at))
                .min()
                .map_or(Quiet::Always, Quiet::Until),
        );
        rows
    }

    /// End of input or shutdown: every waiting call is closed now.
    pub fn finish(
        &mut self,
        lookup: &Lookup<'_>,
        sender: &dyn Fn(&Membership) -> Option<(String, String)>,
    ) -> Vec<NewEvent> {
        let mut rows = self.release(None, lookup, sender);
        for state in self.sessions.values_mut() {
            for call in std::mem::take(&mut state.calls) {
                rows.push(closed_row(&mut self.stats, state, &call));
            }
        }
        self.sessions.clear();
        rows
    }

    fn apply(&mut self, at: OffsetDateTime, sender: Sender, m: &AgentMessage) -> Vec<NewEvent> {
        self.quiet_until = None;
        let key = (
            Arc::clone(&sender.membership.session_id),
            m.agent_session_id.clone(),
        );
        let state = self.sessions.entry(key.clone()).or_insert_with(|| State {
            sender: sender.clone(),
            agent_session_id: m.agent_session_id.clone(),
            transcript: None,
            calls: Vec::new(),
            asks: VecDeque::new(),
            blocked: VecDeque::new(),
            ended: false,
        });
        state.sender = sender;
        if m.transcript.is_some() {
            state.transcript.clone_from(&m.transcript);
        }
        let mut rows = Vec::new();
        match m.kind {
            AgentKind::SessionStart => {}
            AgentKind::Prompt => {
                // A new prompt ends whatever the previous turn left waiting.
                close_all(&mut state.calls, at + CLOSE_GRACE);
                self.stats.prompts += 1;
                rows.push(row(
                    state,
                    at,
                    Category::Prompt,
                    Action::Prompt,
                    m.text.clone().unwrap_or_default(),
                    Outcome::Allowed,
                    // A tool's helper session has no transcript: its prompt is the tool's,
                    // not the user's (amendment 1).
                    state.transcript.is_none(),
                ));
            }
            AgentKind::PermissionRequest => {
                if let Some(call) = state
                    .calls
                    .iter_mut()
                    .find(|c| !c.asked && c.turn == m.turn && c.input_hash == m.input_hash)
                {
                    call.asked = true;
                } else {
                    if state.asks.len() >= ASKS_CAP {
                        state.asks.pop_front();
                    }
                    state.asks.push_back(Ask {
                        turn: m.turn.clone(),
                        input_hash: m.input_hash.clone(),
                    });
                }
            }
            AgentKind::CallStart => {
                if m.call.is_some() && state.calls.iter().any(|c| c.id == m.call) {
                    return rows;
                }
                match m.guard {
                    Some(GuardResult::Blocked) => {
                        if state.blocked.iter().any(|b| same_call(b, m)) {
                            return rows;
                        }
                        self.stats.guard_blocked += 1;
                        if state.blocked.len() >= BLOCKED_CAP {
                            state.blocked.pop_front();
                        }
                        state.blocked.push_back((
                            m.call.clone(),
                            m.turn.clone(),
                            m.input_hash.clone(),
                        ));
                        let (category, action, target) = what(
                            m.call_kind.unwrap_or(CallKind::Other),
                            m.text.as_deref(),
                            m.tool_name.as_deref(),
                        );
                        let mut r = row(
                            state,
                            at,
                            category,
                            action,
                            target,
                            Outcome::DeniedByAgent,
                            state.transcript.is_none(),
                        );
                        guard_flags(&mut r, Flag::BlockedByGuard);
                        rows.push(r);
                        // Refused before it ran: there is no call to wait for.
                        return rows;
                    }
                    Some(GuardResult::WouldBlock) => self.stats.guard_would_block += 1,
                    Some(GuardResult::Error) => self.stats.guard_errors += 1,
                    None => {}
                }
                let asked = match state
                    .asks
                    .iter()
                    .position(|a| a.turn == m.turn && a.input_hash == m.input_hash)
                {
                    Some(i) => {
                        state.asks.remove(i);
                        true
                    }
                    None => false,
                };
                let call = Call {
                    started: at,
                    id: m.call.clone(),
                    turn: m.turn.clone(),
                    input_hash: m.input_hash.clone(),
                    kind: m.call_kind.unwrap_or(CallKind::Other),
                    text: m.text.clone(),
                    tool_name: m.tool_name.clone(),
                    asked,
                    would_block: m.guard == Some(GuardResult::WouldBlock),
                    close_at: at + CALL_TIMEOUT,
                };
                // It may already have run: the hook is asynchronous, so the OS can report the
                // command before the tool's own event arrives.
                let execs = self.execs.get(&key.0);
                if execs.is_some_and(|e| e.iter().any(|(ts, t)| ran(&call, *ts, t))) {
                    if call.would_block {
                        rows.push(ran_row(state, &call, Outcome::Allowed));
                    }
                    return rows;
                }
                if state.calls.len() >= CALLS_CAP {
                    let oldest = state.calls.remove(0);
                    rows.push(closed_row(&mut self.stats, state, &oldest));
                }
                state.calls.push(call);
            }
            AgentKind::CallDone | AgentKind::CallFailed => {
                // A failure fires both events in one tool (amendment 1): the first removes
                // the call, the second finds nothing.
                if let Some(call) = remove_call(&mut state.calls, m)
                    && call.would_block
                {
                    let outcome = if m.kind == AgentKind::CallFailed {
                        Outcome::Failed
                    } else {
                        Outcome::Allowed
                    };
                    rows.push(ran_row(state, &call, outcome));
                }
            }
            AgentKind::Denied => {
                if state.blocked.iter().any(|b| same_call(b, m)) {
                    return rows;
                }
                let call = remove_call(&mut state.calls, m);
                self.stats.declines += 1;
                let (category, action, target) = match &call {
                    Some(c) => what(c.kind, c.text.as_deref(), c.tool_name.as_deref()),
                    None => what(
                        m.call_kind.unwrap_or(CallKind::Other),
                        m.text.as_deref(),
                        m.tool_name.as_deref(),
                    ),
                };
                let at = call.as_ref().map_or(at, |c| c.started);
                let mut r = row(
                    state,
                    at,
                    category,
                    action,
                    target,
                    Outcome::DeniedByAgent,
                    state.transcript.is_none(),
                );
                if call.as_ref().is_some_and(|c| c.would_block) {
                    guard_flags(&mut r, Flag::WouldBlock);
                }
                rows.push(r);
            }
            AgentKind::TurnEnd => {
                for c in &mut state.calls {
                    if m.turn.is_none() || c.turn == m.turn {
                        c.close_at = c.close_at.min(at + CLOSE_GRACE);
                    }
                }
            }
            AgentKind::SessionEnd => {
                state.ended = true;
                close_all(&mut state.calls, at + CLOSE_GRACE);
            }
        }
        rows
    }
}

fn close_all(calls: &mut [Call], at: OffsetDateTime) {
    for c in calls {
        c.close_at = c.close_at.min(at);
    }
}

fn remove_call(calls: &mut Vec<Call>, m: &AgentMessage) -> Option<Call> {
    let i = match &m.call {
        Some(id) => calls.iter().position(|c| c.id.as_ref() == Some(id)),
        None => calls
            .iter()
            .position(|c| c.turn == m.turn && c.input_hash == m.input_hash),
    }?;
    Some(calls.remove(i))
}

/// Whether the command line `target`, run at `ts`, is this shell call's command.
fn ran(call: &Call, ts: OffsetDateTime, target: &str) -> bool {
    call.kind == CallKind::Shell
        && ts >= call.started - CLOSE_GRACE
        && call
            .text
            .as_deref()
            .is_some_and(|t| !t.trim().is_empty() && target.contains(t.trim()))
}

/// The row's category, action and target for a call. A call to something other than a
/// shell or a file (a search, the web, another tool) is recorded by the tool's name.
fn what(kind: CallKind, text: Option<&str>, tool_name: Option<&str>) -> (Category, Action, String) {
    let name = || tool_name.unwrap_or("unknown tool").to_string();
    match kind {
        CallKind::Shell => (
            Category::Command,
            Action::Exec,
            text.map_or_else(name, str::to_string),
        ),
        CallKind::FileRead => (
            Category::File,
            Action::Read,
            text.map_or_else(name, str::to_string),
        ),
        CallKind::FileWrite => (
            Category::File,
            Action::Write,
            text.map_or_else(name, str::to_string),
        ),
        CallKind::Search => (
            Category::File,
            Action::Read,
            text.map_or_else(name, str::to_string),
        ),
        CallKind::Other => (Category::Command, Action::Exec, name()),
    }
}

/// Marks a row the guard matched: what it did, and why (it matches sensitive paths only).
fn guard_flags(r: &mut NewEvent, flag: Flag) {
    r.flags.insert(flag);
    r.flags.insert(Flag::SensitivePath);
}

/// The row for a call the guard would have refused, once it is known to have run.
fn ran_row(state: &State, call: &Call, outcome: Outcome) -> NewEvent {
    let (category, action, target) =
        what(call.kind, call.text.as_deref(), call.tool_name.as_deref());
    let mut r = row(
        state,
        call.started,
        category,
        action,
        target,
        outcome,
        state.transcript.is_none(),
    );
    guard_flags(&mut r, Flag::WouldBlock);
    r
}

/// Whether a refused call (call ID, turn, input hash) is message `m`'s call. Without call IDs
/// both turn and input hash must be known and equal: a missing value never matches.
fn same_call(blocked: &(Option<String>, Option<String>, Option<String>), m: &AgentMessage) -> bool {
    match (&blocked.0, &m.call) {
        (Some(id), Some(call)) => id == call,
        (None, None) => {
            blocked.1.is_some()
                && blocked.2.is_some()
                && blocked.1 == m.turn
                && blocked.2 == m.input_hash
        }
        _ => false,
    }
}

/// The row for a call that never finished.
fn closed_row(stats: &mut AgentStats, state: &State, call: &Call) -> NewEvent {
    let outcome = if call.asked {
        stats.declines += 1;
        Outcome::DeniedByUser
    } else {
        stats.never_ran += 1;
        Outcome::NeverRan
    };
    let (category, action, target) =
        what(call.kind, call.text.as_deref(), call.tool_name.as_deref());
    let mut r = row(
        state,
        call.started,
        category,
        action,
        target,
        outcome,
        state.transcript.is_none(),
    );
    r.flags.insert(Flag::Unconfirmed);
    if call.would_block {
        guard_flags(&mut r, Flag::WouldBlock);
    }
    r
}

fn row(
    state: &State,
    ts: OffsetDateTime,
    category: Category,
    action: Action,
    target: String,
    outcome: Outcome,
    internal: bool,
) -> NewEvent {
    let s = &state.sender;
    let mut flags = BTreeSet::new();
    if internal {
        flags.insert(Flag::Internal);
    }
    NewEvent {
        ts,
        tool: s.tool.clone(),
        session_id: Some(s.membership.session_id.to_string()),
        parent_session_id: s
            .membership
            .parent_session_id
            .as_deref()
            .map(str::to_string),
        pid: s.pid,
        process_path: s.process_path.clone(),
        category,
        action,
        target,
        outcome,
        size_bytes: None,
        bytes_out: None,
        bytes_in: None,
        project: s.membership.project.as_deref().map(str::to_string),
        flags,
        count: 1,
        sources: BTreeSet::from([Source::Agent]),
        agent: Some(AgentLink {
            session_id: state.agent_session_id.clone(),
            transcript: state.transcript.clone(),
        }),
    }
}

#[cfg(test)]
mod tests;
