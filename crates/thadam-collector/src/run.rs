//! Threads and lifetimes (ADR-003 Decisions 8 and 10).
//!
//! ```text
//! OS source   ─▶ [reader thread] ──┐
//!                                  ├─items─▶ [this thread: pipeline + redaction] ─records─▶ [writer thread: store]
//! flow socket ─▶ [listener threads]┤
//! agent socket ▶ [listener threads]┘
//! ```
//!
//! One pipeline thread owns the process tree, so OS events and network flows need no lock
//! (ADR-007 Decision 4). Both channels are bounded. If the writer falls behind, the pipeline waits, then the
//! reader, then the OS logger buffers: nothing is dropped silently. The one exception is a
//! low disk (ADR-009 Decision 4): the writer then counts records instead of writing them,
//! and the catalog records the gap with its count.
//!
//! The writer thread also keeps the heartbeat and, once a minute, records a `dropped` gap per
//! source that lost events in that minute (ADR-013 Decision 1). The pipeline thread publishes
//! its loss counters for it (`Lost`).
//!
//! Agent items, which any tool can produce at will, may hold at most `AGENT_SLOTS` of the
//! item buffer (ADR-015 Decision 2). Beyond that they are dropped and recorded as a `dropped`
//! gap with detail `agent`, so a flood of hook messages cannot hold up OS events.

use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use thadam_core::{EventRecord, Redactor};
use thadam_store::{SegmentStatus, SegmentWriter, StoreError, Written};
use thiserror::Error;

use crate::coverage::{self, Beat, Heartbeat};
use crate::pipeline::{Pipeline, Stats};
use crate::source::agent::{AgentItem, AgentListener};
use crate::source::network::{FlowItem, FlowListener};
use crate::source::{EventSource, SourceItem};

/// The built-in macOS event logger, and the events this slice subscribes to (as Phase 0).
pub const LOGGER: &str = "/usr/bin/eslogger";
pub const LOGGER_EVENTS: &[&str] = &[
    "exec", "fork", "exit", "open", "close", "create", "rename", "unlink",
];

/// Items buffered between reader and pipeline. About 50 s at the 1,330 events/s average
/// measured in Phase 0, enough to cover the start-up snapshot (estimate: under 1 s).
const ITEM_BUFFER: usize = 65_536;
/// Of `ITEM_BUFFER`, how many agent items may wait at once (ADR-015 Decision 2; estimate).
const AGENT_SLOTS: usize = 2_048;
/// Records buffered for the writer (estimate, ADR-003 Decision 8).
const RECORD_BUFFER: usize = 10_000;
/// How long to keep draining after a stop request before giving up on the source.
const STOP_GRACE: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(500);
/// How often the writer applies the retention limits and checks free space (ADR-009
/// Decision 3), beats the heartbeat and records dropped events (ADR-013 Decision 1).
const MAINTAIN_EVERY: Duration = coverage::BEAT_EVERY;

#[derive(Debug, Error)]
pub enum RunError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("cannot set up redaction: {0}")]
    Redactor(#[from] thadam_core::CoreError),
    #[error("event source failed: {0}")]
    Source(String),
    #[error("writer thread stopped unexpectedly")]
    Writer,
}

/// What the pipeline thread receives.
enum Input {
    Os(Result<SourceItem, String>),
    /// The OS source reached its end. Explicit, because the flow listener keeps the channel
    /// open for as long as the process runs.
    OsEnd,
    Net(FlowItem),
    Agent(AgentItem),
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// The source reached its end (replay finished, or the logger exited).
    EndOfInput,
    /// A stop was requested (signal).
    Stopped,
}

/// Starts the built-in logger with JSON output on a pipe.
///
/// The logger gets its own process group, so a terminal Ctrl-C reaches only the collector.
/// The collector then stops the logger itself (`on_stop`) after deciding how to shut down;
/// otherwise the logger could exit first and look like a crash.
pub fn spawn_logger() -> std::io::Result<(Child, BufReader<ChildStdout>)> {
    let mut child = Command::new(LOGGER)
        .args(LOGGER_EVENTS)
        .args(["--format", "json"])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // The logger's own errors (for example a missing Full Disk Access grant) go to the same
    // place as the collector's diagnostics, so the daemon's log shows why it stopped.
    if let Some(err) = child.stderr.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                crate::diag!("eslogger: {line}");
            }
        });
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("logger has no stdout"))?;
    Ok((child, BufReader::new(stdout)))
}

/// Runs until the source ends or `stop` is set.
///
/// ORDERING: `prepare` (the snapshot) runs after the reader has started, so events that
/// happen while the snapshot is taken are buffered, not lost (see `snapshot.rs`).
/// `on_stop` runs once when a stop is first seen; for the live logger it ends the child,
/// which closes the pipe so the remaining output drains. `flows`, when given, is served
/// for the whole run, and so is `agents` (ADR-011).
#[allow(clippy::too_many_arguments)]
pub fn run<S>(
    source: S,
    flows: Option<FlowListener>,
    agents: Option<AgentListener>,
    pipeline: &mut Pipeline,
    store: SegmentWriter,
    stop: &AtomicBool,
    prepare: impl FnOnce(&mut Pipeline),
    on_stop: impl FnOnce(),
    report_every: Duration,
    heartbeat: Option<Heartbeat>,
) -> Result<(Ended, Stats), RunError>
where
    S: EventSource + Send + 'static,
{
    let redactor = Redactor::with_default_detectors()?;
    let (item_tx, item_rx) = sync_channel::<Input>(ITEM_BUFFER);
    let lost = Arc::new(Lost::default());
    if let Some(listener) = flows {
        pipeline.enable_network();
        let tx = item_tx.clone();
        // Not joined either: it waits in accept for as long as the process runs.
        std::thread::spawn(move || listener.serve(move |item| tx.send(Input::Net(item)).is_ok()));
    }
    if let Some(listener) = agents {
        pipeline.enable_agent();
        let tx = item_tx.clone();
        let lost = Arc::clone(&lost);
        // Not joined, as the flow listener.
        std::thread::spawn(move || {
            listener.serve(move |item| !lost.admit_agent() || tx.send(Input::Agent(item)).is_ok())
        });
    }
    let backlog = Arc::new(Backlog::default());
    // Not joined: a reader blocked on a quiet input must not hold up shutdown.
    {
        let backlog = Arc::clone(&backlog);
        std::thread::spawn(move || read_all(source, &item_tx, &backlog));
    }

    let (record_tx, record_rx) = sync_channel::<EventRecord>(RECORD_BUFFER);
    // Shared so progress lines show rows written so far, not only the total at the end.
    let written = Arc::new(AtomicU64::new(0));
    let status = Arc::new(Mutex::new(store.status()));
    let writer = {
        let written = Arc::clone(&written);
        let status = Arc::clone(&status);
        let lost = Arc::clone(&lost);
        std::thread::spawn(move || {
            write_all(
                store,
                &record_rx,
                &written,
                &status,
                &lost,
                heartbeat.as_ref(),
            )
        })
    };

    prepare(pipeline);

    let outcome = process(
        pipeline,
        &redactor,
        &item_rx,
        &record_tx,
        stop,
        on_stop,
        Progress {
            every: report_every,
            written: &written,
            status: &status,
            lost: &lost,
            backlog: &backlog,
        },
    );
    drop(record_tx);
    writer.join().map_err(|_| RunError::Writer)??;
    pipeline.stats.written = written.load(Ordering::Relaxed);
    pipeline.stats.store = status.lock().ok().map(|s| *s);
    let ended = outcome?;
    Ok((ended, pipeline.stats.clone()))
}

/// OS items waiting between the reader and the pipeline. When the OS logger drops events,
/// this tells whether the collector fell behind (queue near `ITEM_BUFFER`) or the logger
/// itself did (queue low). Counts only.
#[derive(Default)]
struct Backlog {
    queued: AtomicUsize,
    peak: AtomicUsize,
}

impl Backlog {
    fn add(&self) {
        let now = self.queued.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak.fetch_max(now, Ordering::Relaxed);
    }

    fn take(&self) {
        self.queued.fetch_sub(1, Ordering::Relaxed);
    }

    /// The highest backlog since the last call.
    fn reset_peak(&self) -> usize {
        self.peak
            .swap(self.queued.load(Ordering::Relaxed), Ordering::Relaxed)
    }
}

fn read_all<S: EventSource>(mut source: S, tx: &SyncSender<Input>, backlog: &Backlog) {
    loop {
        let item = match source.next() {
            Ok(Some(item)) => Ok(item),
            Ok(None) => {
                let _ = tx.send(Input::OsEnd);
                return;
            }
            Err(e) => Err(e.to_string()),
        };
        let failed = item.is_err();
        backlog.add();
        if tx.send(Input::Os(item)).is_err() || failed {
            return;
        }
    }
}

/// Events the sources reported lost so far, published by the pipeline thread.
#[derive(Default)]
struct Lost {
    os: AtomicU64,
    net: AtomicU64,
    /// Agent items dropped over `AGENT_SLOTS`, counted by the agent listener.
    agent: AtomicU64,
    /// Agent items waiting in the item buffer.
    agent_queued: AtomicUsize,
}

impl Lost {
    /// Takes one of `AGENT_SLOTS` for an agent item, or counts it dropped when none is free.
    /// The pipeline thread gives the slot back as it takes the item (`process`).
    fn admit_agent(&self) -> bool {
        if self.agent_queued.fetch_add(1, Ordering::AcqRel) < AGENT_SLOTS {
            return true;
        }
        self.agent_queued.fetch_sub(1, Ordering::AcqRel);
        self.agent.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// What the writer has already recorded of `Lost`, and since when.
struct Recorded {
    since_us: i64,
    os: u64,
    net: u64,
    agent: u64,
}

impl Recorded {
    /// One `dropped` gap per source that lost events since the last call.
    fn record(&mut self, store: &mut SegmentWriter, lost: &Lost) -> Result<(), StoreError> {
        let now = now_us();
        let os = lost.os.load(Ordering::Relaxed);
        let net = lost.net.load(Ordering::Relaxed);
        let agent = lost.agent.load(Ordering::Relaxed);
        for gap in [
            coverage::dropped(self.since_us, now, "os", os.saturating_sub(self.os)),
            coverage::dropped(self.since_us, now, "network", net.saturating_sub(self.net)),
            coverage::dropped(
                self.since_us,
                now,
                "agent",
                agent.saturating_sub(self.agent),
            ),
        ]
        .into_iter()
        .flatten()
        {
            store.record_gap(now, &gap)?;
        }
        *self = Self {
            since_us: now,
            os,
            net,
            agent,
        };
        Ok(())
    }
}

/// Writes the heartbeat. A failure is reported, never fatal: the beat is only a hint.
fn beat(heartbeat: Option<&Heartbeat>, stopped: bool) {
    if let Some(hb) = heartbeat
        && let Err(e) = hb.write(Beat {
            at_us: now_us(),
            stopped,
        })
    {
        crate::diag!("thadam-collector: cannot write the heartbeat: {e}");
    }
}

/// Writes records and, once a minute, applies the retention limits, beats and records
/// dropped events. A record not written because the disk is low is counted by the writer
/// and noted in the catalog on resume.
fn write_all(
    mut store: SegmentWriter,
    rx: &Receiver<EventRecord>,
    written: &AtomicU64,
    status: &Mutex<SegmentStatus>,
    lost: &Lost,
    heartbeat: Option<&Heartbeat>,
) -> Result<(), StoreError> {
    let publish = |store: &SegmentWriter| {
        if let Ok(mut s) = status.lock() {
            *s = store.status();
        }
    };
    beat(heartbeat, false);
    let mut recorded = Recorded {
        since_us: now_us(),
        os: 0,
        net: 0,
        agent: 0,
    };
    store.maintain(now_us())?;
    publish(&store);
    let mut last_maintain = Instant::now();
    loop {
        match rx.recv_timeout(MAINTAIN_EVERY) {
            Ok(record) => {
                let before = store.status();
                if store.append(&record, now_us())? == Written::Row {
                    written.fetch_add(1, Ordering::Relaxed);
                }
                // A rollover opens a segment and runs the limits, so the figures (and the
                // pause state) can change here, not only on the minute.
                let after = store.status();
                if after != before {
                    if after.paused && !before.paused {
                        crate::diag!("thadam-collector: disk low, writing paused");
                    }
                    publish(&store);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if last_maintain.elapsed() >= MAINTAIN_EVERY {
            let was_paused = store.status().paused;
            store.maintain(now_us())?;
            if store.status().paused && !was_paused {
                // One line, counts only (ADR-009 Decision 4).
                crate::diag!("thadam-collector: disk low, writing paused");
            }
            publish(&store);
            recorded.record(&mut store, lost)?;
            beat(heartbeat, false);
            last_maintain = Instant::now();
        }
    }
    publish(&store);
    recorded.record(&mut store, lost)?;
    store.finish(now_us())?;
    beat(heartbeat, true);
    Ok(())
}

/// Wall-clock time in microseconds since the epoch.
pub fn now_us() -> i64 {
    i64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000)
        .unwrap_or(i64::MAX)
}

/// When to print a progress line, and the writer's running figures for it.
struct Progress<'a> {
    every: Duration,
    written: &'a AtomicU64,
    status: &'a Mutex<SegmentStatus>,
    lost: &'a Lost,
    backlog: &'a Backlog,
}

impl Progress<'_> {
    fn publish_lost(&self, stats: &Stats) {
        self.lost.os.store(stats.missed, Ordering::Relaxed);
        self.lost.net.store(stats.net_missed, Ordering::Relaxed);
    }
}

fn process(
    pipeline: &mut Pipeline,
    redactor: &Redactor,
    items: &Receiver<Input>,
    records: &SyncSender<EventRecord>,
    stop: &AtomicBool,
    on_stop: impl FnOnce(),
    progress: Progress<'_>,
) -> Result<Ended, RunError> {
    let mut on_stop = Some(on_stop);
    let mut stop_seen: Option<Instant> = None;
    let mut last_report = Instant::now();
    let started = Instant::now();
    let mut drop_reported = false;

    let ended = loop {
        if stop.load(Ordering::SeqCst) && stop_seen.is_none() {
            stop_seen = Some(Instant::now());
            if let Some(f) = on_stop.take() {
                f();
            }
        }
        if stop_seen.is_some_and(|t| t.elapsed() >= STOP_GRACE) {
            break Ended::Stopped;
        }
        if last_report.elapsed() >= progress.every {
            pipeline.stats.written = progress.written.load(Ordering::Relaxed);
            pipeline.stats.store = progress.status.lock().ok().map(|s| *s);
            crate::diag!(
                "thadam-collector: {} queue_peak={}",
                pipeline.stats,
                progress.backlog.reset_peak()
            );
            last_report = Instant::now();
        }
        match items.recv_timeout(POLL) {
            Ok(Input::Os(Ok(item))) => {
                progress.backlog.take();
                send(pipeline.handle(item), pipeline, redactor, records)?;
                progress.publish_lost(&pipeline.stats);
                if !drop_reported && pipeline.stats.gaps > 0 {
                    drop_reported = true;
                    crate::diag!(
                        "thadam-collector: first OS drop {:.1} s after start, queue {} of {ITEM_BUFFER}",
                        started.elapsed().as_secs_f64(),
                        progress.backlog.queued.load(Ordering::Relaxed)
                    );
                }
            }
            Ok(Input::Net(item)) => {
                send(pipeline.handle_flow(item), pipeline, redactor, records)?;
                progress.publish_lost(&pipeline.stats);
            }
            Ok(Input::Agent(item)) => {
                progress.lost.agent_queued.fetch_sub(1, Ordering::AcqRel);
                send(pipeline.handle_agent(item), pipeline, redactor, records)?;
            }
            Ok(Input::Os(Err(e))) => {
                progress.backlog.take();
                send(pipeline.finish(), pipeline, redactor, records)?;
                return Err(RunError::Source(e));
            }
            Err(RecvTimeoutError::Timeout) => {}
            Ok(Input::OsEnd) | Err(RecvTimeoutError::Disconnected) => {
                break if stop_seen.is_some() {
                    Ended::Stopped
                } else {
                    Ended::EndOfInput
                };
            }
        }
    };
    send(pipeline.finish(), pipeline, redactor, records)?;
    progress.publish_lost(&pipeline.stats);
    Ok(ended)
}

fn send(
    done: Vec<thadam_core::NewEvent>,
    pipeline: &mut Pipeline,
    redactor: &Redactor,
    records: &SyncSender<EventRecord>,
) -> Result<(), RunError> {
    for event in done {
        match EventRecord::new(event, redactor) {
            Ok(record) => records.send(record).map_err(|_| RunError::Writer)?,
            // Counted, never logged: the event may hold a path or command line.
            Err(_) => pipeline.stats.invalid += 1,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_items_over_their_slots_are_counted_dropped() {
        let lost = Lost::default();
        assert!((0..AGENT_SLOTS).all(|_| lost.admit_agent()));
        assert!(!lost.admit_agent());
        assert!(!lost.admit_agent());
        assert_eq!(lost.agent.load(Ordering::Relaxed), 2);
        assert_eq!(lost.agent_queued.load(Ordering::Relaxed), AGENT_SLOTS);
        // The pipeline takes one: one more fits.
        lost.agent_queued.fetch_sub(1, Ordering::AcqRel);
        assert!(lost.admit_agent());
        assert_eq!(lost.agent.load(Ordering::Relaxed), 2);
        let gap = coverage::dropped(0, 1, "agent", 2).unwrap();
        assert_eq!((gap.detail, gap.missed), (Some("agent"), Some(2)));
    }
}
