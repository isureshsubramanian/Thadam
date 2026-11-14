//! Threads and lifetimes (ADR-003 Decisions 8 and 10).
//!
//! ```text
//! OS source   ─▶ [reader thread] ──┐
//!                                  ├─items─▶ [this thread: pipeline + redaction] ─records─▶ [writer thread: store]
//! flow socket ─▶ [listener threads]┘
//! ```
//!
//! One pipeline thread owns the process tree, so OS events and network flows need no lock
//! (ADR-007 Decision 4). Both channels are bounded. If the writer falls behind, the pipeline waits, then the
//! reader, then the OS logger buffers: nothing is dropped silently. The one exception is a
//! low disk (ADR-009 Decision 4): the writer then counts records instead of writing them,
//! and the catalog records the gap with its count.

use std::io::BufReader;
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use thadam_core::{EventRecord, Redactor};
use thadam_store::{SegmentStatus, SegmentWriter, StoreError, Written};
use thiserror::Error;

use crate::pipeline::{Pipeline, Stats};
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
/// Records buffered for the writer (estimate, ADR-003 Decision 8).
const RECORD_BUFFER: usize = 10_000;
/// How long to keep draining after a stop request before giving up on the source.
const STOP_GRACE: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(500);
/// How often the writer applies the retention limits and checks free space (ADR-009
/// Decision 3).
const MAINTAIN_EVERY: Duration = Duration::from_secs(60);

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
        .stderr(Stdio::inherit())
        .spawn()?;
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
/// for the whole run.
#[allow(clippy::too_many_arguments)]
pub fn run<S>(
    source: S,
    flows: Option<FlowListener>,
    pipeline: &mut Pipeline,
    store: SegmentWriter,
    stop: &AtomicBool,
    prepare: impl FnOnce(&mut Pipeline),
    on_stop: impl FnOnce(),
    report_every: Duration,
) -> Result<(Ended, Stats), RunError>
where
    S: EventSource + Send + 'static,
{
    let redactor = Redactor::with_default_detectors()?;
    let (item_tx, item_rx) = sync_channel::<Input>(ITEM_BUFFER);
    if let Some(listener) = flows {
        pipeline.enable_network();
        let tx = item_tx.clone();
        // Not joined either: it waits in accept for as long as the process runs.
        std::thread::spawn(move || listener.serve(move |item| tx.send(Input::Net(item)).is_ok()));
    }
    // Not joined: a reader blocked on a quiet input must not hold up shutdown.
    std::thread::spawn(move || read_all(source, &item_tx));

    let (record_tx, record_rx) = sync_channel::<EventRecord>(RECORD_BUFFER);
    // Shared so progress lines show rows written so far, not only the total at the end.
    let written = Arc::new(AtomicU64::new(0));
    let status = Arc::new(Mutex::new(store.status()));
    let writer = {
        let written = Arc::clone(&written);
        let status = Arc::clone(&status);
        std::thread::spawn(move || write_all(store, &record_rx, &written, &status))
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
        },
    );
    drop(record_tx);
    writer.join().map_err(|_| RunError::Writer)??;
    pipeline.stats.written = written.load(Ordering::Relaxed);
    pipeline.stats.store = status.lock().ok().map(|s| *s);
    let ended = outcome?;
    Ok((ended, pipeline.stats.clone()))
}

fn read_all<S: EventSource>(mut source: S, tx: &SyncSender<Input>) {
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
        if tx.send(Input::Os(item)).is_err() || failed {
            return;
        }
    }
}

/// Writes records and, once a minute, applies the retention limits. A record not written
/// because the disk is low is counted by the writer and noted in the catalog on resume.
fn write_all(
    mut store: SegmentWriter,
    rx: &Receiver<EventRecord>,
    written: &AtomicU64,
    status: &Mutex<SegmentStatus>,
) -> Result<(), StoreError> {
    let publish = |store: &SegmentWriter| {
        if let Ok(mut s) = status.lock() {
            *s = store.status();
        }
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
                        eprintln!("thadam-collector: disk low, writing paused");
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
                eprintln!("thadam-collector: disk low, writing paused");
            }
            publish(&store);
            last_maintain = Instant::now();
        }
    }
    publish(&store);
    store.finish(now_us())
}

fn now_us() -> i64 {
    i64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000)
        .unwrap_or(i64::MAX)
}

/// When to print a progress line, and the writer's running figures for it.
struct Progress<'a> {
    every: Duration,
    written: &'a AtomicU64,
    status: &'a Mutex<SegmentStatus>,
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
            eprintln!("thadam-collector: {}", pipeline.stats);
            last_report = Instant::now();
        }
        match items.recv_timeout(POLL) {
            Ok(Input::Os(Ok(item))) => send(pipeline.handle(item), pipeline, redactor, records)?,
            Ok(Input::Net(item)) => send(pipeline.handle_flow(item), pipeline, redactor, records)?,
            Ok(Input::Os(Err(e))) => {
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
