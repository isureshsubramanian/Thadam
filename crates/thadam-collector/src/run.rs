//! Threads and lifetimes (ADR-003 Decisions 8 and 10).
//!
//! ```text
//! source ─▶ [reader thread] ─items─▶ [this thread: pipeline + redaction] ─records─▶ [writer thread: store]
//! ```
//!
//! Both channels are bounded. If the writer falls behind, the pipeline waits, then the
//! reader, then the OS logger buffers: nothing is dropped silently.

use std::io::BufReader;
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::time::{Duration, Instant};

use thadam_core::{EventRecord, Redactor};
use thadam_store::{Store, StoreError};
use thiserror::Error;

use crate::pipeline::{Pipeline, Stats};
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
/// which closes the pipe so the remaining output drains.
pub fn run<S>(
    source: S,
    pipeline: &mut Pipeline,
    store: Store,
    stop: &AtomicBool,
    prepare: impl FnOnce(&mut Pipeline),
    on_stop: impl FnOnce(),
    report_every: Duration,
) -> Result<(Ended, Stats), RunError>
where
    S: EventSource + Send + 'static,
{
    let redactor = Redactor::with_default_detectors()?;
    let (item_tx, item_rx) = sync_channel::<Result<SourceItem, String>>(ITEM_BUFFER);
    // Not joined: a reader blocked on a quiet input must not hold up shutdown.
    std::thread::spawn(move || read_all(source, &item_tx));

    let (record_tx, record_rx) = sync_channel::<EventRecord>(RECORD_BUFFER);
    // Shared so progress lines show rows written so far, not only the total at the end.
    let written = Arc::new(AtomicU64::new(0));
    let writer = {
        let written = Arc::clone(&written);
        std::thread::spawn(move || write_all(store, &record_rx, &written))
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
        },
    );
    drop(record_tx);
    writer.join().map_err(|_| RunError::Writer)??;
    pipeline.stats.written = written.load(Ordering::Relaxed);
    let ended = outcome?;
    Ok((ended, pipeline.stats.clone()))
}

fn read_all<S: EventSource>(mut source: S, tx: &SyncSender<Result<SourceItem, String>>) {
    loop {
        let item = match source.next() {
            Ok(Some(item)) => Ok(item),
            Ok(None) => return,
            Err(e) => Err(e.to_string()),
        };
        let failed = item.is_err();
        if tx.send(item).is_err() || failed {
            return;
        }
    }
}

fn write_all(
    mut store: Store,
    rx: &Receiver<EventRecord>,
    written: &AtomicU64,
) -> Result<(), StoreError> {
    for record in rx {
        store.append(&record)?;
        written.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

/// When to print a progress line, and the writer's running count for it.
struct Progress<'a> {
    every: Duration,
    written: &'a AtomicU64,
}

fn process(
    pipeline: &mut Pipeline,
    redactor: &Redactor,
    items: &Receiver<Result<SourceItem, String>>,
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
            eprintln!("thadam-collector: {}", pipeline.stats);
            last_report = Instant::now();
        }
        match items.recv_timeout(POLL) {
            Ok(Ok(item)) => send(pipeline.handle(item), pipeline, redactor, records)?,
            Ok(Err(e)) => {
                send(pipeline.finish(), pipeline, redactor, records)?;
                return Err(RunError::Source(e));
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
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
