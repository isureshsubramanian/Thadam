//! The OS event source interface (ADR-003 Decision 2).
//!
//! Everything after the source works on `OsEvent`, so the built-in logger can be replaced
//! by a native Endpoint Security client without touching the tree, classifier or store.
//! `OsEvent` has no environment field: the exec environment never becomes a value here.

pub mod eslogger;

use std::fmt;

use time::OffsetDateTime;

/// Code-signing identity of a running image, as reported by the OS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    /// Part of the operating system; never a registered tool.
    pub platform: bool,
}

/// The process an event is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRef {
    pub pid: u32,
    /// Changes when a pid is reused (and on exec), so stale tree entries can be detected.
    pub pidversion: u32,
    pub ppid: u32,
    /// The process the OS holds responsible for this one, when it differs from itself.
    pub responsible_pid: Option<u32>,
    pub executable: String,
    pub identity: Identity,
}

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    /// `process` is the image before exec; `target` is the new image.
    Exec {
        target: ProcessRef,
        args: Vec<String>,
        cwd: Option<String>,
    },
    Fork {
        child: ProcessRef,
    },
    Exit,
    Open {
        path: String,
        /// Opened with the read flag.
        readable: bool,
        size: Option<i64>,
    },
    Close {
        path: String,
        modified: bool,
        size: Option<i64>,
    },
    Create {
        path: String,
    },
    Rename {
        from: String,
        to: String,
    },
    Unlink {
        path: String,
    },
}

/// One normalised OS event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsEvent {
    pub ts: OffsetDateTime,
    /// Global sequence number from the OS; gaps mean dropped events.
    pub seq: u64,
    pub process: ProcessRef,
    pub kind: EventKind,
}

/// Why an input line produced no event. Carries no content from the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SkipReason {
    /// Not valid JSON, or not an object.
    Malformed,
    /// Valid, but an event type this collector does not handle.
    UnknownEvent,
    /// A handled event type with a required field missing or of the wrong type.
    MissingField,
}

impl SkipReason {
    pub const fn name(self) -> &'static str {
        match self {
            SkipReason::Malformed => "malformed",
            SkipReason::UnknownEvent => "unknown_event",
            SkipReason::MissingField => "missing_field",
        }
    }
}

/// What a source yields. `Event` is much larger than the other variants; boxing it would
/// add an allocation per event on the hot path for no benefit, as items are moved once.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceItem {
    Event(OsEvent),
    /// The OS dropped `missed` events before the next one (sequence number jump).
    Gap {
        missed: u64,
    },
    Skipped(SkipReason),
}

/// Failure to read from the source at all (not a bad line, which is `Skipped`).
#[derive(Debug)]
pub struct SourceError(pub std::io::Error);

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "event source read failed: {}", self.0)
    }
}

impl std::error::Error for SourceError {}

/// A stream of OS events. `Ok(None)` is end of stream.
pub trait EventSource {
    fn next(&mut self) -> Result<Option<SourceItem>, SourceError>;
}
