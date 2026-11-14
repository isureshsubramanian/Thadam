//! The event model (ADR-001 "Event model", ADR-002 Decision 3).
//!
//! CONTRACT: every `wire_name` below is stored in the database, hashed by `encode.rs`, and
//! read by the API. Renaming one breaks verification of existing chains.

use std::collections::BTreeSet;

use garde::Validate;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::detect::{DetectorKind, Redactor};
use crate::encode::CanonicalRow;
use crate::error::CoreError;

/// Longest accepted tool key, session id, path and target, in bytes. These are estimates
/// chosen to bound memory and row size, not measured limits.
pub const MAX_TOOL_KEY: usize = 64;
pub const MAX_SESSION_ID: usize = 128;
pub const MAX_PATH: usize = 4096;
pub const MAX_TARGET: usize = 64 * 1024;
/// Longest target accepted as input, before truncation to `MAX_TARGET`. Bounds memory, not
/// stored size. An estimate: the longest command line seen in the live runs of 14 Nov 2026
/// was 56,338 bytes (a sandbox profile passed inline as an argument).
pub const MAX_TARGET_INPUT: usize = 1024 * 1024;

/// A value with a stable stored name.
pub trait WireName: Copy {
    fn wire_name(self) -> &'static str;
}

macro_rules! wire_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];
        }

        impl WireName for $name {
            fn wire_name(self) -> &'static str {
                match self { $($name::$variant => $wire),+ }
            }
        }
    };
}

wire_enum!(
    /// What kind of activity the event is.
    Category {
        File => "file",
        Command => "command",
        Prompt => "prompt",
        NetworkInternal => "network_internal",
        NetworkExternal => "network_external",
        NetworkVolume => "network_volume",
    }
);

wire_enum!(
    /// What was done.
    Action {
        Read => "read",
        Create => "create",
        Write => "write",
        Rename => "rename",
        Delete => "delete",
        Exec => "exec",
        Connect => "connect",
        Prompt => "prompt",
    }
);

wire_enum!(
    /// How it ended.
    Outcome {
        Allowed => "allowed",
        DeniedByAgent => "denied_by_agent",
        DeniedByUser => "denied_by_user",
        DeniedByOs => "denied_by_os",
        Failed => "failed",
    }
);

wire_enum!(
    /// Why a record deserves attention.
    Flag {
        OutsideProject => "outside_project",
        SensitivePath => "sensitive_path",
        SecretPattern => "secret_pattern",
        UnknownHost => "unknown_host",
        LargeUpload => "large_upload",
        ToolInternal => "tool_internal",
    }
);

wire_enum!(
    /// Which capture path reported the event.
    Source {
        Agent => "agent",
        Os => "os",
        Network => "network",
    }
);

/// Canonical stored form of a set: wire names sorted ascending, joined by `,`.
pub fn wire_set<T: WireName>(items: impl IntoIterator<Item = T>) -> String {
    let mut names: Vec<&'static str> = items.into_iter().map(WireName::wire_name).collect();
    names.sort_unstable();
    names.dedup();
    names.join(",")
}

/// An event as it arrives from a capture source, before validation and redaction. This is
/// the input boundary of the core crate.
#[derive(Debug, Clone, Validate)]
pub struct NewEvent {
    #[garde(skip)]
    pub ts: OffsetDateTime,
    /// Registry key of the tool (never a product name in core code).
    #[garde(length(min = 1, max = MAX_TOOL_KEY), custom(tool_key_charset))]
    pub tool: String,
    #[garde(inner(length(min = 1, max = MAX_SESSION_ID)))]
    pub session_id: Option<String>,
    /// The session that started this one, when one tool delegated to another (ADR-004).
    #[garde(inner(length(min = 1, max = MAX_SESSION_ID)))]
    pub parent_session_id: Option<String>,
    #[garde(skip)]
    pub pid: u32,
    #[garde(length(min = 1, max = MAX_PATH))]
    pub process_path: String,
    #[garde(skip)]
    pub category: Category,
    #[garde(skip)]
    pub action: Action,
    /// Path, command line, host:port or prompt text. Redacted, then truncated to
    /// `MAX_TARGET`, by `EventRecord::new`.
    #[garde(length(max = MAX_TARGET_INPUT))]
    pub target: String,
    #[garde(skip)]
    pub outcome: Outcome,
    #[garde(inner(range(min = 0)))]
    pub size_bytes: Option<i64>,
    #[garde(inner(range(min = 0)))]
    pub bytes_out: Option<i64>,
    #[garde(inner(range(min = 0)))]
    pub bytes_in: Option<i64>,
    #[garde(inner(length(min = 1, max = MAX_PATH)))]
    pub project: Option<String>,
    #[garde(skip)]
    pub flags: BTreeSet<Flag>,
    /// Raw OS events this record stands for (repeated opens collapsed).
    #[garde(range(min = 1))]
    pub count: u32,
    #[garde(custom(non_empty_sources))]
    pub sources: BTreeSet<Source>,
}

/// Cuts a target longer than `MAX_TARGET` at a character boundary and says so. Runs after
/// redaction, so a secret is never cut in half before the detectors have seen all of it.
fn truncate_target(mut text: String) -> String {
    if text.len() <= MAX_TARGET {
        return text;
    }
    let marker = format!(" [truncated, {} bytes in full]", text.len());
    let mut cut = MAX_TARGET.saturating_sub(marker.len());
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text.push_str(&marker);
    text
}

fn tool_key_charset(value: &str, _ctx: &()) -> garde::Result {
    if value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        Ok(())
    } else {
        Err(garde::Error::new(
            "tool key may contain only a-z, 0-9, '-' and '_'",
        ))
    }
}

fn non_empty_sources(value: &BTreeSet<Source>, _ctx: &()) -> garde::Result {
    if value.is_empty() {
        Err(garde::Error::new("at least one source is required"))
    } else {
        Ok(())
    }
}

/// A validated, redacted event ready to append. The only way to build one is
/// `EventRecord::new`, so nothing reaches the store without passing both steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    event_id: Uuid,
    ts_us: i64,
    tool: String,
    session_id: Option<String>,
    parent_session_id: Option<String>,
    pid: u32,
    process_path: String,
    category: Category,
    action: Action,
    target: String,
    outcome: Outcome,
    size_bytes: Option<i64>,
    bytes_out: Option<i64>,
    bytes_in: Option<i64>,
    project: Option<String>,
    flags: BTreeSet<Flag>,
    count: u32,
    detections: String,
    sources: BTreeSet<Source>,
}

impl EventRecord {
    /// Validates the input, redacts the target with every detector, and records what was
    /// found as types and counts only. A secret in the target adds `secret_pattern`.
    pub fn new(input: NewEvent, redactor: &Redactor) -> Result<Self, CoreError> {
        input
            .validate()
            .map_err(|report| CoreError::Invalid(report.to_string()))?;

        let ts_us = i64::try_from(input.ts.unix_timestamp_nanos() / 1_000)
            .map_err(|_| CoreError::TimestampOutOfRange)?;

        let redacted = redactor.redact(&input.target);
        let mut flags = input.flags;
        if redacted.detections.get(DetectorKind::Secret) > 0 {
            flags.insert(Flag::SecretPattern);
        }

        Ok(Self {
            event_id: Uuid::now_v7(),
            ts_us,
            tool: input.tool,
            session_id: input.session_id,
            parent_session_id: input.parent_session_id,
            pid: input.pid,
            process_path: input.process_path,
            category: input.category,
            action: input.action,
            target: truncate_target(redacted.text),
            outcome: input.outcome,
            size_bytes: input.size_bytes,
            bytes_out: input.bytes_out,
            bytes_in: input.bytes_in,
            project: input.project,
            flags,
            count: input.count,
            detections: redacted.detections.to_wire(),
            sources: input.sources,
        })
    }

    pub fn event_id(&self) -> Uuid {
        self.event_id
    }

    /// The stored (redacted) target.
    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn flags(&self) -> &BTreeSet<Flag> {
        &self.flags
    }

    /// Canonical detections, for example `SECRET:1`.
    pub fn detections(&self) -> &str {
        &self.detections
    }

    /// The row as it will be stored and hashed at position `seq`.
    pub fn to_row(&self, seq: i64) -> CanonicalRow {
        CanonicalRow {
            seq,
            event_id: self.event_id.hyphenated().to_string(),
            ts_us: self.ts_us,
            tool: self.tool.clone(),
            session_id: self.session_id.clone(),
            parent_session_id: self.parent_session_id.clone(),
            pid: i64::from(self.pid),
            process_path: self.process_path.clone(),
            category: self.category.wire_name().to_string(),
            action: self.action.wire_name().to_string(),
            target: self.target.clone(),
            outcome: self.outcome.wire_name().to_string(),
            size_bytes: self.size_bytes,
            bytes_out: self.bytes_out,
            bytes_in: self.bytes_in,
            project: self.project.clone(),
            flags: wire_set(self.flags.iter().copied()),
            count: i64::from(self.count),
            detections: self.detections.clone(),
            source: wire_set(self.sources.iter().copied()),
        }
    }
}
