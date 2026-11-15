//! Append-only, hash-chained SQLite event store (ADR-001 "Storage and security rules",
//! ADR-002 Decisions 2 and 3).
//!
//! Every row stores the previous row's hash and its own; `verify` walks the chain. Triggers
//! reject UPDATE and DELETE, which stops accidental or casual change. They do not stop
//! someone with write access to the file; the chain is what makes such change detectable.

mod audit;
mod catalog;
mod disk;
mod schema;
mod segments;

use std::path::Path;

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params_from_iter};
use thadam_core::{CanonicalRow, CoreError, Encoding, EventRecord, GENESIS, row_hash, to_hex};
use thiserror::Error;

pub use audit::{AuditDb, AuditReport};
pub use catalog::{CATALOG_V1_BACKUP, Catalog, CatalogEntry, CatalogReport};
pub use disk::{DiskSpace, SystemDisk};
pub use segments::{
    CATALOG_FILE, DirBreak, DirReport, Gap, GapReason, Limits, MigrateReport, RetiredRange,
    SegmentStatus, SegmentWriter, Written, migrate, verify_dir,
};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error("stored hash at seq {0} is not 32 bytes")]
    BadHashLength(i64),
    #[error("unsupported schema version {0}")]
    SchemaVersion(i64),
    #[error("file error: {0}")]
    Io(#[from] std::io::Error),
    /// The catalog and the segment files disagree in a way the store cannot repair. Carries
    /// a segment name and sequence numbers only.
    #[error("store layout: {0}")]
    Layout(String),
    /// Another process holds the store's writer lock (ADR-010 Decision 4).
    #[error("another collector is writing this store")]
    Locked,
}

/// Where a chain (or a segment of it) starts: the first row's seq and its `prev_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainStart {
    pub seq: i64,
    pub prev_hash: [u8; 32],
}

impl ChainStart {
    pub const GENESIS: ChainStart = ChainStart {
        seq: 1,
        prev_hash: GENESIS,
    };
}

/// The last row of a store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tail {
    pub seq: i64,
    pub hash: [u8; 32],
    pub ts_us: i64,
}

/// The event store. Owns one SQLite connection; one writer per database file.
pub struct Store {
    conn: Connection,
    /// Where this file's part of the chain starts. Seq 1 and the zero hash for a whole
    /// store; the previous segment's end for a segment (ADR-009 Decision 1).
    start: ChainStart,
    /// The file's row encoding, from its schema version. Fixed for the file's lifetime.
    encoding: Encoding,
}

/// Position of a row in the chain after it was appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appended {
    pub seq: i64,
    pub hash: [u8; 32],
}

/// Why verification stopped. Carries sequence numbers and hashes only, never row content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainBreak {
    /// A row is missing or rows were reordered.
    SeqGap { expected: i64, found: i64 },
    /// The row's `prev_hash` does not match the hash of the row before it.
    PrevHashMismatch { seq: i64 },
    /// The row's content no longer matches its stored hash.
    HashMismatch {
        seq: i64,
        stored: String,
        computed: String,
    },
    /// The row could not be read back in canonical form.
    Unreadable { seq: i64 },
}

/// Switches a file the writer is done with to the rollback journal (ADR-009 Decision 6).
///
/// A reader of a WAL file needs its `-shm` file, and SQLite deletes that when the writer
/// closes. A reader running as the user cannot create it again in the root-owned store
/// folder, so a WAL file there is unreadable whenever the collector is stopped. A file in
/// rollback-journal mode needs no side file. Writers switch back to WAL when they open.
/// Fails (and leaves WAL) while another connection has the file open.
pub(crate) fn leave_wal(conn: &Connection) -> Result<(), StoreError> {
    let mode: String =
        conn.pragma_update_and_check(None, "journal_mode", "DELETE", |r| r.get(0))?;
    if mode.eq_ignore_ascii_case("delete") {
        Ok(())
    } else {
        Err(StoreError::Layout(format!("journal mode stayed {mode}")))
    }
}

/// Result of walking the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Rows verified before the first break (all rows if none).
    pub verified: u64,
    pub total: u64,
    pub broken: Option<ChainBreak>,
}

impl VerifyReport {
    pub fn is_ok(&self) -> bool {
        self.broken.is_none()
    }
}

impl Store {
    /// Opens or creates a store and applies the schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_segment(path, ChainStart::GENESIS)
    }

    /// Opens or creates a store whose first row continues a chain at `start`.
    /// A new file gets the current schema; an existing one keeps its own.
    pub fn open_segment(path: impl AsRef<Path>, start: ChainStart) -> Result<Self, StoreError> {
        Self::open_segment_with(path, start, Encoding::CURRENT)
    }

    /// As `open_segment`, creating a new file with `encoding`'s schema. Older encodings are
    /// for tests that build mixed-version folders; the writer only creates current ones.
    #[doc(hidden)]
    pub fn open_segment_with(
        path: impl AsRef<Path>,
        start: ChainStart,
        encoding: Encoding,
    ) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        let encoding = schema::apply(&conn, encoding)?;
        Ok(Self {
            conn,
            start,
            encoding,
        })
    }

    /// The row encoding of this file.
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// Switches the file from WAL to the rollback journal before the writer closes it.
    /// See `leave_wal`.
    pub fn leave_wal(&self) -> Result<(), StoreError> {
        leave_wal(&self.conn)
    }

    /// Opens an existing store without the ability to write, for verification and reads.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_segment_read_only(path, ChainStart::GENESIS)
    }

    /// Opens an existing segment read-only, for verifying it from `start`.
    pub fn open_segment_read_only(
        path: impl AsRef<Path>,
        start: ChainStart,
    ) -> Result<Self, StoreError> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let encoding = schema::check_version(&conn)?;
        Ok(Self {
            conn,
            start,
            encoding,
        })
    }

    /// The first row, if any: its seq, `prev_hash` and time.
    pub fn head(&self) -> Result<Option<(i64, [u8; 32], i64)>, StoreError> {
        let head: Option<(i64, Vec<u8>, i64)> = self
            .conn
            .query_row(
                "SELECT seq, prev_hash, ts_us FROM events ORDER BY seq LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        head.map(|(seq, prev, ts)| {
            to_array(&prev)
                .map(|p| (seq, p, ts))
                .ok_or(StoreError::BadHashLength(seq))
        })
        .transpose()
    }

    /// The last row, if any.
    pub fn tail(&self) -> Result<Option<Tail>, StoreError> {
        let tail: Option<(i64, Vec<u8>, i64)> = self
            .conn
            .query_row(
                "SELECT seq, hash, ts_us FROM events ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        tail.map(|(seq, hash, ts_us)| {
            to_array(&hash)
                .map(|hash| Tail { seq, hash, ts_us })
                .ok_or(StoreError::BadHashLength(seq))
        })
        .transpose()
    }

    /// Number of rows.
    pub fn rows(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Appends one event at the end of the chain, atomically.
    pub fn append(&mut self, record: &EventRecord) -> Result<Appended, StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let tail: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (seq, prev_hash) = match tail {
            None => (self.start.seq, self.start.prev_hash),
            Some((last, hash)) => (
                last + 1,
                to_array(&hash).ok_or(StoreError::BadHashLength(last))?,
            ),
        };
        let row = record.to_row(seq);
        // Fails for a v2 file and a row with agent fields: they would not be in the hash.
        let hash = row_hash(&prev_hash, &row, self.encoding)?;
        let mut values: Vec<Value> = vec![
            row.seq.into(),
            row.event_id.into(),
            row.ts_us.into(),
            row.tool.into(),
            row.session_id.into(),
            row.parent_session_id.into(),
            row.pid.into(),
            row.process_path.into(),
            row.category.into(),
            row.action.into(),
            row.target.into(),
            row.outcome.into(),
            row.size_bytes.into(),
            row.bytes_out.into(),
            row.bytes_in.into(),
            row.project.into(),
            row.flags.into(),
            row.count.into(),
            row.detections.into(),
            row.source.into(),
            prev_hash.to_vec().into(),
            hash.to_vec().into(),
        ];
        if self.encoding >= Encoding::V3 {
            values.push(row.agent_session_id.into());
            values.push(row.transcript.into());
        }
        let columns = columns(self.encoding);
        let marks = (1..=values.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        tx.execute(
            &format!("INSERT INTO events ({columns}) VALUES ({marks})"),
            params_from_iter(values),
        )?;
        tx.commit()?;
        Ok(Appended { seq, hash })
    }

    /// Walks this file's chain from its start and reports the first break, if any.
    pub fn verify(&self) -> Result<VerifyReport, StoreError> {
        let total: i64 = self
            .conn
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))?;
        let total = u64::try_from(total).unwrap_or(0);
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {} FROM events ORDER BY seq",
            columns(self.encoding)
        ))?;
        let mut rows = stmt.query([])?;

        let mut expected_seq: i64 = self.start.seq;
        let mut prev = self.start.prev_hash;
        let mut verified: u64 = 0;
        while let Some(r) = rows.next()? {
            let seq: i64 = r.get(0)?;
            if seq != expected_seq {
                return Ok(broken(
                    verified,
                    total,
                    ChainBreak::SeqGap {
                        expected: expected_seq,
                        found: seq,
                    },
                ));
            }
            let Some((row, stored_prev, stored_hash)) = read_row(r, self.encoding) else {
                return Ok(broken(verified, total, ChainBreak::Unreadable { seq }));
            };
            if stored_prev != prev {
                return Ok(broken(
                    verified,
                    total,
                    ChainBreak::PrevHashMismatch { seq },
                ));
            }
            let computed = row_hash(&prev, &row, self.encoding)?;
            if computed != stored_hash {
                return Ok(broken(
                    verified,
                    total,
                    ChainBreak::HashMismatch {
                        seq,
                        stored: to_hex(&stored_hash),
                        computed: to_hex(&computed),
                    },
                ));
            }
            prev = stored_hash;
            verified += 1;
            expected_seq += 1;
        }
        Ok(VerifyReport {
            verified,
            total,
            broken: None,
        })
    }

    /// Direct access for tests and for the reader side. Writes through this connection are
    /// still subject to the append-only triggers.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

fn broken(verified: u64, total: u64, reason: ChainBreak) -> VerifyReport {
    VerifyReport {
        verified,
        total,
        broken: Some(reason),
    }
}

/// The stored columns of a file with `encoding`, in the order `read_row` reads them.
fn columns(encoding: Encoding) -> &'static str {
    match encoding {
        Encoding::V2 => {
            "seq, event_id, ts_us, tool, session_id, parent_session_id, pid, process_path, \
             category, action, target, outcome, size_bytes, bytes_out, bytes_in, project, flags, \
             count, detections, source, prev_hash, hash"
        }
        Encoding::V3 => {
            "seq, event_id, ts_us, tool, session_id, parent_session_id, pid, process_path, \
             category, action, target, outcome, size_bytes, bytes_out, bytes_in, project, flags, \
             count, detections, source, prev_hash, hash, agent_session_id, transcript"
        }
    }
}

fn to_array(bytes: &[u8]) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).ok()
}

/// Reads a row in canonical form. Any type mismatch (for example text replaced by a blob)
/// makes the row unreadable rather than an error, so verify can report where it broke.
fn read_row(r: &Row<'_>, encoding: Encoding) -> Option<(CanonicalRow, [u8; 32], [u8; 32])> {
    let v3 = encoding >= Encoding::V3;
    let row = CanonicalRow {
        seq: r.get(0).ok()?,
        event_id: r.get(1).ok()?,
        ts_us: r.get(2).ok()?,
        tool: r.get(3).ok()?,
        session_id: r.get(4).ok()?,
        parent_session_id: r.get(5).ok()?,
        pid: r.get(6).ok()?,
        process_path: r.get(7).ok()?,
        category: r.get(8).ok()?,
        action: r.get(9).ok()?,
        target: r.get(10).ok()?,
        outcome: r.get(11).ok()?,
        size_bytes: r.get(12).ok()?,
        bytes_out: r.get(13).ok()?,
        bytes_in: r.get(14).ok()?,
        project: r.get(15).ok()?,
        flags: r.get(16).ok()?,
        count: r.get(17).ok()?,
        detections: r.get(18).ok()?,
        source: r.get(19).ok()?,
        agent_session_id: if v3 { r.get(22).ok()? } else { None },
        transcript: if v3 { r.get(23).ok()? } else { None },
    };
    let prev: Vec<u8> = r.get(20).ok()?;
    let hash: Vec<u8> = r.get(21).ok()?;
    Some((row, to_array(&prev)?, to_array(&hash)?))
}
