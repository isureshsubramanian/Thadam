//! Append-only, hash-chained SQLite event store (ADR-001 "Storage and security rules",
//! ADR-002 Decisions 2 and 3).
//!
//! Every row stores the previous row's hash and its own; `verify` walks the chain. Triggers
//! reject UPDATE and DELETE, which stops accidental or casual change. They do not stop
//! someone with write access to the file; the chain is what makes such change detectable.

mod schema;

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};
use thadam_core::{CanonicalRow, CoreError, EventRecord, GENESIS, row_hash, to_hex};
use thiserror::Error;

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
}

/// The event store. Owns one SQLite connection; one writer per database file.
pub struct Store {
    conn: Connection,
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
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        schema::apply(&conn)?;
        Ok(Self { conn })
    }

    /// Opens an existing store without the ability to write, for verification and reads.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        schema::check_version(&conn)?;
        Ok(Self { conn })
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
            None => (1, GENESIS),
            Some((last, hash)) => (
                last + 1,
                to_array(&hash).ok_or(StoreError::BadHashLength(last))?,
            ),
        };
        let row = record.to_row(seq);
        let hash = row_hash(&prev_hash, &row)?;
        tx.execute(
            "INSERT INTO events (seq, event_id, ts_us, tool, session_id, parent_session_id, pid,
                process_path, category, action, target, outcome, size_bytes, bytes_out, bytes_in,
                project, flags, count, detections, source, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                ?18, ?19, ?20, ?21, ?22)",
            params![
                row.seq,
                row.event_id,
                row.ts_us,
                row.tool,
                row.session_id,
                row.parent_session_id,
                row.pid,
                row.process_path,
                row.category,
                row.action,
                row.target,
                row.outcome,
                row.size_bytes,
                row.bytes_out,
                row.bytes_in,
                row.project,
                row.flags,
                row.count,
                row.detections,
                row.source,
                prev_hash.as_slice(),
                hash.as_slice(),
            ],
        )?;
        tx.commit()?;
        Ok(Appended { seq, hash })
    }

    /// Walks the whole chain from seq 1 and reports the first break, if any.
    pub fn verify(&self) -> Result<VerifyReport, StoreError> {
        let total: i64 = self
            .conn
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))?;
        let total = u64::try_from(total).unwrap_or(0);
        let mut stmt = self.conn.prepare(
            "SELECT seq, event_id, ts_us, tool, session_id, parent_session_id, pid, process_path,
                category, action, target, outcome, size_bytes, bytes_out, bytes_in, project, flags,
                count, detections, source, prev_hash, hash
             FROM events ORDER BY seq",
        )?;
        let mut rows = stmt.query([])?;

        let mut expected_seq: i64 = 1;
        let mut prev = GENESIS;
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
            let Some((row, stored_prev, stored_hash)) = read_row(r) else {
                return Ok(broken(verified, total, ChainBreak::Unreadable { seq }));
            };
            if stored_prev != prev {
                return Ok(broken(
                    verified,
                    total,
                    ChainBreak::PrevHashMismatch { seq },
                ));
            }
            let computed = row_hash(&prev, &row)?;
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

fn to_array(bytes: &[u8]) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).ok()
}

/// Reads a row in canonical form. Any type mismatch (for example text replaced by a blob)
/// makes the row unreadable rather than an error, so verify can report where it broke.
fn read_row(r: &Row<'_>) -> Option<(CanonicalRow, [u8; 32], [u8; 32])> {
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
    };
    let prev: Vec<u8> = r.get(20).ok()?;
    let hash: Vec<u8> = r.get(21).ok()?;
    Some((row, to_array(&prev)?, to_array(&hash)?))
}
