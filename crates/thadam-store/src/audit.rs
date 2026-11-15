//! `audit.db`, the review and access log, written by the root collector (ADR-013 Decision 3).
//!
//! The schema and the chain are exactly those the API created before (ADR-002 Decision 5,
//! ADR-008 Decision 6), so the API reads this file with its existing code, and entries copied
//! from the API's old file keep their hashes.
//!
//! Rollback journal, not WAL: a WAL reader needs the `-shm` file, which the user-level API
//! cannot create in the root-owned folder while the collector is stopped (see `leave_wal`).
//! Writes are a few per minute (estimate), so WAL's concurrency buys nothing here.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use thadam_core::{AuditRow, GENESIS, audit_hash};

use crate::StoreError;

/// 1: the schema the API created (ADR-008).
const AUDIT_VERSION: i64 = 1;
/// How long a write waits for a reader to finish (estimate; reads take milliseconds).
const BUSY: Duration = Duration::from_secs(2);

/// Result of walking the audit chain. Sequence numbers only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    pub verified: u64,
    pub broken_at: Option<i64>,
}

pub struct AuditDb {
    conn: Connection,
}

impl AuditDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(BUSY)?;
        let mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "DELETE", |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(StoreError::Layout(format!(
                "audit journal mode stayed {mode}"
            )));
        }
        conn.pragma_update(None, "synchronous", "FULL")?;
        apply(&conn)?;
        Ok(Self { conn })
    }

    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version != AUDIT_VERSION {
            return Err(StoreError::SchemaVersion(version));
        }
        Ok(Self { conn })
    }

    /// Appends an entry; `seq` and the chain fields are assigned here.
    pub fn append(
        &mut self,
        audit_id: &str,
        ts_us: i64,
        actor_id: &str,
        action: &str,
        target_id: &str,
        outcome: &str,
    ) -> Result<AuditRow, StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (seq, prev) = tail(&tx)?;
        let row = AuditRow {
            seq,
            audit_id: audit_id.to_string(),
            ts_us,
            actor_id: actor_id.to_string(),
            action: action.to_string(),
            target_id: target_id.to_string(),
            outcome: outcome.to_string(),
        };
        insert(&tx, &row, &prev, &audit_hash(&prev, &row)?)?;
        tx.commit()?;
        Ok(row)
    }

    pub fn len(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT count(*) FROM audit", [], |r| r.get(0))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }

    /// Every entry, oldest first.
    pub fn entries(&self) -> Result<Vec<AuditRow>, StoreError> {
        Ok(stored(&self.conn)?
            .into_iter()
            .map(|(row, _, _)| row)
            .collect())
    }

    /// Walks the chain; reports the first entry that does not verify.
    pub fn verify(&self) -> Result<AuditReport, StoreError> {
        verify_rows(&stored(&self.conn)?)
    }

    /// Copies every entry of the API's old, user-owned log into this one, byte for byte
    /// (ADR-013 Decision 3). Only into an empty log, and only a source whose chain verifies;
    /// the copy is walked again before it commits, so a failure leaves this log empty.
    pub fn import(&mut self, source: impl AsRef<Path>) -> Result<u64, StoreError> {
        let src = Self::open_read_only(source)?;
        let rows = stored(&src.conn)?;
        let report = verify_rows(&rows)?;
        if let Some(seq) = report.broken_at {
            return Err(StoreError::Layout(format!(
                "the old audit log's chain is broken at entry {seq}; nothing copied"
            )));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tail(&tx)?.0 != 1 {
            return Err(StoreError::Layout(
                "the audit log already has entries; nothing copied".to_string(),
            ));
        }
        for (row, prev, hash) in &rows {
            insert(&tx, row, prev, hash)?;
        }
        let copied = verify_rows(&stored(&tx)?)?;
        if copied != report {
            return Err(StoreError::Layout(
                "the copied audit log did not verify; nothing copied".to_string(),
            ));
        }
        tx.commit()?;
        Ok(report.verified)
    }
}

type Stored = (AuditRow, [u8; 32], [u8; 32]);

fn tail(conn: &Connection) -> Result<(i64, [u8; 32]), StoreError> {
    let last: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match last {
        None => Ok((1, GENESIS)),
        Some((seq, hash)) => Ok((
            seq + 1,
            <[u8; 32]>::try_from(hash.as_slice()).map_err(|_| StoreError::BadHashLength(seq))?,
        )),
    }
}

fn insert(
    conn: &Connection,
    row: &AuditRow,
    prev: &[u8; 32],
    hash: &[u8; 32],
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO audit (seq, audit_id, ts_us, actor_id, action, target_id, outcome,
            prev_hash, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            row.seq,
            row.audit_id,
            row.ts_us,
            row.actor_id,
            row.action,
            row.target_id,
            row.outcome,
            prev.as_slice(),
            hash.as_slice(),
        ],
    )?;
    Ok(())
}

fn stored(conn: &Connection) -> Result<Vec<Stored>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT seq, audit_id, ts_us, actor_id, action, target_id, outcome, prev_hash, hash
         FROM audit ORDER BY seq",
    )?;
    let rows = stmt.query_map([], |r| {
        let row = AuditRow {
            seq: r.get(0)?,
            audit_id: r.get(1)?,
            ts_us: r.get(2)?,
            actor_id: r.get(3)?,
            action: r.get(4)?,
            target_id: r.get(5)?,
            outcome: r.get(6)?,
        };
        let prev: Vec<u8> = r.get(7)?;
        let hash: Vec<u8> = r.get(8)?;
        Ok((row, prev, hash))
    })?;
    let mut out = Vec::new();
    for item in rows {
        let (row, prev, hash) = item?;
        let fixed =
            |v: &[u8]| <[u8; 32]>::try_from(v).map_err(|_| StoreError::BadHashLength(row.seq));
        out.push((row.clone(), fixed(&prev)?, fixed(&hash)?));
    }
    Ok(out)
}

fn verify_rows(rows: &[Stored]) -> Result<AuditReport, StoreError> {
    let mut prev = GENESIS;
    let mut verified = 0;
    for (expected, (row, stored_prev, stored_hash)) in (1..).zip(rows) {
        if row.seq != expected || *stored_prev != prev || audit_hash(&prev, row)? != *stored_hash {
            return Ok(AuditReport {
                verified,
                broken_at: Some(row.seq),
            });
        }
        prev = *stored_hash;
        verified += 1;
    }
    Ok(AuditReport {
        verified,
        broken_at: None,
    })
}

/// The schema exactly as the API created it (ADR-008 Decision 6), so both read the same file.
fn apply(conn: &Connection) -> Result<(), StoreError> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    match version {
        AUDIT_VERSION => Ok(()),
        0 => {
            conn.execute_batch(
                "BEGIN;
                CREATE TABLE audit (
                    seq       INTEGER PRIMARY KEY,
                    audit_id  TEXT    NOT NULL UNIQUE,
                    ts_us     INTEGER NOT NULL,
                    actor_id  TEXT    NOT NULL,
                    action    TEXT    NOT NULL CHECK (action IN ('sign_in', 'sign_out', 'search', 'export', 'flag_reviewed', 'flag_reopened')),
                    target_id TEXT    NOT NULL DEFAULT '',
                    outcome   TEXT    NOT NULL CHECK (outcome IN ('succeeded', 'failed', 'denied')),
                    prev_hash BLOB    NOT NULL CHECK (length(prev_hash) = 32),
                    hash      BLOB    NOT NULL CHECK (length(hash) = 32)
                ) STRICT;
                CREATE INDEX audit_target ON audit (target_id, seq);
                CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
                    BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
                CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
                    BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
                PRAGMA user_version = 1;
                COMMIT;",
            )?;
            Ok(())
        }
        other => Err(StoreError::SchemaVersion(other)),
    }
}
