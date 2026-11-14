//! The segment catalog (ADR-009 Decision 1): one entry per segment event, append-only and
//! hash-chained with `thadam.catalog.v1`. A segment's state is its latest entry; a state
//! change is a new entry, never an update.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, Row, TransactionBehavior, params};
use thadam_core::{CatalogKind, CatalogRow, GENESIS, catalog_hash};

use crate::StoreError;

/// 1: the first catalog schema.
const CATALOG_VERSION: i64 = 1;

/// One catalog entry as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    pub kind: CatalogKind,
    pub row: CatalogRow,
}

/// Result of walking the catalog's chain. Sequence numbers only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogReport {
    pub verified: u64,
    /// The first entry whose seq, `prev_hash` or hash is wrong, or that cannot be read.
    pub broken_at: Option<i64>,
}

pub struct Catalog {
    conn: Connection,
}

impl Catalog {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        apply(&conn)?;
        Ok(Self { conn })
    }

    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version != CATALOG_VERSION {
            return Err(StoreError::SchemaVersion(version));
        }
        Ok(Self { conn })
    }

    /// Appends an entry; `row.seq` is assigned here.
    pub fn append(&mut self, kind: CatalogKind, mut row: CatalogRow) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let tail: Option<(i64, Vec<u8>)> = rusqlite::OptionalExtension::optional(tx.query_row(
            "SELECT seq, hash FROM catalog ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;
        let (seq, prev) = match tail {
            None => (1, GENESIS),
            Some((last, hash)) => (
                last + 1,
                <[u8; 32]>::try_from(hash.as_slice())
                    .map_err(|_| StoreError::BadHashLength(last))?,
            ),
        };
        row.seq = seq;
        row.kind = kind.wire_name().to_string();
        let hash = catalog_hash(&prev, &row)?;
        tx.execute(
            "INSERT INTO catalog (seq, at_us, kind, segment, first_seq, last_seq, first_prev_hash,
                last_hash, last_ts_us, rows, bytes, reason, detail, from_us, to_us, missed,
                prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            params![
                row.seq,
                row.at_us,
                row.kind,
                row.segment,
                row.first_seq,
                row.last_seq,
                row.first_prev_hash,
                row.last_hash,
                row.last_ts_us,
                row.rows,
                row.bytes,
                row.reason,
                row.detail,
                row.from_us,
                row.to_us,
                row.missed,
                prev.as_slice(),
                hash.as_slice(),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Every entry, oldest first. Fails on an entry it cannot read; `verify` reports where.
    pub fn entries(&self) -> Result<Vec<CatalogEntry>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {COLUMNS} FROM catalog ORDER BY seq"))?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            let (row, _, _) = read(r).ok_or_else(|| {
                StoreError::Layout("unreadable catalog entry; run verify".to_string())
            })?;
            let kind = CatalogKind::from_wire(&row.kind).ok_or_else(|| {
                StoreError::Layout(format!("unknown catalog kind at entry {}", row.seq))
            })?;
            out.push(CatalogEntry { kind, row });
        }
        Ok(out)
    }

    /// Walks the catalog's own chain.
    pub fn verify(&self) -> Result<CatalogReport, StoreError> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {COLUMNS} FROM catalog ORDER BY seq"))?;
        let mut rows = stmt.query([])?;
        let mut prev = GENESIS;
        let mut expected = 1;
        let mut verified = 0;
        while let Some(r) = rows.next()? {
            let seq: i64 = r.get(0)?;
            let ok = read(r).is_some_and(|(row, stored_prev, stored_hash)| {
                seq == expected
                    && stored_prev == prev
                    && CatalogKind::from_wire(&row.kind).is_some()
                    && catalog_hash(&prev, &row).is_ok_and(|h| h == stored_hash)
                    && {
                        prev = stored_hash;
                        true
                    }
            });
            if !ok {
                return Ok(CatalogReport {
                    verified,
                    broken_at: Some(seq),
                });
            }
            verified += 1;
            expected += 1;
        }
        Ok(CatalogReport {
            verified,
            broken_at: None,
        })
    }
}

const COLUMNS: &str = "seq, at_us, kind, segment, first_seq, last_seq, first_prev_hash, last_hash,
    last_ts_us, rows, bytes, reason, detail, from_us, to_us, missed, prev_hash, hash";

fn read(r: &Row<'_>) -> Option<(CatalogRow, [u8; 32], [u8; 32])> {
    let row = CatalogRow {
        seq: r.get(0).ok()?,
        at_us: r.get(1).ok()?,
        kind: r.get(2).ok()?,
        segment: r.get(3).ok()?,
        first_seq: r.get(4).ok()?,
        last_seq: r.get(5).ok()?,
        first_prev_hash: r.get(6).ok()?,
        last_hash: r.get(7).ok()?,
        last_ts_us: r.get(8).ok()?,
        rows: r.get(9).ok()?,
        bytes: r.get(10).ok()?,
        reason: r.get(11).ok()?,
        detail: r.get(12).ok()?,
        from_us: r.get(13).ok()?,
        to_us: r.get(14).ok()?,
        missed: r.get(15).ok()?,
    };
    let prev: Vec<u8> = r.get(16).ok()?;
    let hash: Vec<u8> = r.get(17).ok()?;
    Some((
        row,
        <[u8; 32]>::try_from(prev.as_slice()).ok()?,
        <[u8; 32]>::try_from(hash.as_slice()).ok()?,
    ))
}

fn apply(conn: &Connection) -> Result<(), StoreError> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version == CATALOG_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(StoreError::SchemaVersion(version));
    }
    let kinds = CatalogKind::ALL
        .iter()
        .map(|k| format!("'{}'", k.wire_name()))
        .collect::<Vec<_>>()
        .join(", ");
    conn.execute_batch(&format!(
        "BEGIN;
        CREATE TABLE catalog (
            seq             INTEGER PRIMARY KEY,
            at_us           INTEGER NOT NULL,
            kind            TEXT    NOT NULL CHECK (kind IN ({kinds})),
            segment         TEXT,
            first_seq       INTEGER,
            last_seq        INTEGER,
            first_prev_hash TEXT,
            last_hash       TEXT,
            last_ts_us      INTEGER,
            rows            INTEGER,
            bytes           INTEGER,
            reason          TEXT,
            detail          TEXT,
            from_us         INTEGER,
            to_us           INTEGER,
            missed          INTEGER,
            prev_hash       BLOB    NOT NULL CHECK (length(prev_hash) = 32),
            hash            BLOB    NOT NULL CHECK (length(hash) = 32)
        ) STRICT;
        CREATE TRIGGER catalog_no_update BEFORE UPDATE ON catalog
            BEGIN SELECT RAISE(ABORT, 'catalog is append-only'); END;
        CREATE TRIGGER catalog_no_delete BEFORE DELETE ON catalog
            BEGIN SELECT RAISE(ABORT, 'catalog is append-only'); END;
        PRAGMA user_version = {CATALOG_VERSION};
        COMMIT;"
    ))?;
    Ok(())
}
