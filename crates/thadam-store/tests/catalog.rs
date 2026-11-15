//! Catalog schema version 2 and its migration from version 1 (ADR-013 Decision 1). All data is
//! synthetic.
// Integration tests: unwrap/expect are allowed here (helpers included), not in library code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use thadam_core::{CatalogKind, CatalogRow};
use thadam_store::{Catalog, CatalogReport};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("thadam-cat-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn catalog(&self) -> PathBuf {
        self.0.join("catalog.db")
    }
    fn backup(&self) -> PathBuf {
        self.0.join(thadam_store::CATALOG_V1_BACKUP)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn row(at_us: i64) -> CatalogRow {
    CatalogRow {
        seq: 0,
        at_us,
        kind: String::new(),
        segment: None,
        first_seq: None,
        last_seq: None,
        first_prev_hash: None,
        last_hash: None,
        last_ts_us: None,
        rows: None,
        bytes: None,
        reason: None,
        detail: None,
        from_us: None,
        to_us: None,
        missed: None,
    }
}

fn opened(at_us: i64, segment: &str) -> CatalogRow {
    CatalogRow {
        segment: Some(segment.to_string()),
        first_seq: Some(1),
        first_prev_hash: Some("00".repeat(32)),
        ..row(at_us)
    }
}

fn paused(at_us: i64) -> CatalogRow {
    CatalogRow {
        reason: Some("disk_low".to_string()),
        from_us: Some(at_us - 5_000_000),
        to_us: Some(at_us),
        missed: Some(12),
        ..row(at_us)
    }
}

fn gap(at_us: i64, reason: &str, detail: Option<&str>) -> CatalogRow {
    CatalogRow {
        reason: Some(reason.to_string()),
        detail: detail.map(str::to_string),
        from_us: Some(at_us - 60_000_000),
        to_us: Some(at_us),
        ..row(at_us)
    }
}

/// The version 1 table, exactly as the first collector created it.
const V1_SCHEMA: &str = "
    CREATE TABLE catalog (
        seq             INTEGER PRIMARY KEY CHECK (seq >= 1),
        at_us           INTEGER NOT NULL,
        kind            TEXT    NOT NULL CHECK (kind IN ('opened', 'closed', 'retired', 'archived', 'paused')),
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
    PRAGMA user_version = 1;";

/// A version 1 catalog with three chained entries: written by today's code (same encoding),
/// then copied into the version 1 table.
fn v1_catalog(path: &Path) {
    let scratch = path.with_file_name("scratch.db");
    {
        let mut c = Catalog::open(&scratch).unwrap();
        c.append(CatalogKind::Opened, opened(1_000, "2026-W46.db"))
            .unwrap();
        c.append(CatalogKind::Paused, paused(2_000)).unwrap();
        c.append(CatalogKind::Opened, opened(3_000, "2026-W47.db"))
            .unwrap();
    }
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(V1_SCHEMA).unwrap();
    conn.execute("ATTACH ?1 AS s", [scratch.to_str().unwrap()])
        .unwrap();
    conn.execute_batch("INSERT INTO catalog SELECT * FROM s.catalog; DETACH s;")
        .unwrap();
    drop(conn);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", scratch.display()));
    }
}

fn version(path: &Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap()
}

/// Every stored column of every entry, as bytes-for-bytes comparable values.
fn dump(path: &Path) -> Vec<Vec<rusqlite::types::Value>> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn.prepare("SELECT * FROM catalog ORDER BY seq").unwrap();
    let n = stmt.column_count();
    stmt.query_map([], |r| (0..n).map(|i| r.get(i)).collect())
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn clean(verified: u64) -> CatalogReport {
    CatalogReport {
        verified,
        broken_at: None,
    }
}

#[test]
fn a_new_catalog_is_version_2_and_takes_gap_entries() {
    let tmp = TempDir::new("new");
    let mut c = Catalog::open(tmp.catalog()).unwrap();
    c.append(CatalogKind::Gap, gap(5_000, "not_running", Some("crashed")))
        .unwrap();
    let entries = c.entries().unwrap();
    assert_eq!(entries[0].kind, CatalogKind::Gap);
    assert_eq!(entries[0].row.detail.as_deref(), Some("crashed"));
    assert_eq!(c.verify().unwrap(), clean(1));
    drop(c);
    assert_eq!(version(&tmp.catalog()), 2);
    assert!(!tmp.backup().exists());
}

#[test]
fn version_1_is_migrated_unchanged_keeps_a_copy_and_then_takes_gaps() {
    let tmp = TempDir::new("migrate");
    v1_catalog(&tmp.catalog());
    let before = dump(&tmp.catalog());
    let original = std::fs::read(tmp.catalog()).unwrap();

    // An old reader's view still opens before the writer migrates it.
    assert_eq!(
        Catalog::open_read_only(tmp.catalog())
            .unwrap()
            .verify()
            .unwrap(),
        clean(3)
    );

    let mut c = Catalog::open(tmp.catalog()).unwrap();
    assert_eq!(c.verify().unwrap(), clean(3));
    assert_eq!(dump(&tmp.catalog()), before);
    assert_eq!(version(&tmp.catalog()), 2);
    c.append(CatalogKind::Gap, gap(9_000, "dropped", Some("os")))
        .unwrap();
    assert_eq!(c.verify().unwrap(), clean(4));
    drop(c);

    // The kept copy is the version 1 catalog: same entries, version 1, no gap kind allowed.
    assert_eq!(version(&tmp.backup()), 1);
    assert_eq!(dump(&tmp.backup()), before);
    let copy = Connection::open(tmp.backup()).unwrap();
    assert!(
        copy.execute(
            "INSERT INTO catalog SELECT 99, at_us, 'gap', segment, first_seq, last_seq,
                  first_prev_hash, last_hash, last_ts_us, rows, bytes, reason, detail, from_us,
                  to_us, missed, prev_hash, hash FROM catalog WHERE seq = 1",
            []
        )
        .is_err()
    );
    drop(copy);
    assert_ne!(std::fs::read(tmp.catalog()).unwrap(), original);

    // A second open is a no-op: the copy is not rewritten.
    let copy_bytes = std::fs::read(tmp.backup()).unwrap();
    let c = Catalog::open(tmp.catalog()).unwrap();
    assert_eq!(c.verify().unwrap(), clean(4));
    assert_eq!(std::fs::read(tmp.backup()).unwrap(), copy_bytes);
}

#[test]
fn the_migrated_table_is_still_append_only() {
    let tmp = TempDir::new("triggers");
    v1_catalog(&tmp.catalog());
    drop(Catalog::open(tmp.catalog()).unwrap());
    let conn = Connection::open(tmp.catalog()).unwrap();
    assert!(
        conn.execute("UPDATE catalog SET at_us = 7 WHERE seq = 1", [])
            .is_err()
    );
    assert!(
        conn.execute("DELETE FROM catalog WHERE seq = 3", [])
            .is_err()
    );
    assert!(
        conn.execute(
            "INSERT INTO catalog SELECT 4, at_us, 'bogus', segment, first_seq, last_seq,
                  first_prev_hash, last_hash, last_ts_us, rows, bytes, reason, detail, from_us,
                  to_us, missed, prev_hash, hash FROM catalog WHERE seq = 1",
            []
        )
        .is_err()
    );
}

#[test]
fn a_failed_migration_leaves_version_1_in_place() {
    let tmp = TempDir::new("fail");
    v1_catalog(&tmp.catalog());
    let before = dump(&tmp.catalog());
    // The new table's name is taken, so the rebuild fails partway through its transaction.
    Connection::open(tmp.catalog())
        .unwrap()
        .execute_batch("CREATE TABLE catalog_v2 (x INTEGER)")
        .unwrap();
    assert!(Catalog::open(tmp.catalog()).is_err());
    assert_eq!(version(&tmp.catalog()), 1);
    assert_eq!(dump(&tmp.catalog()), before);
    assert_eq!(
        Catalog::open_read_only(tmp.catalog())
            .unwrap()
            .verify()
            .unwrap(),
        clean(3)
    );
}

#[test]
fn a_catalog_already_broken_migrates_with_the_same_break() {
    let tmp = TempDir::new("broken");
    v1_catalog(&tmp.catalog());
    // A root-level edit: drop the triggers, change entry 2, put them back.
    let conn = Connection::open(tmp.catalog()).unwrap();
    conn.execute_batch(
        "DROP TRIGGER catalog_no_update;
         UPDATE catalog SET missed = 99 WHERE seq = 2;
         CREATE TRIGGER catalog_no_update BEFORE UPDATE ON catalog
             BEGIN SELECT RAISE(ABORT, 'catalog is append-only'); END;",
    )
    .unwrap();
    drop(conn);
    let c = Catalog::open(tmp.catalog()).unwrap();
    assert_eq!(
        c.verify().unwrap(),
        CatalogReport {
            verified: 1,
            broken_at: Some(2)
        }
    );
    assert_eq!(version(&tmp.catalog()), 2);
}

#[test]
fn an_unknown_version_is_refused() {
    let tmp = TempDir::new("future");
    Connection::open(tmp.catalog())
        .unwrap()
        .execute_batch("PRAGMA user_version = 3")
        .unwrap();
    assert!(Catalog::open(tmp.catalog()).is_err());
    assert!(Catalog::open_read_only(tmp.catalog()).is_err());
}
