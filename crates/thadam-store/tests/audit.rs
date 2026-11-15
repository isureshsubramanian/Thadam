//! `audit.db` written by the collector (ADR-013 Decision 3). All data is synthetic.
// Integration tests: unwrap/expect are allowed here (helpers included), not in library code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use thadam_store::{AuditDb, AuditReport};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("thadam-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn clean(verified: u64) -> AuditReport {
    AuditReport {
        verified,
        broken_at: None,
    }
}

/// The API's old file, as its own code wrote it: rows and hashes from the golden vectors,
/// which an independent implementation computed.
fn old_log(path: &Path) {
    let golden: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../thadam-core/testdata/golden-chain.json"
        ))
        .unwrap(),
    )
    .unwrap();
    drop(AuditDb::open(path).unwrap()); // same schema
    let conn = Connection::open(path).unwrap();
    let mut prev = vec![0u8; 32];
    for v in golden["audit_v1"]["rows"].as_array().unwrap() {
        let hash = hex(v["hash"].as_str().unwrap());
        conn.execute(
            "INSERT INTO audit VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                v["seq"].as_i64().unwrap(),
                v["audit_id"].as_str().unwrap(),
                v["ts_us"].as_i64().unwrap(),
                v["actor_id"].as_str().unwrap(),
                v["action"].as_str().unwrap(),
                v["target_id"].as_str().unwrap(),
                v["outcome"].as_str().unwrap(),
                prev,
                hash,
            ],
        )
        .unwrap();
        prev = hex(v["hash"].as_str().unwrap());
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn dump(path: &Path) -> Vec<Vec<rusqlite::types::Value>> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn.prepare("SELECT * FROM audit ORDER BY seq").unwrap();
    let n = stmt.column_count();
    stmt.query_map([], |r| (0..n).map(|i| r.get(i)).collect())
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn appends_chain_and_are_append_only() {
    let tmp = TempDir::new("append");
    let mut db = AuditDb::open(tmp.path("audit.db")).unwrap();
    let a = db
        .append(
            "0193b000-0000-7000-8000-00000000000a",
            10,
            "dev",
            "sign_in",
            "",
            "succeeded",
        )
        .unwrap();
    let b = db
        .append(
            "0193b000-0000-7000-8000-00000000000b",
            20,
            "dev",
            "export",
            "e-1",
            "denied",
        )
        .unwrap();
    assert_eq!((a.seq, b.seq), (1, 2));
    assert_eq!(db.verify().unwrap(), clean(2));
    assert!(
        db.append("x", 30, "dev", "drop_table", "", "succeeded")
            .is_err()
    );
    assert_eq!(db.len().unwrap(), 2);
    drop(db);
    let conn = Connection::open(tmp.path("audit.db")).unwrap();
    assert!(
        conn.execute("UPDATE audit SET outcome = 'failed'", [])
            .is_err()
    );
    assert!(conn.execute("DELETE FROM audit", []).is_err());
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
    assert_eq!(
        AuditDb::open_read_only(tmp.path("audit.db"))
            .unwrap()
            .verify()
            .unwrap(),
        clean(2)
    );
}

#[test]
fn import_copies_the_old_log_byte_for_byte_then_continues_its_chain() {
    let tmp = TempDir::new("import");
    old_log(&tmp.path("old.db"));
    let before = dump(&tmp.path("old.db"));
    let mut db = AuditDb::open(tmp.path("audit.db")).unwrap();
    let n = db.import(tmp.path("old.db")).unwrap();
    assert_eq!(n, before.len() as u64);
    assert_eq!(dump(&tmp.path("audit.db")), before);
    let next = db
        .append(
            "0193b000-0000-7000-8000-0000000000ff",
            1,
            "dev",
            "sign_out",
            "",
            "succeeded",
        )
        .unwrap();
    assert_eq!(next.seq, n as i64 + 1);
    assert_eq!(db.verify().unwrap(), clean(n + 1));
    // The old file is read, never changed.
    assert_eq!(dump(&tmp.path("old.db")), before);
    // A second import is refused: the log has entries.
    assert!(db.import(tmp.path("old.db")).is_err());
    assert_eq!(db.len().unwrap(), n + 1);
}

#[test]
fn a_broken_old_log_is_not_imported() {
    let tmp = TempDir::new("broken");
    old_log(&tmp.path("old.db"));
    let conn = Connection::open(tmp.path("old.db")).unwrap();
    conn.execute_batch(
        "DROP TRIGGER audit_no_update; UPDATE audit SET outcome = 'denied' WHERE seq = 1;",
    )
    .unwrap();
    drop(conn);
    let mut db = AuditDb::open(tmp.path("audit.db")).unwrap();
    assert!(db.import(tmp.path("old.db")).is_err());
    assert!(db.is_empty().unwrap());
}

#[test]
fn a_symlinked_old_log_is_not_imported() {
    let tmp = TempDir::new("symlink");
    old_log(&tmp.path("real.db"));
    std::os::unix::fs::symlink(tmp.path("real.db"), tmp.path("old.db")).unwrap();
    let mut db = AuditDb::open(tmp.path("audit.db")).unwrap();
    let err = db.import(tmp.path("old.db")).unwrap_err().to_string();
    assert!(err.contains("symlink"), "{err}");
    assert!(db.is_empty().unwrap());
}
