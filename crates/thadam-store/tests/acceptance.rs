//! Slice 1 acceptance tests (ADR-002). All data is synthetic.
// Integration tests: unwrap/expect are allowed here (helpers included), not in library code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use thadam_core::{
    Action, Category, EventRecord, ExecObservation, Flag, NewEvent, Outcome, Redactor, Source,
};
use thadam_store::{ChainBreak, Store};
use time::macros::datetime;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("thadam-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn db(&self) -> PathBuf {
        self.0.join("events.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn file_read(path: &str) -> NewEvent {
    NewEvent {
        ts: datetime!(2026-11-12 16:20:09 UTC),
        tool: "tool-a".into(),
        session_id: Some("s-7f3e".into()),
        pid: 48211,
        process_path: "/bin/cat".into(),
        category: Category::File,
        action: Action::Read,
        target: path.into(),
        outcome: Outcome::Allowed,
        size_bytes: Some(2048),
        bytes_out: None,
        bytes_in: None,
        project: Some("/Users/dev/projects/sample-app".into()),
        flags: BTreeSet::new(),
        count: 1,
        sources: BTreeSet::from([Source::Os]),
    }
}

fn command(line: String) -> NewEvent {
    NewEvent {
        process_path: "/usr/bin/curl".into(),
        category: Category::Command,
        action: Action::Exec,
        target: line,
        size_bytes: None,
        ..file_read("")
    }
}

fn store_with_rows(dir: &TempDir, n: usize) -> Store {
    let redactor = Redactor::with_default_detectors().unwrap();
    let mut store = Store::open(dir.db()).unwrap();
    for i in 0..n {
        let rec = EventRecord::new(
            file_read(&format!("/Users/dev/projects/sample-app/src/f{i}.rs")),
            &redactor,
        )
        .unwrap();
        store.append(&rec).unwrap();
    }
    store
}

/// Simulates someone with direct write access to the file: drops the triggers first.
fn drop_triggers(store: &Store) {
    store
        .connection()
        .execute_batch("DROP TRIGGER events_no_update; DROP TRIGGER events_no_delete;")
        .unwrap();
}

#[test]
fn intact_chain_verifies() {
    let dir = TempDir::new("intact");
    let store = store_with_rows(&dir, 5);
    let report = store.verify().unwrap();
    assert!(report.is_ok());
    assert_eq!(report.verified, 5);
}

#[test]
fn tampered_row_breaks_verification_at_that_seq() {
    let dir = TempDir::new("tamper");
    let store = store_with_rows(&dir, 5);
    drop_triggers(&store);
    store
        .connection()
        .execute(
            "UPDATE events SET target = '/Users/dev/other.txt' WHERE seq = 3",
            [],
        )
        .unwrap();
    let report = store.verify().unwrap();
    assert_eq!(report.verified, 2);
    assert!(matches!(
        report.broken,
        Some(ChainBreak::HashMismatch { seq: 3, .. })
    ));
}

#[test]
fn deleted_row_is_detected() {
    let dir = TempDir::new("delete");
    let store = store_with_rows(&dir, 5);
    drop_triggers(&store);
    store
        .connection()
        .execute("DELETE FROM events WHERE seq = 4", [])
        .unwrap();
    let report = store.verify().unwrap();
    assert_eq!(report.verified, 3);
    assert_eq!(
        report.broken,
        Some(ChainBreak::SeqGap {
            expected: 4,
            found: 5
        })
    );
}

#[test]
fn reordered_rows_are_detected() {
    let dir = TempDir::new("reorder");
    let store = store_with_rows(&dir, 4);
    drop_triggers(&store);
    store
        .connection()
        .execute_batch(
            "UPDATE events SET seq = 100 WHERE seq = 2;
             UPDATE events SET seq = 2 WHERE seq = 3;
             UPDATE events SET seq = 3 WHERE seq = 100;",
        )
        .unwrap();
    let report = store.verify().unwrap();
    assert_eq!(report.verified, 1);
    assert!(report.broken.is_some());
}

#[test]
fn update_and_delete_are_rejected() {
    let dir = TempDir::new("append-only");
    let store = store_with_rows(&dir, 2);
    let upd = store
        .connection()
        .execute("UPDATE events SET target = 'x' WHERE seq = 1", []);
    let del = store
        .connection()
        .execute("DELETE FROM events WHERE seq = 1", []);
    for result in [upd, del] {
        let err = result.unwrap_err().to_string();
        assert!(err.contains("append-only"), "unexpected error: {err}");
    }
    assert!(store.verify().unwrap().is_ok());
}

#[test]
fn token_in_command_line_is_stored_redacted() {
    let dir = TempDir::new("token");
    let redactor = Redactor::with_default_detectors().unwrap();
    let mut store = Store::open(dir.db()).unwrap();
    let line = r#"curl -H "Authorization: Bearer synthToken0123456789abcdef" https://api.example.test/v1/items"#;
    let rec = EventRecord::new(command(line.into()), &redactor).unwrap();
    store.append(&rec).unwrap();

    let (target, detections, flags): (String, String, String) = store
        .connection()
        .query_row(
            "SELECT target, detections, flags FROM events WHERE seq = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        target,
        r#"curl -H "Authorization: Bearer [SECRET]" https://api.example.test/v1/items"#
    );
    assert_eq!(detections, "SECRET:1");
    assert_eq!(flags, "secret_pattern");
    assert!(rec.flags().contains(&Flag::SecretPattern));
}

#[test]
fn email_in_command_line_is_stored_redacted() {
    let dir = TempDir::new("email");
    let redactor = Redactor::with_default_detectors().unwrap();
    let mut store = Store::open(dir.db()).unwrap();
    let rec = EventRecord::new(
        command("git config user.email dev.sample@example.test".into()),
        &redactor,
    )
    .unwrap();
    store.append(&rec).unwrap();
    let (target, detections): (String, String) = store
        .connection()
        .query_row(
            "SELECT target, detections FROM events WHERE seq = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(target, "git config user.email [EMAIL]");
    assert_eq!(detections, "EMAIL:1");
}

#[test]
fn exec_environment_never_reaches_the_database() {
    const MARKER: &str = "env-marker-7c2d91";
    let dir = TempDir::new("env");
    let redactor = Redactor::with_default_detectors().unwrap();
    {
        let mut store = Store::open(dir.db()).unwrap();
        let obs = ExecObservation {
            executable: "/usr/bin/make".into(),
            args: vec!["make".into(), "test".into()],
            cwd: Some("/Users/dev/projects/sample-app".into()),
            env: vec![format!("SAMPLE_API_KEY={MARKER}"), "HOME=/Users/dev".into()],
        };
        let rec = EventRecord::new(command(obs.into_command_line()), &redactor).unwrap();
        store.append(&rec).unwrap();
        assert!(store.verify().unwrap().is_ok());
    }
    assert!(!dir_contains(&dir.0, MARKER.as_bytes()));
}

#[test]
fn invalid_input_is_rejected_before_storage() {
    let redactor = Redactor::with_default_detectors().unwrap();
    let mut bad_tool = file_read("/x");
    bad_tool.tool = "Tool A".into();
    assert!(EventRecord::new(bad_tool, &redactor).is_err());
    let mut bad_size = file_read("/x");
    bad_size.size_bytes = Some(-1);
    assert!(EventRecord::new(bad_size, &redactor).is_err());
    let mut bad_count = file_read("/x");
    bad_count.count = 0;
    assert!(EventRecord::new(bad_count, &redactor).is_err());
    let mut no_source = file_read("/x");
    no_source.sources.clear();
    assert!(EventRecord::new(no_source, &redactor).is_err());
}

#[test]
fn reopened_store_continues_the_chain() {
    let dir = TempDir::new("reopen");
    drop(store_with_rows(&dir, 3));
    let redactor = Redactor::with_default_detectors().unwrap();
    let mut store = Store::open(dir.db()).unwrap();
    let appended = store
        .append(
            &EventRecord::new(
                file_read("/Users/dev/projects/sample-app/README.md"),
                &redactor,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(appended.seq, 4);
    let ro = Store::open_read_only(dir.db()).unwrap();
    assert_eq!(ro.verify().unwrap().verified, 4);
}

fn dir_contains(dir: &Path, needle: &[u8]) -> bool {
    std::fs::read_dir(dir).unwrap().any(|entry| {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        bytes.windows(needle.len()).any(|w| w == needle)
    })
}

#[test]
fn verify_command_reports_ok_then_the_broken_seq() {
    let dir = TempDir::new("cli");
    let store = store_with_rows(&dir, 3);
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_thadam-store"))
            .arg("verify")
            .arg(dir.db())
            .output()
            .unwrap()
    };

    let ok = run();
    assert_eq!(ok.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&ok.stdout),
        "OK    3 rows verified\n"
    );

    drop_triggers(&store);
    store
        .connection()
        .execute("UPDATE events SET count = 9 WHERE seq = 2", [])
        .unwrap();
    let bad = run();
    assert_eq!(bad.status.code(), Some(1));
    let out = String::from_utf8_lossy(&bad.stdout);
    assert!(
        out.starts_with("FAIL  chain broken at seq 2: stored hash "),
        "{out}"
    );
    assert!(
        out.contains("1 rows verified before the break; 2 rows not trusted"),
        "{out}"
    );
}
