//! ADR-009 acceptance tests: segments, retention, the free-space guard, archive, recovery and
//! migration. All data is synthetic.
// Integration tests: unwrap/expect are allowed here (helpers included), not in library code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::Connection;
use thadam_core::{Action, Category, EventRecord, NewEvent, Outcome, Redactor, Source};
use thadam_store::{
    CATALOG_FILE, DirBreak, DiskSpace, Limits, SegmentWriter, Store, Written, migrate, verify_dir,
};
use time::OffsetDateTime;
use time::macros::datetime;

const GB: u64 = 1_000_000_000;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("thadam-seg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn store(&self) -> PathBuf {
        self.0.join("store")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A free-space source the test controls.
#[derive(Clone)]
struct FakeDisk(Arc<AtomicU64>);

impl FakeDisk {
    fn new(free: u64) -> Self {
        Self(Arc::new(AtomicU64::new(free)))
    }
    fn set(&self, free: u64) {
        self.0.store(free, Ordering::SeqCst);
    }
}

impl DiskSpace for FakeDisk {
    fn free_bytes(&self, _dir: &Path) -> io::Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

fn plenty() -> Box<FakeDisk> {
    Box::new(FakeDisk::new(500 * GB))
}

fn us(t: OffsetDateTime) -> i64 {
    i64::try_from(t.unix_timestamp_nanos() / 1_000).unwrap()
}

fn record(ts: OffsetDateTime, i: usize) -> EventRecord {
    let redactor = Redactor::with_default_detectors().unwrap();
    EventRecord::new(
        NewEvent {
            ts,
            tool: "tool-a".into(),
            session_id: Some("s-7f3e".into()),
            parent_session_id: None,
            pid: 48211,
            process_path: "/bin/cat".into(),
            category: Category::File,
            action: Action::Read,
            target: format!("/Users/dev/projects/sample-app/src/f{i}.rs"),
            outcome: Outcome::Allowed,
            size_bytes: Some(2048),
            bytes_out: None,
            bytes_in: None,
            project: Some("/Users/dev/projects/sample-app".into()),
            flags: BTreeSet::new(),
            count: 1,
            sources: BTreeSet::from([Source::Os]),
        },
        &redactor,
    )
    .unwrap()
}

/// Writes `n` rows at each of the given times.
fn write(w: &mut SegmentWriter, times: &[OffsetDateTime], n: usize) {
    for (k, t) in times.iter().enumerate() {
        for i in 0..n {
            assert_eq!(
                w.append(&record(*t, k * n + i), us(*t)).unwrap(),
                Written::Row
            );
        }
    }
}

fn segment_files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("events-") && n.ends_with(".db"))
        .collect();
    names.sort();
    names
}

/// Four weeks of synthetic rows: W44, W45, W46 closed, W47 active.
fn four_weeks() -> [OffsetDateTime; 4] {
    [
        datetime!(2026-10-28 10:00 UTC),
        datetime!(2026-11-04 10:00 UTC),
        datetime!(2026-11-11 10:00 UTC),
        datetime!(2026-11-18 10:00 UTC),
    ]
}

#[test]
fn rows_across_a_week_boundary_land_in_two_chained_files() {
    let tmp = TempDir::new("rollover");
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
    // Sunday 23:59 UTC is ISO week 46; Monday 00:01 is week 47.
    write(
        &mut w,
        &[
            datetime!(2026-11-15 23:59 UTC),
            datetime!(2026-11-16 00:01 UTC),
        ],
        3,
    );
    drop(w);
    assert_eq!(
        segment_files(&tmp.store()),
        ["events-2026-W46.db", "events-2026-W47.db"]
    );
    let report = verify_dir(tmp.store()).unwrap();
    assert_eq!(report.broken, None);
    assert_eq!(report.verified_rows, 6);
    assert_eq!(report.segments_checked, 2);
    // seq continues: the second file starts at 4.
    let second = Store::open_read_only(tmp.store().join("events-2026-W47.db"));
    // Opened as a whole store it fails verification at its first row: it does not start
    // at genesis, which shows the files are one chain, not two.
    assert!(!second.unwrap().verify().unwrap().is_ok());
}

#[test]
fn reopening_continues_the_active_segment_and_the_chain() {
    let tmp = TempDir::new("reopen");
    let t = datetime!(2026-11-12 10:00 UTC);
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
    write(&mut w, &[t], 2);
    drop(w);
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
    write(&mut w, &[t, datetime!(2026-11-17 10:00 UTC)], 2);
    drop(w);
    assert_eq!(segment_files(&tmp.store()).len(), 2);
    let report = verify_dir(tmp.store()).unwrap();
    assert_eq!(report.broken, None);
    assert_eq!(report.verified_rows, 6);
}

#[test]
fn a_late_row_stays_in_the_active_segment() {
    let tmp = TempDir::new("late");
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
    write(
        &mut w,
        &[
            datetime!(2026-11-17 10:00 UTC),
            datetime!(2026-11-12 10:00 UTC),
        ],
        1,
    );
    drop(w);
    assert_eq!(segment_files(&tmp.store()), ["events-2026-W47.db"]);
    assert_eq!(verify_dir(tmp.store()).unwrap().broken, None);
}

#[test]
fn age_limit_retires_the_oldest_closed_segments_and_never_the_active() {
    let tmp = TempDir::new("age");
    let limits = Limits {
        max_age_days: 7,
        ..Limits::default()
    };
    let mut w = SegmentWriter::open(tmp.store(), limits, plenty()).unwrap();
    let weeks = four_weeks();
    write(&mut w, &weeks, 2);
    // A month later every closed segment is past the limit; the active one stays.
    w.maintain(us(datetime!(2026-12-20 10:00 UTC))).unwrap();
    assert_eq!(w.status().retired, 3);
    drop(w);
    assert_eq!(segment_files(&tmp.store()), ["events-2026-W47.db"]);
    let report = verify_dir(tmp.store()).unwrap();
    assert_eq!(report.broken, None);
    assert_eq!(report.verified_rows, 2);
    let retired: Vec<(i64, i64, &str)> = report
        .retired
        .iter()
        .map(|r| (r.first_seq, r.last_seq, r.reason.as_str()))
        .collect();
    assert_eq!(retired, [(1, 2, "age"), (3, 4, "age"), (5, 6, "age")]);
}

#[test]
fn age_limit_keeps_segments_with_recent_rows() {
    let tmp = TempDir::new("age-keep");
    let limits = Limits {
        max_age_days: 7,
        ..Limits::default()
    };
    let mut w = SegmentWriter::open(tmp.store(), limits, plenty()).unwrap();
    write(&mut w, &four_weeks(), 1);
    // At 10:00 on 18 Nov, W46's last row (11 Nov 10:00) is exactly 7 days old and stays;
    // only W44 (28 Oct) and W45 (4 Nov) are older.
    w.maintain(us(datetime!(2026-11-18 10:00 UTC))).unwrap();
    drop(w);
    assert_eq!(
        segment_files(&tmp.store()),
        ["events-2026-W46.db", "events-2026-W47.db"]
    );
    assert_eq!(verify_dir(tmp.store()).unwrap().retired.len(), 2);
}

#[test]
fn size_limit_retires_oldest_first_down_to_the_active_segment() {
    let tmp = TempDir::new("size");
    let limits = Limits {
        max_store_bytes: 1,
        ..Limits::default()
    };
    let mut w = SegmentWriter::open(tmp.store(), limits, plenty()).unwrap();
    write(&mut w, &four_weeks(), 2);
    w.maintain(us(datetime!(2026-11-18 11:00 UTC))).unwrap();
    drop(w);
    assert_eq!(segment_files(&tmp.store()), ["events-2026-W47.db"]);
    let report = verify_dir(tmp.store()).unwrap();
    assert_eq!(report.broken, None);
    assert!(
        report
            .retired
            .iter()
            .all(|r| r.reason == "size" && !r.archived)
    );
    assert_eq!(report.retired.len(), 3);
}

#[test]
fn a_deleted_segment_the_catalog_does_not_explain_is_a_break() {
    let tmp = TempDir::new("missing");
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
    write(&mut w, &four_weeks(), 2);
    drop(w);
    std::fs::remove_file(tmp.store().join("events-2026-W45.db")).unwrap();
    assert_eq!(
        verify_dir(tmp.store()).unwrap().broken,
        Some(DirBreak::Missing {
            segment: "events-2026-W45.db".into()
        })
    );
}

#[test]
fn an_edited_row_in_a_closed_segment_is_a_break() {
    let tmp = TempDir::new("edited");
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
    write(&mut w, &four_weeks(), 2);
    drop(w);
    let conn = Connection::open(tmp.store().join("events-2026-W45.db")).unwrap();
    conn.execute_batch(
        "DROP TRIGGER events_no_update; UPDATE events SET target = '/tmp/other' WHERE seq = 4;",
    )
    .unwrap();
    drop(conn);
    let broken = verify_dir(tmp.store()).unwrap().broken;
    assert!(
        matches!(&broken, Some(DirBreak::Segment { segment, .. }) if segment == "events-2026-W45.db"),
        "{broken:?}"
    );
}

#[test]
fn a_replaced_segment_does_not_continue_the_chain() {
    let tmp = TempDir::new("replaced");
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
    write(&mut w, &four_weeks(), 2);
    drop(w);
    // Swap a closed segment for a freshly built, internally valid one.
    let fake = tmp.0.join("fake.db");
    let mut s = Store::open(&fake).unwrap();
    s.append(&record(datetime!(2026-11-04 10:00 UTC), 0))
        .unwrap();
    drop(s);
    std::fs::rename(&fake, tmp.store().join("events-2026-W45.db")).unwrap();
    assert!(verify_dir(tmp.store()).unwrap().broken.is_some());
}

#[test]
fn a_removed_or_changed_catalog_entry_is_a_break() {
    // A removed entry shows at the next one (the gap); a changed one at itself.
    for (name, sql, entry) in [
        (
            "cat-del",
            "DROP TRIGGER catalog_no_delete; DELETE FROM catalog WHERE seq = 2;",
            3,
        ),
        (
            "cat-upd",
            "DROP TRIGGER catalog_no_update; UPDATE catalog SET reason = 'x' WHERE seq = 2;",
            2,
        ),
    ] {
        let tmp = TempDir::new(name);
        let mut w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
        write(&mut w, &four_weeks(), 1);
        drop(w);
        let conn = Connection::open(tmp.store().join(CATALOG_FILE)).unwrap();
        conn.execute_batch(sql).unwrap();
        drop(conn);
        assert_eq!(
            verify_dir(tmp.store()).unwrap().broken,
            Some(DirBreak::Catalog { entry }),
            "{name}"
        );
    }
}

#[test]
fn low_disk_retires_then_pauses_then_records_the_gap() {
    let tmp = TempDir::new("guard");
    let disk = FakeDisk::new(500 * GB);
    let mut w =
        SegmentWriter::open(tmp.store(), Limits::default(), Box::new(disk.clone())).unwrap();
    let weeks = four_weeks();
    write(&mut w, &weeks, 2);

    // Below the 10 GB floor: every closed segment goes, then writing pauses.
    disk.set(5 * GB);
    let paused_at = us(datetime!(2026-11-18 11:00 UTC));
    w.maintain(paused_at).unwrap();
    assert!(w.status().paused);
    assert_eq!(w.status().retired, 3);
    for i in 0..4 {
        assert_eq!(
            w.append(&record(weeks[3], 100 + i), paused_at).unwrap(),
            Written::Dropped
        );
    }
    assert_eq!(w.status().missed, 4);

    // Space recovers: the gap is recorded and writing resumes.
    disk.set(50 * GB);
    let resumed_at = us(datetime!(2026-11-18 12:00 UTC));
    w.maintain(resumed_at).unwrap();
    assert!(!w.status().paused);
    assert_eq!(
        w.append(&record(weeks[3], 200), resumed_at).unwrap(),
        Written::Row
    );
    drop(w);

    let report = verify_dir(tmp.store()).unwrap();
    assert_eq!(report.broken, None);
    assert_eq!(report.pauses, [(paused_at, resumed_at, 4)]);
    assert!(report.retired.iter().all(|r| r.reason == "low_disk"));
    assert_eq!(report.verified_rows, 3);
}

#[test]
fn a_pause_still_open_at_shutdown_is_recorded() {
    let tmp = TempDir::new("guard-finish");
    let disk = FakeDisk::new(5 * GB);
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), Box::new(disk)).unwrap();
    let t = datetime!(2026-11-18 10:00 UTC);
    // The first row opens the segment, the guard runs and pauses: the row is dropped.
    assert_eq!(w.append(&record(t, 0), us(t)).unwrap(), Written::Dropped);
    w.finish(us(t) + 1).unwrap();
    assert_eq!(
        verify_dir(tmp.store()).unwrap().pauses,
        [(us(t), us(t) + 1, 1)]
    );
}

#[test]
fn an_unreadable_free_space_figure_purges_nothing() {
    struct Broken;
    impl DiskSpace for Broken {
        fn free_bytes(&self, _dir: &Path) -> io::Result<u64> {
            Err(io::Error::other("no figure"))
        }
    }
    let tmp = TempDir::new("guard-unknown");
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), Box::new(Broken)).unwrap();
    write(&mut w, &four_weeks(), 1);
    w.maintain(us(datetime!(2026-11-18 11:00 UTC))).unwrap();
    assert_eq!(w.status().retired, 0);
    assert!(!w.status().paused);
}

#[test]
fn with_an_archive_folder_segments_are_moved_not_deleted() {
    let tmp = TempDir::new("archive");
    let archive = tmp.0.join("archive");
    let limits = Limits {
        max_store_bytes: 1,
        archive_dir: Some(archive.clone()),
        ..Limits::default()
    };
    let mut w = SegmentWriter::open(tmp.store(), limits, plenty()).unwrap();
    write(&mut w, &four_weeks(), 2);
    w.maintain(us(datetime!(2026-11-18 11:00 UTC))).unwrap();
    drop(w);
    assert_eq!(segment_files(&tmp.store()), ["events-2026-W47.db"]);
    assert_eq!(
        segment_files(&archive),
        [
            "events-2026-W44.db",
            "events-2026-W45.db",
            "events-2026-W46.db"
        ]
    );
    let report = verify_dir(tmp.store()).unwrap();
    assert_eq!(report.broken, None);
    assert!(report.retired.iter().all(|r| r.archived));
    // The archived copy is the real thing: its rows are intact.
    let moved = Store::open_read_only(archive.join("events-2026-W44.db")).unwrap();
    assert!(moved.verify().unwrap().is_ok());
}

#[test]
fn a_retirement_interrupted_before_the_delete_is_finished_at_open() {
    let tmp = TempDir::new("crash");
    let limits = Limits {
        max_store_bytes: 1,
        ..Limits::default()
    };
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
    write(&mut w, &four_weeks(), 1);
    drop(w);
    // Keep a copy, retire, then put the file back: as if the delete never happened.
    let seg = tmp.store().join("events-2026-W44.db");
    let saved = tmp.0.join("saved.db");
    std::fs::copy(&seg, &saved).unwrap();
    let mut w = SegmentWriter::open(tmp.store(), limits, plenty()).unwrap();
    w.maintain(us(datetime!(2026-11-18 11:00 UTC))).unwrap();
    drop(w);
    std::fs::copy(&saved, &seg).unwrap();

    let report = verify_dir(tmp.store()).unwrap();
    assert_eq!(report.broken, None);
    assert_eq!(
        report.warnings,
        ["events-2026-W44.db: retired but still present"]
    );

    let w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
    assert!(w.warnings().is_empty());
    drop(w);
    assert!(!seg.exists());
    assert!(verify_dir(tmp.store()).unwrap().warnings.is_empty());
}

#[test]
fn an_unknown_file_in_the_folder_is_reported() {
    let tmp = TempDir::new("unknown");
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
    write(&mut w, &four_weeks(), 1);
    drop(w);
    std::fs::write(tmp.store().join("events-2026-W01.db"), b"").unwrap();
    let report = verify_dir(tmp.store()).unwrap();
    assert_eq!(report.broken, None);
    assert_eq!(report.unknown_files, ["events-2026-W01.db"]);
}

#[test]
fn migration_copies_a_single_file_store_without_changing_a_row() {
    let tmp = TempDir::new("migrate");
    let old = tmp.0.join("events.db");
    let t = datetime!(2026-11-14 10:00 UTC);
    let mut s = Store::open(&old).unwrap();
    for i in 0..5 {
        s.append(&record(t, i)).unwrap();
    }
    let old_tail = s.tail().unwrap().unwrap();
    // Leave the connection open, so some rows may still be in the WAL.
    let report = migrate(&old, tmp.store(), us(t)).unwrap();
    assert_eq!(report.segment, "events-2026-W46.db");
    assert_eq!(report.rows, 5);
    drop(s);

    let copy = Store::open_read_only(tmp.store().join(&report.segment)).unwrap();
    assert_eq!(copy.tail().unwrap(), Some(old_tail));
    drop(copy);
    assert!(
        Store::open_read_only(&old)
            .unwrap()
            .verify()
            .unwrap()
            .is_ok()
    );

    // The writer continues the chain in a new file for the same week.
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
    assert_eq!(w.status().segments, 1);
    write(&mut w, &[t], 2);
    // The status already counts the segment the first row opened.
    assert_eq!(w.status().segments, 2);
    drop(w);
    assert_eq!(
        segment_files(&tmp.store()),
        ["events-2026-W46-2.db", "events-2026-W46.db"]
    );
    let dir = verify_dir(tmp.store()).unwrap();
    assert_eq!(dir.broken, None);
    assert_eq!(dir.verified_rows, 7);

    // Never over an existing store.
    assert!(migrate(&old, tmp.store(), us(t)).is_err());
}

#[test]
fn migration_refuses_a_store_that_does_not_verify() {
    let tmp = TempDir::new("migrate-bad");
    let old = tmp.0.join("events.db");
    let t = datetime!(2026-11-14 10:00 UTC);
    let mut s = Store::open(&old).unwrap();
    for i in 0..3 {
        s.append(&record(t, i)).unwrap();
    }
    s.connection()
        .execute_batch(
            "DROP TRIGGER events_no_update; UPDATE events SET target = '/x' WHERE seq = 2;",
        )
        .unwrap();
    drop(s);
    assert!(migrate(&old, tmp.store(), us(t)).is_err());
    assert!(!tmp.store().join(CATALOG_FILE).exists());
}

fn journal_mode(path: &Path) -> String {
    let conn =
        Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    conn.pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap()
}

#[test]
fn only_files_being_written_are_in_wal_mode() {
    let tmp = TempDir::new("journal");
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
    write(&mut w, &four_weeks(), 1);
    // While the writer runs: closed segments are in the rollback journal, the active one
    // and the catalog in WAL.
    assert_eq!(
        journal_mode(&tmp.store().join("events-2026-W46.db")),
        "delete"
    );
    assert_eq!(journal_mode(&tmp.store().join("events-2026-W47.db")), "wal");
    assert_eq!(journal_mode(&tmp.store().join(CATALOG_FILE)), "wal");
    w.finish(us(datetime!(2026-11-18 11:00 UTC))).unwrap();
    for name in ["events-2026-W47.db", CATALOG_FILE] {
        assert_eq!(journal_mode(&tmp.store().join(name)), "delete", "{name}");
    }
    // A new writer switches back.
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
    write(&mut w, &[datetime!(2026-11-18 12:00 UTC)], 1);
    assert_eq!(journal_mode(&tmp.store().join("events-2026-W47.db")), "wal");
}

/// The live finding behind this: a user process could not open the WAL files in the
/// root-owned folder once the collector had stopped, because it could not create `-shm`.
#[test]
fn a_stopped_store_verifies_from_a_folder_the_reader_cannot_write() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new("readonly-dir");
    let mut w = SegmentWriter::open(tmp.store(), Limits::default(), plenty()).unwrap();
    write(&mut w, &four_weeks(), 2);
    drop(w);
    let set = |mode| {
        std::fs::set_permissions(tmp.store(), std::fs::Permissions::from_mode(mode)).unwrap();
    };
    set(0o555);
    let report = verify_dir(tmp.store());
    set(0o755);
    let report = report.unwrap();
    assert_eq!(report.broken, None);
    assert_eq!(report.verified_rows, 8);
}
