//! Weekly segment files, retention and the free-space guard (ADR-009).
//!
//! ```text
//! <store dir>/catalog.db            one entry per segment event, chained (catalog.rs)
//! <store dir>/events-2026-W46.db    closed
//! <store dir>/events-2026-W47.db    active: the only file written
//! ```
//!
//! The event chain runs through the segments: `seq` continues and a segment's first row uses
//! the previous segment's last hash as `prev_hash`. Purging removes whole closed segments,
//! never rows, and records each removal in the catalog first, so `verify_dir` can tell a
//! retired segment from a missing one.

use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use thadam_core::{CatalogKind, CatalogRow, EventRecord, to_hex};
use time::OffsetDateTime;

use crate::catalog::{Catalog, CatalogEntry};
use crate::disk::DiskSpace;
use crate::{ChainBreak, ChainStart, Store, StoreError, Tail};

pub const CATALOG_FILE: &str = "catalog.db";
const DAY_US: i64 = 86_400 * 1_000_000;
const GB: u64 = 1_000_000_000;

/// Retention limits (ADR-009 Decision 3). Whichever is hit first applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_age_days: u32,
    pub max_store_bytes: u64,
    pub min_free_bytes: u64,
    /// When set, retiring moves a segment here instead of deleting it (Decision 5).
    pub archive_dir: Option<PathBuf>,
}

impl Default for Limits {
    /// The ADR's defaults, all estimates: 90 days, 20 GB, 10 GB free.
    fn default() -> Self {
        Self {
            max_age_days: 90,
            max_store_bytes: 20 * GB,
            min_free_bytes: 10 * GB,
            archive_dir: None,
        }
    }
}

/// What happened to one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Written {
    Row,
    /// Writing is paused for lack of disk space; the record was counted, not written.
    Dropped,
}

/// Counts for the collector's stats line. No content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SegmentStatus {
    pub store_bytes: u64,
    pub free_bytes: u64,
    pub segments: usize,
    pub paused: bool,
    /// Records not written while paused, over the writer's life.
    pub missed: u64,
    pub retired: u64,
}

/// A segment as the catalog describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Segment {
    name: String,
    state: CatalogKind,
    start: ChainStart,
    /// Set once closed: last seq, last hash, last row time, rows.
    end: Option<(i64, [u8; 32], i64, i64)>,
    detail: Option<String>,
    reason: Option<String>,
}

struct Active {
    name: String,
    week: (i32, u8),
    store: Store,
}

struct Pause {
    from_us: i64,
    missed: u64,
}

/// The collector's writer: one active segment, rollover each ISO week, retention and the
/// free-space guard.
pub struct SegmentWriter {
    dir: PathBuf,
    catalog: Catalog,
    limits: Limits,
    disk: Box<dyn DiskSpace>,
    active: Option<Active>,
    /// Closed segments still on disk, oldest first.
    closed: Vec<Segment>,
    /// Every segment name the catalog knows, for unique names.
    known: Vec<String>,
    next: ChainStart,
    pause: Option<Pause>,
    status: SegmentStatus,
    warnings: Vec<String>,
}

impl SegmentWriter {
    /// Opens (or creates) the store folder, finishes any retirement a crash interrupted, and
    /// reopens the active segment.
    pub fn open(
        dir: impl AsRef<Path>,
        limits: Limits,
        disk: Box<dyn DiskSpace>,
    ) -> Result<Self, StoreError> {
        let dir = dir.as_ref().to_path_buf();
        DirBuilder::new().recursive(true).mode(0o755).create(&dir)?;
        let catalog = Catalog::open(dir.join(CATALOG_FILE))?;
        let segments = segments_from(&catalog.entries()?)?;
        let mut warnings = Vec::new();
        let mut closed = Vec::new();
        let mut opened = Vec::new();
        for seg in &segments {
            let path = dir.join(&seg.name);
            match seg.state {
                // Recorded as removed but still here: the crash came between the two steps.
                CatalogKind::Retired if path.exists() => remove_segment_files(&path)?,
                CatalogKind::Archived if path.exists() => match seg.detail.as_deref() {
                    Some(dest) => move_file(&path, Path::new(dest))?,
                    None => warnings.push(format!("{}: archived without a destination", seg.name)),
                },
                CatalogKind::Closed if !path.exists() => {
                    warnings.push(format!("{}: closed segment missing, not retired", seg.name));
                }
                CatalogKind::Closed => closed.push(seg.clone()),
                CatalogKind::Opened => opened.push(seg.clone()),
                _ => {}
            }
        }
        if opened.len() > 1 {
            return Err(StoreError::Layout(format!(
                "{} segments are marked active",
                opened.len()
            )));
        }
        let last_closed = segments
            .iter()
            .filter_map(|s| s.end.map(|(seq, hash, _, _)| (s.start.seq, seq, hash)))
            .max_by_key(|(first, _, _)| *first);
        let mut next = match last_closed {
            Some((_, seq, hash)) => ChainStart {
                seq: seq + 1,
                prev_hash: hash,
            },
            None => ChainStart::GENESIS,
        };
        let active = match opened.pop() {
            Some(seg) => {
                let week = week_of_name(&seg.name).ok_or_else(|| {
                    StoreError::Layout(format!("{}: not a segment name", seg.name))
                })?;
                let store = Store::open_segment(dir.join(&seg.name), seg.start)?;
                next = match store.tail()? {
                    Some(t) => ChainStart {
                        seq: t.seq + 1,
                        prev_hash: t.hash,
                    },
                    None => seg.start,
                };
                Some(Active {
                    name: seg.name,
                    week,
                    store,
                })
            }
            None => None,
        };
        let mut writer = Self {
            dir,
            catalog,
            limits,
            disk,
            active,
            closed,
            known: segments.into_iter().map(|s| s.name).collect(),
            next,
            pause: None,
            status: SegmentStatus::default(),
            warnings,
        };
        writer.refresh_status();
        Ok(writer)
    }

    /// Problems found at open that the writer could not repair (for the collector to print).
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn status(&self) -> SegmentStatus {
        self.status
    }

    /// Writes one record to the active segment, opening or rolling over as its week needs.
    pub fn append(&mut self, record: &EventRecord, now_us: i64) -> Result<Written, StoreError> {
        let week = iso_week(record.ts_us());
        let roll = match &self.active {
            None => true,
            // A row older than the active week stays in the active segment (ADR-009 Risks).
            Some(a) => week > a.week,
        };
        if roll {
            self.close_active(now_us)?;
            self.open_active(week, now_us)?;
            self.maintain(now_us)?;
        }
        if let Some(p) = &mut self.pause {
            p.missed += 1;
            self.status.missed += 1;
            return Ok(Written::Dropped);
        }
        let active = self
            .active
            .as_mut()
            .ok_or_else(|| StoreError::Layout("no active segment".to_string()))?;
        let appended = active.store.append(record)?;
        self.next = ChainStart {
            seq: appended.seq + 1,
            prev_hash: appended.hash,
        };
        Ok(Written::Row)
    }

    /// Applies the limits: age, then size, then free space; pauses or resumes writing.
    /// Called once a minute and after each rollover.
    pub fn maintain(&mut self, now_us: i64) -> Result<(), StoreError> {
        let oldest_kept = now_us - i64::from(self.limits.max_age_days) * DAY_US;
        while self
            .closed
            .first()
            .and_then(|s| s.end)
            .is_some_and(|(_, _, last_ts, _)| last_ts < oldest_kept)
        {
            self.retire_oldest("age", now_us)?;
        }
        while self.store_bytes() > self.limits.max_store_bytes && !self.closed.is_empty() {
            self.retire_oldest("size", now_us)?;
        }
        // An unreadable free-space figure changes nothing: never purge on a guess.
        if let Ok(mut free) = self.disk.free_bytes(&self.dir) {
            while free < self.limits.min_free_bytes && !self.closed.is_empty() {
                self.retire_oldest("low_disk", now_us)?;
                free = self.disk.free_bytes(&self.dir).unwrap_or(free);
            }
            self.status.free_bytes = free;
            if free < self.limits.min_free_bytes {
                if self.pause.is_none() {
                    self.pause = Some(Pause {
                        from_us: now_us,
                        missed: 0,
                    });
                }
            } else {
                self.resume(now_us)?;
            }
        }
        self.refresh_status();
        Ok(())
    }

    /// At shutdown: records an unfinished pause so the gap is never silent.
    pub fn finish(mut self, now_us: i64) -> Result<(), StoreError> {
        self.resume(now_us)
    }

    fn resume(&mut self, now_us: i64) -> Result<(), StoreError> {
        if let Some(p) = self.pause.take() {
            self.catalog.append(
                CatalogKind::Paused,
                CatalogRow {
                    at_us: now_us,
                    reason: Some("low_disk".to_string()),
                    from_us: Some(p.from_us),
                    to_us: Some(now_us),
                    missed: Some(i64::try_from(p.missed).unwrap_or(i64::MAX)),
                    ..CatalogRow::default()
                },
            )?;
        }
        Ok(())
    }

    fn open_active(&mut self, week: (i32, u8), now_us: i64) -> Result<(), StoreError> {
        let name = unique_name(&self.dir, week, &self.known);
        // ORDERING: catalog entry first, then the file. A crash between them leaves an
        // `opened` entry whose file `open` creates; never a file the catalog doesn't know.
        self.catalog.append(
            CatalogKind::Opened,
            CatalogRow {
                at_us: now_us,
                segment: Some(name.clone()),
                first_seq: Some(self.next.seq),
                first_prev_hash: Some(to_hex(&self.next.prev_hash)),
                ..CatalogRow::default()
            },
        )?;
        let store = Store::open_segment(self.dir.join(&name), self.next)?;
        self.known.push(name.clone());
        self.active = Some(Active { name, week, store });
        Ok(())
    }

    fn close_active(&mut self, now_us: i64) -> Result<(), StoreError> {
        let Some(active) = self.active.take() else {
            return Ok(());
        };
        let start = match active.store.head()? {
            Some((seq, prev, _)) => ChainStart {
                seq,
                prev_hash: prev,
            },
            None => self.next,
        };
        let rows = active.store.rows()?;
        // An empty segment ends where it started: its "last hash" is the one before it.
        let tail = active.store.tail()?.unwrap_or(Tail {
            seq: start.seq - 1,
            hash: start.prev_hash,
            ts_us: now_us,
        });
        // Closing the connection checkpoints the WAL into the file before it is measured.
        drop(active.store);
        let path = self.dir.join(&active.name);
        let bytes = segment_bytes(&path);
        let rows = i64::try_from(rows).unwrap_or(i64::MAX);
        self.catalog.append(
            CatalogKind::Closed,
            CatalogRow {
                at_us: now_us,
                segment: Some(active.name.clone()),
                first_seq: Some(start.seq),
                last_seq: Some(tail.seq),
                first_prev_hash: Some(to_hex(&start.prev_hash)),
                last_hash: Some(to_hex(&tail.hash)),
                last_ts_us: Some(tail.ts_us),
                rows: Some(rows),
                bytes: Some(i64::try_from(bytes).unwrap_or(i64::MAX)),
                ..CatalogRow::default()
            },
        )?;
        self.closed.push(Segment {
            name: active.name,
            state: CatalogKind::Closed,
            start,
            end: Some((tail.seq, tail.hash, tail.ts_us, rows)),
            detail: None,
            reason: None,
        });
        Ok(())
    }

    /// Retires the oldest closed segment: catalog entry first, then delete or move.
    fn retire_oldest(&mut self, reason: &str, now_us: i64) -> Result<(), StoreError> {
        if self.closed.is_empty() {
            return Ok(());
        }
        let seg = self.closed.remove(0);
        let path = self.dir.join(&seg.name);
        let (last_seq, last_hash, last_ts, rows) =
            seg.end
                .unwrap_or((seg.start.seq - 1, seg.start.prev_hash, now_us, 0));
        let dest = self.limits.archive_dir.as_ref().map(|d| d.join(&seg.name));
        let kind = if dest.is_some() {
            CatalogKind::Archived
        } else {
            CatalogKind::Retired
        };
        self.catalog.append(
            kind,
            CatalogRow {
                at_us: now_us,
                segment: Some(seg.name.clone()),
                first_seq: Some(seg.start.seq),
                last_seq: Some(last_seq),
                first_prev_hash: Some(to_hex(&seg.start.prev_hash)),
                last_hash: Some(to_hex(&last_hash)),
                last_ts_us: Some(last_ts),
                rows: Some(rows),
                reason: Some(reason.to_string()),
                detail: dest.as_ref().map(|d| d.display().to_string()),
                ..CatalogRow::default()
            },
        )?;
        match dest {
            Some(dest) => move_file(&path, &dest)?,
            None => remove_segment_files(&path)?,
        }
        self.status.retired += 1;
        Ok(())
    }

    fn store_bytes(&self) -> u64 {
        let active = self
            .active
            .as_ref()
            .map_or(0, |a| segment_bytes(&self.dir.join(&a.name)));
        self.closed
            .iter()
            .map(|s| segment_bytes(&self.dir.join(&s.name)))
            .sum::<u64>()
            + active
    }

    fn refresh_status(&mut self) {
        self.status.store_bytes = self.store_bytes();
        self.status.segments = self.closed.len() + usize::from(self.active.is_some());
        self.status.paused = self.pause.is_some();
    }
}

// ---- Verify across segments ----

/// Why a store folder failed verification. Segment names and sequence numbers only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirBreak {
    /// The catalog's own chain is broken at this entry.
    Catalog { entry: i64 },
    /// A segment the catalog says is kept is not on disk.
    Missing { segment: String },
    /// A segment does not start where the one before it ended.
    Continuity { segment: String },
    /// A segment's rows don't match what the catalog recorded when it closed.
    Mismatch { segment: String },
    /// A segment's own chain is broken.
    Segment { segment: String, reason: ChainBreak },
}

/// A retired or archived range, for the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetiredRange {
    pub segment: String,
    pub first_seq: i64,
    pub last_seq: i64,
    pub archived: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirReport {
    pub catalog_entries: u64,
    pub segments_checked: usize,
    pub verified_rows: u64,
    pub retired: Vec<RetiredRange>,
    /// (from_us, to_us, missed) for each pause.
    pub pauses: Vec<(i64, i64, i64)>,
    /// `.db` files in the folder that the catalog doesn't know.
    pub unknown_files: Vec<String>,
    /// Not breaks: e.g. a retired segment still on disk (a crash before the delete).
    pub warnings: Vec<String>,
    pub broken: Option<DirBreak>,
}

/// Verifies a store folder: the catalog's chain, then every kept segment in order, each
/// starting exactly where the previous one (kept or retired) ended.
pub fn verify_dir(dir: impl AsRef<Path>) -> Result<DirReport, StoreError> {
    let dir = dir.as_ref();
    let catalog = Catalog::open_read_only(dir.join(CATALOG_FILE))?;
    let mut report = DirReport::default();
    let check = catalog.verify()?;
    report.catalog_entries = check.verified;
    if let Some(entry) = check.broken_at {
        report.broken = Some(DirBreak::Catalog { entry });
        return Ok(report);
    }
    let entries = catalog.entries()?;
    for e in &entries {
        if e.kind == CatalogKind::Paused {
            report.pauses.push((
                e.row.from_us.unwrap_or(0),
                e.row.to_us.unwrap_or(0),
                e.row.missed.unwrap_or(0),
            ));
        }
    }
    let segments = segments_from(&entries)?;
    let mut expected = ChainStart::GENESIS;
    for seg in &segments {
        if seg.start != expected {
            report.broken = Some(DirBreak::Continuity {
                segment: seg.name.clone(),
            });
            return Ok(report);
        }
        match seg.state {
            CatalogKind::Retired | CatalogKind::Archived => {
                let (last_seq, last_hash, _, _) = seg.end.ok_or_else(|| {
                    StoreError::Layout(format!("{}: retired without an end", seg.name))
                })?;
                if dir.join(&seg.name).exists() {
                    report
                        .warnings
                        .push(format!("{}: retired but still present", seg.name));
                }
                report.retired.push(RetiredRange {
                    segment: seg.name.clone(),
                    first_seq: seg.start.seq,
                    last_seq,
                    archived: seg.state == CatalogKind::Archived,
                    reason: seg.reason.clone().unwrap_or_default(),
                });
                expected = ChainStart {
                    seq: last_seq + 1,
                    prev_hash: last_hash,
                };
            }
            CatalogKind::Closed | CatalogKind::Opened => {
                let path = dir.join(&seg.name);
                if !path.exists() {
                    report.broken = Some(DirBreak::Missing {
                        segment: seg.name.clone(),
                    });
                    return Ok(report);
                }
                let store = Store::open_segment_read_only(&path, seg.start)?;
                let r = store.verify()?;
                report.verified_rows += r.verified;
                report.segments_checked += 1;
                if let Some(reason) = r.broken {
                    report.broken = Some(DirBreak::Segment {
                        segment: seg.name.clone(),
                        reason,
                    });
                    return Ok(report);
                }
                let tail = store.tail()?;
                expected = match (seg.end, tail) {
                    (Some((last_seq, last_hash, _, rows)), t) => {
                        let matches = i64::try_from(r.verified).ok() == Some(rows)
                            && match t {
                                Some(t) => t.seq == last_seq && t.hash == last_hash,
                                None => rows == 0,
                            };
                        if !matches {
                            report.broken = Some(DirBreak::Mismatch {
                                segment: seg.name.clone(),
                            });
                            return Ok(report);
                        }
                        ChainStart {
                            seq: last_seq + 1,
                            prev_hash: last_hash,
                        }
                    }
                    (None, Some(t)) => ChainStart {
                        seq: t.seq + 1,
                        prev_hash: t.hash,
                    },
                    (None, None) => seg.start,
                };
            }
            _ => {}
        }
    }
    let names: Vec<&str> = segments.iter().map(|s| s.name.as_str()).collect();
    for entry in fs::read_dir(dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.ends_with(".db") && name != CATALOG_FILE && !names.contains(&name.as_str()) {
            report.unknown_files.push(name);
        }
    }
    report.unknown_files.sort();
    Ok(report)
}

// ---- Migration (ADR-009 Decision 7) ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrateReport {
    pub segment: String,
    pub rows: u64,
    pub bytes: u64,
}

/// Copies a single-file store into a new store folder as its first, closed segment, and
/// seeds the catalog. The original is not changed. The copy is made with `VACUUM INTO`, so
/// rows still in the original's WAL are included; every row keeps its seq and hash.
pub fn migrate(
    old_db: impl AsRef<Path>,
    dir: impl AsRef<Path>,
    now_us: i64,
) -> Result<MigrateReport, StoreError> {
    let (old_db, dir) = (old_db.as_ref(), dir.as_ref());
    if dir.join(CATALOG_FILE).exists() {
        return Err(StoreError::Layout(
            "the destination already has a catalog".to_string(),
        ));
    }
    let old = Store::open_read_only(old_db)?;
    let check = old.verify()?;
    if !check.is_ok() {
        return Err(StoreError::Layout(
            "the source store does not verify; not migrating".to_string(),
        ));
    }
    let (Some((_, _, first_ts)), Some(tail)) = (old.head()?, old.tail()?) else {
        return Err(StoreError::Layout("the source store is empty".to_string()));
    };
    DirBuilder::new().recursive(true).mode(0o755).create(dir)?;
    let name = unique_name(dir, iso_week(first_ts), &[]);
    let dest = dir.join(&name);
    old.connection()
        .execute("VACUUM INTO ?1", [dest.to_string_lossy().as_ref()])?;
    drop(old);
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o644))?;
    let copy = Store::open_read_only(&dest)?;
    let copied = copy.verify()?;
    if !copied.is_ok() || copied.verified != check.verified || copy.tail()? != Some(tail) {
        return Err(StoreError::Layout(
            "the copy does not match the source".to_string(),
        ));
    }
    drop(copy);
    let bytes = segment_bytes(&dest);
    let mut catalog = Catalog::open(dir.join(CATALOG_FILE))?;
    let rows = i64::try_from(check.verified).unwrap_or(i64::MAX);
    let genesis = to_hex(&ChainStart::GENESIS.prev_hash);
    catalog.append(
        CatalogKind::Opened,
        CatalogRow {
            at_us: now_us,
            segment: Some(name.clone()),
            first_seq: Some(1),
            first_prev_hash: Some(genesis.clone()),
            reason: Some("migrated".to_string()),
            ..CatalogRow::default()
        },
    )?;
    catalog.append(
        CatalogKind::Closed,
        CatalogRow {
            at_us: now_us,
            segment: Some(name.clone()),
            first_seq: Some(1),
            last_seq: Some(tail.seq),
            first_prev_hash: Some(genesis),
            last_hash: Some(to_hex(&tail.hash)),
            last_ts_us: Some(tail.ts_us),
            rows: Some(rows),
            bytes: Some(i64::try_from(bytes).unwrap_or(i64::MAX)),
            reason: Some("migrated".to_string()),
            ..CatalogRow::default()
        },
    )?;
    drop(catalog);
    fs::set_permissions(dir.join(CATALOG_FILE), fs::Permissions::from_mode(0o644))?;
    let report = verify_dir(dir)?;
    if report.broken.is_some() {
        return Err(StoreError::Layout(
            "the new store folder does not verify".to_string(),
        ));
    }
    Ok(MigrateReport {
        segment: name,
        rows: check.verified,
        bytes,
    })
}

// ---- Helpers ----

fn segments_from(entries: &[CatalogEntry]) -> Result<Vec<Segment>, StoreError> {
    let mut out: Vec<Segment> = Vec::new();
    for e in entries {
        let Some(name) = e.row.segment.clone() else {
            continue;
        };
        let bad =
            || StoreError::Layout(format!("{name}: catalog entry {} is incomplete", e.row.seq));
        let start = ChainStart {
            seq: e.row.first_seq.ok_or_else(bad)?,
            prev_hash: e
                .row
                .first_prev_hash
                .as_deref()
                .and_then(from_hex)
                .ok_or_else(bad)?,
        };
        let end = match e.kind {
            CatalogKind::Opened => None,
            _ => Some((
                e.row.last_seq.ok_or_else(bad)?,
                e.row
                    .last_hash
                    .as_deref()
                    .and_then(from_hex)
                    .ok_or_else(bad)?,
                e.row.last_ts_us.ok_or_else(bad)?,
                e.row.rows.ok_or_else(bad)?,
            )),
        };
        match out.iter_mut().find(|s| s.name == name) {
            Some(seg) => {
                if seg.start != start {
                    return Err(StoreError::Layout(format!("{name}: catalog start changed")));
                }
                seg.state = e.kind;
                seg.end = end.or(seg.end);
                seg.detail = e.row.detail.clone();
                seg.reason = e.row.reason.clone();
            }
            None => out.push(Segment {
                name,
                state: e.kind,
                start,
                end,
                detail: e.row.detail.clone(),
                reason: e.row.reason.clone(),
            }),
        }
    }
    out.sort_by_key(|s| s.start.seq);
    Ok(out)
}

/// ISO year and week (UTC) of a time in microseconds.
fn iso_week(ts_us: i64) -> (i32, u8) {
    let t = OffsetDateTime::from_unix_timestamp_nanos(i128::from(ts_us) * 1_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let (year, week, _) = t.to_iso_week_date();
    (year, week)
}

fn week_of_name(name: &str) -> Option<(i32, u8)> {
    let rest = name.strip_prefix("events-")?;
    let year: i32 = rest.get(0..4)?.parse().ok()?;
    let week: u8 = rest.get(4..)?.strip_prefix("-W")?.get(0..2)?.parse().ok()?;
    Some((year, week))
}

/// `events-YYYY-Www.db`, or `events-YYYY-Www-N.db` if that name was ever used or exists.
fn unique_name(dir: &Path, (year, week): (i32, u8), known: &[String]) -> String {
    let base = format!("events-{year:04}-W{week:02}");
    let taken = |n: &str| known.iter().any(|k| k == n) || dir.join(n).exists();
    let first = format!("{base}.db");
    if !taken(&first) {
        return first;
    }
    (2..)
        .map(|i| format!("{base}-{i}.db"))
        .find(|n| !taken(n))
        .unwrap_or(first)
}

fn from_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The segment file plus its WAL, in bytes.
fn segment_bytes(path: &Path) -> u64 {
    let size = |p: &Path| fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    size(path) + size(&side(path, "-wal"))
}

fn side(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

fn remove_segment_files(path: &Path) -> Result<(), StoreError> {
    for p in [path.to_path_buf(), side(path, "-wal"), side(path, "-shm")] {
        match fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Moves a closed segment, across file systems if needed (copy, then delete).
fn move_file(from: &Path, to: &Path) -> Result<(), StoreError> {
    if let Some(parent) = to.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(parent)?;
    }
    if fs::rename(from, to).is_err() {
        fs::copy(from, to)?;
    }
    remove_segment_files(from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_weeks() {
        assert_eq!(week_of_name("events-2026-W46.db"), Some((2026, 46)));
        assert_eq!(week_of_name("events-2026-W46-2.db"), Some((2026, 46)));
        assert_eq!(week_of_name("catalog.db"), None);
        // 2026-11-15 is a Sunday, still ISO week 46; the 16th starts week 47.
        assert_eq!(iso_week(1_794_787_200_000_000 - 1), (2026, 46));
        assert_eq!(iso_week(1_794_787_200_000_000), (2026, 47));
        // 2027-01-01 belongs to ISO week 53 of 2026.
        assert_eq!(iso_week(1_798_761_600_000_000), (2026, 53));
    }

    #[test]
    fn hex_round_trip() {
        let h = [0xabu8; 32];
        assert_eq!(from_hex(&to_hex(&h)), Some(h));
        assert_eq!(from_hex("zz"), None);
    }
}
