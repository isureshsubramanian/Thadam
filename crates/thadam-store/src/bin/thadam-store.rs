//! `thadam-store verify <db | store dir>`: walks the hash chain and reports the first break.
//! For a store folder (ADR-009) it walks the catalog and every kept segment, and names the
//! retired ranges and writing pauses.
//! `thadam-store migrate <old db> <store dir>`: copies a single-file store into a new store
//! folder as its first segment. The old file is not changed.
//! Exit codes: 0 chain intact (or migrated), 1 chain broken, 2 usage or I/O error.

use std::path::Path;
use std::process::ExitCode;

use thadam_store::{ChainBreak, DirBreak, Store, migrate, verify_dir};

const USAGE: &str =
    "usage: thadam-store verify <db | store dir>\n       thadam-store migrate <old db> <store dir>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd, path] if cmd == "verify" && Path::new(path).is_dir() => verify_folder(path),
        [cmd, path] if cmd == "verify" => verify_file(path),
        [cmd, old, dir] if cmd == "migrate" => migrate_store(old, dir),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn verify_file(path: &str) -> ExitCode {
    let report = match Store::open_read_only(path).and_then(|s| s.verify()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    match report.broken {
        None => {
            println!("OK    {} rows verified", report.verified);
            ExitCode::SUCCESS
        }
        Some(reason) => {
            println!("FAIL  {}", describe(&reason));
            println!(
                "      {} rows verified before the break; {} rows not trusted",
                report.verified,
                report.total.saturating_sub(report.verified)
            );
            ExitCode::from(1)
        }
    }
}

fn verify_folder(dir: &str) -> ExitCode {
    let report = match verify_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    for r in &report.retired {
        let how = if r.archived { "archived" } else { "retired" };
        println!(
            "      {how}: seq {}-{}, {}, {}",
            r.first_seq, r.last_seq, r.reason, r.segment
        );
    }
    for (from_us, to_us, missed) in &report.pauses {
        println!(
            "      writing paused (low disk): {from_us}-{to_us} us, {missed} rows not written"
        );
    }
    for name in &report.unknown_files {
        println!("      warning: {name} is not in the catalog");
    }
    for w in &report.warnings {
        println!("      warning: {w}");
    }
    match report.broken {
        None => {
            println!(
                "OK    {} rows verified in {} segments; catalog {} entries",
                report.verified_rows, report.segments_checked, report.catalog_entries
            );
            ExitCode::SUCCESS
        }
        Some(b) => {
            let detail = match b {
                DirBreak::Catalog { entry } => format!("catalog chain broken at entry {entry}"),
                DirBreak::Missing { segment } => {
                    format!("{segment} is missing and the catalog does not say it was retired")
                }
                DirBreak::Continuity { segment } => {
                    format!("{segment} does not start where the segment before it ended")
                }
                DirBreak::Mismatch { segment } => {
                    format!("{segment} does not match what the catalog recorded when it closed")
                }
                DirBreak::Segment { segment, reason } => {
                    format!("{segment}: {}", describe(&reason))
                }
            };
            println!("FAIL  {detail}");
            println!(
                "      {} rows verified before the break",
                report.verified_rows
            );
            ExitCode::from(1)
        }
    }
}

fn migrate_store(old: &str, dir: &str) -> ExitCode {
    println!("step  verify {old}, copy it into {dir} as the first segment, seed the catalog");
    let now_us = i64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000)
        .unwrap_or(i64::MAX);
    match migrate(old, dir, now_us) {
        Ok(r) => {
            println!(
                "OK    {} rows copied to {} ({} bytes); the new folder verifies",
                r.rows, r.segment, r.bytes
            );
            println!("      {old} was not changed; remove it only after checking the new folder");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn describe(reason: &ChainBreak) -> String {
    match reason {
        ChainBreak::SeqGap { expected, found } => {
            format!("seq gap: expected {expected}, found {found}")
        }
        ChainBreak::PrevHashMismatch { seq } => {
            format!(
                "chain broken at seq {seq}: prev_hash does not match row {}",
                seq - 1
            )
        }
        ChainBreak::HashMismatch {
            seq,
            stored,
            computed,
        } => {
            format!("chain broken at seq {seq}: stored hash {stored}, recomputed {computed}")
        }
        ChainBreak::Unreadable { seq } => format!("row at seq {seq} is unreadable"),
    }
}
