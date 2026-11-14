//! Writes a synthetic store folder with the real store code, for the API's tests
//! (api/tests/*/StoreFixture.cs runs it). Not shipped. All data is synthetic.
//!
//!   cargo run -q -p thadam-store --example fixture -- <empty or new folder>
//!
//! Layout: four ISO weeks (2026-W44 to W47, UTC), a 14-day age limit. W44 is retired when
//! W46 opens and W45 when W47 opens, so the folder has two retired ranges (seq 1-4); W46 is
//! closed and W47 is the active segment. Rows cover the cases the API
//! must show: a session with a delegated child session, project and outside-project files,
//! a redacted secret in a command, a refused write, an unknown host, and tool-internal reads.
// An example, not library code: unwrap/expect are allowed here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::io;
use std::path::Path;

use thadam_core::{Action, Category, EventRecord, Flag, NewEvent, Outcome, Redactor, Source};
use thadam_store::{DiskSpace, Limits, SegmentWriter, Written};
use time::OffsetDateTime;
use time::macros::datetime;

const PROJECT: &str = "/Users/dev/projects/sample-app";

struct PlentyOfSpace;

impl DiskSpace for PlentyOfSpace {
    fn free_bytes(&self, _dir: &Path) -> io::Result<u64> {
        Ok(500_000_000_000)
    }
}

struct Row {
    ts: OffsetDateTime,
    tool: &'static str,
    session: &'static str,
    parent: Option<&'static str>,
    pid: u32,
    process: &'static str,
    category: Category,
    action: Action,
    target: String,
    outcome: Outcome,
    flags: &'static [Flag],
    count: u32,
}

fn row(ts: OffsetDateTime, session: &'static str, action: Action, target: &str) -> Row {
    Row {
        ts,
        tool: "cli_agent",
        session,
        parent: None,
        pid: 41_000,
        process: "/bin/cat",
        category: Category::File,
        action,
        target: target.to_string(),
        outcome: Outcome::Allowed,
        flags: &[],
        count: 1,
    }
}

fn rows() -> Vec<Row> {
    let w44 = datetime!(2026-10-27 09:00 UTC);
    let w45 = datetime!(2026-11-03 09:00 UTC);
    let w46 = datetime!(2026-11-11 09:00 UTC);
    let w47 = datetime!(2026-11-17 09:00 UTC);
    let src = |n: &str| format!("{PROJECT}/src/{n}");
    let mut out = vec![
        row(w44, "s-old1", Action::Read, &src("old.rs")),
        row(w44, "s-old1", Action::Read, &src("older.rs")),
        row(w45, "s-a1", Action::Read, &src("lib.rs")),
        Row {
            outcome: Outcome::DeniedByUser,
            ..row(w45, "s-a1", Action::Write, &src("lib.rs"))
        },
        row(w46, "s-b1", Action::Read, &src("main.rs")),
        Row {
            flags: &[Flag::OutsideProject],
            count: 12,
            ..row(w46, "s-b1", Action::Read, "/Users/dev/.cargo/registry/src/index/pkg/lib.rs")
        },
        Row {
            process: "/usr/bin/curl",
            category: Category::Command,
            action: Action::Exec,
            flags: &[Flag::SecretPattern],
            target: "curl -H \"Authorization: Bearer ghp_0123456789abcdefghij0123456789abcdef\" https://api.example.test/v1".into(),
            ..row(w46, "s-b1", Action::Exec, "")
        },
        // A session delegated from s-b1 to another tool.
        Row {
            tool: "desktop_assistant",
            parent: Some("s-b1"),
            pid: 41_100,
            ..row(w46 + time::Duration::minutes(5), "s-b2", Action::Read, &src("README.md"))
        },
        Row {
            tool: "desktop_assistant",
            parent: Some("s-b1"),
            pid: 41_100,
            flags: &[Flag::OutsideProject],
            ..row(w46 + time::Duration::minutes(6), "s-b2", Action::Write, "/Users/dev/notes/todo.md")
        },
        row(w47, "s-c1", Action::Read, &src("main.rs")),
        Row {
            flags: &[Flag::ToolInternal],
            count: 40,
            ..row(w47, "s-c1", Action::Read, "/Users/dev/.cli-agent/state.json")
        },
        Row {
            process: "/usr/bin/curl",
            category: Category::NetworkExternal,
            action: Action::Connect,
            flags: &[Flag::UnknownHost],
            ..row(w47 + time::Duration::minutes(1), "s-c1", Action::Connect, "203.0.113.7:443")
        },
        Row {
            outcome: Outcome::DeniedByOs,
            ..row(w47 + time::Duration::minutes(2), "s-c1", Action::Read, "/Users/dev/locked.txt")
        },
    ];
    // Plain reads so the active segment has more than a handful of rows.
    for i in 0..20 {
        out.push(row(
            w47 + time::Duration::minutes(10 + i),
            "s-c1",
            Action::Read,
            &src(&format!("mod{i}.rs")),
        ));
    }
    out
}

fn main() {
    let dir = std::env::args().nth(1).expect("usage: fixture <folder>");
    let limits = Limits {
        max_age_days: 14,
        ..Limits::default()
    };
    let mut writer = SegmentWriter::open(&dir, limits, Box::new(PlentyOfSpace)).unwrap();
    let redactor = Redactor::with_default_detectors().unwrap();
    for (i, r) in rows().into_iter().enumerate() {
        let event = NewEvent {
            ts: r.ts + time::Duration::seconds(i64::try_from(i).unwrap()),
            tool: r.tool.into(),
            session_id: Some(r.session.into()),
            parent_session_id: r.parent.map(Into::into),
            pid: r.pid,
            process_path: r.process.into(),
            category: r.category,
            action: r.action,
            target: r.target,
            outcome: r.outcome,
            size_bytes: (r.category == Category::File).then_some(1024),
            bytes_out: (r.category == Category::NetworkExternal).then_some(5_000),
            bytes_in: (r.category == Category::NetworkExternal).then_some(20_000),
            project: Some(PROJECT.into()),
            flags: r.flags.iter().copied().collect::<BTreeSet<_>>(),
            count: r.count,
            sources: BTreeSet::from([Source::Os]),
            agent: None,
        };
        let record = EventRecord::new(event, &redactor).unwrap();
        let at = record.ts_us();
        assert_eq!(writer.append(&record, at).unwrap(), Written::Row);
    }
    writer
        .finish(
            i64::try_from(datetime!(2026-11-18 00:00 UTC).unix_timestamp_nanos() / 1_000).unwrap(),
        )
        .unwrap();
    println!("{dir}");
}
