//! Writes a large synthetic store folder for the API's search benchmark (ADR-008
//! acceptance test 6). Not shipped. All data is synthetic and deterministic.
//!
//!   cargo run --release -p thadam-store --example bench_store -- <empty folder> [rows]
//!
//! Default 5,000,000 rows spread over the 28 days before now, two tools, five projects:
//! 80% file rows (5% of them outside the project), 10% commands, 10% network flows.
// An example, not library code: unwrap/expect are allowed here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::time::Instant;

use thadam_core::{Action, Category, EventRecord, Flag, NewEvent, Outcome, Redactor, Source};
use thadam_store::{DiskSpace, Limits, SegmentWriter, Written};
use time::{Duration, OffsetDateTime};

struct PlentyOfSpace;

impl DiskSpace for PlentyOfSpace {
    fn free_bytes(&self, _dir: &Path) -> io::Result<u64> {
        Ok(500_000_000_000)
    }
}

/// A small deterministic generator (xorshift64*), so runs are repeatable without a crate.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const HOSTS: &[&str] = &[
    "api.example-agent.test:443",
    "crates.example.test:443",
    "github.example.test:443",
    "203.0.113.7:443",
];

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("usage: bench_store <folder> [rows]");
    let rows: u64 = args.next().map_or(5_000_000, |s| s.parse().unwrap());
    let now = OffsetDateTime::now_utc();
    let start = now - Duration::days(28);
    let step_us = (28 * 86_400_000_000_i64) / i64::try_from(rows).unwrap();
    let mut writer = SegmentWriter::open(&dir, Limits::default(), Box::new(PlentyOfSpace)).unwrap();
    let redactor = Redactor::with_default_detectors().unwrap();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let began = Instant::now();

    for i in 0..rows {
        let ts = start + Duration::microseconds(step_us * i64::try_from(i).unwrap());
        let tool = if rng.below(10) < 6 {
            "cli_agent"
        } else {
            "desktop_assistant"
        };
        let project_n = rng.below(5);
        let project = format!("/Users/dev/projects/project-{project_n}");
        let session = format!("s-{}-{}", project_n, i / 2_000);
        let kind = rng.below(10);
        let mut flags = BTreeSet::new();
        let (category, action, target, process) = match kind {
            0 => (
                Category::Command,
                Action::Exec,
                format!("cargo test -p crate{} --release", rng.below(50)),
                "/usr/bin/cargo",
            ),
            1 => {
                let host = HOSTS[usize::try_from(rng.below(4)).unwrap()];
                if host.starts_with("203.") {
                    flags.insert(Flag::UnknownHost);
                }
                (
                    Category::NetworkExternal,
                    Action::Connect,
                    host.to_string(),
                    "/usr/bin/curl",
                )
            }
            _ if rng.below(20) == 0 => {
                flags.insert(Flag::OutsideProject);
                (
                    Category::File,
                    Action::Read,
                    format!(
                        "/Users/dev/.cargo/registry/src/index/pkg{}/src/lib.rs",
                        rng.below(500)
                    ),
                    "/bin/cat",
                )
            }
            _ => (
                Category::File,
                if rng.below(5) == 0 {
                    Action::Write
                } else {
                    Action::Read
                },
                format!(
                    "{project}/src/module{}/file{}.rs",
                    rng.below(200),
                    rng.below(1_000)
                ),
                "/bin/cat",
            ),
        };
        let network = category == Category::NetworkExternal;
        let event = NewEvent {
            ts,
            tool: tool.into(),
            session_id: Some(session),
            parent_session_id: None,
            pid: 40_000 + u32::try_from(rng.below(1_000)).unwrap(),
            process_path: process.into(),
            category,
            action,
            target,
            outcome: Outcome::Allowed,
            size_bytes: (category == Category::File).then_some(4_096),
            bytes_out: network.then(|| i64::try_from(rng.below(100_000)).unwrap()),
            bytes_in: network.then(|| i64::try_from(rng.below(1_000_000)).unwrap()),
            project: Some(project),
            flags,
            count: 1,
            sources: BTreeSet::from([Source::Os]),
            agent: None,
        };
        let record = EventRecord::new(event, &redactor).unwrap();
        let at = record.ts_us();
        assert_eq!(writer.append(&record, at).unwrap(), Written::Row);
        if (i + 1) % 1_000_000 == 0 {
            eprintln!(
                "bench_store: {} rows, {:.0} s",
                i + 1,
                began.elapsed().as_secs_f64()
            );
        }
    }
    let end = i64::try_from(now.unix_timestamp_nanos() / 1_000).unwrap();
    writer.finish(end).unwrap();
    println!("{dir}");
}
