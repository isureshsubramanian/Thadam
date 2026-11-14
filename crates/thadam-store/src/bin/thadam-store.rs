//! `thadam-store verify <db>`: walks the hash chain and reports the first break.
//! Exit codes: 0 chain intact, 1 chain broken, 2 usage or I/O error.

use std::process::ExitCode;

use thadam_store::{ChainBreak, Store};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [cmd, path] = args.as_slice() else {
        eprintln!("usage: thadam-store verify <db>");
        return ExitCode::from(2);
    };
    if cmd != "verify" {
        eprintln!("usage: thadam-store verify <db>");
        return ExitCode::from(2);
    }
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
            let detail = match reason {
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
                    format!(
                        "chain broken at seq {seq}: stored hash {stored}, recomputed {computed}"
                    )
                }
                ChainBreak::Unreadable { seq } => format!("row at seq {seq} is unreadable"),
            };
            println!("FAIL  {detail}");
            println!(
                "      {} rows verified before the break; {} rows not trusted",
                report.verified,
                report.total.saturating_sub(report.verified)
            );
            ExitCode::from(1)
        }
    }
}
