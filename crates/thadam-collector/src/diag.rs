//! Diagnostics: stderr, or a log file that rotates by size (ADR-010 Decision 6).
//!
//! Lines hold counts and errors only, never paths, hosts, command lines or values. Under
//! launchd the process never restarts on its own, so the file is rotated here: a rename-based
//! rotator outside the process would leave the open handle writing to the renamed file.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use time::OffsetDateTime;

/// Rotate at about 1 MB (estimate: about 2.5 days of stats lines at 390 KB/day, ADR-010).
pub const MAX_BYTES: u64 = 1_000_000;
/// Rotated files kept besides the current one.
pub const KEEP: usize = 5;

/// Where diagnostics go. `None` until `to_file` succeeds: stderr.
static SINK: Mutex<Option<RotatingLog>> = Mutex::new(None);

/// Writes one diagnostic line.
#[macro_export]
macro_rules! diag {
    ($($arg:tt)*) => { $crate::diag::line(&format!($($arg)*)) };
}

/// Sends every later line to `path` instead of stderr.
///
/// ORDERING: call only after the store's writer lock is held (ADR-010 Decision 4). A second
/// collector that is refused the store then never opens, writes or rotates this file.
pub fn to_file(path: &Path) -> io::Result<()> {
    let log = RotatingLog::open(path, MAX_BYTES, KEEP)?;
    if let Ok(mut sink) = SINK.lock() {
        *sink = Some(log);
    }
    Ok(())
}

pub fn line(msg: &str) {
    if let Ok(mut sink) = SINK.lock()
        && let Some(log) = sink.as_mut()
        && log.write_line(&format!("{} {msg}", stamp())).is_ok()
    {
        return;
    }
    // No log file, or it failed: stderr still reaches launchd's file or the terminal.
    eprintln!("{msg}");
}

/// UTC, to the second.
fn stamp() -> String {
    let t = OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// A log file that is renamed to `.1` (and older ones shifted up to `.<keep>`, the oldest
/// removed) before a line would take it past `max_bytes`.
pub struct RotatingLog {
    path: PathBuf,
    max_bytes: u64,
    keep: usize,
    file: File,
    size: u64,
}

impl RotatingLog {
    /// Opens `path` for appending (0644; its folder 0755 if missing).
    pub fn open(path: &Path, max_bytes: u64, keep: usize) -> io::Result<Self> {
        if let Some(dir) = path.parent() {
            DirBuilder::new().recursive(true).mode(0o755).create(dir)?;
        }
        let file = append(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            max_bytes,
            keep,
            file,
            size,
        })
    }

    pub fn write_line(&mut self, text: &str) -> io::Result<()> {
        let len = u64::try_from(text.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if self.size > 0 && self.size.saturating_add(len) > self.max_bytes {
            self.rotate()?;
        }
        writeln!(self.file, "{text}")?;
        self.size = self.size.saturating_add(len);
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        let numbered = |n: usize| {
            let mut name = self.path.clone().into_os_string();
            name.push(format!(".{n}"));
            PathBuf::from(name)
        };
        match fs::remove_file(numbered(self.keep)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        for n in (1..self.keep).rev() {
            let from = numbered(n);
            if from.exists() {
                fs::rename(&from, numbered(n + 1))?;
            }
        }
        fs::rename(&self.path, numbered(1))?;
        self.file = append(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

fn append(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o644)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("thadam-diag-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn rotates_at_the_limit_and_keeps_only_the_newest() {
        let dir = temp("rotate");
        let path = dir.join("collector.log");
        // 10-byte lines (9 characters + newline), at most 30 bytes per file.
        let mut log = RotatingLog::open(&path, 30, 2).unwrap();
        for i in 0..10 {
            log.write_line(&format!("line {i:04}")).unwrap();
        }
        assert_eq!(
            files(&dir),
            ["collector.log", "collector.log.1", "collector.log.2"]
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "line 0009\n");
        assert_eq!(
            fs::read_to_string(dir.join("collector.log.1")).unwrap(),
            "line 0006\nline 0007\nline 0008\n"
        );
        assert_eq!(
            fs::read_to_string(dir.join("collector.log.2")).unwrap(),
            "line 0003\nline 0004\nline 0005\n"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reopening_appends_and_counts_the_existing_size() {
        let dir = temp("reopen");
        let path = dir.join("collector.log");
        RotatingLog::open(&path, 30, 2)
            .unwrap()
            .write_line("line 0001")
            .unwrap();
        let mut log = RotatingLog::open(&path, 30, 2).unwrap();
        log.write_line("line 0002").unwrap();
        log.write_line("line 0003").unwrap();
        log.write_line("line 0004").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "line 0004\n");
        assert_eq!(
            fs::read_to_string(dir.join("collector.log.1")).unwrap(),
            "line 0001\nline 0002\nline 0003\n"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
