//! Free disk space (ADR-009 Decision 4). Read with the OS's own `df`, run directly with no
//! shell, because the workspace forbids `unsafe` (so no `statvfs` call) and this needs no new
//! dependency. Behind a trait so tests can fake a full disk.

use std::io;
use std::path::Path;
use std::process::Command;

pub trait DiskSpace: Send {
    /// Bytes available to the store's folder.
    fn free_bytes(&self, dir: &Path) -> io::Result<u64>;
}

/// The real disk, via `/bin/df -k -P`.
pub struct SystemDisk;

impl DiskSpace for SystemDisk {
    fn free_bytes(&self, dir: &Path) -> io::Result<u64> {
        let out = Command::new("/bin/df")
            .args(["-k", "-P"])
            .arg(dir)
            .output()?;
        if !out.status.success() {
            return Err(io::Error::other("df failed"));
        }
        parse_df(&String::from_utf8_lossy(&out.stdout))
            .ok_or_else(|| io::Error::other("unexpected df output"))
    }
}

/// The "Available" column (1 KiB blocks) of `df -k -P`'s second line, in bytes.
fn parse_df(text: &str) -> Option<u64> {
    let line = text.lines().nth(1)?;
    let kib: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
    kib.checked_mul(1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_posix_df_output() {
        let text = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                    /dev/disk3s5 1952640000 1400000000 513802240 74% /System/Volumes/Data\n";
        assert_eq!(parse_df(text), Some(513_802_240 * 1024));
        assert_eq!(parse_df("Filesystem\n"), None);
        assert_eq!(parse_df(""), None);
    }

    #[test]
    fn reads_this_machines_temp_folder() {
        assert!(SystemDisk.free_bytes(&std::env::temp_dir()).unwrap() > 0);
    }
}
