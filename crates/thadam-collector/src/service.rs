//! The collector as a launch daemon (ADR-010): the installed binary's place, the launchd job,
//! and the checks `install` makes before a root daemon may run a file.

use std::fmt::Write as _;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub const LABEL: &str = "com.nerttiyana.thadam.collector";
/// Root-owned, beside the store and registry (Decision 1).
pub const BIN_DIR: &str = "/Library/Application Support/Thadam/bin";
pub const BIN: &str = "/Library/Application Support/Thadam/bin/thadam-collector";
pub const PLIST: &str = "/Library/LaunchDaemons/com.nerttiyana.thadam.collector.plist";
pub const LOG: &str = "/Library/Logs/Thadam/collector.log";
pub const DEFAULT_REGISTRY: &str = "/Library/Application Support/Thadam/registry.json";
pub const DEFAULT_STORE: &str = "/Library/Application Support/Thadam/store";

/// The launchd job (Decision 2). Always kept alive: only `launchctl bootout` stops it.
/// stderr goes to the log too: launchd reopens it at each start, so errors from before the
/// collector opens its own log (a bad registry, say) are not lost.
pub fn plist(bin: &str, registry: &str, store: &str, log: &str) -> String {
    let mut args = String::new();
    for a in [
        bin,
        "run",
        "--registry",
        registry,
        "--store",
        store,
        "--log",
        log,
    ] {
        let _ = writeln!(args, "    <string>{}</string>", xml(a));
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{args}  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#,
        label = LABEL,
        log = xml(log),
    )
}

fn xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Every folder from `dir` up to `/` must be owned by `owner` and not writable by group or
/// others, or another account could swap the binary a root daemon runs (Decision 1).
/// Returns the first folder that fails.
pub fn unsafe_folder(dir: &Path, owner: u32) -> std::io::Result<Option<String>> {
    for folder in dir.ancestors() {
        let meta = std::fs::metadata(folder)?;
        // Sticky folders like /tmp are world-writable by design; they are refused too.
        if meta.uid() != owner || meta.mode() & 0o022 != 0 {
            return Ok(Some(folder.display().to_string()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("thadam-service-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        dir
    }

    #[test]
    fn the_job_runs_the_installed_binary_and_escapes_paths() {
        let p = plist(
            "/synthetic/bin/thadam-collector",
            "/synthetic/r & <x>.json",
            "/synthetic/store",
            "/synthetic/c.log",
        );
        assert!(p.contains("<string>/synthetic/r &amp; &lt;x&gt;.json</string>"));
        assert!(p.contains("<key>KeepAlive</key>\n  <true/>"));
        let args: Vec<&str> = p
            .lines()
            .skip_while(|l| !l.contains("<array>"))
            .skip(1)
            .take_while(|l| !l.contains("</array>"))
            .map(|l| {
                l.trim()
                    .trim_start_matches("<string>")
                    .trim_end_matches("</string>")
            })
            .collect();
        assert_eq!(
            args,
            [
                "/synthetic/bin/thadam-collector",
                "run",
                "--registry",
                "/synthetic/r &amp; &lt;x&gt;.json",
                "--store",
                "/synthetic/store",
                "--log",
                "/synthetic/c.log"
            ]
        );
    }

    #[test]
    fn the_job_is_a_valid_property_list() {
        if !Path::new("/usr/bin/plutil").exists() {
            return; // not macOS
        }
        let dir = temp("plist");
        let path = dir.join("job.plist");
        std::fs::write(&path, plist(BIN, DEFAULT_REGISTRY, DEFAULT_STORE, LOG)).unwrap();
        let status = std::process::Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&path)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_folder_others_can_write_is_refused() {
        let dir = temp("folders");
        let leaf = dir.join("a/b");
        let me = std::fs::metadata(&leaf).unwrap().uid();
        // Wrong owner for the whole path: the leaf is reported first.
        assert_eq!(
            unsafe_folder(&leaf, me + 1).unwrap(),
            Some(leaf.display().to_string())
        );
        std::fs::set_permissions(dir.join("a"), std::fs::Permissions::from_mode(0o775)).unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The leaf is fine; its group-writable parent is not.
        let found = unsafe_folder(&leaf, me).unwrap();
        assert_eq!(found, Some(dir.join("a").display().to_string()));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
