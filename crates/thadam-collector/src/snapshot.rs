//! Process-table snapshot at collector start (ADR-003 Decision 4).
//!
//! Without it, processes that started before the collector have no known ancestry: in
//! Phase 0 a test binary's chain ended at a build tool whose parent never produced an event.
//!
//! ORDERING: the snapshot must be taken AFTER the OS event source is running, with its
//! output buffered until the snapshot is applied (see `run.rs`). Otherwise a process that
//! starts between the snapshot and the first event is missed.

use std::collections::HashMap;
use std::process::Command;

use crate::registry::{Registry, ToolId};
use crate::source::Identity;

/// One row of the process table. `argv0` is what the process calls itself, which is not a
/// trustworthy path; it is used only to skip the OS's own binaries cheaply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcEntry {
    pub pid: u32,
    pub ppid: u32,
    pub argv0: String,
}

/// Where the snapshot reads the process table from.
pub trait ProcessTable: Sync {
    fn list(&self) -> Result<Vec<ProcEntry>, SnapshotError>;
    /// Executable path and code-signing identity of the running code.
    fn identity(&self, pid: u32) -> Option<(String, Identity)>;
    fn cwd(&self, pid: u32) -> Option<String>;
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("cannot list processes: {0}")]
    List(String),
}

/// A session root found in the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRoot {
    pub pid: u32,
    pub tool: ToolId,
    pub cwd: Option<String>,
}

/// Running AI tool processes at start. `members` maps every member pid (roots included) to
/// the pid of its nearest registered ancestor (itself for a root); `parents` holds each
/// member's parent pid. Roots are ordered ancestors first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub roots: Vec<SnapshotRoot>,
    pub members: HashMap<u32, u32>,
    pub parents: HashMap<u32, u32>,
}

/// argv[0] prefixes of the OS's own binaries, which can't be registered tools.
const OS_PREFIXES: &[&str] = &["/System/", "/usr/", "/bin/", "/sbin/"];

/// Parallel identity lookups. About 11 ms each, measured 14 Nov 2026 (100 lookups, 1.08 s);
/// four workers is an estimate that keeps start-up under a second for ~100 candidates.
const WORKERS: usize = 4;

/// Longest ancestor chain followed, so a corrupt table with a cycle can't loop forever.
const MAX_DEPTH: usize = 512;

fn is_os_binary(argv0: &str) -> bool {
    !argv0.starts_with("/usr/local/") && OS_PREFIXES.iter().any(|p| argv0.starts_with(p))
}

/// Finds the running tool processes and their descendants.
pub fn take(table: &dyn ProcessTable, registry: &Registry) -> Result<Snapshot, SnapshotError> {
    let entries = table.list()?;
    let parent: HashMap<u32, u32> = entries.iter().map(|e| (e.pid, e.ppid)).collect();
    let candidates: Vec<u32> = entries
        .iter()
        .filter(|e| e.pid != 0 && !is_os_binary(&e.argv0))
        .map(|e| e.pid)
        .collect();

    let tools = lookup_tools(table, registry, &candidates);

    // Nearest registered ancestor (itself included) for each process.
    let mut members = HashMap::new();
    let mut root_set: HashMap<u32, ToolId> = HashMap::new();
    for e in &entries {
        let mut pid = e.pid;
        for _ in 0..MAX_DEPTH {
            if let Some(tool) = tools.get(&pid) {
                members.insert(e.pid, pid);
                root_set.insert(pid, *tool);
                break;
            }
            match parent.get(&pid) {
                Some(&p) if p != pid && p != 0 => pid = p,
                _ => break,
            }
        }
    }

    let depth = |mut pid: u32| {
        let mut d = 0usize;
        while let Some(&p) = parent.get(&pid) {
            if p == pid || p == 0 || d >= MAX_DEPTH {
                break;
            }
            pid = p;
            d += 1;
        }
        d
    };
    let mut roots: Vec<SnapshotRoot> = root_set
        .into_iter()
        .map(|(pid, tool)| SnapshotRoot {
            pid,
            tool,
            cwd: table.cwd(pid),
        })
        .collect();
    roots.sort_by_key(|r| (depth(r.pid), r.pid));
    let parents = members
        .keys()
        .filter_map(|pid| parent.get(pid).map(|p| (*pid, *p)))
        .collect();
    Ok(Snapshot {
        roots,
        members,
        parents,
    })
}

fn lookup_tools(
    table: &dyn ProcessTable,
    registry: &Registry,
    candidates: &[u32],
) -> HashMap<u32, ToolId> {
    if candidates.is_empty() {
        return HashMap::new();
    }
    let chunk = candidates.len().div_ceil(WORKERS);
    std::thread::scope(|scope| {
        let handles: Vec<_> = candidates
            .chunks(chunk)
            .map(|pids| {
                scope.spawn(move || {
                    pids.iter()
                        .filter_map(|&pid| {
                            let (exe, identity) = table.identity(pid)?;
                            registry.match_identity(&exe, &identity).map(|t| (pid, t))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .filter_map(|h| h.join().ok())
            .flatten()
            .collect()
    })
}

/// The real process table, read with the OS's own tools. No shell is involved: absolute
/// paths and argument arrays only, so nothing in a process name can become a command.
/// Their output is parsed here and never logged.
pub struct SystemProcessTable;

impl ProcessTable for SystemProcessTable {
    fn list(&self) -> Result<Vec<ProcEntry>, SnapshotError> {
        let out = Command::new("/bin/ps")
            .args(["-axww", "-o", "pid=,ppid=,comm="])
            .output()
            .map_err(|e| SnapshotError::List(e.to_string()))?;
        if !out.status.success() {
            return Err(SnapshotError::List(format!(
                "ps exited with {}",
                out.status
            )));
        }
        Ok(parse_ps(&String::from_utf8_lossy(&out.stdout)))
    }

    fn identity(&self, pid: u32) -> Option<(String, Identity)> {
        // codesign reads the running code's signature, not the file on disk.
        let out = Command::new("/usr/bin/codesign")
            .args(["-dv", "--verbose=2", &pid.to_string()])
            .output()
            .ok()?;
        parse_codesign(&String::from_utf8_lossy(&out.stderr))
    }

    fn cwd(&self, pid: u32) -> Option<String> {
        let out = Command::new("/usr/sbin/lsof")
            .args(["-a", "-p", &pid.to_string(), "-d", "cwd", "-Fn"])
            .output()
            .ok()?;
        parse_lsof_cwd(&String::from_utf8_lossy(&out.stdout))
    }
}

/// Parses `ps -o pid=,ppid=,comm=` output. argv[0] may contain spaces.
pub fn parse_ps(text: &str) -> Vec<ProcEntry> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, rest) = line.split_once(char::is_whitespace)?;
            let rest = rest.trim_start();
            let (ppid, argv0) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            Some(ProcEntry {
                pid: pid.parse().ok()?,
                ppid: ppid.parse().ok()?,
                argv0: argv0.trim().to_string(),
            })
        })
        .collect()
}

/// Parses `codesign -dv` output (written to stderr).
pub fn parse_codesign(text: &str) -> Option<(String, Identity)> {
    let mut executable = None;
    let mut identity = Identity::default();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Executable=") {
            executable = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("Identifier=") {
            identity.signing_id = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("TeamIdentifier=") {
            if v != "not set" && !v.is_empty() {
                identity.team_id = Some(v.to_string());
            }
        } else if line.starts_with("Platform identifier=") {
            identity.platform = true;
        }
    }
    Some((executable?, identity))
}

/// Parses `lsof -Fn` output: the `n` line holds the path.
pub fn parse_lsof_cwd(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix('n'))
        .filter(|p| p.starts_with('/'))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic table: pid -> (ppid, argv0, identity, cwd).
    type Row = (
        u32,
        u32,
        &'static str,
        Option<Identity>,
        Option<&'static str>,
    );
    struct Fake(Vec<Row>);

    impl ProcessTable for Fake {
        fn list(&self) -> Result<Vec<ProcEntry>, SnapshotError> {
            Ok(self
                .0
                .iter()
                .map(|(pid, ppid, argv0, _, _)| ProcEntry {
                    pid: *pid,
                    ppid: *ppid,
                    argv0: (*argv0).to_string(),
                })
                .collect())
        }
        fn identity(&self, pid: u32) -> Option<(String, Identity)> {
            let row = self.0.iter().find(|r| r.0 == pid)?;
            assert!(!is_os_binary(row.2), "OS binaries must not be looked up");
            row.3.clone().map(|id| (row.2.to_string(), id))
        }
        fn cwd(&self, pid: u32) -> Option<String> {
            self.0
                .iter()
                .find(|r| r.0 == pid)
                .and_then(|r| r.4)
                .map(str::to_string)
        }
    }

    fn agent() -> Option<Identity> {
        Some(Identity {
            team_id: Some("TEAM000001".into()),
            signing_id: Some("com.example.cli-agent".into()),
            platform: false,
        })
    }

    fn other() -> Option<Identity> {
        Some(Identity {
            team_id: Some("TEAM000009".into()),
            signing_id: Some("com.example.terminal".into()),
            platform: false,
        })
    }

    fn registry() -> Registry {
        Registry::parse(
            r#"{"version":1,"tools":[{"key":"cli_agent","match":[{"team_id":"TEAM000001","signing_id":"com.example.cli-agent"}]}]}"#,
        )
        .unwrap()
    }

    #[test]
    fn pre_existing_build_chain_is_attributed() {
        // terminal -> shell -> agent (version-named binary) -> build tool -> test binary
        let table = Fake(vec![
            (1, 0, "/sbin/launchd", None, None),
            (
                100,
                1,
                "/Applications/Term.app/Contents/MacOS/Term",
                other(),
                None,
            ),
            (200, 100, "-zsh", None, None),
            (
                300,
                200,
                "agent",
                agent(),
                Some("/Users/test/projects/demo"),
            ),
            (400, 300, "/Users/test/.cargo/bin/cargo", None, None),
            (
                500,
                400,
                "/Users/test/projects/demo/target/debug/deps/demo-1a2b",
                None,
                None,
            ),
            (
                600,
                1,
                "/Applications/Other.app/Contents/MacOS/Other",
                other(),
                None,
            ),
        ]);
        let snap = take(&table, &registry()).unwrap();
        assert_eq!(snap.roots.len(), 1);
        assert_eq!(snap.roots[0].pid, 300);
        assert_eq!(
            snap.roots[0].cwd.as_deref(),
            Some("/Users/test/projects/demo")
        );
        for pid in [300, 400, 500] {
            assert_eq!(snap.members.get(&pid), Some(&300), "pid {pid}");
        }
        for pid in [1, 100, 200, 600] {
            assert!(!snap.members.contains_key(&pid), "pid {pid}");
        }
    }

    #[test]
    fn nested_roots_are_ordered_ancestors_first() {
        let table = Fake(vec![
            (10, 1, "agent", agent(), None),
            (20, 10, "agent", agent(), None),
            (30, 20, "child", None, None),
        ]);
        let snap = take(&table, &registry()).unwrap();
        let order: Vec<u32> = snap.roots.iter().map(|r| r.pid).collect();
        assert_eq!(order, vec![10, 20]);
        assert_eq!(snap.members.get(&30), Some(&20));
    }

    #[test]
    fn a_parent_cycle_does_not_hang() {
        let table = Fake(vec![(7, 8, "a", None, None), (8, 7, "b", None, None)]);
        let snap = take(&table, &registry()).unwrap();
        assert!(snap.members.is_empty());
    }

    #[test]
    fn parses_tool_output() {
        let ps = "    1     0 /sbin/launchd\n  412     1 /Applications/Sample App.app/Contents/MacOS/Sample App\n  bad line\n";
        let rows = parse_ps(ps);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[1].argv0,
            "/Applications/Sample App.app/Contents/MacOS/Sample App"
        );

        let cs = "Executable=/Users/test/.local/bin/agent-2.4.1\nIdentifier=com.example.cli-agent\nFormat=Mach-O thin (arm64)\nTeamIdentifier=TEAM000001\n";
        let (exe, id) = parse_codesign(cs).unwrap();
        assert_eq!(exe, "/Users/test/.local/bin/agent-2.4.1");
        assert_eq!(id.team_id.as_deref(), Some("TEAM000001"));
        assert!(!id.platform);
        let adhoc = "Executable=/x\nIdentifier=x-55aa\nTeamIdentifier=not set\n";
        assert_eq!(parse_codesign(adhoc).unwrap().1.team_id, None);
        let platform = "Executable=/bin/zsh\nIdentifier=com.apple.zsh\nPlatform identifier=16\n";
        assert!(parse_codesign(platform).unwrap().1.platform);
        assert!(parse_codesign("code object is not signed at all\n").is_none());

        assert_eq!(
            parse_lsof_cwd("p300\nfcwd\nn/Users/test/projects/demo\n").as_deref(),
            Some("/Users/test/projects/demo")
        );
        assert_eq!(parse_lsof_cwd(""), None);
    }
}
