//! Which records may be rolled up, and under which folder (ADR-005).
//!
//! This module only decides eligibility. `collapse.rs` applies it: it merges Rule 1 rows
//! per folder and spends each process's read budget for Rule 2.

use thadam_core::{Action, Category, Flag, NewEvent};

use crate::registry::{Registry, under};
use crate::source::{EventKind, OsEvent};

/// How a record may be rolled up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rollup {
    /// Always its own row.
    Never,
    /// Rule 1: under this roll-up folder (no trailing `/`).
    Folder(String),
    /// Rule 2: a read that counts against its process's budget; once the budget is spent it
    /// is rolled up under this group folder (no trailing `/`).
    Budget(String),
}

/// Flags that keep a row individual: these are the rows the audit exists for (ADR-005
/// Decision 3). `secret_pattern` is checked by the pipeline, which holds the detectors.
const KEEP_FLAGS: &[Flag] = &[
    Flag::SensitivePath,
    Flag::OutsideProject,
    Flag::SecretPattern,
];

pub fn hint(event: &OsEvent, record: &NewEvent, registry: &Registry) -> Rollup {
    if record.category != Category::File || record.flags.iter().any(|f| KEEP_FLAGS.contains(f)) {
        return Rollup::Never;
    }
    // What the agent binaries themselves touch is primary evidence.
    if registry
        .match_identity(&event.process.executable, &event.process.identity)
        .is_some()
    {
        return Rollup::Never;
    }
    let project = record.project.as_deref();
    let paths: Vec<&str> = match &event.kind {
        EventKind::Rename { from, to } => vec![from, to],
        EventKind::Open { path, .. }
        | EventKind::Close { path, .. }
        | EventKind::Create { path }
        | EventKind::Unlink { path } => vec![path],
        _ => return Rollup::Never,
    };
    let folders: Vec<Option<String>> = paths
        .iter()
        .map(|p| rollup_folder(p, project, registry))
        .collect();
    match folders.as_slice() {
        [Some(f)] => return Rollup::Folder(f.clone()),
        [Some(a), Some(b)] if a == b => return Rollup::Folder(a.clone()),
        // A rename crossing a roll-up boundary stays individual.
        [_, _] => return Rollup::Never,
        _ => {}
    }
    match (record.action, paths.as_slice()) {
        (Action::Read, [path]) => Rollup::Budget(group_folder(path, project)),
        _ => Rollup::Never,
    }
}

/// The roll-up folder `path` lies in, if any: a listed prefix anywhere, or a folder with a
/// listed name inside the project.
pub fn rollup_folder(path: &str, project: Option<&str>, registry: &Registry) -> Option<String> {
    if let Some(prefix) = registry
        .rollup_paths()
        .iter()
        .find_map(|p| p.matched_prefix(path))
    {
        return Some(prefix.to_string());
    }
    let project = project?;
    let relative = path.strip_prefix(project)?.strip_prefix('/')?;
    let parts: Vec<&str> = relative.split('/').collect();
    // The last part is the file itself; only folders above it count.
    let folders = parts.len().saturating_sub(1);
    let names = registry.rollup_names();
    let i = parts[..folders]
        .iter()
        .position(|p| names.iter().any(|n| n == p))?;
    Some(format!("{project}/{}", parts[..=i].join("/")))
}

/// Where Rule 2 groups a read: the first folder below the project root, or the first two
/// folders of the path when it is outside the project.
pub fn group_folder(path: &str, project: Option<&str>) -> String {
    if let Some(project) = project.filter(|p| under(path, p) && path != *p) {
        let relative = path.get(project.len() + 1..).unwrap_or("");
        return match relative.split_once('/') {
            Some((top, _)) => format!("{project}/{top}"),
            None => project.to_string(),
        };
    }
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let keep = parts.len().saturating_sub(1).min(2);
    format!("/{}", parts[..keep].join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use thadam_core::{Outcome, Source};
    use time::macros::datetime;

    use crate::source::{Identity, ProcessRef};

    const PROJECT: &str = "/Users/test/projects/demo";

    fn registry() -> Registry {
        Registry::parse(
            r#"{"version":1,"tools":[{"key":"cli_agent","match":[{"team_id":"TEAM000001","signing_id":"com.example.cli-agent"}]}]}"#,
        )
        .unwrap()
    }

    fn event(exe: &str, kind: EventKind) -> OsEvent {
        OsEvent {
            ts: datetime!(2026-11-14 09:33:00 UTC),
            seq: 1,
            process: ProcessRef {
                pid: 4400,
                pidversion: 1,
                ppid: 300,
                responsible_pid: None,
                executable: exe.into(),
                identity: Identity::default(),
            },
            kind,
        }
    }

    fn record(action: Action, target: &str, flags: &[Flag]) -> NewEvent {
        NewEvent {
            ts: datetime!(2026-11-14 09:33:00 UTC),
            tool: "cli_agent".into(),
            session_id: Some("s1".into()),
            parent_session_id: None,
            pid: 4400,
            process_path: "/x/rustc".into(),
            category: Category::File,
            action,
            target: target.into(),
            outcome: Outcome::Allowed,
            size_bytes: None,
            bytes_out: None,
            bytes_in: None,
            project: Some(PROJECT.into()),
            flags: flags.iter().copied().collect(),
            count: 1,
            sources: BTreeSet::from([Source::Os]),
        }
    }

    fn create(path: &str) -> (OsEvent, NewEvent) {
        (
            event("/x/rustc", EventKind::Create { path: path.into() }),
            record(Action::Create, path, &[]),
        )
    }

    fn read(path: &str) -> (OsEvent, NewEvent) {
        let kind = EventKind::Open {
            path: path.into(),
            readable: true,
            size: None,
        };
        (event("/usr/bin/git", kind), record(Action::Read, path, &[]))
    }

    #[test]
    fn build_output_in_the_project_rolls_up_by_folder() {
        let r = registry();
        let (e, rec) = create("/Users/test/projects/demo/target/debug/deps/a.o");
        assert_eq!(
            hint(&e, &rec, &r),
            Rollup::Folder("/Users/test/projects/demo/target".into())
        );
        // Nested project folder: the first matching name wins.
        let (e, rec) = create("/Users/test/projects/demo/web/node_modules/x/index.js");
        assert_eq!(
            hint(&e, &rec, &r),
            Rollup::Folder("/Users/test/projects/demo/web/node_modules".into())
        );
        // A file named like the folder is not a folder.
        let (e, rec) = create("/Users/test/projects/demo/src/target");
        assert_eq!(hint(&e, &rec, &r), Rollup::Never);
    }

    #[test]
    fn cache_prefixes_roll_up_anywhere_but_names_only_inside_the_project() {
        let r = registry();
        let (e, mut rec) = read("/Users/test/.cargo/registry/src/x/lib.rs");
        rec.project = None;
        assert_eq!(
            hint(&e, &rec, &r),
            Rollup::Folder("/Users/test/.cargo/registry".into())
        );
        assert_eq!(
            rollup_folder("/Users/test/other/target/a.o", Some(PROJECT), &r),
            None
        );
    }

    #[test]
    fn flagged_rows_commands_and_agent_processes_stay_individual() {
        let r = registry();
        let path = "/Users/test/projects/demo/target/.env";
        let flagged = record(Action::Read, path, &[Flag::SensitivePath]);
        let (e, _) = read(path);
        assert_eq!(hint(&e, &flagged, &r), Rollup::Never);

        let mut exec = record(Action::Exec, "cargo build", &[]);
        exec.category = Category::Command;
        assert_eq!(hint(&e, &exec, &r), Rollup::Never);

        let (mut agent_event, rec) = create("/Users/test/projects/demo/target/a.o");
        agent_event.process.identity = Identity {
            team_id: Some("TEAM000001".into()),
            signing_id: Some("com.example.cli-agent".into()),
            platform: false,
        };
        assert_eq!(hint(&agent_event, &rec, &r), Rollup::Never);
    }

    #[test]
    fn renames_roll_up_only_within_one_folder() {
        let r = registry();
        let inside = event(
            "/x/rustc",
            EventKind::Rename {
                from: format!("{PROJECT}/target/a.tmp"),
                to: format!("{PROJECT}/target/a.o"),
            },
        );
        let rec = record(Action::Rename, "", &[]);
        assert_eq!(
            hint(&inside, &rec, &r),
            Rollup::Folder(format!("{PROJECT}/target"))
        );
        let crossing = event(
            "/x/rustc",
            EventKind::Rename {
                from: format!("{PROJECT}/target/a.o"),
                to: format!("{PROJECT}/src/a.o"),
            },
        );
        assert_eq!(hint(&crossing, &rec, &r), Rollup::Never);
    }

    #[test]
    fn other_reads_count_against_the_budget_and_writes_never_do() {
        let r = registry();
        let (e, rec) = read("/Users/test/projects/demo/src/deep/main.rs");
        assert_eq!(
            hint(&e, &rec, &r),
            Rollup::Budget("/Users/test/projects/demo/src".into())
        );
        let write = record(Action::Write, "/Users/test/projects/demo/src/main.rs", &[]);
        let we = event(
            "/x/rustfmt",
            EventKind::Close {
                path: "/Users/test/projects/demo/src/main.rs".into(),
                modified: true,
                size: None,
            },
        );
        assert_eq!(hint(&we, &write, &r), Rollup::Never);
    }

    #[test]
    fn group_folders() {
        assert_eq!(
            group_folder(&format!("{PROJECT}/README.md"), Some(PROJECT)),
            PROJECT
        );
        assert_eq!(
            group_folder(&format!("{PROJECT}/src/a/b.rs"), Some(PROJECT)),
            format!("{PROJECT}/src")
        );
        assert_eq!(
            group_folder("/System/Library/Frameworks/X.framework/X", Some(PROJECT)),
            "/System/Library"
        );
        assert_eq!(group_folder("/dev/null", None), "/dev");
        assert_eq!(group_folder("/a", None), "/");
    }
}
