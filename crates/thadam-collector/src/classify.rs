//! Turns an OS event from a tool's process tree into a record (ADR-003 Decision 7).

use std::collections::BTreeSet;

use thadam_core::{Action, Category, ExecObservation, Flag, NewEvent, Outcome, Source};

use crate::registry::{PathPattern, Registry, Tool, home_relative, under};
use crate::source::{EventKind, OsEvent};
use crate::tree::Membership;

/// Prefixes never flagged as outside the project: the OS, temporary folders and devices.
/// Recorded, just not flagged. An estimate of what reads as noise, to tune by replay.
const NOT_OUTSIDE: &[&str] = &[
    "/System/",
    "/usr/",
    "/bin/",
    "/sbin/",
    "/Library/Apple/",
    "/private/var/db/",
    "/dev/",
    "/private/tmp/",
    "/private/var/folders/",
];

/// Folders under a home folder that hold credentials.
const SENSITIVE_HOME_DIRS: &[&str] = &[".ssh", ".gnupg", "Library/Keychains", ".netrc"];
const SENSITIVE_EXTENSIONS: &[&str] = &["pem", "p12", "key"];
const SENSITIVE_NAME_PREFIXES: &[&str] = &["id_rsa", "id_ed25519"];

/// `launchctl` subcommands that start a job outside the caller's process tree (ADR-015
/// Decision 3). `list`, `print` and the like only read.
const LAUNCHCTL_STARTS: &[&str] = &["submit", "load", "bootstrap", "kickstart", "asuser"];
/// Programs whose every run hands work to another process or a later time.
const ALWAYS_HAND_OFF: &[&str] = &["osascript", "crontab", "at"];
/// Folders whose property lists launchd starts by itself.
const LAUNCH_FOLDERS: &[&str] = &["/Library/LaunchAgents/", "/Library/LaunchDaemons/"];
const HOME_LAUNCH_FOLDER: &str = "Library/LaunchAgents/";

/// The record for an event, or `None` for events that only update the tree.
pub fn classify(event: &OsEvent, member: &Membership, registry: &Registry) -> Option<NewEvent> {
    let tool = registry.tool(member.tool)?;
    let (category, action, target, size, process_path, paths) = match &event.kind {
        EventKind::Exec { target, args, cwd } => {
            let line = ExecObservation {
                executable: target.executable.clone(),
                args: args.clone(),
                cwd: cwd.clone(),
                // The source never reads the environment; nothing to drop here.
                env: Vec::new(),
            }
            .into_command_line();
            (
                Category::Command,
                Action::Exec,
                line,
                None,
                target.executable.clone(),
                vec![],
            )
        }
        // A write open becomes a row only if it is refused (ADR-006); a successful write is
        // recorded from its close.
        EventKind::Open {
            path,
            readable,
            writable,
            size,
        } if *readable || *writable => {
            let action = if *readable {
                Action::Read
            } else {
                Action::Write
            };
            file(action, path, *size, event)
        }
        EventKind::Close {
            path,
            modified: true,
            size,
        } => file(Action::Write, path, *size, event),
        EventKind::Create { path } => file(Action::Create, path, None, event),
        EventKind::Unlink { path } => file(Action::Delete, path, None, event),
        EventKind::Rename { from, to } => (
            Category::File,
            Action::Rename,
            format!("{from} -> {to}"),
            None,
            event.process.executable.clone(),
            vec![from.clone(), to.clone()],
        ),
        EventKind::Open { .. }
        | EventKind::Close { .. }
        | EventKind::Fork { .. }
        | EventKind::Exit => {
            return None;
        }
    };

    let mut flags = BTreeSet::new();
    for path in &paths {
        flags.extend(path_flags(path, action, tool, member, registry));
    }
    // A rename from a temporary file in the state folder onto a configuration file is a
    // configuration change, shown by default (ADR-017 Decision 2).
    if flags.contains(&Flag::ToolConfigChange) {
        flags.remove(&Flag::ToolInternal);
    }
    let hands_off = match &event.kind {
        EventKind::Exec { target, args, .. } => launches_outside(&target.executable, args),
        _ => {
            matches!(action, Action::Write | Action::Create | Action::Rename)
                && paths.iter().any(|p| is_launch_folder(p))
        }
    };
    if hands_off {
        flags.insert(Flag::LaunchOutside);
    }

    Some(NewEvent {
        ts: event.ts,
        tool: tool.key.clone(),
        session_id: Some(member.session_id.to_string()),
        parent_session_id: member.parent_session_id.as_deref().map(str::to_string),
        pid: event.process.pid,
        process_path,
        category,
        action,
        target,
        outcome: Outcome::Allowed,
        size_bytes: size,
        bytes_out: None,
        bytes_in: None,
        project: member.project.as_deref().map(str::to_string),
        flags,
        count: 1,
        sources: BTreeSet::from([Source::Os]),
        agent: None,
    })
}

/// True when the command starts something launchd, another app or a scheduler will run,
/// outside the tool's process tree. `args` includes the program name, as the OS reports it.
fn launches_outside(executable: &str, args: &[String]) -> bool {
    let name = executable.rsplit('/').next().unwrap_or(executable);
    let rest = args.get(1..).unwrap_or_default();
    match name {
        "launchctl" => rest
            .iter()
            .find(|a| !a.starts_with('-'))
            .is_some_and(|sub| LAUNCHCTL_STARTS.contains(&sub.as_str())),
        // `-a`/`-b` name an app, `-n` starts a new instance, possibly in a cluster as `-na`;
        // a plain `open file.txt` or `open https://...` hands a document to its usual app.
        "open" => rest.iter().any(|a| {
            let a = a.trim_end_matches('/');
            a.ends_with(".app")
                || a == "--new"
                || (a.starts_with('-') && !a.starts_with("--") && a.contains(['a', 'b', 'n']))
        }),
        _ => ALWAYS_HAND_OFF.contains(&name),
    }
}

fn is_launch_folder(path: &str) -> bool {
    LAUNCH_FOLDERS.iter().any(|f| under(path, f))
        || home_relative(path).is_some_and(|rel| under(rel, HOME_LAUNCH_FOLDER))
}

type Parts = (Category, Action, String, Option<i64>, String, Vec<String>);

fn file(action: Action, path: &str, size: Option<i64>, event: &OsEvent) -> Parts {
    (
        Category::File,
        action,
        path.to_string(),
        size,
        event.process.executable.clone(),
        vec![path.to_string()],
    )
}

/// Flags that follow from a path alone.
pub fn path_flags(
    path: &str,
    action: Action,
    tool: &Tool,
    member: &Membership,
    registry: &Registry,
) -> Vec<Flag> {
    let mut flags = Vec::new();
    let changes = matches!(
        action,
        Action::Write | Action::Create | Action::Delete | Action::Rename
    );
    // A change to the tool's configuration is not routine state (ADR-017 Decision 2); a read
    // of it is.
    let config_change = changes && tool.is_config_path(path);
    let internal = tool.is_state_path(path);
    if config_change {
        flags.push(Flag::ToolConfigChange);
    } else if internal {
        flags.push(Flag::ToolInternal);
    }
    if is_sensitive(path, registry.sensitive()) {
        flags.push(Flag::SensitivePath);
    }
    if let Some(project) = member.project.as_deref() {
        let exempt = internal
            || under(path, project)
            || is_system_path(path)
            || registry.not_outside().iter().any(|p| p.contains(path));
        if !exempt {
            flags.push(Flag::OutsideProject);
        }
    }
    flags
}

/// The OS, temporary folders and devices. `/usr/local/` holds user-installed software, so it
/// is not exempt.
fn is_system_path(path: &str) -> bool {
    !under(path, "/usr/local/") && NOT_OUTSIDE.iter().any(|p| under(path, p))
}

fn is_sensitive(path: &str, extra: &[PathPattern]) -> bool {
    if extra.iter().any(|p| p.contains(path)) {
        return true;
    }
    if home_relative(path).is_some_and(|rel| SENSITIVE_HOME_DIRS.iter().any(|d| under(rel, d))) {
        return true;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    if name == ".env" || name.starts_with(".env.") {
        return true;
    }
    if SENSITIVE_NAME_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return true;
    }
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => SENSITIVE_EXTENSIONS.contains(&ext),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{Identity, ProcessRef};
    use std::sync::Arc;
    use time::macros::datetime;

    fn registry() -> Registry {
        Registry::parse(
            r#"{"version":1,"tools":[{"key":"cli_agent","match":[{"team_id":"TEAM000001","signing_id":"com.example.cli-agent"}],"state_dirs":["~/.cli-agent/"],
                 "config_files":["~/.cli-agent/settings.json","~/.cli-agent.json"]}],
               "paths":{"not_outside":["/opt/toolchains/"],"sensitive":["~/.config/sample-cloud/"]}}"#,
        )
        .unwrap()
    }

    fn member(r: &Registry, project: Option<&str>) -> Membership {
        let id = Identity {
            team_id: Some("TEAM000001".into()),
            signing_id: Some("com.example.cli-agent".into()),
            platform: false,
        };
        Membership {
            tool: r.match_identity("/x", &id).unwrap(),
            session_id: Arc::from("s1"),
            project: project.map(Arc::from),
            root_pid: 300,
            parent_session_id: None,
        }
    }

    fn ev(kind: EventKind) -> OsEvent {
        OsEvent {
            ts: datetime!(2026-11-14 09:33:00 UTC),
            seq: 1,
            process: ProcessRef {
                pid: 4300,
                pidversion: 1,
                ppid: 300,
                responsible_pid: None,
                executable: "/usr/bin/cat".into(),
                identity: Identity::default(),
            },
            kind,
        }
    }

    fn read(path: &str) -> EventKind {
        EventKind::Open {
            path: path.into(),
            readable: true,
            writable: false,
            size: Some(10),
        }
    }

    fn flags_for(path: &str, project: Option<&str>) -> BTreeSet<Flag> {
        let r = registry();
        classify(&ev(read(path)), &member(&r, project), &r)
            .unwrap()
            .flags
    }

    const PROJECT: Option<&str> = Some("/Users/test/projects/demo");

    #[test]
    fn maps_each_event_kind() {
        let r = registry();
        let m = member(&r, PROJECT);
        let action = |k: EventKind| classify(&ev(k), &m, &r).map(|e| (e.category, e.action));
        assert_eq!(action(read("/a")), Some((Category::File, Action::Read)));
        let open = |readable, writable| EventKind::Open {
            path: "/a".into(),
            readable,
            writable,
            size: None,
        };
        assert_eq!(
            action(open(false, true)),
            Some((Category::File, Action::Write))
        );
        assert_eq!(
            action(open(true, true)),
            Some((Category::File, Action::Read))
        );
        assert_eq!(action(open(false, false)), None);
        let close = |modified| EventKind::Close {
            path: "/a".into(),
            modified,
            size: None,
        };
        assert_eq!(action(close(true)), Some((Category::File, Action::Write)));
        assert_eq!(action(close(false)), None);
        assert_eq!(
            action(EventKind::Create { path: "/a".into() }),
            Some((Category::File, Action::Create))
        );
        assert_eq!(
            action(EventKind::Unlink { path: "/a".into() }),
            Some((Category::File, Action::Delete))
        );
        assert_eq!(action(EventKind::Exit), None);
    }

    #[test]
    fn exec_target_is_the_command_line_of_the_new_image() {
        let r = registry();
        let target = ProcessRef {
            executable: "/usr/bin/git".into(),
            ..ev(EventKind::Exit).process
        };
        let rec = classify(
            &ev(EventKind::Exec {
                target,
                args: vec![
                    "git".into(),
                    "commit".into(),
                    "-m".into(),
                    "first draft".into(),
                ],
                cwd: Some("/Users/test/projects/demo".into()),
            }),
            &member(&r, PROJECT),
            &r,
        )
        .unwrap();
        assert_eq!(rec.target, "git commit -m \"first draft\"");
        assert_eq!(rec.process_path, "/usr/bin/git");
        assert_eq!(
            (rec.category, rec.action),
            (Category::Command, Action::Exec)
        );
        assert_eq!(rec.project.as_deref(), PROJECT);
        assert_eq!(rec.tool, "cli_agent");
    }

    fn exec_flags(executable: &str, args: &[&str]) -> BTreeSet<Flag> {
        let r = registry();
        let target = ProcessRef {
            executable: executable.into(),
            ..ev(EventKind::Exit).process
        };
        classify(
            &ev(EventKind::Exec {
                target,
                args: args.iter().map(|a| a.to_string()).collect(),
                cwd: Some("/Users/test/projects/demo".into()),
            }),
            &member(&r, PROJECT),
            &r,
        )
        .unwrap()
        .flags
    }

    #[test]
    fn hand_offs_outside_the_tree_are_flagged() {
        let launches: &[(&str, &[&str])] = &[
            (
                "/bin/launchctl",
                &["launchctl", "submit", "-l", "job", "--", "/bin/sh"],
            ),
            (
                "/bin/launchctl",
                &["launchctl", "load", "-w", "agent.plist"],
            ),
            (
                "/bin/launchctl",
                &["launchctl", "bootstrap", "gui/501", "agent.plist"],
            ),
            (
                "/bin/launchctl",
                &["launchctl", "kickstart", "-k", "gui/501/job"],
            ),
            ("/bin/launchctl", &["launchctl", "asuser", "501", "/bin/sh"]),
            (
                "/usr/bin/osascript",
                &["osascript", "-e", "do shell script \"x\""],
            ),
            ("/usr/bin/open", &["open", "-a", "Terminal", "run.sh"]),
            ("/usr/bin/open", &["open", "-b", "com.example.app"]),
            ("/usr/bin/open", &["open", "-na", "Terminal"]),
            ("/usr/bin/open", &["open", "/Applications/Sample.app"]),
            ("/usr/bin/open", &["open", "/Applications/Sample.app/"]),
            ("/usr/bin/crontab", &["crontab", "jobs.txt"]),
            ("/usr/bin/at", &["at", "now", "+", "1", "minute"]),
        ];
        for (exe, args) in launches {
            assert!(
                exec_flags(exe, args).contains(&Flag::LaunchOutside),
                "{args:?}"
            );
        }
        let ordinary: &[(&str, &[&str])] = &[
            ("/usr/bin/open", &["open", "notes.txt"]),
            ("/usr/bin/open", &["open", "https://example.test/docs"]),
            ("/usr/bin/open", &["open", "-g", "notes.txt"]),
            ("/bin/launchctl", &["launchctl", "list"]),
            ("/bin/launchctl", &["launchctl", "print", "gui/501/job"]),
            ("/usr/bin/git", &["git", "commit", "-m", "load the app"]),
        ];
        for (exe, args) in ordinary {
            assert!(
                !exec_flags(exe, args).contains(&Flag::LaunchOutside),
                "{args:?}"
            );
        }
    }

    #[test]
    fn writing_a_launch_property_list_is_flagged() {
        let r = registry();
        let create = |path: &str| {
            classify(
                &ev(EventKind::Create { path: path.into() }),
                &member(&r, PROJECT),
                &r,
            )
            .unwrap()
            .flags
        };
        for path in [
            "/Users/test/Library/LaunchAgents/com.example.job.plist",
            "/Library/LaunchAgents/com.example.job.plist",
            "/Library/LaunchDaemons/com.example.job.plist",
        ] {
            assert!(create(path).contains(&Flag::LaunchOutside), "{path}");
        }
        assert!(
            !create("/Users/test/projects/demo/LaunchAgents/x.plist")
                .contains(&Flag::LaunchOutside)
        );
        // Reading one only looks.
        assert!(
            !flags_for(
                "/Users/test/Library/LaunchAgents/com.example.job.plist",
                PROJECT
            )
            .contains(&Flag::LaunchOutside)
        );
    }

    #[test]
    fn project_and_system_paths_are_not_outside() {
        assert!(flags_for("/Users/test/projects/demo/src/main.rs", PROJECT).is_empty());
        assert!(flags_for("/usr/lib/libSystem.B.dylib", PROJECT).is_empty());
        assert!(flags_for("/private/var/folders/xy/T/tmp.1", PROJECT).is_empty());
        assert!(flags_for("/opt/toolchains/bin/cc", PROJECT).is_empty());
        assert_eq!(
            flags_for("/usr/local/etc/app.conf", PROJECT),
            BTreeSet::from([Flag::OutsideProject])
        );
        assert_eq!(
            flags_for("/Users/test/projects/demo-other/x", PROJECT),
            BTreeSet::from([Flag::OutsideProject])
        );
        // Unknown project: never outside.
        assert!(flags_for("/Users/test/Documents/x", None).is_empty());
    }

    #[test]
    fn tool_state_is_internal_not_outside() {
        assert_eq!(
            flags_for("/Users/test/.cli-agent/history.jsonl", PROJECT),
            BTreeSet::from([Flag::ToolInternal])
        );
    }

    #[test]
    fn changes_to_tool_config_are_flagged_and_shown() {
        let r = registry();
        let flags = |kind: EventKind| classify(&ev(kind), &member(&r, PROJECT), &r).unwrap().flags;
        let settings = "/Users/test/.cli-agent/settings.json";
        let change = BTreeSet::from([Flag::ToolConfigChange]);
        assert_eq!(
            flags(EventKind::Close {
                path: settings.into(),
                modified: true,
                size: Some(10),
            }),
            change
        );
        assert_eq!(
            flags(EventKind::Create {
                path: settings.into()
            }),
            change
        );
        assert_eq!(
            flags(EventKind::Unlink {
                path: settings.into()
            }),
            change
        );
        // A refused write open is an attempted change.
        assert_eq!(
            flags(EventKind::Open {
                path: settings.into(),
                readable: false,
                writable: true,
                size: None,
            }),
            change
        );
        // Written whole to a temporary file in the state folder, then renamed over it.
        assert_eq!(
            flags(EventKind::Rename {
                from: "/Users/test/.cli-agent/settings.json.tmp".into(),
                to: settings.into(),
            }),
            change
        );
        // Outside a state folder it is also outside the project.
        assert_eq!(
            flags(EventKind::Create {
                path: "/Users/test/.cli-agent.json".into()
            }),
            BTreeSet::from([Flag::OutsideProject, Flag::ToolConfigChange])
        );
        // Reading it, and changing other state, stay routine.
        assert_eq!(
            flags_for(settings, PROJECT),
            BTreeSet::from([Flag::ToolInternal])
        );
        assert_eq!(
            flags(EventKind::Create {
                path: "/Users/test/.cli-agent/history.jsonl".into()
            }),
            BTreeSet::from([Flag::ToolInternal])
        );
    }

    #[test]
    fn sensitive_paths() {
        for path in [
            "/Users/test/.ssh/config",
            "/Users/test/.gnupg/pubring.kbx",
            "/Users/test/Library/Keychains/login.keychain-db",
            "/Users/test/.netrc",
            "/Users/test/projects/demo/.env",
            "/Users/test/projects/demo/.env.local",
            "/Users/test/projects/demo/certs/server.pem",
            "/Users/test/projects/demo/id_ed25519.pub",
            "/Users/test/.config/sample-cloud/credentials",
        ] {
            assert!(
                flags_for(path, PROJECT).contains(&Flag::SensitivePath),
                "{path}"
            );
        }
        for path in [
            "/Users/test/projects/demo/.environment",
            "/Users/test/projects/demo/keyboard.rs",
            "/Users/test/projects/demo/.key",
            "/Users/test/.sshx/config",
        ] {
            assert!(
                !flags_for(path, PROJECT).contains(&Flag::SensitivePath),
                "{path}"
            );
        }
    }

    #[test]
    fn rename_checks_both_paths() {
        let r = registry();
        let rec = classify(
            &ev(EventKind::Rename {
                from: "/Users/test/projects/demo/a.txt".into(),
                to: "/Users/test/.ssh/a.txt".into(),
            }),
            &member(&r, PROJECT),
            &r,
        )
        .unwrap();
        assert_eq!(
            rec.target,
            "/Users/test/projects/demo/a.txt -> /Users/test/.ssh/a.txt"
        );
        assert_eq!(
            rec.flags,
            BTreeSet::from([Flag::OutsideProject, Flag::SensitivePath])
        );
    }
}
