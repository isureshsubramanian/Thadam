//! Process tree (ADR-003 Decision 3): which processes belong to which AI tool session.
//!
//! Only member processes are stored; the rest of the system's processes (96.7% of events
//! in Phase 0) are never kept.

use std::collections::HashMap;
use std::sync::Arc;

use uuid::Uuid;

use crate::registry::{Registry, ToolId, home_relative};
use crate::snapshot::Snapshot;
use crate::source::{EventKind, OsEvent, ProcessRef};

/// The session a process belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub tool: ToolId,
    pub session_id: Arc<str>,
    pub project: Option<Arc<str>>,
    pub root_pid: u32,
    /// The session that started this one, when one tool delegated to another (ADR-004).
    pub parent_session_id: Option<Arc<str>>,
}

#[derive(Debug, Clone)]
struct Entry {
    /// `None` for processes seeded from the snapshot, until their first event says.
    pidversion: Option<u32>,
    membership: Membership,
    /// The running image, once an event has named it (network rows need it, ADR-007).
    executable: Option<Arc<str>>,
}

/// What the tree concluded from one event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    /// Membership of the process the event is about, after the event (after exec, the
    /// new image's).
    pub member: Option<Membership>,
    /// The session whose record this event becomes. Same as `member`, except for the exec
    /// that starts a delegated session: deciding to run the other tool is the delegating
    /// tool's action, so that one row belongs to the parent session (ADR-004 Decision 3).
    pub actor: Option<Membership>,
    /// Set when the event was the exit of a session root.
    pub session_ended: Option<Arc<str>>,
}

impl Observation {
    fn same(member: Option<Membership>, session_ended: Option<Arc<str>>) -> Self {
        Self {
            actor: member.clone(),
            member,
            session_ended,
        }
    }
}

#[derive(Debug, Default)]
pub struct ProcessTree {
    members: HashMap<u32, Entry>,
    responsible_attribution: bool,
}

impl ProcessTree {
    pub fn new(responsible_attribution: bool) -> Self {
        Self {
            members: HashMap::new(),
            responsible_attribution,
        }
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Seeds membership from the start-up snapshot, as if the roots' execs had been
    /// observed: a root nested under a root of the same tool joins the outer session, and
    /// one nested under a different tool starts a session linked to it.
    pub fn seed(&mut self, snapshot: &Snapshot) {
        let mut sessions: HashMap<u32, Membership> = HashMap::new();
        for root in &snapshot.roots {
            let membership = match enclosing(snapshot, &sessions, root.pid) {
                Some(outer) if outer.tool == root.tool => outer,
                outer => Membership {
                    tool: root.tool,
                    session_id: new_session_id(),
                    project: project_from_cwd(root.cwd.as_deref()),
                    root_pid: root.pid,
                    parent_session_id: outer.map(|m| m.session_id),
                },
            };
            sessions.insert(root.pid, membership);
        }
        for (pid, root) in &snapshot.members {
            if let Some(m) = sessions.get(root) {
                self.members.insert(
                    *pid,
                    Entry {
                        pidversion: None,
                        membership: m.clone(),
                        executable: None,
                    },
                );
            }
        }
    }

    /// Updates the tree with one event and reports the membership it implies.
    pub fn observe(&mut self, event: &OsEvent, registry: &Registry) -> Observation {
        let current = self.resolve(&event.process);
        match &event.kind {
            EventKind::Exec { target, cwd, .. } => {
                let (member, actor) = match registry
                    .match_identity(&target.executable, &target.identity)
                {
                    Some(tool) if current.as_ref().is_some_and(|m| m.tool == tool) => {
                        (current.clone(), current)
                    }
                    Some(tool) => {
                        let started = Membership {
                            tool,
                            session_id: new_session_id(),
                            project: project_from_cwd(cwd.as_deref()),
                            root_pid: event.process.pid,
                            parent_session_id: current.as_ref().map(|m| Arc::clone(&m.session_id)),
                        };
                        let actor = current.or_else(|| Some(started.clone()));
                        (Some(started), actor)
                    }
                    None => (current.clone(), current),
                };
                if let Some(m) = &member {
                    self.insert(
                        event.process.pid,
                        target.pidversion,
                        m.clone(),
                        &target.executable,
                    );
                }
                Observation {
                    member,
                    actor,
                    session_ended: None,
                }
            }
            EventKind::Fork { child } => {
                if let Some(m) = &current {
                    self.insert(child.pid, child.pidversion, m.clone(), &child.executable);
                }
                Observation::same(current, None)
            }
            EventKind::Exit => {
                let session_ended = current.as_ref().and_then(|m| {
                    (m.root_pid == event.process.pid).then(|| Arc::clone(&m.session_id))
                });
                self.members.remove(&event.process.pid);
                Observation::same(current, session_ended)
            }
            _ => Observation::same(current, None),
        }
    }

    /// Membership of the process an event is about. Falls back to its parent (a missed
    /// fork) and then to the process the OS holds responsible (helpers started by the
    /// system launcher), and remembers the result.
    fn resolve(&mut self, process: &ProcessRef) -> Option<Membership> {
        if let Some(entry) = self.members.get_mut(&process.pid) {
            match entry.pidversion {
                Some(v) if v == process.pidversion => return Some(entry.membership.clone()),
                // Versions only grow. An older one is a late event from the image before an
                // exec (the OS closes close-on-exec files then), not a reused pid: it must not
                // evict the new image's membership (capture 3, 14 Nov 2026).
                Some(v) if process.pidversion < v => return None,
                None => {
                    entry.pidversion = Some(process.pidversion);
                    entry.executable = Some(Arc::from(process.executable.as_str()));
                    return Some(entry.membership.clone());
                }
                // The pid was reused by a process we never saw start.
                Some(_) => {
                    self.members.remove(&process.pid);
                }
            }
        }
        let inherited = self
            .members
            .get(&process.ppid)
            .filter(|_| process.ppid != process.pid)
            .or_else(|| {
                process
                    .responsible_pid
                    .filter(|_| self.responsible_attribution)
                    .and_then(|r| self.members.get(&r))
            })
            .map(|e| e.membership.clone())?;
        self.insert(
            process.pid,
            process.pidversion,
            inherited.clone(),
            &process.executable,
        );
        Some(inherited)
    }

    /// Membership and executable for a network flow (ADR-007 Decision 4), without changing
    /// the tree: the process itself if it is the same image, else the nearest member among
    /// the ancestors the extension captured at flow start (executable then unknown).
    pub fn lookup(
        &self,
        pid: u32,
        pidversion: u32,
        ancestors: &[u32],
    ) -> Option<(Membership, Option<Arc<str>>)> {
        if let Some(entry) = self.members.get(&pid)
            && entry.pidversion.is_none_or(|v| v == pidversion)
        {
            return Some((entry.membership.clone(), entry.executable.clone()));
        }
        ancestors
            .iter()
            .filter(|a| **a != pid)
            .find_map(|a| self.members.get(a))
            .map(|e| (e.membership.clone(), None))
    }

    /// The running image of a member process, once an event has named it.
    pub fn executable(&self, pid: u32) -> Option<Arc<str>> {
        self.members.get(&pid).and_then(|e| e.executable.clone())
    }

    fn insert(&mut self, pid: u32, pidversion: u32, membership: Membership, executable: &str) {
        self.members.insert(
            pid,
            Entry {
                pidversion: Some(pidversion),
                membership,
                executable: Some(Arc::from(executable)),
            },
        );
    }
}

/// For a nested root: the session of the nearest enclosing root, whatever its tool. The
/// root's own member entry points to itself, so look at its parent's. Roots arrive
/// ancestors first, so the enclosing session is already in `sessions`.
fn enclosing(
    snapshot: &Snapshot,
    sessions: &HashMap<u32, Membership>,
    root_pid: u32,
) -> Option<Membership> {
    let parent = snapshot.parents.get(&root_pid)?;
    let outer_root = snapshot.members.get(parent)?;
    sessions.get(outer_root).cloned()
}

fn new_session_id() -> Arc<str> {
    Arc::from(Uuid::now_v7().hyphenated().to_string())
}

/// The session's project folder: the root's working directory, unless that is `/` or a
/// home folder, which would make every path look like it is outside a project.
pub fn project_from_cwd(cwd: Option<&str>) -> Option<Arc<str>> {
    let cwd = cwd?;
    let trimmed = cwd.strip_suffix('/').unwrap_or(cwd);
    if trimmed.is_empty() || !trimmed.starts_with('/') || trimmed == "/var/root" {
        return None;
    }
    let with_slash = format!("{trimmed}/");
    if home_relative(&with_slash) == Some("") {
        return None;
    }
    Some(Arc::from(trimmed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::SnapshotRoot;
    use crate::source::Identity;
    use time::macros::datetime;

    fn registry(responsible: bool) -> Registry {
        Registry::parse(&format!(
            r#"{{"version":1,"tools":[
              {{"key":"cli_agent","match":[{{"team_id":"TEAM000001","signing_id":"com.example.cli-agent"}}]}},
              {{"key":"other_agent","match":[{{"team_id":"TEAM000002","signing_id":"com.example.other"}}]}}
            ],"attribution":{{"responsible_process":{responsible}}}}}"#
        ))
        .unwrap()
    }

    fn proc(pid: u32, ppid: u32, exe: &str) -> ProcessRef {
        ProcessRef {
            pid,
            pidversion: 1,
            ppid,
            responsible_pid: None,
            executable: exe.into(),
            identity: Identity::default(),
        }
    }

    fn signed(mut p: ProcessRef, team: &str, id: &str) -> ProcessRef {
        p.identity = Identity {
            team_id: Some(team.into()),
            signing_id: Some(id.into()),
            platform: false,
        };
        p
    }

    fn ev(process: ProcessRef, kind: EventKind) -> OsEvent {
        OsEvent {
            ts: datetime!(2026-11-14 09:33:00 UTC),
            seq: 1,
            process,
            kind,
        }
    }

    fn exec_agent(pid: u32, ppid: u32, cwd: &str) -> OsEvent {
        let target = signed(
            proc(pid, ppid, "/Users/test/.local/bin/2.4.1"),
            "TEAM000001",
            "com.example.cli-agent",
        );
        ev(
            proc(pid, ppid, "/bin/zsh"),
            EventKind::Exec {
                target,
                args: vec!["agent".into()],
                cwd: Some(cwd.into()),
            },
        )
    }

    fn fork(parent: u32, child: u32) -> OsEvent {
        ev(
            proc(parent, 1, "/x"),
            EventKind::Fork {
                child: proc(child, parent, "/x"),
            },
        )
    }

    fn open(p: ProcessRef) -> OsEvent {
        ev(
            p,
            EventKind::Open {
                path: "/tmp/x".into(),
                readable: true,
                writable: false,
                size: None,
            },
        )
    }

    #[test]
    fn exec_of_registered_identity_starts_a_session_and_children_join() {
        let r = registry(true);
        let mut t = ProcessTree::new(true);
        let root = t
            .observe(&exec_agent(300, 200, "/Users/test/projects/demo"), &r)
            .member
            .unwrap();
        assert_eq!(root.project.as_deref(), Some("/Users/test/projects/demo"));
        assert_eq!(root.root_pid, 300);

        t.observe(&fork(300, 301), &r);
        t.observe(&fork(301, 302), &r);
        let grandchild = t
            .observe(&open(proc(302, 301, "/usr/bin/cat")), &r)
            .member
            .unwrap();
        assert_eq!(grandchild.session_id, root.session_id);
        assert!(
            t.observe(&open(proc(999, 1, "/bin/x")), &r)
                .member
                .is_none()
        );
    }

    #[test]
    fn lookup_finds_the_flow_process_or_its_nearest_member_ancestor() {
        let r = registry(true);
        let mut t = ProcessTree::new(true);
        let root = t
            .observe(&exec_agent(300, 200, "/Users/test/p"), &r)
            .member
            .unwrap();
        t.observe(&fork(300, 301), &r);
        let len = t.len();

        let (m, exe) = t.lookup(300, 1, &[200, 1]).unwrap();
        assert_eq!(m.session_id, root.session_id);
        assert_eq!(exe.as_deref(), Some("/Users/test/.local/bin/2.4.1"));
        assert_eq!(t.lookup(301, 1, &[300]).unwrap().1.as_deref(), Some("/x"));
        // Gone from the tree (or a different image): the captured ancestors still find
        // the session, but not the executable.
        let (m, exe) = t.lookup(450, 7, &[301, 300, 200]).unwrap();
        assert_eq!(m.session_id, root.session_id);
        assert_eq!(exe, None);
        assert_eq!(t.lookup(301, 9, &[300]).unwrap().1, None);
        assert!(t.lookup(999, 1, &[1]).is_none());
        // Read only.
        assert_eq!(t.len(), len);
    }

    #[test]
    fn missed_fork_is_recovered_from_ppid() {
        let r = registry(true);
        let mut t = ProcessTree::new(true);
        let root = t
            .observe(&exec_agent(300, 200, "/Users/test/p"), &r)
            .member
            .unwrap();
        let m = t
            .observe(&open(proc(450, 300, "/bin/cat")), &r)
            .member
            .unwrap();
        assert_eq!(m.session_id, root.session_id);
    }

    #[test]
    fn responsible_process_attribution_follows_config() {
        let r = registry(true);
        let mut helper = proc(800, 1, "/Applications/X.app/helper");
        helper.responsible_pid = Some(300);

        let mut on = ProcessTree::new(true);
        on.observe(&exec_agent(300, 200, "/Users/test/p"), &r);
        assert!(on.observe(&open(helper.clone()), &r).member.is_some());

        let mut off = ProcessTree::new(false);
        off.observe(&exec_agent(300, 200, "/Users/test/p"), &r);
        assert!(off.observe(&open(helper), &r).member.is_none());
    }

    #[test]
    fn nested_same_tool_stays_and_different_tool_starts_new_session() {
        let r = registry(true);
        let mut t = ProcessTree::new(true);
        let root = t
            .observe(&exec_agent(300, 200, "/Users/test/p"), &r)
            .member
            .unwrap();
        t.observe(&fork(300, 310), &r);
        let same = t
            .observe(&exec_agent(310, 300, "/Users/test/p"), &r)
            .member
            .unwrap();
        assert_eq!(same.session_id, root.session_id);

        t.observe(&fork(300, 320), &r);
        let target = signed(
            proc(320, 300, "/opt/other"),
            "TEAM000002",
            "com.example.other",
        );
        let other = t
            .observe(
                &ev(
                    proc(320, 300, "/x"),
                    EventKind::Exec {
                        target,
                        args: vec![],
                        cwd: None,
                    },
                ),
                &r,
            )
            .member
            .unwrap();
        assert_ne!(other.session_id, root.session_id);
        assert_eq!(r.tool(other.tool).unwrap().key, "other_agent");
        assert_eq!(other.project, None);
    }

    #[test]
    fn root_exit_ends_session_and_reused_pid_is_not_attributed() {
        let r = registry(true);
        let mut t = ProcessTree::new(true);
        let root = t
            .observe(&exec_agent(300, 200, "/Users/test/p"), &r)
            .member
            .unwrap();
        t.observe(&fork(300, 301), &r);
        let exit_child = t.observe(&ev(proc(301, 300, "/x"), EventKind::Exit), &r);
        assert_eq!(exit_child.session_ended, None);
        let exit_root = t.observe(&ev(proc(300, 200, "/x"), EventKind::Exit), &r);
        assert_eq!(exit_root.session_ended, Some(root.session_id));
        // pid 301 reused by an unrelated process whose parent is not a member.
        assert!(
            t.observe(&open(proc(301, 1, "/bin/x")), &r)
                .member
                .is_none()
        );
    }

    #[test]
    fn stale_pidversion_drops_membership() {
        let r = registry(true);
        let mut t = ProcessTree::new(true);
        t.observe(&exec_agent(300, 200, "/Users/test/p"), &r);
        t.observe(&fork(300, 301), &r);
        let mut reused = proc(301, 1, "/bin/x");
        reused.pidversion = 9;
        assert!(t.observe(&open(reused), &r).member.is_none());
    }

    #[test]
    fn late_event_from_before_an_exec_keeps_the_new_session() {
        let r = registry(true);
        let mut t = ProcessTree::new(true);
        // A shell child (version 5) execs the agent (version 6).
        let mut exec = exec_agent(300, 200, "/Users/test/p");
        exec.process.pidversion = 5;
        if let EventKind::Exec { target, .. } = &mut exec.kind {
            target.pidversion = 6;
        }
        let session = t.observe(&exec, &r).member.unwrap().session_id;
        // A close-on-exec close of the shell image, reported after the exec.
        let mut before = proc(300, 200, "/bin/zsh");
        before.pidversion = 5;
        assert!(t.observe(&open(before), &r).member.is_none());
        // The agent and its children still belong to the session.
        let mut agent = proc(300, 200, "/Users/test/.local/bin/2.4.1");
        agent.pidversion = 6;
        let member = t.observe(
            &ev(
                agent,
                EventKind::Fork {
                    child: proc(301, 300, "/x"),
                },
            ),
            &r,
        );
        assert_eq!(member.member.unwrap().session_id, session);
        assert_eq!(
            t.observe(&open(proc(301, 300, "/x")), &r)
                .member
                .unwrap()
                .session_id,
            session
        );
    }

    #[test]
    fn snapshot_seed_attributes_existing_processes() {
        let r = registry(true);
        let tool = r
            .match_identity(
                "/x",
                &signed(proc(1, 0, "/x"), "TEAM000001", "com.example.cli-agent").identity,
            )
            .unwrap();
        let mut snap = Snapshot::default();
        snap.roots.push(SnapshotRoot {
            pid: 300,
            tool,
            cwd: Some("/Users/test/p".into()),
        });
        snap.roots.push(SnapshotRoot {
            pid: 310,
            tool,
            cwd: Some("/Users/test/p".into()),
        });
        for (pid, root, parent) in [
            (300, 300, 200),
            (310, 310, 300),
            (400, 300, 300),
            (500, 310, 310),
        ] {
            snap.members.insert(pid, root);
            snap.parents.insert(pid, parent);
        }
        let mut t = ProcessTree::new(true);
        t.seed(&snap);
        let a = t
            .observe(&open(proc(500, 310, "/bin/x")), &r)
            .member
            .unwrap();
        let b = t
            .observe(&open(proc(400, 300, "/bin/x")), &r)
            .member
            .unwrap();
        assert_eq!(
            a.session_id, b.session_id,
            "nested same-tool root joins the outer session"
        );
        assert_eq!(a.project.as_deref(), Some("/Users/test/p"));
    }

    fn exec_other(pid: u32, ppid: u32) -> OsEvent {
        let target = signed(
            proc(pid, ppid, "/Users/test/.nvm/bin/other"),
            "TEAM000002",
            "com.example.other",
        );
        ev(
            proc(pid, ppid, "/Users/test/.nvm/bin/node"),
            EventKind::Exec {
                target,
                args: vec!["other".into(), "exec".into()],
                cwd: Some("/Users/test/projects/demo".into()),
            },
        )
    }

    #[test]
    fn delegated_tool_gets_a_linked_session_and_the_parent_owns_the_exec() {
        let r = registry(true);
        let mut t = ProcessTree::new(true);
        let root = t
            .observe(&exec_agent(300, 200, "/Users/test/projects/demo"), &r)
            .member
            .unwrap();
        assert_eq!(root.parent_session_id, None);
        // agent -> shell -> interpreter -> other tool
        t.observe(&fork(300, 310), &r);
        t.observe(&fork(310, 320), &r);
        let obs = t.observe(&exec_other(320, 310), &r);
        let child = obs.member.unwrap();
        assert_eq!(r.tool(child.tool).unwrap().key, "other_agent");
        assert_ne!(child.session_id, root.session_id);
        assert_eq!(child.parent_session_id, Some(Arc::clone(&root.session_id)));
        // The delegating exec is the agent's own action.
        assert_eq!(obs.actor.unwrap().session_id, root.session_id);

        // The other tool's descendants inherit the link and their rows are its own.
        t.observe(&fork(320, 330), &r);
        let build = t.observe(&open(proc(330, 320, "/Users/test/.cargo/bin/cargo")), &r);
        let m = build.actor.unwrap();
        assert_eq!(m.session_id, child.session_id);
        assert_eq!(m.parent_session_id, Some(Arc::clone(&root.session_id)));
    }

    #[test]
    fn three_levels_link_each_session_to_its_immediate_parent() {
        let r = registry(true);
        let mut t = ProcessTree::new(true);
        let a = t
            .observe(&exec_agent(300, 200, "/Users/test/p"), &r)
            .member
            .unwrap();
        t.observe(&fork(300, 310), &r);
        let b = t.observe(&exec_other(310, 300), &r).member.unwrap();
        t.observe(&fork(310, 320), &r);
        let c = t
            .observe(&exec_agent(320, 310, "/Users/test/p"), &r)
            .member
            .unwrap();
        assert_eq!(b.parent_session_id, Some(Arc::clone(&a.session_id)));
        assert_eq!(c.parent_session_id, Some(Arc::clone(&b.session_id)));
        assert_ne!(c.session_id, a.session_id);
    }

    #[test]
    fn snapshot_links_a_running_delegated_tool_to_its_parent() {
        let r = registry(true);
        let id = |team: &str, sid: &str| signed(proc(1, 0, "/x"), team, sid).identity;
        let agent = r
            .match_identity("/x", &id("TEAM000001", "com.example.cli-agent"))
            .unwrap();
        let other = r
            .match_identity("/x", &id("TEAM000002", "com.example.other"))
            .unwrap();
        let mut snap = Snapshot::default();
        snap.roots.push(SnapshotRoot {
            pid: 300,
            tool: agent,
            cwd: Some("/Users/test/p".into()),
        });
        snap.roots.push(SnapshotRoot {
            pid: 320,
            tool: other,
            cwd: Some("/Users/test/p".into()),
        });
        for (pid, root, parent) in [
            (300, 300, 200),
            (310, 300, 300),
            (320, 320, 310),
            (330, 320, 320),
        ] {
            snap.members.insert(pid, root);
            snap.parents.insert(pid, parent);
        }
        let mut t = ProcessTree::new(true);
        t.seed(&snap);
        let parent = t
            .observe(&open(proc(310, 300, "/bin/zsh")), &r)
            .member
            .unwrap();
        let child = t
            .observe(&open(proc(330, 320, "/bin/x")), &r)
            .member
            .unwrap();
        assert_eq!(r.tool(child.tool).unwrap().key, "other_agent");
        assert_eq!(
            child.parent_session_id,
            Some(Arc::clone(&parent.session_id))
        );
        assert_eq!(parent.parent_session_id, None);
    }

    #[test]
    fn project_ignores_root_and_home() {
        assert_eq!(project_from_cwd(Some("/")), None);
        assert_eq!(project_from_cwd(Some("/Users/test")), None);
        assert_eq!(project_from_cwd(Some("/Users/test/")), None);
        assert_eq!(project_from_cwd(None), None);
        assert_eq!(
            project_from_cwd(Some("/Users/test/projects/demo/")).as_deref(),
            Some("/Users/test/projects/demo")
        );
    }
}
