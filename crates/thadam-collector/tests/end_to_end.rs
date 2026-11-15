//! Collector acceptance tests (ADR-003) through the real binary and a real store.
//! All data is synthetic: example identities, `/Users/test/` paths, made-up values.
// Integration tests: unwrap/expect are allowed here (helpers included), not in library code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use thadam_store::{Store, verify_dir};

const BIN: &str = env!("CARGO_BIN_EXE_thadam-collector");
const ENV_MARKER: &str = "SYNTHETIC-ENV-MARKER-7c41";

const REGISTRY: &str = r#"{
  "version": 1,
  "tools": [
    { "key": "cli_agent",
      "match": [ { "team_id": "TEAM000001", "signing_id": "com.example.cli-agent" } ],
      "state_dirs": [ "~/.cli-agent/" ],
      "network": { "known_hosts": [ "*.example-agent.test" ] } },
    { "key": "second_agent",
      "match": [ { "team_id": "TEAM000002", "signing_id": "com.example.second-agent" } ] }
  ]
}"#;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "thadam-collector-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("registry.json"), REGISTRY).unwrap();
        Self(dir)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A process object in the logger's shape.
fn process(pid: u32, ppid: u32, exe: &str, signed: bool) -> String {
    process_v(pid, 1, ppid, exe, signed)
}

fn process_v(pid: u32, pidversion: u32, ppid: u32, exe: &str, signed: bool) -> String {
    let identity = if signed {
        r#""team_id":"TEAM000001","signing_id":"com.example.cli-agent""#
    } else {
        r#""team_id":"","signing_id":"com.example.other""#
    };
    format!(
        r#"{{"audit_token":{{"pid":{pid},"pidversion":{pidversion},"euid":501}},"ppid":{ppid},"original_ppid":{ppid},"responsible_audit_token":{{"pid":{pid},"pidversion":{pidversion}}},"executable":{{"path":"{exe}","path_truncated":false}},{identity},"is_platform_binary":false,"start_time":"2026-11-14T09:30:00.000000Z"}}"#
    )
}

fn line(seq: u64, secs: u32, proc_json: &str, kind: &str, body: &str) -> String {
    format!(
        r#"{{"schema_version":1,"version":8,"time":"2026-11-14T09:33:{secs:02}.120000000Z","global_seq_num":{seq},"seq_num":1,"event_type":0,"action_type":1,"process":{proc_json},"event":{{"{kind}":{body}}}}}"#
    )
}

fn file(path: &str) -> String {
    format!(r#"{{"path":"{path}","path_truncated":false,"stat":{{"st_size":512}}}}"#)
}

/// The ADR-003 sample: an agent runs a command with a credential in it, a child reads a
/// project file 47 times and a key file once, and an unrelated process reads a file.
fn sample_stream() -> String {
    let shell = process(4211, 4100, "/bin/zsh", false);
    let agent = process(4211, 4100, "/Users/test/.local/bin/2.4.1", true);
    let child = process(4300, 4211, "/usr/bin/cat", false);
    let unrelated = process(
        9999,
        1,
        "/Applications/Other.app/Contents/MacOS/Other",
        false,
    );
    let mut lines = Vec::new();
    let mut seq = 100u64;
    let mut next = |skip: u64| {
        seq += 1 + skip;
        seq
    };
    lines.push(line(
        next(0),
        0,
        &shell,
        "exec",
        &format!(
            r#"{{"target":{agent},"args":["agent","--project","demo"],"env":["API_KEY={ENV_MARKER}"],"cwd":{}}}"#,
            file("/Users/test/projects/demo")
        ),
    ));
    lines.push(line(
        next(0),
        0,
        &agent,
        "fork",
        &format!(r#"{{"child":{child}}}"#),
    ));
    lines.push(line(
        next(0),
        0,
        &child,
        "exec",
        &format!(
            r#"{{"target":{child},"args":["git","push","https://dev:Hunter2pass@git.example.test/repo"],"env":["TOKEN={ENV_MARKER}"],"cwd":{}}}"#,
            file("/Users/test/projects/demo")
        ),
    ));
    for i in 0..47u32 {
        lines.push(line(
            next(0),
            1 + (i * 20) / 47,
            &child,
            "open",
            &format!(
                r#"{{"fflag":1,"file":{}}}"#,
                file("/Users/test/projects/demo/src/main.rs")
            ),
        ));
    }
    lines.push(line(
        next(0),
        22,
        &child,
        "open",
        &format!(
            r#"{{"fflag":1,"file":{}}}"#,
            file("/Users/test/.ssh/config")
        ),
    ));
    lines.push(line(
        next(0),
        23,
        &agent,
        "open",
        &format!(
            r#"{{"fflag":3,"file":{}}}"#,
            file("/Users/test/.cli-agent/history.jsonl")
        ),
    ));
    lines.push(line(
        next(0),
        24,
        &unrelated,
        "open",
        &format!(
            r#"{{"fflag":1,"file":{}}}"#,
            file("/Users/test/Documents/unrelated.txt")
        ),
    ));
    lines.push("this is not json".into());
    // A skipped line still advances the sequence, so it is not counted as dropped.
    lines.push(line(next(0), 25, &unrelated, "mmap", "{}"));
    // The OS dropped 10 events here.
    lines.push(line(next(10), 26, &child, "exit", r#"{"stat":0}"#));
    with_closes(&(lines.join("\n") + "\n"))
}

/// Adds the close that follows every successful open, as the OS logger reports it, and
/// renumbers the sequence so existing gaps stay where they were (ADR-006: a read is recorded
/// once its close is seen).
fn with_closes(stream: &str) -> String {
    let mut out = Vec::new();
    let mut added = 0u64;
    for text in stream.lines() {
        let Ok(mut event) = serde_json::from_str::<serde_json::Value>(text) else {
            out.push(text.to_string());
            continue;
        };
        let seq = event["global_seq_num"].as_u64().unwrap() + added;
        event["global_seq_num"] = seq.into();
        let close = event["event"]["open"]["file"].clone();
        out.push(event.to_string());
        if !close.is_null() {
            added += 1;
            event["global_seq_num"] = (seq + 1).into();
            event["event"] = serde_json::json!({"close": {"modified": false, "target": close}});
            out.push(event.to_string());
        }
    }
    out.join("\n") + "\n"
}

/// The one segment file a short synthetic run writes (ADR-009: the store is a folder).
fn only_segment(store: &Path) -> Option<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(store)
        .ok()?
        .map(|e| e.unwrap().path())
        .filter(|p| {
            let name = p.file_name().unwrap().to_string_lossy();
            name.starts_with("events-") && name.ends_with(".db")
        })
        .collect();
    assert!(found.len() <= 1, "expected one segment, found {found:?}");
    found.pop()
}

fn run_stdin(dir: &TempDir, input: &str, extra: &[&str]) -> (std::process::Output, PathBuf) {
    let store = dir.path("store");
    let mut child = Command::new(BIN)
        .args(["run", "--source", "stdin", "--registry"])
        .arg(dir.path("registry.json"))
        .arg("--store")
        .arg(&store)
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    // A run that failed at setup leaves no segment; callers then only look at the output.
    let db = only_segment(&store).unwrap_or_else(|| store.join("none.db"));
    (out, db)
}

/// (category, action, target, count, flags, detections) in seq order.
fn rows(db: &Path) -> Vec<(String, String, String, i64, String, String)> {
    // Segments open on their first row, so a run that kept nothing has no file.
    if !db.exists() {
        return Vec::new();
    }
    let store = Store::open_read_only(db).unwrap();
    let mut stmt = store
        .connection()
        .prepare("SELECT category, action, target, count, flags, detections, tool FROM events ORDER BY seq")
        .unwrap();
    stmt.query_map([], |r| {
        let tool: String = r.get(6)?;
        assert_eq!(tool, "cli_agent");
        Ok((
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
        ))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

fn db_files_contain(dir: &TempDir, needle: &str) -> bool {
    std::fs::read_dir(dir.path("store")).unwrap().any(|entry| {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        (name.starts_with("events-") || name.starts_with("catalog.db"))
            && std::fs::read(&path)
                .unwrap()
                .windows(needle.len())
                .any(|w| w == needle.as_bytes())
    })
}

#[test]
fn sample_stream_produces_the_adr_rows() {
    let dir = TempDir::new("sample");
    let (out, db) = run_stdin(&dir, &sample_stream(), &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");

    let got = rows(&db);
    let summary: Vec<(&str, &str, &str, i64, &str, &str)> = got
        .iter()
        .map(|(c, a, t, n, f, d)| {
            (
                c.as_str(),
                a.as_str(),
                t.as_str(),
                *n,
                f.as_str(),
                d.as_str(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("command", "exec", "agent --project demo", 1, "", ""),
            (
                "command",
                "exec",
                // The email detector also matches `pass@host`; the merged span keeps the SECRET label.
                "git push https://dev:[SECRET]/repo",
                1,
                "secret_pattern",
                "SECRET:1"
            ),
            // Windows close in the order they opened; ts keeps the first occurrence.
            (
                "file",
                "read",
                "/Users/test/projects/demo/src/main.rs",
                47,
                "",
                ""
            ),
            (
                "file",
                "read",
                "/Users/test/.ssh/config",
                1,
                "outside_project,sensitive_path",
                ""
            ),
            (
                "file",
                "read",
                "/Users/test/.cli-agent/history.jsonl",
                1,
                "tool_internal",
                ""
            ),
        ]
    );

    // Diagnostics: counts only, never paths or values.
    assert!(stderr.contains("gaps=1 missed=10"), "{stderr}");
    assert!(stderr.contains("skipped_malformed=1"), "{stderr}");
    assert!(stderr.contains("skipped_unknown_event=1"), "{stderr}");
    assert!(!stderr.contains("/Users/test"), "{stderr}");
    assert!(!stderr.contains("Hunter2pass"), "{stderr}");
}

#[test]
fn environment_never_reaches_the_database() {
    let dir = TempDir::new("env");
    let (out, _) = run_stdin(&dir, &sample_stream(), &[]);
    assert!(out.status.success());
    assert!(!db_files_contain(&dir, ENV_MARKER));
    assert!(!db_files_contain(&dir, "Hunter2pass"));
}

#[test]
fn the_written_chain_verifies() {
    let dir = TempDir::new("verify");
    let (out, db) = run_stdin(&dir, &sample_stream(), &[]);
    assert!(out.status.success());
    let report = Store::open_read_only(&db).unwrap().verify().unwrap();
    assert!(report.is_ok());
    assert_eq!(report.total, 5);
    // The folder as a whole verifies too, and the stats line reports the store.
    let folder = verify_dir(dir.path("store")).unwrap();
    assert_eq!(folder.broken, None);
    assert_eq!(folder.verified_rows, 5);
    assert!(String::from_utf8_lossy(&out.stderr).contains(" store_mb="));
}

#[test]
fn window_length_is_configurable() {
    // With a 5 s window the 47 reads spread over 20 s split into several records.
    let dir = TempDir::new("window");
    let (out, db) = run_stdin(&dir, &sample_stream(), &["--window-secs", "5"]);
    assert!(out.status.success());
    let main_rs: Vec<i64> = rows(&db)
        .into_iter()
        .filter(|r| r.2.ends_with("main.rs"))
        .map(|r| r.3)
        .collect();
    assert!(main_rs.len() > 1, "{main_rs:?}");
    assert_eq!(main_rs.iter().sum::<i64>(), 47);
}

#[test]
fn unrelated_processes_produce_nothing() {
    let dir = TempDir::new("unrelated");
    let unrelated = process(
        9999,
        1,
        "/Applications/Other.app/Contents/MacOS/Other",
        false,
    );
    let input: String = (0..100)
        .map(|i| {
            line(
                i,
                (i % 60) as u32,
                &unrelated,
                "open",
                &format!(r#"{{"fflag":1,"file":{}}}"#, file("/Users/test/x")),
            ) + "\n"
        })
        .collect();
    let (out, db) = run_stdin(&dir, &input, &[]);
    assert!(out.status.success());
    assert!(rows(&db).is_empty());
}

/// (reason, detail, missed) of every gap entry in the store's catalog (ADR-013 Decision 1).
fn gaps(dir: &TempDir) -> Vec<(String, Option<String>, Option<i64>)> {
    let report = verify_dir(dir.path("store")).unwrap();
    assert_eq!(report.broken, None);
    report
        .gaps
        .into_iter()
        .map(|g| (g.reason.unwrap(), g.detail, g.missed))
        .collect()
}

#[test]
fn a_restart_is_recorded_as_a_gap_and_a_logger_jump_as_dropped_events() {
    let dir = TempDir::new("gaps");
    let (out, _) = run_stdin(&dir, &sample_stream(), &[]);
    assert!(out.status.success());
    // A first start has no heartbeat to go on, so it claims no gap; the sample's own logger
    // jump (10 events) is one dropped entry. A clean end says stopped.
    let dropped = |n| ("dropped".to_string(), Some("os".to_string()), Some(n));
    assert_eq!(gaps(&dir), [dropped(10)]);
    let beat = std::fs::read_to_string(dir.path("store").join("collector.heartbeat")).unwrap();
    assert!(beat.starts_with("stopped "), "{beat}");

    // The logger's sequence jumps from 10 to 14: three events lost.
    let unrelated = process(
        9999,
        1,
        "/Applications/Other.app/Contents/MacOS/Other",
        false,
    );
    let input: String = [10, 14, 15]
        .iter()
        .map(|&i| {
            line(
                i,
                1,
                &unrelated,
                "open",
                &format!(r#"{{"fflag":1,"file":{}}}"#, file("/Users/test/x")),
            ) + "\n"
        })
        .collect();
    let (out, _) = run_stdin(&dir, &input, &[]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains(" missed=3"));
    assert_eq!(
        gaps(&dir),
        [
            dropped(10),
            ("not_running".to_string(), Some("stopped".to_string()), None),
            dropped(3),
        ]
    );
}

#[test]
fn a_killed_collector_is_recorded_as_crashed() {
    let dir = TempDir::new("crash");
    let store = dir.path("store");
    let mut child = Command::new(BIN)
        .args(["run", "--source", "stdin", "--registry"])
        .arg(dir.path("registry.json"))
        .arg("--store")
        .arg(&store)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let beat = store.join("collector.heartbeat");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !std::fs::read_to_string(&beat).is_ok_and(|b| b.starts_with("running ")) {
        assert!(std::time::Instant::now() < deadline, "no heartbeat");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    child.kill().unwrap(); // SIGKILL: no clean stop
    child.wait().unwrap();
    let (out, _) = run_stdin(&dir, "", &[]);
    assert!(out.status.success());
    assert_eq!(
        gaps(&dir),
        [("not_running".to_string(), Some("crashed".to_string()), None)]
    );
}

#[test]
fn usage_and_registry_errors_exit_2_without_values() {
    let dir = TempDir::new("usage");
    let out = Command::new(BIN).arg("bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(2));

    let bad = dir.path("bad.json");
    std::fs::write(
        &bad,
        r#"{"version":1,"tools":[{"key":"t","match":[{"team_id":"lower00001","signing_id":"x"}]}]}"#,
    )
    .unwrap();
    let out = Command::new(BIN)
        .arg("check-registry")
        .arg(&bad)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("team_id"), "{stderr}");
    assert!(!stderr.contains("lower00001"), "{stderr}");

    let out = Command::new(BIN)
        .arg("check-registry")
        .arg(dir.path("registry.json"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("cli_agent"));

    let (out, _) = run_stdin(&dir, "", &["--window-secs", "0"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn interrupt_stops_cleanly_and_flushes_open_windows() {
    let dir = TempDir::new("sigint");
    let store = dir.path("store");
    let mut child = Command::new(BIN)
        .args(["run", "--source", "stdin", "--registry"])
        .arg(dir.path("registry.json"))
        .arg("--store")
        .arg(&store)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Keep stdin open so the run can only end through the signal.
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(sample_stream().as_bytes()).unwrap();
    stdin.flush().unwrap();
    // Rows appear only after the signal handler is installed (it is set up before the
    // pipeline starts), so wait for them rather than for a fixed time.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        let ready = only_segment(&store).is_some_and(|db| {
            Store::open_read_only(&db)
                .and_then(|s| s.verify())
                .is_ok_and(|r| r.total > 0)
        });
        if ready {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let status = Command::new("/bin/kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let out = child.wait_with_output().unwrap();
    drop(stdin);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The 47-read window was still open when the signal arrived.
    assert!(
        rows(&only_segment(&store).unwrap())
            .iter()
            .any(|r| r.3 == 47)
    );
}

/// A process signed as the second registered tool.
fn second_tool(pid: u32, ppid: u32) -> String {
    process(pid, ppid, "/Users/test/.nvm/bin/second-agent", false).replace(
        r#""team_id":"","signing_id":"com.example.other""#,
        r#""team_id":"TEAM000002","signing_id":"com.example.second-agent""#,
    )
}

#[test]
fn delegated_sessions_are_linked_to_their_parent() {
    // agent -> shell -> interpreter -> second tool -> build tool (live run 2's chain)
    let shell0 = process(4211, 4100, "/bin/zsh", false);
    let agent = process(4211, 4100, "/Users/test/.local/bin/2.4.1", true);
    let shell = process(4300, 4211, "/bin/zsh", false);
    let node = process(4301, 4300, "/Users/test/.nvm/bin/node", false);
    let second = second_tool(4301, 4300);
    let cargo = process(4400, 4301, "/Users/test/.cargo/bin/cargo", false);
    let cwd = file("/Users/test/projects/demo");
    let lines = [
        line(1, 0, &shell0, "exec", &format!(r#"{{"target":{agent},"args":["agent"],"cwd":{cwd}}}"#)),
        line(2, 1, &agent, "fork", &format!(r#"{{"child":{shell}}}"#)),
        line(3, 1, &shell, "fork", &format!(r#"{{"child":{node}}}"#)),
        line(4, 2, &node, "exec", &format!(r#"{{"target":{second},"args":["second-agent","exec","fix the tests"],"cwd":{cwd}}}"#)),
        line(5, 3, &second, "fork", &format!(r#"{{"child":{cargo}}}"#)),
        line(6, 4, &cargo, "create", &format!(r#"{{"destination":{{"existing_file":{}}}}}"#, file("/Users/test/projects/demo/target/debug/demo"))),
    ]
    .join("\n")
        + "\n";
    let dir = TempDir::new("delegation");
    let (out, db) = run_stdin(&dir, &lines, &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let store = Store::open_read_only(&db).unwrap();
    assert!(store.verify().unwrap().is_ok());
    let got: Vec<(String, String, String, Option<String>)> = store
        .connection()
        .prepare("SELECT tool, action, session_id, parent_session_id FROM events ORDER BY seq")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(got.len(), 3, "{got:?}");
    let (agent_session, delegated_session) = (&got[0].2, &got[2].2);
    // Row 1: the agent starts. Row 2: the agent runs the second tool (its own action).
    assert_eq!(
        (got[0].0.as_str(), got[0].3.as_deref()),
        ("cli_agent", None)
    );
    assert_eq!(
        (
            got[1].0.as_str(),
            got[1].1.as_str(),
            &got[1].2,
            got[1].3.as_deref()
        ),
        ("cli_agent", "exec", agent_session, None)
    );
    // Row 3: the build output belongs to the second tool's session, linked to the agent's.
    assert_eq!(got[2].0, "second_agent");
    assert_ne!(delegated_session, agent_session);
    assert_eq!(got[2].3.as_deref(), Some(agent_session.as_str()));
}

/// ADR-005 acceptance 8: a synthetic build. A compiler creates 3,000 files under the
/// project's `target/`, a scanner reads 250 source files, a formatter rewrites 250, the
/// agent itself reads one file, and a key-like file inside `target/` is read.
fn build_stream() -> String {
    let shell = process(4211, 4100, "/bin/zsh", false);
    let agent = process(4211, 4100, "/Users/test/.local/bin/2.4.1", true);
    let compiler = process(4500, 4211, "/Users/test/.rustup/bin/rustc", false);
    let scanner = process(4600, 4211, "/usr/bin/git", false);
    let formatter = process(4700, 4211, "/Users/test/.cargo/bin/rustfmt", false);
    let project = "/Users/test/projects/demo";
    let mut seq = 100u64;
    let mut lines = Vec::new();
    let mut push = |secs: u32, proc_json: &str, kind: &str, body: String| {
        seq += 1;
        lines.push(line(seq, secs, proc_json, kind, &body));
    };
    push(
        0,
        &shell,
        "exec",
        format!(
            r#"{{"target":{agent},"args":["agent"],"env":[],"cwd":{}}}"#,
            file(project)
        ),
    );
    for child in [&compiler, &scanner, &formatter] {
        push(0, &agent, "fork", format!(r#"{{"child":{child}}}"#));
    }
    for i in 0..3_000u32 {
        push(
            1 + i / 300,
            &compiler,
            "create",
            format!(
                r#"{{"destination":{{"new_path":{{"dir":{{"path":"{project}/target/debug/deps"}},"filename":"f{i}.o"}}}}}}"#
            ),
        );
    }
    for i in 0..250u32 {
        push(
            12,
            &scanner,
            "open",
            format!(
                r#"{{"fflag":1,"file":{}}}"#,
                file(&format!("{project}/src/m{i}.rs"))
            ),
        );
        push(
            13,
            &formatter,
            "close",
            format!(
                r#"{{"modified":true,"target":{}}}"#,
                file(&format!("{project}/src/m{i}.rs"))
            ),
        );
    }
    push(
        14,
        &compiler,
        "open",
        format!(
            r#"{{"fflag":1,"file":{}}}"#,
            file(&format!("{project}/target/.env"))
        ),
    );
    push(
        14,
        &agent,
        "open",
        format!(
            r#"{{"fflag":1,"file":{}}}"#,
            file(&format!("{project}/target/debug/build.log"))
        ),
    );
    with_closes(&(lines.join("\n") + "\n"))
}

/// (process_path, action, target, count, flags).
type Row = (String, String, String, i64, String);

#[test]
fn build_output_and_bulk_scans_are_rolled_up() {
    let dir = TempDir::new("rollup");
    let (out, db) = run_stdin(&dir, &build_stream(), &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let store = Store::open_read_only(&db).unwrap();
    let report = store.verify().unwrap();
    let mut stmt = store
        .connection()
        .prepare("SELECT process_path, action, target, count, flags FROM events ORDER BY seq")
        .unwrap();
    let all: Vec<Row> = stmt
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(report.total as usize, all.len());
    let by = |exe: &str, action: &str| -> Vec<&Row> {
        all.iter()
            .filter(|r| r.0.ends_with(exe) && r.1 == action)
            .collect()
    };

    // Rule 1: 3,000 creates in one window become one row.
    let creates = by("/rustc", "create");
    assert_eq!(creates.len(), 1, "{creates:?}");
    assert_eq!(
        creates[0].2,
        "/Users/test/projects/demo/target/** (3000 files)"
    );
    assert_eq!(creates[0].3, 3_000);
    assert!(creates[0].4.contains("rolled_up"));

    // Rule 2: the scanner keeps 100 individual reads, the other 150 roll up under src/.
    let reads = by("/git", "read");
    let (rolled, individual): (Vec<&&Row>, Vec<&&Row>) =
        reads.iter().partition(|r| r.4.contains("rolled_up"));
    assert_eq!(individual.len(), 100);
    assert_eq!(rolled.len(), 1);
    assert_eq!(rolled[0].2, "/Users/test/projects/demo/src/** (150 files)");
    assert_eq!(rolled[0].3, 150);

    // Writes outside roll-up folders stay one row per file.
    let writes = by("/rustfmt", "write");
    assert_eq!(writes.len(), 250);
    assert!(writes.iter().all(|r| !r.4.contains("rolled_up")));

    // Never rolled up: a sensitive path inside target/, the agent's own read, the command.
    let env = by("/rustc", "read");
    assert_eq!(env.len(), 1);
    assert!(env[0].2.ends_with("/target/.env") && env[0].4.contains("sensitive_path"));
    let agent = by("/2.4.1", "read");
    assert_eq!(agent.len(), 1);
    assert!(agent[0].2.ends_with("/target/debug/build.log"));
    assert_eq!(by("/2.4.1", "exec").len(), 1);

    // 1 exec + 1 create + 101 reads + 250 writes + 2 kept reads instead of 3,503 rows.
    assert_eq!(all.len(), 355, "{all:?}");
}

/// ADR-006 acceptance: an open the OS refused has no close. The agent's twelve attempts and
/// `cat`'s one become `denied_by_os` rows, not reads; a closed open stays an allowed read.
#[test]
fn refused_opens_are_recorded_as_denied_by_os() {
    let shell = process(4211, 4100, "/bin/zsh", false);
    let agent = process(4211, 4100, "/Users/test/.local/bin/2.4.1", true);
    let cat = process(4800, 4211, "/bin/cat", false);
    let locked = file("/Users/test/outside/locked.txt");
    let notes = file("/Users/test/outside/notes.txt");
    let mut seq = 100u64;
    let mut lines = Vec::new();
    let mut push = |secs: u32, proc_json: &str, kind: &str, body: String| {
        seq += 1;
        lines.push(line(seq, secs, proc_json, kind, &body));
    };
    push(
        0,
        &shell,
        "exec",
        format!(
            r#"{{"target":{agent},"args":["agent"],"env":[],"cwd":{}}}"#,
            file("/Users/test/projects/demo")
        ),
    );
    for _ in 0..12 {
        push(
            1,
            &agent,
            "open",
            format!(r#"{{"fflag":1,"file":{locked}}}"#),
        );
    }
    push(
        2,
        &agent,
        "open",
        format!(r#"{{"fflag":1,"file":{notes}}}"#),
    );
    push(
        2,
        &agent,
        "close",
        format!(r#"{{"modified":false,"target":{notes}}}"#),
    );
    push(3, &agent, "fork", format!(r#"{{"child":{cat}}}"#));
    push(3, &cat, "open", format!(r#"{{"fflag":1,"file":{locked}}}"#));
    push(3, &cat, "exit", r#"{"stat":256}"#.into());
    push(4, &agent, "exit", r#"{"stat":0}"#.into());
    let input = lines.join("\n") + "\n";

    let dir = TempDir::new("refused");
    let (out, db) = run_stdin(&dir, &input, &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let store = Store::open_read_only(&db).unwrap();
    store.verify().unwrap();
    let mut stmt = store
        .connection()
        .prepare("SELECT process_path, action, outcome, target, count, size_bytes FROM events WHERE category = 'file' ORDER BY seq")
        .unwrap();
    let rows: Vec<(String, String, String, String, i64, Option<i64>)> = stmt
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let find = |exe: &str, target: &str| {
        rows.iter()
            .find(|r| r.0.ends_with(exe) && r.3.ends_with(target))
            .unwrap_or_else(|| panic!("{exe} {target}: {rows:?}"))
    };
    let agent_locked = find("/2.4.1", "/locked.txt");
    assert_eq!(
        (agent_locked.1.as_str(), agent_locked.2.as_str()),
        ("read", "denied_by_os")
    );
    assert_eq!(agent_locked.4, 12);
    assert_eq!(agent_locked.5, None);
    let cat_locked = find("/cat", "/locked.txt");
    assert_eq!(cat_locked.2, "denied_by_os");
    let agent_notes = find("/2.4.1", "/notes.txt");
    assert_eq!(agent_notes.2, "allowed");
    assert_eq!(rows.len(), 3, "{rows:?}");
}

/// One `thadam.flow.v1` record. Times are on the sample stream's clock (09:33:SS).
fn flow(kind: &str, n: u32, secs: u32, fields: &str) -> String {
    format!(
        r#"{{"v":1,"kind":"{kind}","flow":"0192f3a4-0000-7000-8000-{n:012}","ts":"2026-11-14T09:33:{secs:02}.500Z"{fields}}}"#
    )
}

fn flow_open(n: u32, secs: u32, pid: u32, ppids: &str, ip: &str, host: Option<&str>) -> String {
    let host = match host {
        Some(h) => format!(r#","host":"{h}","host_from":"api""#),
        None => r#","host_from":"none""#.to_string(),
    };
    flow(
        "open",
        n,
        secs,
        &format!(
            r#","pid":{pid},"pidversion":1,"ppids":{ppids},"proto":"tcp","direction":"out","remote_ip":"{ip}","remote_port":443{host}"#
        ),
    )
}

fn flow_bytes(kind: &str, n: u32, secs: u32, out: u64, inn: u64) -> String {
    flow(
        kind,
        n,
        secs,
        &format!(r#","bytes_out":{out},"bytes_in":{inn}"#),
    )
}

/// ADR-007 acceptance tests 2, 8 and 9: flow records arrive on the socket before the OS
/// events that say whose they are; they are held, attributed, collapsed and written, and
/// the chain verifies.
#[test]
fn network_flows_are_attributed_to_sessions() {
    let dir = TempDir::new("net");
    let socket = dir.path("s").join("f.sock");
    let store = dir.path("store");
    let mut child = Command::new(BIN)
        .args(["run", "--source", "stdin", "--registry"])
        .arg(dir.path("registry.json"))
        .arg("--store")
        .arg(&store)
        .arg("--flow-socket")
        .arg(&socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut conn = loop {
        if let Ok(c) = std::os::unix::net::UnixStream::connect(&socket) {
            break c;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "socket never appeared"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    };

    let records = [
        // The agent (pid 4211) calls its API twice.
        flow_open(
            1,
            5,
            4211,
            "[4100,1]",
            "203.0.113.7",
            Some("api.example-agent.test"),
        ),
        flow_bytes("stats", 1, 6, 300, 4000),
        flow_bytes("close", 1, 7, 320, 4100),
        flow_open(
            2,
            8,
            4211,
            "[4100,1]",
            "203.0.113.7",
            Some("api.example-agent.test"),
        ),
        flow_bytes("close", 2, 9, 80, 900),
        // A short-lived helper the OS stream never shows, found through its ancestors;
        // its connection is refused.
        flow_open(3, 10, 4400, "[4300,4211,4100]", "198.51.100.20", None),
        flow_bytes("close", 3, 10, 0, 0),
        // An unrelated app: never written.
        flow_open(
            4,
            11,
            9999,
            "[1]",
            "198.51.100.30",
            Some("www.example.test"),
        ),
        flow_bytes("close", 4, 12, 50, 5000),
        // The child (pid 4300) connects just before its exit at 09:33:26.12. Released by that
        // exit event *before* the tree removes the child, so its executable is still known.
        flow_open(
            5,
            25,
            4300,
            "[4211,4100]",
            "203.0.113.7",
            Some("api.example-agent.test"),
        ),
        flow_bytes("close", 5, 25, 10, 20),
        r#"{"v":1,"kind":"gap","ts":"2026-11-14T09:33:12Z","missed":7}"#.to_string(),
        r#"{"v":1,"kind":"open","unexpected":"198.51.100.99"}"#.to_string(),
    ];
    conn.write_all((records.join("\n") + "\n").as_bytes())
        .unwrap();
    drop(conn);
    // The listener reads on its own thread; give it time before the OS stream ends the run.
    std::thread::sleep(std::time::Duration::from_millis(500));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(sample_stream().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");

    let store = Store::open_read_only(only_segment(&store).unwrap()).unwrap();
    assert!(store.verify().unwrap().is_ok());
    let conn = store.connection();
    let exec_session: String = conn
        .query_row(
            "SELECT session_id FROM events WHERE action = 'exec' ORDER BY seq LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT category, target, count, outcome, flags, bytes_out, bytes_in, process_path,
                    session_id, source
             FROM events WHERE action = 'connect' ORDER BY seq",
        )
        .unwrap();
    type Net = (
        String,
        String,
        i64,
        String,
        String,
        i64,
        i64,
        String,
        String,
        String,
    );
    let got: Vec<Net> = stmt
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
                r.get(9)?,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let want = |target: &str, count, outcome: &str, flags: &str, out, inn, exe: &str| {
        (
            "network_external".to_string(),
            target.to_string(),
            count,
            outcome.to_string(),
            flags.to_string(),
            out,
            inn,
            exe.to_string(),
            exec_session.clone(),
            "network".to_string(),
        )
    };
    assert_eq!(
        got,
        vec![
            want(
                "api.example-agent.test:443",
                2,
                "allowed",
                "",
                400,
                5000,
                "/Users/test/.local/bin/2.4.1"
            ),
            want(
                "198.51.100.20:443",
                1,
                "failed",
                "unknown_host",
                0,
                0,
                "(unknown)"
            ),
            want(
                "api.example-agent.test:443",
                1,
                "allowed",
                "",
                10,
                20,
                "/usr/bin/cat"
            ),
        ]
    );

    assert!(stderr.contains("net_gaps=1 net_missed=7"), "{stderr}");
    assert!(stderr.contains("flows=11 flows_kept=4"), "{stderr}");
    assert!(stderr.contains("flows_rejected_malformed=1"), "{stderr}");
    for leak in ["example.test", "198.51.100", "203.0.113"] {
        assert!(!stderr.contains(leak), "{stderr}");
    }
}

/// ADR-010 Decision 4: while one collector holds the store, a second is refused before it
/// binds the network socket or opens the log, so it can take neither from the first.
#[test]
fn a_second_collector_is_refused_and_touches_neither_socket_nor_log() {
    let tmp = TempDir::new("second");
    let store = tmp.path("store");
    let held = thadam_store::SegmentWriter::open(
        &store,
        thadam_store::Limits::default(),
        Box::new(thadam_store::SystemDisk),
    )
    .unwrap();
    let out = Command::new(BIN)
        .arg("run")
        .arg("--registry")
        .arg(tmp.path("registry.json"))
        .arg("--store")
        .arg(&store)
        .args(["--source", "stdin", "--flow-socket"])
        .arg(tmp.path("flow.sock"))
        .arg("--log")
        .arg(tmp.path("collector.log"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("another collector is writing this store")
    );
    assert!(!tmp.path("flow.sock").exists());
    assert!(!tmp.path("collector.log").exists());
    drop(held);
}

/// `--log` sends the diagnostics to the file, with a UTC time on each line.
#[test]
fn diagnostics_go_to_the_log_file_when_given() {
    let tmp = TempDir::new("log");
    let mut child = Command::new(BIN)
        .arg("run")
        .arg("--registry")
        .arg(tmp.path("registry.json"))
        .arg("--store")
        .arg(tmp.path("store"))
        .args(["--source", "stdin", "--log"])
        .arg(tmp.path("collector.log"))
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(
        out.stderr.is_empty(),
        "nothing on stderr once the log is open"
    );
    let log = std::fs::read_to_string(tmp.path("collector.log")).unwrap();
    let last = log.lines().last().unwrap();
    assert!(last.contains(" thadam-collector: final events=0"), "{last}");
    assert!(
        last.as_bytes().get(19) == Some(&b'Z'),
        "UTC stamp first: {last}"
    );
}

/// One `thadam.agent.v1` line sent as the hook does: write, then wait for the acknowledgement.
fn send_agent(socket: &Path, line: &str) {
    let mut c = std::os::unix::net::UnixStream::connect(socket).unwrap();
    c.write_all(format!("{line}\n").as_bytes()).unwrap();
    c.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut ack = [0u8; 1];
    std::io::Read::read_exact(&mut c, &mut ack).unwrap();
}

#[test]
fn agent_messages_from_the_hook_become_rows_of_its_session() {
    // This test process plays the hook: the OS stream says the tool started it, and the
    // collector is told the hook program is this test binary. Its pid and pidversion come
    // from the kernel, as the collector will read them.
    let me = {
        let dir = std::env::temp_dir().join(format!("tp-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let l = std::os::unix::net::UnixListener::bind(dir.join("p.sock")).unwrap();
        let _c = std::os::unix::net::UnixStream::connect(dir.join("p.sock")).unwrap();
        let (s, _) = l.accept().unwrap();
        let peer = thadam_collector::peer::peer_of(&s).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        peer
    };
    let exe = std::env::current_exe().unwrap();
    let exe = exe.to_str().unwrap();
    let dir = TempDir::new("agent");
    let socket = dir.path("a").join("a.sock");
    let store = dir.path("store");
    let mut child = Command::new(BIN)
        .args(["run", "--source", "stdin", "--registry"])
        .arg(dir.path("registry.json"))
        .arg("--store")
        .arg(&store)
        .arg("--agent-socket")
        .arg(&socket)
        .args(["--hook-bin", exe])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !socket.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "socket never appeared"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let session = r#""agent_session_id":"a-51c2","transcript":"/Users/test/.cli-agent/a-51c2.jsonl","turn":"p-1""#;
    let call = r#""input_hash":"0000000000000000000000000000000000000000000000000000000000000001","tool_name":"Shell","call_kind":"shell","text":"rm -rf build/""#;
    for line in [
        format!(
            r#"{{"v":"thadam.agent.v1","tool":"claimed","kind":"prompt",{session},"text":"mail dev@example.test the key sk-ant-SYNTHETICSYNTHETICSYNTHETIC0000"}}"#
        ),
        format!(
            r#"{{"v":"thadam.agent.v1","tool":"claimed","kind":"permission_request",{session},{call}}}"#
        ),
        format!(
            r#"{{"v":"thadam.agent.v1","tool":"claimed","kind":"call_start",{session},"call":"c-1",{call}}}"#
        ),
    ] {
        send_agent(&socket, &line);
    }
    // Another program in no session at all: written nowhere.
    if Path::new("/usr/bin/nc").exists() {
        let mut nc = Command::new("/usr/bin/nc")
            .args(["-U", socket.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        nc.stdin
            .take()
            .unwrap()
            .write_all(
                format!(r#"{{"v":"thadam.agent.v1","tool":"cli_agent","kind":"prompt",{session},"text":"FORGED"}}"#)
                    .as_bytes(),
            )
            .unwrap();
        let _ = nc.wait();
    }
    std::thread::sleep(std::time::Duration::from_millis(300));

    let root = process(4100, 1, "/Users/test/.local/bin/2.4.1", true);
    let stream = [
        line(
            1,
            0,
            &process(4100, 1, "/bin/zsh", false),
            "exec",
            &format!(
                r#"{{"target":{root},"args":["agent"],"env":[],"cwd":{}}}"#,
                file("/Users/test/projects/demo")
            ),
        ),
        line(
            2,
            1,
            &root,
            "fork",
            &format!(
                r#"{{"child":{}}}"#,
                process_v(me.pid, me.pidversion, 4100, "/bin/sh", false)
            ),
        ),
        line(
            3,
            1,
            &process_v(me.pid, me.pidversion, 4100, "/bin/sh", false),
            "exec",
            &format!(
                r#"{{"target":{},"args":["hook"],"env":[],"cwd":{}}}"#,
                process_v(me.pid, me.pidversion, 4100, exe, false),
                file("/Users/test/projects/demo")
            ),
        ),
    ]
    .join("\n")
        + "\n";
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stream.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");

    let mut agent_rows = Vec::new();
    for entry in std::fs::read_dir(&store).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !(name.starts_with("events-") && name.ends_with(".db")) {
            continue;
        }
        let db = Store::open_read_only(&path).unwrap();
        let mut stmt = db
            .connection()
            .prepare(
                "SELECT tool, category, outcome, target, flags, detections, agent_session_id, transcript
                 FROM events WHERE source = 'agent' ORDER BY seq",
            )
            .unwrap();
        agent_rows.extend(
            stmt.query_map([], |r| {
                Ok((0..8)
                    .map(|i| r.get::<_, Option<String>>(i).unwrap().unwrap_or_default())
                    .collect::<Vec<_>>())
            })
            .unwrap()
            .map(Result::unwrap),
        );
    }
    assert_eq!(agent_rows.len(), 2, "{agent_rows:?}\n{stderr}");
    let prompt = &agent_rows[0];
    // Joined to the sender's session and tool, whatever the message claimed.
    assert_eq!(prompt[0], "cli_agent");
    assert_eq!(prompt[1], "prompt");
    assert!(
        prompt[3].contains("[EMAIL]") && !prompt[3].contains("dev@example.test"),
        "{}",
        prompt[3]
    );
    assert!(!prompt[3].contains("SYNTHETICSYNTHETIC"), "{}", prompt[3]);
    assert_eq!(prompt[6], "a-51c2");
    assert_eq!(prompt[7], "/Users/test/.cli-agent/a-51c2.jsonl");
    let decline = &agent_rows[1];
    assert_eq!(decline[1], "command");
    assert_eq!(decline[2], "denied_by_user");
    assert_eq!(decline[3], "rm -rf build/");
    assert!(decline[4].contains("unconfirmed"));
    assert!(!db_files_contain(&dir, "FORGED"));
    assert!(stderr.contains("agent_kept=3"), "{stderr}");
    if Path::new("/usr/bin/nc").exists() {
        assert!(stderr.contains("agent_refused=1"), "{stderr}");
    }
    // The hook's own run is kept, marked internal (hidden by default in the dashboard).
    let db = Store::open_read_only(only_segment(&store).unwrap()).unwrap();
    let hook_flags: String = db
        .connection()
        .query_row(
            "SELECT flags FROM events WHERE source = 'os' AND target = 'hook'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(hook_flags, "tool_internal");
    let verify = verify_dir(&store).unwrap();
    assert_eq!(verify.broken, None);
}

fn audit_ask(socket: &Path, line: &str) -> serde_json::Value {
    use std::io::BufRead;
    let mut c = std::os::unix::net::UnixStream::connect(socket).unwrap();
    c.write_all(line.as_bytes()).unwrap();
    let mut reply = String::new();
    std::io::BufReader::new(&mut c)
        .read_line(&mut reply)
        .unwrap();
    serde_json::from_str(&reply).unwrap()
}

#[test]
fn the_api_appends_through_the_collector_after_the_old_log_is_imported() {
    // This test process plays the installed API (ADR-013 Decision 3).
    let tmp = TempDir::new("audit");
    let db = tmp.path("audit").join("audit.db");
    let old = tmp.path("old-audit.db");
    {
        let mut log = thadam_store::AuditDb::open(&old).unwrap();
        log.append(
            "0193b000-0000-7000-8000-000000000001",
            1,
            "dev",
            "sign_in",
            "",
            "succeeded",
        )
        .unwrap();
        log.append(
            "0193b000-0000-7000-8000-000000000002",
            2,
            "dev",
            "search",
            "",
            "succeeded",
        )
        .unwrap();
    }
    let import = Command::new(BIN)
        .args(["import-audit", "--from"])
        .arg(&old)
        .arg("--audit-db")
        .arg(&db)
        .output()
        .unwrap();
    assert!(
        import.status.success(),
        "{}",
        String::from_utf8_lossy(&import.stderr)
    );
    assert!(String::from_utf8_lossy(&import.stdout).contains("2 audit entries copied"));
    // Once only.
    let again = Command::new(BIN)
        .args(["import-audit", "--from"])
        .arg(&old)
        .arg("--audit-db")
        .arg(&db)
        .output()
        .unwrap();
    assert!(!again.status.success());

    let socket = tmp.path("sock").join("audit.sock");
    let mut child = Command::new(BIN)
        .args(["run", "--source", "stdin", "--registry"])
        .arg(tmp.path("registry.json"))
        .arg("--store")
        .arg(tmp.path("store"))
        .arg("--audit-socket")
        .arg(&socket)
        .arg("--audit-db")
        .arg(&db)
        .arg("--api-bin")
        .arg(std::env::current_exe().unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !socket.exists() {
        assert!(std::time::Instant::now() < deadline, "no audit socket");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let reply = audit_ask(
        &socket,
        "{\"contract\":\"thadam.audit-append.v1\",\"actor\":\"dev\",\"action\":\"export\",\"target\":\"0193b000-0000-7000-8000-0000000000e1\",\"outcome\":\"succeeded\"}\n",
    );
    assert_eq!(reply["seq"], 3);
    // Another program is refused; nothing is written.
    let refused = Command::new("/usr/bin/nc")
        .args(["-U"])
        .arg(&socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut nc| {
            nc.stdin
                .take()
                .unwrap()
                .write_all(b"{\"contract\":\"thadam.audit-append.v1\",\"ping\":true}\n")?;
            nc.wait_with_output()
        })
        .unwrap();
    assert!(String::from_utf8_lossy(&refused.stdout).contains("refused"));
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let log = thadam_store::AuditDb::open_read_only(&db).unwrap();
    assert_eq!(log.len().unwrap(), 3);
    assert_eq!(log.verify().unwrap().broken_at, None);
    assert_eq!(log.entries().unwrap()[2].action, "export");
}
