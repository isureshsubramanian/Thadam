//! Collector acceptance tests (ADR-003) through the real binary and a real store.
//! All data is synthetic: example identities, `/Users/test/` paths, made-up values.
// Integration tests: unwrap/expect are allowed here (helpers included), not in library code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use thadam_store::Store;

const BIN: &str = env!("CARGO_BIN_EXE_thadam-collector");
const ENV_MARKER: &str = "SYNTHETIC-ENV-MARKER-7c41";

const REGISTRY: &str = r#"{
  "version": 1,
  "tools": [
    { "key": "cli_agent",
      "match": [ { "team_id": "TEAM000001", "signing_id": "com.example.cli-agent" } ],
      "state_dirs": [ "~/.cli-agent/" ] },
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
    let identity = if signed {
        r#""team_id":"TEAM000001","signing_id":"com.example.cli-agent""#
    } else {
        r#""team_id":"","signing_id":"com.example.other""#
    };
    format!(
        r#"{{"audit_token":{{"pid":{pid},"pidversion":1,"euid":501}},"ppid":{ppid},"original_ppid":{ppid},"responsible_audit_token":{{"pid":{pid},"pidversion":1}},"executable":{{"path":"{exe}","path_truncated":false}},{identity},"is_platform_binary":false,"start_time":"2026-11-14T09:30:00.000000Z"}}"#
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
    lines.join("\n") + "\n"
}

fn run_stdin(dir: &TempDir, input: &str, extra: &[&str]) -> (std::process::Output, PathBuf) {
    let db = dir.path("events.db");
    let mut child = Command::new(BIN)
        .args(["run", "--source", "stdin", "--registry"])
        .arg(dir.path("registry.json"))
        .arg("--store")
        .arg(&db)
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
    (child.wait_with_output().unwrap(), db)
}

/// (category, action, target, count, flags, detections) in seq order.
fn rows(db: &Path) -> Vec<(String, String, String, i64, String, String)> {
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
    std::fs::read_dir(&dir.0).unwrap().any(|entry| {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        name.starts_with("events.db")
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
    let db = dir.path("events.db");
    let mut child = Command::new(BIN)
        .args(["run", "--source", "stdin", "--registry"])
        .arg(dir.path("registry.json"))
        .arg("--store")
        .arg(&db)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Keep stdin open so the run can only end through the signal.
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(sample_stream().as_bytes()).unwrap();
    stdin.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
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
    assert!(rows(&db).iter().any(|r| r.3 == 47));
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
