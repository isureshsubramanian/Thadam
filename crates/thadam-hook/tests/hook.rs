//! The hook as the tools run it: payload in, one line out, and the program itself silent
//! and quick whatever happens. All data is synthetic.
// Integration tests: unwrap/expect are allowed here, not in library code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PROMPT: &str = r#"{"session_id":"a-1","prompt_id":"p-1","hook_event_name":"UserPromptSubmit","prompt":"hello"}"#;

#[test]
fn handle_maps_or_drops() {
    let line = thadam_hook::handle("claude_code", PROMPT.as_bytes()).unwrap();
    assert!(line.contains(r#""kind":"prompt""#));
    assert_eq!(thadam_hook::handle("no_such_tool", PROMPT.as_bytes()), None);
    assert_eq!(thadam_hook::handle("claude_code", b"not json"), None);
    // A large tool output is read and dropped; the event still gets through.
    let big_output = format!(
        r#"{{"session_id":"a-1","hook_event_name":"PostToolUse","tool_name":"Read","tool_input":{{"file_path":"/Users/dev/a.txt"}},"tool_response":"{}"}}"#,
        "x".repeat(4 * 1024 * 1024)
    );
    let line = thadam_hook::handle("claude_code", big_output.as_bytes()).unwrap();
    assert!(line.len() < 400);
    // A prompt over the message limit is dropped (validation), as is a payload over the read
    // limit.
    let huge_prompt = format!(
        r#"{{"session_id":"a-1","hook_event_name":"UserPromptSubmit","prompt":"{}"}}"#,
        "x".repeat(2 * 1024 * 1024)
    );
    assert_eq!(
        thadam_hook::handle("claude_code", huge_prompt.as_bytes()),
        None
    );
    let too_big = vec![b' '; thadam_hook::MAX_PAYLOAD + 1];
    assert_eq!(thadam_hook::handle("claude_code", &too_big), None);
    let long_id = PROMPT.replace("a-1", &"a".repeat(500));
    assert_eq!(thadam_hook::handle("claude_code", long_id.as_bytes()), None);
}

#[test]
fn send_delivers_one_line_and_gives_up_quietly_when_nobody_listens() {
    let dir = std::env::temp_dir().join(format!("thadam-hook-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("agent.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let line = thadam_hook::handle("claude_code", PROMPT.as_bytes()).unwrap();
    // A collector that acknowledges, as the real one does once it knows the sender.
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"\n").unwrap();
        let mut got = String::new();
        BufReader::new(stream).read_line(&mut got).unwrap();
        (got, listener)
    });
    thadam_hook::send(&path, &line).unwrap();
    let (got, listener) = server.join().unwrap();
    assert_eq!(got.trim_end(), line);
    // One that never acknowledges: the hook gives up within its budget.
    let silent = std::thread::spawn({
        let path = path.clone();
        move || {
            let _ = std::fs::remove_file(&path);
            let l = UnixListener::bind(&path).unwrap();
            let (s, _) = l.accept().unwrap();
            std::thread::sleep(Duration::from_millis(400));
            drop(s);
        }
    });
    drop(listener);
    std::thread::sleep(Duration::from_millis(50));
    let start = Instant::now();
    assert_eq!(thadam_hook::send(&path, &line), None);
    assert!(
        start.elapsed() < Duration::from_millis(350),
        "{:?}",
        start.elapsed()
    );
    silent.join().unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(thadam_hook::send(&path, &line), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_program_exits_0_with_no_output_and_quickly() {
    // The real socket path is not ours to create; with or without a collector there, the
    // program must behave the same.
    // The first run of a newly built file includes the OS's one-time check of it (measured
    // at about 340 ms here, 15 Nov 2026); time only later runs, as the tools see them.
    Command::new(env!("CARGO_BIN_EXE_thadam-hook"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    for args in [
        &["--tool", "claude_code"][..],
        &["--tool", "no_such_tool"][..],
        &["--tool"][..],
        &[][..],
    ] {
        for input in [PROMPT.as_bytes(), b"garbage".as_slice()] {
            let start = Instant::now();
            let mut child = Command::new(env!("CARGO_BIN_EXE_thadam-hook"))
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(input).unwrap();
            let out = child.wait_with_output().unwrap();
            let took = start.elapsed();
            assert!(out.status.success(), "{args:?}");
            assert!(out.stdout.is_empty() && out.stderr.is_empty(), "{args:?}");
            // ADR-011 Tests: under 50 ms (generous for a debug build on a busy machine).
            assert!(took < Duration::from_millis(250), "{args:?} took {took:?}");
        }
    }
}
