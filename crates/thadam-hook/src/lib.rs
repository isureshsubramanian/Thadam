//! `thadam-hook`: run by an AI tool on each hook event (ADR-011 Decision 2). Reads the
//! event from stdin, keeps only what Decision 4 allows, and sends one `thadam.agent.v1`
//! line to the collector. It always exits 0 and writes nothing to stderr. It writes to
//! stdout only to refuse a call that Thadam's guard blocks (ADR-018); with the guard off
//! for the tool, it cannot block, deny or change what the tool does.

pub mod adapters;
pub mod guard;
pub mod install;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Time allowed to hand the line to the collector (ADR-011 Decision 2).
pub const SEND_BUDGET: Duration = Duration::from_millis(200);

/// Largest hook payload read. Larger than the 1 MiB the message itself may carry
/// (`MAX_TARGET_INPUT`): a finished call's payload includes the tool's whole output, which
/// is dropped, and losing that event would make the call look as if it never ran. An
/// estimate; the largest output seen in the probe was 29,876 bytes.
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// What the hook does with one payload.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reply {
    /// The tool's refusal, printed to stdout, when the guard blocks the call.
    pub stdout: Option<String>,
    /// The line for the collector.
    pub line: Option<String>,
}

/// Maps one hook payload to the reply. Nothing at all for an unknown tool or event, not
/// JSON, too large, or a field out of range. `home` expands `~/` in the call's paths.
pub fn run(
    tool: &str,
    payload: &[u8],
    registry: &dyn Fn() -> guard::Registry,
    home: Option<&str>,
    resolve: &mut dyn FnMut(&str) -> guard::Resolved,
) -> Reply {
    if payload.len() > MAX_PAYLOAD {
        return Reply::default();
    }
    let Some(adapter) = adapters::by_key(tool) else {
        return Reply::default();
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return Reply::default();
    };
    let Some(mut message) = (adapter.parse)(&value) else {
        return Reply::default();
    };
    // The guard decides before validation, so a call too large to record is still refused
    // (review D); such a call then has no line for the collector.
    let cwd = value.get("cwd").and_then(serde_json::Value::as_str);
    let mut stdout = None;
    if let Some(d) = guard::check(
        &message,
        cwd,
        home,
        registry,
        adapter.deny.is_some(),
        resolve,
    ) {
        if d.result == thadam_core::GuardResult::Blocked
            && let (Some(deny), Some(path)) = (adapter.deny, d.path.as_deref())
        {
            stdout = Some(deny(&guard::reason(path)));
        }
        message.guard = Some(d.result);
    }
    let line = garde::Validate::validate(&message)
        .ok()
        .and_then(|()| serde_json::to_string(&message).ok());
    Reply { stdout, line }
}

/// The collector line for one payload, without the guard (the line `run` sends when the
/// guard is off).
pub fn handle(tool: &str, payload: &[u8]) -> Option<String> {
    let mut as_written = |p: &str| guard::Resolved::Path(p.to_string());
    run(
        tool,
        payload,
        &|| guard::Registry::Missing,
        None,
        &mut as_written,
    )
    .line
}

/// Reads at most one byte more than the limit, so an oversized payload is seen as such.
pub fn read_payload(input: impl Read) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let limit = u64::try_from(MAX_PAYLOAD).ok()?.saturating_add(1);
    input.take(limit).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Sends one line, then waits for the collector's one-byte acknowledgement before closing.
/// Any failure (collector down, slow, refused) loses the line silently.
///
/// ORDERING (the other side is `AgentListener::serve` in the collector): the collector asks
/// the kernel who is connected before it acknowledges, so this process must still be
/// connected then; closing straight after writing could make the line unattributable.
pub fn send(socket: &Path, line: &str) -> Option<()> {
    let started = std::time::Instant::now();
    let mut stream = UnixStream::connect(socket).ok()?;
    stream.set_write_timeout(Some(SEND_BUDGET)).ok()?;
    stream.write_all(line.as_bytes()).ok()?;
    stream.write_all(b"\n").ok()?;
    stream.flush().ok()?;
    let left = SEND_BUDGET.checked_sub(started.elapsed())?;
    stream
        .set_read_timeout(Some(left.max(Duration::from_millis(1))))
        .ok()?;
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).ok()
}
