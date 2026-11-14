//! `thadam-hook`: run by an AI tool on each hook event (ADR-011 Decision 2). Reads the
//! event from stdin, keeps only what Decision 4 allows, and sends one `thadam.agent.v1`
//! line to the collector. It never writes to stdout or stderr and always exits 0, so it
//! cannot block, deny or change what the tool does.

pub mod adapters;
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

/// Maps one hook payload to the line to send, or `None` when there is nothing to send
/// (unknown tool or event, not JSON, too large, or a field out of range).
pub fn handle(tool: &str, payload: &[u8]) -> Option<String> {
    if payload.len() > MAX_PAYLOAD {
        return None;
    }
    let adapter = adapters::by_key(tool)?;
    let value: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let message = (adapter.parse)(&value)?;
    garde::Validate::validate(&message).ok()?;
    serde_json::to_string(&message).ok()
}

/// Reads at most one byte more than the limit, so an oversized payload is seen as such.
pub fn read_payload(input: impl Read) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let limit = u64::try_from(MAX_PAYLOAD).ok()?.saturating_add(1);
    input.take(limit).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Sends one line; any failure (collector down, slow, refused) loses the line silently.
pub fn send(socket: &Path, line: &str) -> Option<()> {
    let mut stream = UnixStream::connect(socket).ok()?;
    stream.set_write_timeout(Some(SEND_BUDGET)).ok()?;
    stream.write_all(line.as_bytes()).ok()?;
    stream.write_all(b"\n").ok()?;
    stream.flush().ok()
}
