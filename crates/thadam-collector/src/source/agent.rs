//! Agent messages attributed to the kernel-reported sender (ADR-011 Decision 3).

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::peer::{exe_of, peer_of};
use garde::Validate;

/// JSON overhead allowance is an estimate.
const MAX_LINE: usize = thadam_core::model::MAX_TARGET_INPUT + 64 * 1024;
/// The hook sends one line; these connection budgets are estimates.
const MAX_LINES: usize = 16;
const READ_TIMEOUT: Duration = Duration::from_secs(2);
/// Connections read at once (ADR-015 Decision 2; estimate: a few tools, each with short-lived
/// hook calls). Over that, a new connection is closed unread.
pub const MAX_CONNECTIONS: usize = 32;

use thadam_core::AgentMessage;
use time::OffsetDateTime;

/// The sending process, from the socket itself (never from the message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub pid: u32,
    pub pidversion: u32,
}

/// Why a line was not accepted. Counts only, for the stats line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AgentReject {
    /// The socket could not say who sent it.
    NoPeer,
    TooLong,
    /// Not UTF-8, not JSON, or not a `thadam.agent.v1` message.
    Malformed,
    /// A valid message whose fields fail validation.
    Invalid,
    /// Sent by a program other than the installed hook; closed before anything was read.
    NotHook,
    /// `MAX_CONNECTIONS` were already open; closed before anything was read.
    Busy,
}

impl AgentReject {
    pub fn name(self) -> &'static str {
        match self {
            AgentReject::NoPeer => "no_peer",
            AgentReject::TooLong => "too_long",
            AgentReject::Malformed => "malformed",
            AgentReject::Invalid => "invalid",
            AgentReject::NotHook => "not_hook",
            AgentReject::Busy => "busy",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentItem {
    Message {
        peer: Peer,
        /// When the collector read the line (UTC).
        received: OffsetDateTime,
        message: Box<AgentMessage>,
    },
    Rejected(AgentReject),
}

#[derive(Debug)]
pub struct AgentListener {
    listener: UnixListener,
    path: PathBuf,
    hook_bin: PathBuf,
}

impl AgentListener {
    /// Binds the socket. `hook_bin` is the only program whose messages are read (ADR-015
    /// Decision 2); it is compared as the kernel reports the sender's executable.
    pub fn bind(path: impl AsRef<Path>, hook_bin: &Path) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let listener = bind_owned_socket(&path, "agent socket")?;
        let hook_bin = hook_bin
            .canonicalize()
            .unwrap_or_else(|_| hook_bin.to_path_buf());
        Ok(Self {
            listener,
            path,
            hook_bin,
        })
    }

    pub fn serve<F>(self, send: F)
    where
        F: Fn(AgentItem) -> bool + Clone + Send + 'static,
    {
        let open = Arc::new(AtomicUsize::new(0));
        for stream in self.listener.incoming() {
            let Ok(stream) = stream else { continue };
            // ORDERING (the other side is `thadam_hook::send`): the sender's identity is read
            // while it waits for the acknowledgement below, so it is still connected. A
            // sender that writes and closes at once could be gone before the kernel is asked.
            let peer = match peer_of(&stream) {
                Ok(peer) => peer,
                Err(_) => {
                    if !send(AgentItem::Rejected(AgentReject::NoPeer)) {
                        return;
                    }
                    continue;
                }
            };
            // Checked before a thread starts or a byte is read, so neither another program nor
            // a flood of connections costs more than this check. Closed unanswered.
            let refused = if !exe_of(peer.pid).is_ok_and(|exe| exe == self.hook_bin) {
                Some(AgentReject::NotHook)
            } else if open.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
                open.fetch_sub(1, Ordering::AcqRel);
                Some(AgentReject::Busy)
            } else {
                None
            };
            if let Some(reason) = refused {
                drop(stream);
                if !send(AgentItem::Rejected(reason)) {
                    return;
                }
                continue;
            }
            let send = send.clone();
            let open = Arc::clone(&open);
            std::thread::spawn(move || {
                let _slot = Slot(open);
                // ORDERING: the read timeout is set before the acknowledgement, while the
                // sender is still waiting for it. The sender closes as soon as it has the
                // acknowledgement, and macOS refuses socket options on a connection its peer
                // has closed, so setting it afterwards lost the message whenever the sender
                // won that race (its line is still buffered and readable).
                if stream.set_read_timeout(Some(READ_TIMEOUT)).is_err() {
                    return;
                }
                // The acknowledgement: one byte, after the identity is known.
                if (&stream).write_all(&[ACK]).is_ok() {
                    read_connection(stream, peer, &send);
                }
            });
        }
    }
}

/// One of `MAX_CONNECTIONS`, given back when its thread ends however it ends.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for AgentListener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Binds a socket anyone may connect to (0666) in a folder only this process may change:
/// created 0755 if missing, refused if writable by others or owned by someone else. A stale
/// socket at the path is replaced; any other file there is refused. `what` names the socket
/// in errors. Shared by the agent and audit sockets.
pub(crate) fn bind_owned_socket(path: &Path, what: &str) -> io::Result<UnixListener> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{what} needs a folder"),
            )
        })?;
    if !dir.exists() {
        DirBuilder::new().recursive(true).mode(0o755).create(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
    }
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{what} folder must not be writable by others"),
        ));
    }
    // A newly created file has our effective uid, without a second unsafe interface.
    let probe = dir.join(format!(".owner-{}", uuid::Uuid::now_v7()));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)?;
    let owner = file.metadata().map(|m| m.uid());
    fs::remove_file(&probe)?;
    if meta.uid() != owner? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{what} folder must be owned by this process"),
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{what} path exists and is not a socket"),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

/// Sent once the sender's identity has been read (see `serve`).
pub const ACK: u8 = b'\n';

/// Reads the sender's lines; the caller has set the read timeout (see `serve`).
fn read_connection(stream: UnixStream, peer: Peer, send: &impl Fn(AgentItem) -> bool) {
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    for _ in 0..MAX_LINES {
        let item = match read_line_limited(&mut reader, &mut buf, MAX_LINE) {
            Ok(Line::End) | Err(_) => return,
            Ok(Line::TooLong) => AgentItem::Rejected(AgentReject::TooLong),
            Ok(Line::Done) => match std::str::from_utf8(&buf) {
                Ok(text) if text.trim().is_empty() => continue,
                Ok(text) => match serde_json::from_str::<AgentMessage>(text) {
                    Err(_) => AgentItem::Rejected(AgentReject::Malformed),
                    Ok(message) if message.validate().is_err() => {
                        AgentItem::Rejected(AgentReject::Invalid)
                    }
                    Ok(message) => AgentItem::Message {
                        peer,
                        received: OffsetDateTime::now_utc(),
                        message: Box::new(message),
                    },
                },
                Err(_) => AgentItem::Rejected(AgentReject::Malformed),
            },
        };
        if !send(item) {
            return;
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Line {
    /// A line is in the buffer, without its newline.
    Done,
    /// A line over the limit was read and thrown away.
    TooLong,
    End,
}

/// Reads one line into `buf`, keeping at most `max` bytes in memory however long it is. Shared
/// by the agent, flow and audit sockets.
pub(crate) fn read_line_limited(
    reader: &mut impl BufRead,
    buf: &mut Vec<u8>,
    max: usize,
) -> io::Result<Line> {
    buf.clear();
    let mut too_long = false;
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            return Ok(match (too_long, buf.is_empty()) {
                (true, _) => Line::TooLong,
                (false, true) => Line::End,
                // A last line without a newline still counts.
                (false, false) => Line::Done,
            });
        }
        let (part, found) = match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => (&chunk[..i], Some(i + 1)),
            None => (chunk, None),
        };
        if !too_long {
            if buf.len() + part.len() > max {
                too_long = true;
                buf.clear();
            } else {
                buf.extend_from_slice(part);
            }
        }
        let used = found.unwrap_or(chunk.len());
        reader.consume(used);
        if found.is_some() {
            return Ok(if too_long { Line::TooLong } else { Line::Done });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::mpsc;

    /// The test binary stands in for the hook.
    fn me() -> PathBuf {
        std::env::current_exe().unwrap()
    }

    fn folder() -> PathBuf {
        std::env::temp_dir().join(format!("ta-{:08x}", uuid::Uuid::now_v7().as_u128() as u32))
    }

    #[test]
    fn bind_permissions_and_cleanup() {
        let dir = folder();
        let path = dir.join("agent.sock");
        let listener = AgentListener::bind(&path, &me()).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o755);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o666);
        drop(listener);
        assert!(!path.exists());
        let stale = UnixListener::bind(&path).unwrap();
        drop(stale);
        drop(AgentListener::bind(&path, &me()).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_writable_folder_and_plain_file() {
        let dir = folder();
        fs::create_dir(&dir).unwrap();
        let path = dir.join("agent.sock");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(
            AgentListener::bind(&path, &me()).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&path, b"keep").unwrap();
        assert_eq!(
            AgentListener::bind(&path, &me()).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&path).unwrap(), b"keep");
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn messages_and_rejections() {
        let dir = folder();
        let path = dir.join("agent.sock");
        let listener = AgentListener::bind(&path, &me()).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || listener.serve(move |item| tx.send(item).is_ok()));
        let message =
            AgentMessage::new("tool-a", thadam_core::agent::AgentKind::Prompt, "session-1");
        let valid = serde_json::to_string(&message).unwrap();
        let cases = [
            (b"garbage".to_vec(), AgentReject::Malformed),
            (vec![0xff], AgentReject::Malformed),
            (
                valid
                    .replace("thadam.agent.v1", "thadam.agent.v0")
                    .into_bytes(),
                AgentReject::Invalid,
            ),
            (
                valid.replace("session-1", "").into_bytes(),
                AgentReject::Invalid,
            ),
            (
                valid.replace('}', ",\"unknown\":1}").into_bytes(),
                AgentReject::Malformed,
            ),
            (vec![b'x'; MAX_LINE + 1], AgentReject::TooLong),
        ];
        let mut client = UnixStream::connect(&path).unwrap();
        writeln!(client, "{valid}").unwrap();
        wait_ack(&mut client);
        let item = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let AgentItem::Message {
            peer, message: got, ..
        } = item
        else {
            panic!("missing message")
        };
        assert_eq!(peer.pid, std::process::id());
        assert_ne!(peer.pidversion, 0);
        assert_eq!(*got, message);
        drop(client);
        for (line, reason) in cases {
            let mut client = UnixStream::connect(&path).unwrap();
            client.write_all(&line).unwrap();
            client.write_all(b"\n").unwrap();
            // As the hook does: wait for the acknowledgement, then close.
            wait_ack(&mut client);
            drop(client);
            let got = rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|e| panic!("no item for the {reason:?} case: {e}"));
            assert_eq!(got, AgentItem::Rejected(reason));
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn another_program_is_closed_unread() {
        let dir = folder();
        let path = dir.join("agent.sock");
        let listener = AgentListener::bind(&path, Path::new("/usr/bin/true")).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || listener.serve(move |item| tx.send(item).is_ok()));
        let message =
            AgentMessage::new("tool-a", thadam_core::agent::AgentKind::Prompt, "session-1");
        let mut client = UnixStream::connect(&path).unwrap();
        // Before the collector can close it: macOS refuses options on a closed connection.
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let _ = writeln!(client, "{}", serde_json::to_string(&message).unwrap());
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            AgentItem::Rejected(AgentReject::NotHook)
        );
        // No acknowledgement: the connection is closed.
        assert!(matches!(client.read(&mut [0]), Ok(0) | Err(_)));
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_connection_over_the_limit_is_closed() {
        let dir = folder();
        let path = dir.join("agent.sock");
        let listener = AgentListener::bind(&path, &me()).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || listener.serve(move |item| tx.send(item).is_ok()));
        // Each held open and silent, so each keeps its slot until its read times out.
        let mut held: Vec<UnixStream> = (0..MAX_CONNECTIONS)
            .map(|_| {
                let mut c = UnixStream::connect(&path).unwrap();
                wait_ack(&mut c);
                c
            })
            .collect();
        let mut over = UnixStream::connect(&path).unwrap();
        over.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            AgentItem::Rejected(AgentReject::Busy)
        );
        assert!(matches!(over.read(&mut [0]), Ok(0) | Err(_)));
        // A slot given back is free again.
        drop(held.pop());
        std::thread::sleep(Duration::from_millis(100));
        let mut again = UnixStream::connect(&path).unwrap();
        wait_ack(&mut again);
        drop(held);
        fs::remove_dir_all(dir).unwrap();
    }

    fn wait_ack(client: &mut UnixStream) {
        let mut ack = [0u8; 1];
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        std::io::Read::read_exact(client, &mut ack).unwrap();
        assert_eq!(ack[0], ACK);
    }

    #[test]
    fn idle_connection_times_out_while_another_is_read() {
        let dir = folder();
        fs::create_dir(&dir).unwrap();
        let path = dir.join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let mut idle = UnixStream::connect(&path).unwrap();
        let (stream, _) = listener.accept().unwrap();
        // As `serve` does before acknowledging.
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        let peer = Peer {
            pid: std::process::id(),
            pidversion: 1,
        };
        let worker = std::thread::spawn(move || read_connection(stream, peer, &|_| true));
        let mut active = UnixStream::connect(&path).unwrap();
        let (stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        let (tx, rx) = mpsc::channel();
        let other = std::thread::spawn(move || {
            read_connection(stream, peer, &|item| tx.send(item).is_ok())
        });
        writeln!(active, "garbage").unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            AgentItem::Rejected(AgentReject::Malformed)
        );
        drop(active);
        idle.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(idle.read(&mut [0]).unwrap(), 0);
        worker.join().unwrap();
        other.join().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
