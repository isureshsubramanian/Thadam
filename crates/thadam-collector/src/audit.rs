//! The audit socket: the API asks, the collector writes `audit.db` (ADR-013 Decision 3).
//!
//! The log lives in a root-owned folder, so a program running as the user can read it but
//! neither change nor delete it, as with the event store. Only the installed API may append:
//! the kernel says which process is connected, and its executable must be the installed one.
//! The installed API sits in a root-owned folder, so no user-level program can replace it.
//! A user-level program that starts that same API can still add entries (with the API's own
//! checks), but nothing can take one away.
//!
//! One request per connection, served one at a time: a single writer, and a few requests a
//! minute (estimate).

use std::fs::{self, DirBuilder};
use std::io::{self, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use thadam_core::{AuditCommand, AuditError, AuditReply, AuditRequest, MAX_AUDIT_LINE};
use thadam_store::{AuditDb, StoreError};

use crate::peer::{exe_of, peer_of};
use crate::run::now_us;
use crate::source::agent::{Line, bind_owned_socket, read_line_limited};

/// How long one client may take to send its line or read the reply (estimate).
const IO_TIMEOUT: Duration = Duration::from_secs(2);

pub struct AuditListener {
    listener: UnixListener,
    path: PathBuf,
    db: AuditDb,
    api_bin: PathBuf,
}

impl AuditListener {
    /// Opens (or creates) the log, then binds the socket. `api_bin` is the only program whose
    /// requests are accepted.
    pub fn bind(socket: &Path, db: &Path, api_bin: &Path) -> Result<Self, StoreError> {
        let db = open_log(db)?;
        // Compared resolved, as the kernel reports the resolved path.
        let api_bin = api_bin
            .canonicalize()
            .unwrap_or_else(|_| api_bin.to_path_buf());
        let listener = bind_owned_socket(socket, "audit socket")?;
        Ok(Self {
            listener,
            path: socket.to_path_buf(),
            db,
            api_bin,
        })
    }

    pub fn serve(mut self) {
        loop {
            let Ok((stream, _)) = self.listener.accept() else {
                continue;
            };
            let reply = self.answer(&stream);
            let _ = write_reply(&stream, &reply);
        }
    }

    fn answer(&mut self, stream: &UnixStream) -> AuditReply {
        let error = |error| AuditReply::Error { error };
        // ORDERING: the request is read first, so a refused sender gets its reply instead of
        // a connection closed while it writes. It then waits for the reply, so it is still
        // alive while its identity is read.
        let command = read_request(stream);
        let from_api = peer_of(stream)
            .and_then(|p| exe_of(p.pid))
            .is_ok_and(|exe| exe == self.api_bin);
        if !from_api {
            crate::diag!(
                "thadam-collector: audit request refused: sender is not the installed API"
            );
            return error(AuditError::Refused);
        }
        let Some(command) = command else {
            return error(AuditError::Invalid);
        };
        match command {
            AuditCommand::Ping => AuditReply::Pong { ok: true },
            AuditCommand::Append {
                actor,
                action,
                target,
                outcome,
            } => {
                let id = uuid::Uuid::now_v7().to_string();
                match self
                    .db
                    .append(&id, now_us(), &actor, &action, &target, &outcome)
                {
                    Ok(row) => AuditReply::Appended {
                        seq: row.seq,
                        audit_id: row.audit_id,
                        ts_us: row.ts_us,
                    },
                    Err(e) => {
                        // The error names files and sequence numbers only, never fields.
                        crate::diag!("thadam-collector: cannot write the audit log: {e}");
                        error(AuditError::Unavailable)
                    }
                }
            }
        }
    }
}

impl Drop for AuditListener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Opens the log, creating its folder (0755) and file (0644) when missing: readable by the
/// API, writable by the collector only.
pub fn open_log(db: &Path) -> Result<AuditDb, StoreError> {
    if let Some(dir) = db.parent().filter(|d| !d.as_os_str().is_empty())
        && !dir.exists()
    {
        DirBuilder::new().recursive(true).mode(0o755).create(dir)?;
    }
    let log = AuditDb::open(db)?;
    fs::set_permissions(db, fs::Permissions::from_mode(0o644))?;
    Ok(log)
}

fn read_request(stream: &UnixStream) -> Option<AuditCommand> {
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    match read_line_limited(&mut reader, &mut buf, MAX_AUDIT_LINE).ok()? {
        Line::Done => {}
        Line::TooLong | Line::End => return None,
    }
    serde_json::from_slice::<AuditRequest>(&buf).ok()?.command()
}

fn write_reply(mut stream: &UnixStream, reply: &AuditReply) -> io::Result<()> {
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut line = serde_json::to_vec(reply).map_err(io::Error::other)?;
    line.push(b'\n');
    stream.write_all(&line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Read};

    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Self {
            let d = std::env::temp_dir()
                .join(format!("tau-{:08x}", uuid::Uuid::now_v7().as_u128() as u32));
            std::fs::create_dir(&d).unwrap();
            Self(d)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn start(dir: &Dir, api_bin: &Path) -> PathBuf {
        let socket = dir.0.join("s").join("audit.sock");
        let listener =
            AuditListener::bind(&socket, &dir.0.join("log").join("audit.db"), api_bin).unwrap();
        std::thread::spawn(move || listener.serve());
        socket
    }

    fn ask(socket: &Path, line: &str) -> String {
        let mut c = UnixStream::connect(socket).unwrap();
        c.write_all(line.as_bytes()).unwrap();
        let mut reply = String::new();
        BufReader::new(&mut c).read_line(&mut reply).unwrap();
        let mut rest = Vec::new();
        assert_eq!(
            c.read_to_end(&mut rest).unwrap(),
            0,
            "one reply, then closed"
        );
        reply
    }

    const APPEND: &str = r#"{"contract":"thadam.audit-append.v1","actor":"dev","action":"search","target":"","outcome":"succeeded"}
"#;

    #[test]
    fn the_installed_api_appends_and_pings() {
        let dir = Dir::new();
        let socket = start(&dir, &std::env::current_exe().unwrap());
        assert_eq!(
            ask(
                &socket,
                "{\"contract\":\"thadam.audit-append.v1\",\"ping\":true}\n"
            ),
            "{\"ok\":true}\n"
        );
        let first: serde_json::Value = serde_json::from_str(&ask(&socket, APPEND)).unwrap();
        let second: serde_json::Value = serde_json::from_str(&ask(&socket, APPEND)).unwrap();
        assert_eq!(
            (first["seq"].as_i64(), second["seq"].as_i64()),
            (Some(1), Some(2))
        );
        assert!(first["auditId"].as_str().is_some_and(|id| id.len() == 36));
        assert!(first["tsUs"].as_i64().is_some_and(|t| t > 0));
        assert_eq!(ask(&socket, "not json\n"), "{\"error\":\"invalid\"}\n");
        assert_eq!(
            ask(&socket, &APPEND.replace("search", "drop")),
            "{\"error\":\"invalid\"}\n"
        );
        let log = AuditDb::open_read_only(dir.0.join("log").join("audit.db")).unwrap();
        assert_eq!(log.len().unwrap(), 2);
        assert_eq!(log.verify().unwrap().broken_at, None);
        let mode = std::fs::metadata(dir.0.join("log").join("audit.db"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[test]
    fn any_other_program_is_refused_and_nothing_is_written() {
        let dir = Dir::new();
        let socket = start(&dir, Path::new("/usr/bin/true"));
        assert_eq!(ask(&socket, APPEND), "{\"error\":\"refused\"}\n");
        let log = AuditDb::open_read_only(dir.0.join("log").join("audit.db")).unwrap();
        assert!(log.is_empty().unwrap());
    }
}
