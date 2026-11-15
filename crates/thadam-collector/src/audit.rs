//! The audit socket: the API asks, the collector writes `audit.db` (ADR-013 Decision 3) and
//! decides who is signed in (ADR-015 Decision 1).
//!
//! The log lives in a root-owned folder, so a program running as the user can read it but
//! neither change nor delete it, as with the event store. Only the installed API may connect:
//! the kernel says which process is connected, and its executable must be the installed one.
//! That alone is not enough, since any program running as the user can start the installed
//! API with its own data folder. So the collector also checks the dashboard password against
//! a root-only verifier and hands out sessions; every append must carry a live one, and is
//! written as that session's actor. A program that does not know the password cannot add an
//! entry, whatever it starts.
//!
//! Sessions live in memory: they end when the collector restarts, when the password changes,
//! after `SESSION_IDLE` unused, or on sign-out. Only a hash of each token is kept.
//!
//! One request per connection, served one at a time: a single writer, and a few requests a
//! minute (estimate). So that no client can hold the socket and lock the API out (sign-in is
//! audited), the sender is identified before anything is read, another program gets its
//! refusal within `REFUSED_WAIT`, and the API has `IO_TIMEOUT` in all to send its line, not
//! per read.

use std::collections::HashMap;
use std::fs::{self, DirBuilder};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use sha2::{Digest, Sha256};
use thadam_core::{AuditCommand, AuditError, AuditReply, AuditRequest, MAX_AUDIT_LINE, Password};
use thadam_store::{AuditDb, StoreError};

use crate::credentials;

use crate::peer::{exe_of, peer_of};
use crate::run::now_us;
use crate::source::agent::{Line, bind_owned_socket, read_line_limited};

/// How long, in all, the API may take to send its line, and to read the reply (estimate).
const IO_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a refused sender's line is waited for, so that it reads its refusal rather than
/// finding the connection closed while it writes (estimate).
const REFUSED_WAIT: Duration = Duration::from_millis(200);

/// Sign-in attempts allowed before each further one must wait (ADR-015 Decision 1).
const FREE_ATTEMPTS: u32 = 5;
/// The longest wait between attempts once they are limited (estimate).
const MAX_WAIT: Duration = Duration::from_secs(300);
/// Sessions at once; the oldest is ended to make room (estimate: one browser, a few tabs).
const MAX_SESSIONS: usize = 16;

/// Where the verifier is and how sessions behave. `system()` in the daemon; tests weaken the
/// iterations and shorten the idle time.
#[derive(Debug, Clone)]
pub struct Access {
    pub credentials: PathBuf,
    pub min_iterations: u32,
    pub session_idle: Duration,
}

impl Access {
    pub fn system() -> Self {
        Self {
            credentials: PathBuf::from(thadam_core::CREDENTIALS),
            min_iterations: credentials::ITERATIONS,
            // As the API's cookie (ADR-008 Decision 2).
            session_idle: Duration::from_secs(8 * 3600),
        }
    }
}

struct Session {
    actor: String,
    last: Instant,
}

/// Wrong passwords so far, and when the last one came.
#[derive(Default)]
struct Attempts {
    failures: u32,
    last: Option<Instant>,
}

impl Attempts {
    /// How long until the next attempt may be checked, if it must wait: 2^n seconds after the
    /// last failure once `FREE_ATTEMPTS` have failed, up to `MAX_WAIT`.
    fn wait(&self, now: Instant) -> Option<Duration> {
        let extra = self.failures.checked_sub(FREE_ATTEMPTS)?;
        let delay = Duration::from_secs(1u64 << extra.min(16)).min(MAX_WAIT);
        let left = (self.last? + delay).saturating_duration_since(now);
        (!left.is_zero()).then_some(left)
    }
}

pub struct AuditListener {
    listener: UnixListener,
    path: PathBuf,
    db: AuditDb,
    api_bin: PathBuf,
    access: Access,
    /// Keyed by SHA-256 of the token, so memory never holds a usable token for long.
    sessions: HashMap<[u8; 32], Session>,
    attempts: Attempts,
    /// The verifier's last change; a new one ends every session and clears the attempts.
    stamp: Option<SystemTime>,
}

impl AuditListener {
    /// Opens (or creates) the log, then binds the socket. `api_bin` is the only program whose
    /// requests are accepted.
    pub fn bind(
        socket: &Path,
        db: &Path,
        api_bin: &Path,
        access: Access,
    ) -> Result<Self, StoreError> {
        let db = open_log(db)?;
        // Compared resolved, as the kernel reports the resolved path.
        let api_bin = api_bin
            .canonicalize()
            .unwrap_or_else(|_| api_bin.to_path_buf());
        let listener = bind_owned_socket(socket, "audit socket")?;
        let stamp = credentials::stamp(&access.credentials);
        Ok(Self {
            listener,
            path: socket.to_path_buf(),
            db,
            api_bin,
            access,
            sessions: HashMap::new(),
            attempts: Attempts::default(),
            stamp,
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
        // ORDERING: the sender is identified while it is connected, before anything is read,
        // so a program that is not the API cannot hold the socket for longer than
        // `REFUSED_WAIT`. Its line is still read (briefly), so that it is not writing into a
        // closed connection when it should be reading its refusal.
        let from_api = peer_of(stream)
            .and_then(|p| exe_of(p.pid))
            .is_ok_and(|exe| exe == self.api_bin);
        if !from_api {
            let _ = read_request(stream, REFUSED_WAIT);
            crate::diag!(
                "thadam-collector: audit request refused: sender is not the installed API"
            );
            return AuditReply::error(AuditError::Refused);
        }
        let Some(command) = read_request(stream, IO_TIMEOUT) else {
            return AuditReply::error(AuditError::Invalid);
        };
        self.notice_new_password();
        let now = Instant::now();
        match command {
            AuditCommand::Ping { session: None } => AuditReply::Pong { ok: true },
            AuditCommand::Ping {
                session: Some(token),
            } => match self.live(&token, now) {
                Some(_) => AuditReply::Pong { ok: true },
                None => AuditReply::error(AuditError::SessionEnded),
            },
            AuditCommand::SignIn { actor, password } => self.sign_in(actor, &password, now),
            AuditCommand::SignOut { session } => {
                let Some(found) = self.sessions.remove(&key(&session)) else {
                    return AuditReply::error(AuditError::SessionEnded);
                };
                self.write(&found.actor, "sign_out", "", "succeeded")
            }
            AuditCommand::Append {
                session,
                action,
                target,
                outcome,
            } => match self.live(&session, now) {
                Some(actor) => self.write(&actor, &action, &target, &outcome),
                None => AuditReply::error(AuditError::SessionEnded),
            },
        }
    }

    fn sign_in(&mut self, actor: String, password: &Password, now: Instant) -> AuditReply {
        if let Some(left) = self.attempts.wait(now) {
            // Refused unchecked, so waiting cannot be skipped by guessing faster.
            return match self.write(&actor, "sign_in", "", "denied") {
                AuditReply::Appended { .. } => AuditReply::Error {
                    error: AuditError::Wait,
                    retry_after: Some(left.as_secs() + u64::from(left.subsec_nanos() > 0)),
                },
                unavailable => unavailable,
            };
        }
        let stored = match credentials::load(&self.access.credentials) {
            Ok(stored) => stored,
            Err(e) => {
                crate::diag!(
                    "thadam-collector: cannot read the credentials file: {}",
                    e.kind()
                );
                None
            }
        };
        let Some(stored) = stored else {
            return match self.write(&actor, "sign_in", "", "failed") {
                AuditReply::Appended { .. } => AuditReply::error(AuditError::NoPassword),
                unavailable => unavailable,
            };
        };
        if !stored.verify(password.expose(), self.access.min_iterations) {
            self.attempts.failures = self.attempts.failures.saturating_add(1);
            self.attempts.last = Some(now);
            return match self.write(&actor, "sign_in", "", "failed") {
                AuditReply::Appended { .. } => AuditReply::error(AuditError::WrongPassword),
                unavailable => unavailable,
            };
        }
        let token = match credentials::new_token() {
            Ok(token) => token,
            Err(e) => {
                crate::diag!(
                    "thadam-collector: no random source for a session: {}",
                    e.kind()
                );
                return AuditReply::error(AuditError::Unavailable);
            }
        };
        // ORDERING: the entry is written before the session exists, so a sign-in that could
        // not be audited gives no session.
        match self.write(&actor, "sign_in", "", "succeeded") {
            AuditReply::Appended { .. } => {}
            unavailable => return unavailable,
        }
        self.attempts = Attempts::default();
        self.sessions
            .retain(|_, s| now.duration_since(s.last) < self.access.session_idle);
        if self.sessions.len() >= MAX_SESSIONS
            && let Some(oldest) = self
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.last)
                .map(|(k, _)| *k)
        {
            self.sessions.remove(&oldest);
        }
        self.sessions.insert(
            key(&token),
            Session {
                actor: actor.clone(),
                last: now,
            },
        );
        AuditReply::SignedIn {
            session: token,
            actor,
        }
    }

    /// The session's actor when it is live, which also keeps it alive; an idle one is ended.
    fn live(&mut self, token: &str, now: Instant) -> Option<String> {
        let k = key(token);
        let session = self.sessions.get_mut(&k)?;
        if now.duration_since(session.last) >= self.access.session_idle {
            self.sessions.remove(&k);
            return None;
        }
        session.last = now;
        Some(session.actor.clone())
    }

    /// A new password (`set-password` rewrote the file) ends every session and clears the
    /// wait, so the owner can always get back in.
    fn notice_new_password(&mut self) {
        let stamp = credentials::stamp(&self.access.credentials);
        if stamp != self.stamp {
            self.stamp = stamp;
            self.sessions.clear();
            self.attempts = Attempts::default();
        }
    }

    fn write(&mut self, actor: &str, action: &str, target: &str, outcome: &str) -> AuditReply {
        let id = uuid::Uuid::now_v7().to_string();
        match self
            .db
            .append(&id, now_us(), actor, action, target, outcome)
        {
            Ok(row) => AuditReply::Appended {
                seq: row.seq,
                audit_id: row.audit_id,
                ts_us: row.ts_us,
            },
            Err(e) => {
                // The error names files and sequence numbers only, never fields.
                crate::diag!("thadam-collector: cannot write the audit log: {e}");
                AuditReply::error(AuditError::Unavailable)
            }
        }
    }
}

fn key(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
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

/// Reads one request line, giving up once `within` has passed since the call, however the
/// sender spaces its bytes.
fn read_request(stream: &UnixStream, within: Duration) -> Option<AuditCommand> {
    let mut reader = BufReader::new(Deadline {
        stream,
        until: Instant::now() + within,
    });
    let mut buf = Vec::new();
    match read_line_limited(&mut reader, &mut buf, MAX_AUDIT_LINE).ok()? {
        Line::Done => {}
        Line::TooLong | Line::End => return None,
    }
    serde_json::from_slice::<AuditRequest>(&buf).ok()?.command()
}

/// A reader whose every read waits only for the time left before `until`.
struct Deadline<'a> {
    stream: &'a UnixStream,
    until: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        let mut stream = self.stream;
        stream.read(buf)
    }
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
    use crate::credentials::CredentialFile;
    use std::io::{BufRead, Read};

    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Self {
            let d = std::env::temp_dir()
                .join(format!("tau-{:08x}", uuid::Uuid::now_v7().as_u128() as u32));
            std::fs::create_dir(&d).unwrap();
            Self(d)
        }
        fn credentials(&self) -> PathBuf {
            self.0.join("credentials.json")
        }
        fn set_password(&self, password: &str) {
            credentials::save(
                &self.credentials(),
                &CredentialFile::create(password, 1).unwrap(),
            )
            .unwrap();
        }
        fn log(&self) -> AuditDb {
            AuditDb::open_read_only(self.0.join("log").join("audit.db")).unwrap()
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const PASSWORD: &str = "made up pass phrase";

    fn start_with(dir: &Dir, api_bin: &Path, idle: Duration) -> PathBuf {
        let socket = dir.0.join("s").join("audit.sock");
        let access = Access {
            credentials: dir.credentials(),
            min_iterations: 1,
            session_idle: idle,
        };
        let listener = AuditListener::bind(
            &socket,
            &dir.0.join("log").join("audit.db"),
            api_bin,
            access,
        )
        .unwrap();
        std::thread::spawn(move || listener.serve());
        socket
    }

    fn start(dir: &Dir) -> PathBuf {
        start_with(
            dir,
            &std::env::current_exe().unwrap(),
            Duration::from_secs(3600),
        )
    }

    fn ask(socket: &Path, line: &str) -> serde_json::Value {
        let mut c = UnixStream::connect(socket).unwrap();
        c.write_all(line.as_bytes()).unwrap();
        c.write_all(b"\n").unwrap();
        let mut reply = String::new();
        BufReader::new(&mut c).read_line(&mut reply).unwrap();
        let mut rest = Vec::new();
        assert_eq!(
            c.read_to_end(&mut rest).unwrap(),
            0,
            "one reply, then closed"
        );
        serde_json::from_str(&reply).unwrap()
    }

    fn sign_in(socket: &Path, actor: &str, password: &str) -> serde_json::Value {
        ask(
            socket,
            &serde_json::json!({"contract": thadam_core::AUDIT_WIRE, "actor": actor, "password": password})
                .to_string(),
        )
    }

    fn append(socket: &Path, session: &str, action: &str) -> serde_json::Value {
        ask(
            socket,
            &serde_json::json!({"contract": thadam_core::AUDIT_WIRE, "session": session,
                "action": action, "target": "0193b000-0000-7000-8000-000000000001", "outcome": "succeeded"})
                .to_string(),
        )
    }

    fn ping(socket: &Path, session: Option<&str>) -> serde_json::Value {
        let mut v = serde_json::json!({"contract": thadam_core::AUDIT_WIRE, "ping": true});
        if let Some(s) = session {
            v["session"] = s.into();
        }
        ask(socket, &v.to_string())
    }

    fn error(v: &serde_json::Value) -> &str {
        v["error"].as_str().unwrap_or("")
    }

    #[test]
    fn signs_in_appends_as_the_session_and_signs_out() {
        let dir = Dir::new();
        dir.set_password(PASSWORD);
        let socket = start(&dir);
        assert_eq!(ping(&socket, None), serde_json::json!({"ok": true}));

        let signed = sign_in(&socket, "dev", PASSWORD);
        let session = signed["session"].as_str().unwrap().to_string();
        assert_eq!(session.len(), thadam_core::SESSION_HEX);
        assert_eq!(signed["actor"], "dev");
        assert_eq!(
            ping(&socket, Some(&session)),
            serde_json::json!({"ok": true})
        );

        let first = append(&socket, &session, "flag_reviewed");
        let second = append(&socket, &session, "search");
        assert_eq!(
            (first["seq"].as_i64(), second["seq"].as_i64()),
            (Some(2), Some(3))
        );
        assert!(first["auditId"].as_str().is_some_and(|id| id.len() == 36));

        assert_eq!(
            ask(
                &socket,
                &serde_json::json!({"contract": thadam_core::AUDIT_WIRE, "signOut": true, "session": session})
                    .to_string()
            )["seq"],
            4
        );
        assert_eq!(error(&append(&socket, &session, "search")), "session_ended");
        assert_eq!(error(&ping(&socket, Some(&session))), "session_ended");

        let log = dir.log();
        let rows: Vec<_> = log
            .entries()
            .unwrap()
            .into_iter()
            .map(|r| (r.actor_id, r.action, r.outcome))
            .collect();
        let row = |a: &str, o: &str| ("dev".to_string(), a.to_string(), o.to_string());
        assert_eq!(
            rows,
            [
                row("sign_in", "succeeded"),
                row("flag_reviewed", "succeeded"),
                row("search", "succeeded"),
                row("sign_out", "succeeded"),
            ]
        );
        assert_eq!(log.verify().unwrap().broken_at, None);
        let mode = std::fs::metadata(dir.0.join("log").join("audit.db"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[test]
    fn nothing_is_appended_without_a_live_session() {
        let dir = Dir::new();
        dir.set_password(PASSWORD);
        let socket = start(&dir);
        let made_up = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            error(&append(&socket, made_up, "flag_reviewed")),
            "session_ended"
        );
        // The v1 append, as a program that started the API with its own data folder sends it.
        assert_eq!(
            error(&ask(
                &socket,
                r#"{"contract":"thadam.audit-append.v1","actor":"dev","action":"flag_reviewed","target":"x","outcome":"succeeded"}"#
            )),
            "invalid"
        );
        // Sign-in entries come from the collector only.
        assert_eq!(error(&append(&socket, made_up, "sign_in")), "invalid");
        assert!(dir.log().is_empty().unwrap());
    }

    #[test]
    fn wrong_passwords_are_recorded_then_must_wait_and_a_new_password_clears_it() {
        let dir = Dir::new();
        dir.set_password(PASSWORD);
        let socket = start(&dir);
        assert_eq!(
            error(&sign_in(&socket, "dev", "a wrong pass phrase")),
            "wrong_password"
        );
        for _ in 1..FREE_ATTEMPTS {
            assert_eq!(
                error(&sign_in(&socket, "dev", "a wrong pass phrase")),
                "wrong_password"
            );
        }
        // Now limited: even the right password waits, unchecked.
        let limited = sign_in(&socket, "dev", PASSWORD);
        assert_eq!(error(&limited), "wait");
        assert_eq!(limited["retryAfter"], 1);
        let outcomes: Vec<_> = dir
            .log()
            .entries()
            .unwrap()
            .into_iter()
            .map(|r| r.outcome)
            .collect();
        assert_eq!(outcomes.iter().filter(|o| *o == "failed").count(), 5);
        assert_eq!(outcomes.last().map(String::as_str), Some("denied"));

        // The owner resets the password with sudo: the wait is cleared at once.
        std::thread::sleep(Duration::from_millis(20));
        dir.set_password("a new made up pass phrase");
        assert!(sign_in(&socket, "dev", "a new made up pass phrase")["session"].is_string());
    }

    #[test]
    fn the_wait_doubles_and_is_capped() {
        let now = Instant::now();
        let after = |failures| {
            Attempts {
                failures,
                last: Some(now),
            }
            .wait(now)
        };
        assert_eq!(after(FREE_ATTEMPTS - 1), None);
        assert_eq!(after(FREE_ATTEMPTS), Some(Duration::from_secs(1)));
        assert_eq!(after(FREE_ATTEMPTS + 3), Some(Duration::from_secs(8)));
        assert_eq!(after(FREE_ATTEMPTS + 40), Some(MAX_WAIT));
        let later = Attempts {
            failures: FREE_ATTEMPTS,
            last: Some(now),
        };
        assert_eq!(later.wait(now + Duration::from_secs(1)), None);
    }

    #[test]
    fn without_a_password_sign_in_says_so() {
        let dir = Dir::new();
        let socket = start(&dir);
        assert_eq!(error(&sign_in(&socket, "dev", PASSWORD)), "no_password");
        let entries = dir.log().entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].outcome, "failed");
    }

    #[test]
    fn a_new_password_or_idle_time_ends_sessions() {
        let dir = Dir::new();
        dir.set_password(PASSWORD);
        let socket = start(&dir);
        let session = sign_in(&socket, "dev", PASSWORD)["session"]
            .as_str()
            .unwrap()
            .to_string();
        std::thread::sleep(Duration::from_millis(20));
        dir.set_password("a new made up pass phrase");
        assert_eq!(error(&ping(&socket, Some(&session))), "session_ended");

        let quick = Dir::new();
        quick.set_password(PASSWORD);
        let socket = start_with(
            &quick,
            &std::env::current_exe().unwrap(),
            Duration::from_millis(300),
        );
        let session = sign_in(&socket, "dev", PASSWORD)["session"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            ping(&socket, Some(&session)),
            serde_json::json!({"ok": true})
        );
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(error(&append(&socket, &session, "search")), "session_ended");
    }

    #[test]
    fn a_client_that_trickles_bytes_is_cut_off_and_the_next_one_is_served() {
        let dir = Dir::new();
        let socket = start(&dir);
        let mut slow = UnixStream::connect(&socket).unwrap();
        let started = Instant::now();
        // One byte every 300 ms: each read is quick, but the whole line never arrives.
        let mut cut_off = false;
        for _ in 0..20 {
            if slow.write_all(b" ").is_err() {
                cut_off = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        let mut reply = String::new();
        let _ = BufReader::new(&mut slow).read_line(&mut reply);
        assert!(cut_off || reply == "{\"error\":\"invalid\"}\n", "{reply}");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(ping(&socket, None), serde_json::json!({"ok": true}));
    }

    #[test]
    fn a_silent_other_program_is_refused_quickly() {
        let dir = Dir::new();
        let socket = start_with(&dir, Path::new("/usr/bin/true"), Duration::from_secs(60));
        let mut silent = UnixStream::connect(&socket).unwrap();
        let started = Instant::now();
        let mut reply = String::new();
        BufReader::new(&mut silent).read_line(&mut reply).unwrap();
        assert_eq!(reply, "{\"error\":\"refused\"}\n");
        assert!(started.elapsed() < IO_TIMEOUT);
    }

    #[test]
    fn any_other_program_is_refused_and_nothing_is_written() {
        let dir = Dir::new();
        dir.set_password(PASSWORD);
        let socket = start_with(&dir, Path::new("/usr/bin/true"), Duration::from_secs(60));
        assert_eq!(error(&sign_in(&socket, "dev", PASSWORD)), "refused");
        assert!(dir.log().is_empty().unwrap());
    }
}
