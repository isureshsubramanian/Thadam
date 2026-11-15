//! Canonical encoding `thadam.audit.v1` for `audit.db`, the review and access log (ADR-002
//! Decision 5, ADR-008 Decision 6). Written by the collector from ADR-013 Decision 3 on.
//!
//! CONTRACT: these bytes are hashed into the audit log's own chain, with the same primitives as
//! `thadam.event.v2` (see `encode.rs`). The .NET API verifies the same chain; the golden vectors
//! in `testdata/golden-chain.json` (`audit_v1`) pin both.
//!
//! Field order: seq, audit_id, ts_us, actor_id, action, target_id, outcome.

use garde::Validate;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::encode::{put_int, put_text};
use crate::error::CoreError;

pub const AUDIT_DOMAIN: &str = "thadam.audit.v1";
/// The wire between the API and the collector (ADR-013 Decision 3, ADR-015 Decision 1).
/// v2: the collector checks the password and issues sessions; every append carries one.
pub const AUDIT_WIRE: &str = "thadam.audit-append.v2";
/// Where the collector listens for audit entries.
pub const AUDIT_SOCKET: &str = "/var/run/thadam-audit/audit.sock";
/// The root-owned log the collector writes and the API reads.
pub const AUDIT_DB: &str = "/Library/Application Support/Thadam/audit/audit.db";
/// The dashboard password's verifier, root-only (ADR-015 Decision 1).
pub const CREDENTIALS: &str = "/Library/Application Support/Thadam/credentials.json";
/// The installed API, the only program whose requests the collector accepts.
pub const API_BIN: &str = "/Library/Application Support/Thadam/app/thadam-api";
/// Longest request line, in bytes: a password of `MAX_PASSWORD` characters, JSON-escaped.
pub const MAX_AUDIT_LINE: usize = 8192;
/// NIST SP 800-63B-4 §3.1.1.2: at least 15 characters for a password used alone.
pub const MIN_PASSWORD: usize = 15;
pub const MAX_PASSWORD: usize = 1024;
/// A session token: 32 random bytes, as lower-case hex.
pub const SESSION_HEX: usize = 64;
const MAX_ACTOR: usize = 64;
const MAX_AUDIT_TARGET: usize = 128;

/// The actions `audit.db` accepts, as stored.
pub const AUDIT_ACTIONS: &[&str] = &[
    "sign_in",
    "sign_out",
    "search",
    "export",
    "flag_reviewed",
    "flag_reopened",
];
/// The actions the API may append; the collector writes sign-in and sign-out itself.
pub const APPEND_ACTIONS: &[&str] = &["search", "export", "flag_reviewed", "flag_reopened"];
/// The outcomes `audit.db` accepts, as stored.
pub const AUDIT_OUTCOMES: &[&str] = &["succeeded", "failed", "denied"];

/// One audit entry: IDs only, never queries, values or results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub seq: i64,
    pub audit_id: String,
    pub ts_us: i64,
    pub actor_id: String,
    pub action: String,
    pub target_id: String,
    pub outcome: String,
}

pub fn encode_audit(row: &AuditRow) -> Result<Vec<u8>, CoreError> {
    let mut buf = Vec::with_capacity(160);
    put_text(&mut buf, AUDIT_DOMAIN)?;
    put_int(&mut buf, row.seq);
    put_text(&mut buf, &row.audit_id)?;
    put_int(&mut buf, row.ts_us);
    put_text(&mut buf, &row.actor_id)?;
    put_text(&mut buf, &row.action)?;
    put_text(&mut buf, &row.target_id)?;
    put_text(&mut buf, &row.outcome)?;
    Ok(buf)
}

/// `SHA-256(prev_hash || encode_audit(row))`.
pub fn audit_hash(prev_hash: &[u8; 32], row: &AuditRow) -> Result<[u8; 32], CoreError> {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(encode_audit(row)?);
    Ok(hasher.finalize().into())
}

/// A password in transit. Never printed: its `Debug` shows a placeholder, so no log line,
/// panic message or test failure can carry it.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Password(String);

impl Password {
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password([hidden])")
    }
}

/// One request line on the audit socket. One request per connection; the collector answers
/// with one `AuditReply` line. The shapes (anything else is invalid):
///
/// - `{"contract","ping":true[,"session"]}`: is the collector there (and is this session live)?
/// - `{"contract","actor","password"}`: sign in; the collector writes the `sign_in` entry.
/// - `{"contract","signOut":true,"session"}`: end the session; the collector writes `sign_out`.
/// - `{"contract","session","action","target","outcome"}`: append, as the session's actor.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditRequest {
    #[garde(custom(is_audit_wire))]
    pub contract: String,
    #[garde(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping: Option<bool>,
    #[garde(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_out: Option<bool>,
    #[garde(inner(custom(is_session)))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[garde(inner(length(min = 1, max = MAX_ACTOR), custom(is_actor)))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[garde(inner(custom(is_password)))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Password>,
    #[garde(inner(custom(one_of(APPEND_ACTIONS))))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[garde(inner(length(max = MAX_AUDIT_TARGET), custom(is_target)))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[garde(inner(custom(one_of(AUDIT_OUTCOMES))))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
}

/// What a valid request asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditCommand {
    Ping {
        session: Option<String>,
    },
    SignIn {
        actor: String,
        password: Password,
    },
    SignOut {
        session: String,
    },
    Append {
        session: String,
        action: String,
        target: String,
        outcome: String,
    },
}

impl AuditRequest {
    /// The command, when the fields are valid and form exactly one of the shapes.
    pub fn command(self) -> Option<AuditCommand> {
        self.validate().ok()?;
        match self {
            Self {
                ping: Some(true),
                sign_out: None,
                session,
                actor: None,
                password: None,
                action: None,
                target: None,
                outcome: None,
                ..
            } => Some(AuditCommand::Ping { session }),
            Self {
                ping: None,
                sign_out: None,
                session: None,
                actor: Some(actor),
                password: Some(password),
                action: None,
                target: None,
                outcome: None,
                ..
            } => Some(AuditCommand::SignIn { actor, password }),
            Self {
                ping: None,
                sign_out: Some(true),
                session: Some(session),
                actor: None,
                password: None,
                action: None,
                target: None,
                outcome: None,
                ..
            } => Some(AuditCommand::SignOut { session }),
            Self {
                ping: None,
                sign_out: None,
                session: Some(session),
                actor: None,
                password: None,
                action: Some(action),
                target: Some(target),
                outcome: Some(outcome),
                ..
            } => Some(AuditCommand::Append {
                session,
                action,
                target,
                outcome,
            }),
            _ => None,
        }
    }
}

/// The collector's answer. Exactly one of the shapes is serialised.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AuditReply {
    #[serde(rename_all = "camelCase")]
    Appended {
        seq: i64,
        audit_id: String,
        ts_us: i64,
    },
    /// A new session, and the actor the collector will write for it.
    SignedIn {
        session: String,
        actor: String,
    },
    Pong {
        ok: bool,
    },
    #[serde(rename_all = "camelCase")]
    Error {
        error: AuditError,
        /// For `wait`: seconds until the next sign-in attempt is checked.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after: Option<u64>,
    },
}

impl AuditReply {
    pub fn error(error: AuditError) -> Self {
        Self::Error {
            error,
            retry_after: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditError {
    /// The sender is not the installed API.
    Refused,
    /// The line or a field failed validation.
    Invalid,
    /// The collector could not write the entry.
    Unavailable,
    /// The session is unknown or has expired: sign in again.
    SessionEnded,
    /// The password does not match.
    WrongPassword,
    /// No password has been set: `sudo thadam-collector set-password`.
    NoPassword,
    /// Too many wrong passwords: the next attempt is checked after `retry_after` seconds.
    Wait,
}

fn is_session(value: &str, _ctx: &()) -> garde::Result {
    if value.len() == SESSION_HEX
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(garde::Error::new("not a session"))
    }
}

fn is_password(value: &Password, _ctx: &()) -> garde::Result {
    let chars = value.expose().chars().count();
    if (1..=MAX_PASSWORD).contains(&chars) {
        Ok(())
    } else {
        Err(garde::Error::new("password length"))
    }
}

fn is_audit_wire(value: &str, _ctx: &()) -> garde::Result {
    if value == AUDIT_WIRE {
        Ok(())
    } else {
        Err(garde::Error::new("unknown wire version"))
    }
}

fn one_of(allowed: &'static [&'static str]) -> impl Fn(&str, &()) -> garde::Result {
    move |value, _| {
        if allowed.contains(&value) {
            Ok(())
        } else {
            Err(garde::Error::new("not an allowed value"))
        }
    }
}

fn is_actor(value: &str, _ctx: &()) -> garde::Result {
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b))
    {
        Ok(())
    } else {
        Err(garde::Error::new("not an actor id"))
    }
}

fn is_target(value: &str, _ctx: &()) -> garde::Result {
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
    {
        Ok(())
    } else {
        Err(garde::Error::new("not a target id"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> Option<AuditCommand> {
        serde_json::from_str::<AuditRequest>(line).ok()?.command()
    }

    const S: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn the_four_request_shapes_parse() {
        assert_eq!(
            parse(r#"{"contract":"thadam.audit-append.v2","ping":true}"#),
            Some(AuditCommand::Ping { session: None })
        );
        assert_eq!(
            parse(&format!(
                r#"{{"contract":"thadam.audit-append.v2","ping":true,"session":"{S}"}}"#
            )),
            Some(AuditCommand::Ping {
                session: Some(S.into())
            })
        );
        assert_eq!(
            parse(
                r#"{"contract":"thadam.audit-append.v2","actor":"dev","password":"made up pass phrase"}"#
            ),
            Some(AuditCommand::SignIn {
                actor: "dev".into(),
                password: Password::new("made up pass phrase"),
            })
        );
        assert_eq!(
            parse(&format!(
                r#"{{"contract":"thadam.audit-append.v2","signOut":true,"session":"{S}"}}"#
            )),
            Some(AuditCommand::SignOut { session: S.into() })
        );
        assert_eq!(
            parse(&format!(
                r#"{{"contract":"thadam.audit-append.v2","session":"{S}","action":"export","target":"0193b000-0000-7000-8000-000000000001","outcome":"denied"}}"#
            )),
            Some(AuditCommand::Append {
                session: S.into(),
                action: "export".into(),
                target: "0193b000-0000-7000-8000-000000000001".into(),
                outcome: "denied".into(),
            })
        );
    }

    #[test]
    fn anything_else_is_invalid() {
        let lines = [
            r#"{"contract":"thadam.audit-append.v1","ping":true}"#.to_string(),
            r#"{"contract":"thadam.audit-append.v2","ping":false}"#.to_string(),
            r#"{"contract":"thadam.audit-append.v2","ping":true,"actor":"dev"}"#.to_string(),
            // v1's append, without a session, is refused.
            r#"{"contract":"thadam.audit-append.v2","actor":"dev","action":"search","target":"","outcome":"succeeded"}"#.to_string(),
            format!(r#"{{"contract":"thadam.audit-append.v2","session":"{S}","action":"search","outcome":"succeeded"}}"#),
            // The collector writes sign-in and sign-out itself.
            format!(r#"{{"contract":"thadam.audit-append.v2","session":"{S}","action":"sign_in","target":"","outcome":"succeeded"}}"#),
            format!(r#"{{"contract":"thadam.audit-append.v2","session":"{S}","action":"delete_all","target":"","outcome":"succeeded"}}"#),
            format!(r#"{{"contract":"thadam.audit-append.v2","session":"{S}","action":"search","target":"","outcome":"maybe"}}"#),
            format!(r#"{{"contract":"thadam.audit-append.v2","session":"{S}","action":"search","target":"rm -rf /","outcome":"failed"}}"#),
            format!(r#"{{"contract":"thadam.audit-append.v2","session":"{S}","action":"search","target":"","outcome":"failed","extra":1}}"#),
            format!(r#"{{"contract":"thadam.audit-append.v2","session":"{}","action":"search","target":"","outcome":"failed"}}"#, S.to_uppercase()),
            r#"{"contract":"thadam.audit-append.v2","session":"abc","action":"search","target":"","outcome":"failed"}"#.to_string(),
            r#"{"contract":"thadam.audit-append.v2","signOut":true}"#.to_string(),
            r#"{"contract":"thadam.audit-append.v2","actor":"dev","password":""}"#.to_string(),
            r#"{"contract":"thadam.audit-append.v2","actor":"a b","password":"made up pass phrase"}"#.to_string(),
            format!(r#"{{"contract":"thadam.audit-append.v2","actor":"dev","password":"made up pass phrase","session":"{S}"}}"#),
            format!(r#"{{"contract":"thadam.audit-append.v2","actor":"dev","password":"{}"}}"#, "x".repeat(MAX_PASSWORD + 1)),
        ];
        for line in &lines {
            assert_eq!(parse(line), None, "{line}");
        }
        let long = format!(
            r#"{{"contract":"thadam.audit-append.v2","session":"{S}","action":"search","target":"{}","outcome":"failed"}}"#,
            "a".repeat(129)
        );
        assert_eq!(parse(&long), None);
    }

    #[test]
    fn a_password_never_prints() {
        let command = parse(
            r#"{"contract":"thadam.audit-append.v2","actor":"dev","password":"made up pass phrase"}"#,
        );
        let shown = format!("{command:?}");
        assert!(!shown.contains("made up"), "{shown}");
        assert!(shown.contains("[hidden]"), "{shown}");
    }

    #[test]
    fn replies_have_the_contract_shapes() {
        let ok = AuditReply::Appended {
            seq: 12,
            audit_id: "0193b000-0000-7000-8000-00000000000c".into(),
            ts_us: 1_794_700_800_000_000,
        };
        assert_eq!(
            serde_json::to_string(&ok).unwrap_or_default(),
            r#"{"seq":12,"auditId":"0193b000-0000-7000-8000-00000000000c","tsUs":1794700800000000}"#
        );
        assert_eq!(
            serde_json::to_string(&AuditReply::Pong { ok: true }).unwrap_or_default(),
            r#"{"ok":true}"#
        );
        assert_eq!(
            serde_json::to_string(&AuditReply::SignedIn {
                session: S.into(),
                actor: "dev".into()
            })
            .unwrap_or_default(),
            format!(r#"{{"session":"{S}","actor":"dev"}}"#)
        );
        assert_eq!(
            serde_json::to_string(&AuditReply::error(AuditError::Refused)).unwrap_or_default(),
            r#"{"error":"refused"}"#
        );
        assert_eq!(
            serde_json::to_string(&AuditReply::Error {
                error: AuditError::Wait,
                retry_after: Some(8)
            })
            .unwrap_or_default(),
            r#"{"error":"wait","retryAfter":8}"#
        );
        for (error, wire) in [
            (AuditError::SessionEnded, "session_ended"),
            (AuditError::WrongPassword, "wrong_password"),
            (AuditError::NoPassword, "no_password"),
        ] {
            assert_eq!(
                serde_json::to_string(&AuditReply::error(error)).unwrap_or_default(),
                format!(r#"{{"error":"{wire}"}}"#)
            );
        }
    }
}
