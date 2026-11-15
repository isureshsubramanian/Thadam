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
/// The append wire between the API and the collector (ADR-013 Decision 3).
pub const AUDIT_WIRE: &str = "thadam.audit-append.v1";
/// Where the collector listens for audit entries.
pub const AUDIT_SOCKET: &str = "/var/run/thadam-audit/audit.sock";
/// The root-owned log the collector writes and the API reads.
pub const AUDIT_DB: &str = "/Library/Application Support/Thadam/audit/audit.db";
/// The installed API, the only program whose entries the collector accepts.
pub const API_BIN: &str = "/Library/Application Support/Thadam/app/thadam-api";
/// Longest request line, in bytes.
pub const MAX_AUDIT_LINE: usize = 4096;
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

/// One request line on the audit socket: an append, or `{"contract":...,"ping":true}`.
/// One request per connection; the collector answers with one `AuditReply` line.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct AuditRequest {
    #[garde(custom(is_audit_wire))]
    pub contract: String,
    #[garde(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping: Option<bool>,
    #[garde(inner(length(min = 1, max = MAX_ACTOR), custom(is_actor)))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[garde(inner(custom(one_of(AUDIT_ACTIONS))))]
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
    Ping,
    Append {
        actor: String,
        action: String,
        target: String,
        outcome: String,
    },
}

impl AuditRequest {
    /// The command, when the fields are valid and form exactly one of the two shapes.
    pub fn command(self) -> Option<AuditCommand> {
        self.validate().ok()?;
        match self {
            Self {
                ping: Some(true),
                actor: None,
                action: None,
                target: None,
                outcome: None,
                ..
            } => Some(AuditCommand::Ping),
            Self {
                ping: None,
                actor: Some(actor),
                action: Some(action),
                target: Some(target),
                outcome: Some(outcome),
                ..
            } => Some(AuditCommand::Append {
                actor,
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
    Pong {
        ok: bool,
    },
    Error {
        error: AuditError,
    },
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

    #[test]
    fn the_two_request_shapes_parse() {
        assert_eq!(
            parse(r#"{"contract":"thadam.audit-append.v1","ping":true}"#),
            Some(AuditCommand::Ping)
        );
        assert_eq!(
            parse(
                r#"{"contract":"thadam.audit-append.v1","actor":"dev","action":"export","target":"0193b000-0000-7000-8000-000000000001","outcome":"denied"}"#
            ),
            Some(AuditCommand::Append {
                actor: "dev".into(),
                action: "export".into(),
                target: "0193b000-0000-7000-8000-000000000001".into(),
                outcome: "denied".into(),
            })
        );
    }

    #[test]
    fn anything_else_is_invalid() {
        for line in [
            r#"{"contract":"thadam.audit-append.v2","ping":true}"#,
            r#"{"contract":"thadam.audit-append.v1","ping":false}"#,
            r#"{"contract":"thadam.audit-append.v1","ping":true,"actor":"dev"}"#,
            r#"{"contract":"thadam.audit-append.v1","actor":"dev","action":"search","outcome":"succeeded"}"#,
            r#"{"contract":"thadam.audit-append.v1","actor":"dev","action":"delete_all","target":"","outcome":"succeeded"}"#,
            r#"{"contract":"thadam.audit-append.v1","actor":"dev","action":"search","target":"","outcome":"maybe"}"#,
            r#"{"contract":"thadam.audit-append.v1","actor":"","action":"search","target":"","outcome":"failed"}"#,
            r#"{"contract":"thadam.audit-append.v1","actor":"a b","action":"search","target":"","outcome":"failed"}"#,
            r#"{"contract":"thadam.audit-append.v1","actor":"dev","action":"search","target":"rm -rf /","outcome":"failed"}"#,
            r#"{"contract":"thadam.audit-append.v1","actor":"dev","action":"search","target":"","outcome":"failed","extra":1}"#,
        ] {
            assert_eq!(parse(line), None, "{line}");
        }
        let long = format!(
            r#"{{"contract":"thadam.audit-append.v1","actor":"dev","action":"search","target":"{}","outcome":"failed"}}"#,
            "a".repeat(129)
        );
        assert_eq!(parse(&long), None);
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
            serde_json::to_string(&AuditReply::Error {
                error: AuditError::Refused
            })
            .unwrap_or_default(),
            r#"{"error":"refused"}"#
        );
    }
}
