//! Canonical encoding `thadam.event.v2` (ADR-002 Decision 2; ADR-004 added
//! `parent_session_id` and retired v1).
//!
//! CONTRACT: these bytes are hashed into the chain. Any reader that verifies the chain
//! (the store's `verify`, and the .NET API in phase 3) must produce the identical bytes,
//! so the field order, the wire names in `model.rs` and the rules below cannot change
//! without a new domain tag. The golden vectors in this module's tests pin them.
//!
//! - text: u32 big-endian byte length, then the UTF-8 bytes as stored
//! - null: u32 big-endian 0xFFFF_FFFF (never a valid text length: lengths are capped)
//! - integer: i64 big-endian. Nullable integers are validated non-negative, so their first
//!   byte is never 0xFF and a null cannot be confused with a value.

use crate::error::CoreError;

pub const EVENT_DOMAIN: &str = "thadam.event.v2";
const NULL_MARKER: u32 = u32::MAX;

/// A stored event row in the primitive form that is hashed. The store reads rows back in
/// this form, so verification never depends on parsing the values into enums.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRow {
    pub seq: i64,
    pub event_id: String,
    pub ts_us: i64,
    pub tool: String,
    pub session_id: Option<String>,
    /// The session that started this one (ADR-004); `None` for a top-level session.
    pub parent_session_id: Option<String>,
    pub pid: i64,
    pub process_path: String,
    pub category: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub size_bytes: Option<i64>,
    pub bytes_out: Option<i64>,
    pub bytes_in: Option<i64>,
    pub project: Option<String>,
    pub flags: String,
    pub count: i64,
    pub detections: String,
    pub source: String,
}

/// Encodes a row in the field order fixed by ADR-002 and ADR-004.
pub fn encode(row: &CanonicalRow) -> Result<Vec<u8>, CoreError> {
    let mut buf = Vec::with_capacity(256 + row.target.len() + row.process_path.len());
    put_text(&mut buf, EVENT_DOMAIN)?;
    put_int(&mut buf, row.seq);
    put_text(&mut buf, &row.event_id)?;
    put_int(&mut buf, row.ts_us);
    put_text(&mut buf, &row.tool)?;
    put_opt_text(&mut buf, row.session_id.as_deref())?;
    put_opt_text(&mut buf, row.parent_session_id.as_deref())?;
    put_int(&mut buf, row.pid);
    put_text(&mut buf, &row.process_path)?;
    put_text(&mut buf, &row.category)?;
    put_text(&mut buf, &row.action)?;
    put_text(&mut buf, &row.target)?;
    put_text(&mut buf, &row.outcome)?;
    put_opt_int(&mut buf, row.size_bytes);
    put_opt_int(&mut buf, row.bytes_out);
    put_opt_int(&mut buf, row.bytes_in);
    put_opt_text(&mut buf, row.project.as_deref())?;
    put_text(&mut buf, &row.flags)?;
    put_int(&mut buf, row.count);
    put_text(&mut buf, &row.detections)?;
    put_text(&mut buf, &row.source)?;
    Ok(buf)
}

pub(crate) fn put_text(buf: &mut Vec<u8>, s: &str) -> Result<(), CoreError> {
    let len = u32::try_from(s.len()).map_err(|_| CoreError::FieldTooLong)?;
    if len == NULL_MARKER {
        return Err(CoreError::FieldTooLong);
    }
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
    Ok(())
}

pub(crate) fn put_opt_text(buf: &mut Vec<u8>, s: Option<&str>) -> Result<(), CoreError> {
    match s {
        Some(s) => put_text(buf, s),
        None => {
            buf.extend_from_slice(&NULL_MARKER.to_be_bytes());
            Ok(())
        }
    }
}

pub(crate) fn put_int(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_opt_int(buf: &mut Vec<u8>, v: Option<i64>) {
    match v {
        Some(v) => put_int(buf, v),
        None => buf.extend_from_slice(&NULL_MARKER.to_be_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{GENESIS, row_hash, to_hex};

    /// Golden vectors. The expected hashes were computed by a separate implementation of
    /// the spec above, not by this code. A .NET verifier must reproduce them exactly.
    fn golden_rows() -> (CanonicalRow, CanonicalRow) {
        let r1 = CanonicalRow {
            seq: 1,
            event_id: "0193a6f2-7c1e-7b4a-9d2e-5f8c1a3b6e90".into(),
            ts_us: 1_794_583_912_418_000,
            tool: "tool-a".into(),
            session_id: Some("s-7f3e".into()),
            parent_session_id: None,
            pid: 48211,
            process_path: "/usr/bin/curl".into(),
            category: "command".into(),
            action: "exec".into(),
            target: "curl -H \"Authorization: Bearer [SECRET]\" https://api.example.test/v1/items"
                .into(),
            outcome: "allowed".into(),
            size_bytes: None,
            bytes_out: None,
            bytes_in: None,
            project: Some("/Users/dev/projects/sample-app".into()),
            flags: "secret_pattern".into(),
            count: 1,
            detections: "SECRET:1".into(),
            source: "os".into(),
        };
        let r2 = CanonicalRow {
            seq: 2,
            event_id: "0193a6f2-7c1f-7000-8000-000000000002".into(),
            ts_us: 1_794_583_913_000_000,
            tool: "tool-a".into(),
            session_id: Some("s-9a01".into()),
            parent_session_id: Some("s-7f3e".into()),
            pid: 48212,
            process_path: "/bin/cat".into(),
            category: "file".into(),
            action: "read".into(),
            target: "/Users/dev/projects/sample-app/src/main.rs".into(),
            outcome: "allowed".into(),
            size_bytes: Some(2048),
            bytes_out: None,
            bytes_in: Some(0),
            project: None,
            flags: String::new(),
            count: 418,
            detections: String::new(),
            source: "agent,os".into(),
        };
        (r1, r2)
    }

    #[test]
    fn golden_vectors_match_independent_implementation() {
        let (r1, r2) = golden_rows();
        let h1 = row_hash(&GENESIS, &r1).unwrap();
        assert_eq!(
            to_hex(&h1),
            "cca2e7aa25a5885bf7340e0e111749dad90bb3727401a46090aea3ec6598ba92"
        );
        let h2 = row_hash(&h1, &r2).unwrap();
        assert_eq!(
            to_hex(&h2),
            "ba2352eb629780821ce40c27aa8421ed957e981ce340ba70c60fbb19aae0d586"
        );
    }

    #[test]
    fn null_and_empty_text_encode_differently() {
        let (_, mut a) = golden_rows();
        let mut b = a.clone();
        a.project = None;
        b.project = Some(String::new());
        assert_ne!(encode(&a).unwrap(), encode(&b).unwrap());
        let (mut c, _) = golden_rows();
        let mut d = c.clone();
        c.parent_session_id = None;
        d.parent_session_id = Some(String::new());
        assert_ne!(encode(&c).unwrap(), encode(&d).unwrap());
    }

    #[test]
    fn every_field_change_changes_the_hash() {
        let (base, _) = golden_rows();
        let h = row_hash(&GENESIS, &base).unwrap();
        let mut variants = Vec::new();
        let mut v = base.clone();
        v.seq = 2;
        variants.push(v);
        let mut v = base.clone();
        v.target.push(' ');
        variants.push(v);
        let mut v = base.clone();
        v.outcome = "denied_by_user".into();
        variants.push(v);
        let mut v = base.clone();
        v.count = 2;
        variants.push(v);
        let mut v = base.clone();
        v.detections = String::new();
        variants.push(v);
        let mut v = base.clone();
        v.parent_session_id = Some("s-0000".into());
        variants.push(v);
        for v in variants {
            assert_ne!(row_hash(&GENESIS, &v).unwrap(), h);
        }
        assert_ne!(row_hash(&[1u8; 32], &base).unwrap(), h);
    }
}
