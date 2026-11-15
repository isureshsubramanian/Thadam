//! The shared test-vector file must match this implementation. The API's C# verifier reads
//! the same file (api/tests/Thadam.Store.Tests/GoldenVectorTests.cs), so the two chain
//! implementations cannot drift apart without one of the two test suites failing.
// Integration tests: unwrap/expect are allowed here, not in library code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use thadam_core::{
    AUDIT_DOMAIN, AuditRow, CATALOG_DOMAIN, CanonicalRow, CatalogRow, Encoding, GENESIS,
    audit_hash, catalog_hash,
    encode::{EVENT_DOMAIN_V2, EVENT_DOMAIN_V3},
    row_hash, to_hex,
};

fn file() -> Value {
    serde_json::from_str(include_str!("../testdata/golden-chain.json")).unwrap()
}

fn text(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap().to_string()
}

fn opt_text(v: &Value, k: &str) -> Option<String> {
    v[k].as_str().map(str::to_string)
}

fn int(v: &Value, k: &str) -> i64 {
    v[k].as_i64().unwrap()
}

fn opt_int(v: &Value, k: &str) -> Option<i64> {
    v[k].as_i64()
}

fn event_vectors(key: &str, domain: &str, encoding: Encoding) {
    let f = file();
    assert_eq!(f[key]["domain"], domain);
    let mut prev = GENESIS;
    for v in f[key]["rows"].as_array().unwrap() {
        let row = CanonicalRow {
            seq: int(v, "seq"),
            event_id: text(v, "event_id"),
            ts_us: int(v, "ts_us"),
            tool: text(v, "tool"),
            session_id: opt_text(v, "session_id"),
            parent_session_id: opt_text(v, "parent_session_id"),
            pid: int(v, "pid"),
            process_path: text(v, "process_path"),
            category: text(v, "category"),
            action: text(v, "action"),
            target: text(v, "target"),
            outcome: text(v, "outcome"),
            size_bytes: opt_int(v, "size_bytes"),
            bytes_out: opt_int(v, "bytes_out"),
            bytes_in: opt_int(v, "bytes_in"),
            project: opt_text(v, "project"),
            flags: text(v, "flags"),
            count: int(v, "count"),
            detections: text(v, "detections"),
            source: text(v, "source"),
            // Absent from v2 vectors: null.
            agent_session_id: opt_text(v, "agent_session_id"),
            transcript: opt_text(v, "transcript"),
        };
        let h = row_hash(&prev, &row, encoding).unwrap();
        assert_eq!(to_hex(&h), text(v, "hash"));
        prev = h;
    }
}

#[test]
fn event_v2_vectors_match() {
    event_vectors("event_v2", EVENT_DOMAIN_V2, Encoding::V2);
}

#[test]
fn event_v3_vectors_match() {
    event_vectors("event_v3", EVENT_DOMAIN_V3, Encoding::V3);
}

#[test]
fn catalog_vectors_match() {
    let f = file();
    assert_eq!(f["catalog_v1"]["domain"], CATALOG_DOMAIN);
    let mut prev = GENESIS;
    for v in f["catalog_v1"]["rows"].as_array().unwrap() {
        let row = CatalogRow {
            seq: int(v, "seq"),
            at_us: int(v, "at_us"),
            kind: text(v, "kind"),
            segment: opt_text(v, "segment"),
            first_seq: opt_int(v, "first_seq"),
            last_seq: opt_int(v, "last_seq"),
            first_prev_hash: opt_text(v, "first_prev_hash"),
            last_hash: opt_text(v, "last_hash"),
            last_ts_us: opt_int(v, "last_ts_us"),
            rows: opt_int(v, "rows"),
            bytes: opt_int(v, "bytes"),
            reason: opt_text(v, "reason"),
            detail: opt_text(v, "detail"),
            from_us: opt_int(v, "from_us"),
            to_us: opt_int(v, "to_us"),
            missed: opt_int(v, "missed"),
        };
        let h = catalog_hash(&prev, &row).unwrap();
        assert_eq!(to_hex(&h), text(v, "hash"));
        prev = h;
    }
}

#[test]
fn audit_v1_vectors_match() {
    let f = file();
    assert_eq!(f["audit_v1"]["domain"], AUDIT_DOMAIN);
    let mut prev = GENESIS;
    let rows = f["audit_v1"]["rows"].as_array().unwrap();
    assert!(!rows.is_empty());
    for v in rows {
        let row = AuditRow {
            seq: int(v, "seq"),
            audit_id: text(v, "audit_id"),
            ts_us: int(v, "ts_us"),
            actor_id: text(v, "actor_id"),
            action: text(v, "action"),
            target_id: text(v, "target_id"),
            outcome: text(v, "outcome"),
        };
        let h = audit_hash(&prev, &row).unwrap();
        assert_eq!(to_hex(&h), text(v, "hash"));
        prev = h;
    }
}
