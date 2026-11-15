//! Canonical encoding `thadam.catalog.v1` for the store's segment catalog (ADR-009 Decision 1).
//!
//! CONTRACT: these bytes are hashed into the catalog's own chain, with the same primitives as
//! `thadam.event.v2` (see `encode.rs`). Any reader that verifies the catalog (the store's
//! `verify`, and the .NET API) must produce identical bytes. The golden vectors below pin them.
//!
//! Field order: seq, at_us, kind, segment, first_seq, last_seq, first_prev_hash, last_hash,
//! last_ts_us, rows, bytes, reason, detail, from_us, to_us, missed. Hashes are lower-case hex
//! text.

use sha2::{Digest, Sha256};

use crate::encode::{put_int, put_opt_int, put_opt_text, put_text};
use crate::error::CoreError;

pub const CATALOG_DOMAIN: &str = "thadam.catalog.v1";

/// What a catalog entry records. A segment's state is its latest entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogKind {
    /// A segment became the active one.
    Opened,
    /// A segment was closed; it holds `first_seq..=last_seq`.
    Closed,
    /// A closed segment's file was deleted by the retention policy.
    Retired,
    /// A closed segment's file was moved to the archive folder.
    Archived,
    /// Writing was paused for lack of disk space; `missed` rows were not written.
    Paused,
    /// A window the collector did not watch (ADR-013 Decision 1): `from_us..to_us`, `reason`
    /// (`not_running`, `machine_off`, `before_start`, `dropped`), `detail`, and `missed` for
    /// `dropped`. No segment.
    Gap,
}

impl CatalogKind {
    pub const ALL: &'static [CatalogKind] = &[
        CatalogKind::Opened,
        CatalogKind::Closed,
        CatalogKind::Retired,
        CatalogKind::Archived,
        CatalogKind::Paused,
        CatalogKind::Gap,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            CatalogKind::Opened => "opened",
            CatalogKind::Closed => "closed",
            CatalogKind::Retired => "retired",
            CatalogKind::Archived => "archived",
            CatalogKind::Paused => "paused",
            CatalogKind::Gap => "gap",
        }
    }

    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.wire_name() == s)
    }
}

/// A catalog row in the primitive form that is hashed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CatalogRow {
    pub seq: i64,
    pub at_us: i64,
    pub kind: String,
    pub segment: Option<String>,
    pub first_seq: Option<i64>,
    pub last_seq: Option<i64>,
    pub first_prev_hash: Option<String>,
    pub last_hash: Option<String>,
    pub last_ts_us: Option<i64>,
    pub rows: Option<i64>,
    pub bytes: Option<i64>,
    pub reason: Option<String>,
    pub detail: Option<String>,
    pub from_us: Option<i64>,
    pub to_us: Option<i64>,
    pub missed: Option<i64>,
}

pub fn encode_catalog(row: &CatalogRow) -> Result<Vec<u8>, CoreError> {
    let mut buf = Vec::with_capacity(256);
    put_text(&mut buf, CATALOG_DOMAIN)?;
    put_int(&mut buf, row.seq);
    put_int(&mut buf, row.at_us);
    put_text(&mut buf, &row.kind)?;
    put_opt_text(&mut buf, row.segment.as_deref())?;
    put_opt_int(&mut buf, row.first_seq);
    put_opt_int(&mut buf, row.last_seq);
    put_opt_text(&mut buf, row.first_prev_hash.as_deref())?;
    put_opt_text(&mut buf, row.last_hash.as_deref())?;
    put_opt_int(&mut buf, row.last_ts_us);
    put_opt_int(&mut buf, row.rows);
    put_opt_int(&mut buf, row.bytes);
    put_opt_text(&mut buf, row.reason.as_deref())?;
    put_opt_text(&mut buf, row.detail.as_deref())?;
    put_opt_int(&mut buf, row.from_us);
    put_opt_int(&mut buf, row.to_us);
    put_opt_int(&mut buf, row.missed);
    Ok(buf)
}

/// `SHA-256(prev_hash || encode_catalog(row))`.
pub fn catalog_hash(prev_hash: &[u8; 32], row: &CatalogRow) -> Result<[u8; 32], CoreError> {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(encode_catalog(row)?);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{GENESIS, to_hex};

    /// Golden rows. The expected hashes were computed by a separate implementation of the
    /// spec above, not by this code. A .NET verifier must reproduce them exactly.
    fn golden() -> (CatalogRow, CatalogRow) {
        let closed = CatalogRow {
            seq: 1,
            at_us: 1_794_700_800_000_000,
            kind: "closed".into(),
            segment: Some("events-2026-W46.db".into()),
            first_seq: Some(1),
            last_seq: Some(208_268),
            first_prev_hash: Some("0".repeat(64)),
            last_hash: Some("ab".repeat(32)),
            last_ts_us: Some(1_794_700_771_000_000),
            rows: Some(208_268),
            bytes: Some(184_475_648),
            ..CatalogRow::default()
        };
        let paused = CatalogRow {
            seq: 2,
            at_us: 1_794_701_000_000_000,
            kind: "paused".into(),
            reason: Some("low_disk".into()),
            from_us: Some(1_794_700_900_000_000),
            to_us: Some(1_794_700_960_000_000),
            missed: Some(42),
            ..CatalogRow::default()
        };
        (closed, paused)
    }

    #[test]
    fn golden_vectors_match_independent_implementation() {
        let (a, b) = golden();
        let h1 = catalog_hash(&GENESIS, &a).unwrap();
        let h2 = catalog_hash(&h1, &b).unwrap();
        assert_eq!(to_hex(&h1), GOLDEN_1);
        assert_eq!(to_hex(&h2), GOLDEN_2);
    }

    const GOLDEN_1: &str = "b02565f139b576a65c9cc901542765fe55e7e6ea14d0fa1dfdbdc135b999469e";
    const GOLDEN_2: &str = "0b15506ac5347994dda3639160fff66837dcf4b22983f9ef5962c7b655171b60";

    #[test]
    fn kinds_round_trip_and_nulls_differ_from_empty() {
        for k in CatalogKind::ALL {
            assert_eq!(CatalogKind::from_wire(k.wire_name()), Some(*k));
        }
        assert_eq!(CatalogKind::from_wire("deleted"), None);
        let (mut a, _) = golden();
        let mut b = a.clone();
        a.reason = None;
        b.reason = Some(String::new());
        assert_ne!(encode_catalog(&a).unwrap(), encode_catalog(&b).unwrap());
    }
}
