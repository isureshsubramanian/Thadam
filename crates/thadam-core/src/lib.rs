//! Thadam core: the event model, the canonical encoding and hash chain that make the
//! store tamper-evident, and the sensitive-data detectors that redact text before it is
//! stored. This crate performs no I/O.

pub mod catalog;
pub mod chain;
pub mod detect;
pub mod detectors;
pub mod encode;
pub mod error;
pub mod exec;
pub mod model;

pub use catalog::{CATALOG_DOMAIN, CatalogKind, CatalogRow, catalog_hash, encode_catalog};
pub use chain::{GENESIS, row_hash, to_hex};
pub use detect::{Detections, Detector, DetectorKind, Redacted, Redactor};
pub use encode::{CanonicalRow, Encoding, encode};
pub use error::CoreError;
pub use exec::ExecObservation;
pub use model::{
    Action, AgentLink, Category, EventRecord, Flag, NewEvent, Outcome, Source, WireName,
};
