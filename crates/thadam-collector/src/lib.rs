//! Thadam collector (ADR-003): reads OS events, keeps those from AI tool process trees,
//! turns them into records and appends them to the store.

pub mod agent_rows;
pub mod audit;
pub mod classify;
pub mod collapse;
pub mod coverage;
pub mod credentials;
pub mod diag;
pub mod netflow;
pub mod pairing;
pub mod peer;
pub mod pipeline;
pub mod registry;
pub mod rollup;
pub mod run;
pub mod service;
pub mod snapshot;
pub mod source;
pub mod tree;
