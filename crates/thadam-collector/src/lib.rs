//! Thadam collector (ADR-003): reads OS events, keeps those from AI tool process trees,
//! turns them into records and appends them to the store.

pub mod classify;
pub mod collapse;
pub mod pairing;
pub mod pipeline;
pub mod registry;
pub mod rollup;
pub mod run;
pub mod snapshot;
pub mod source;
pub mod tree;
