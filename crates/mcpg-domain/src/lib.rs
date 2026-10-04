//! Domain model and core business rules for mcp-gate.
//!
//! Pure crate: policy evaluation, path resolution, events, findings, and verdicts.
#![forbid(unsafe_code)]

pub mod config;
pub mod env;
pub mod fs_view;
pub mod verdict;

#[cfg(feature = "testing")]
pub mod testing;
