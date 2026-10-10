//! Domain model and core business rules for mcp-gate.
//!
//! Pure crate: policy evaluation, path resolution, events, findings, and verdicts.
#![forbid(unsafe_code)]

pub mod canary;
pub mod config;
pub mod env;
pub mod evaluator;
pub mod event;
pub mod exec_deps;
pub mod fs_view;
pub mod host;
pub mod landlock_plan;
pub mod leak;
pub mod mode;
pub mod path;
pub mod policy;
pub mod seed;
pub mod verdict;

#[cfg(feature = "testing")]
pub mod testing;
pub mod rules;
