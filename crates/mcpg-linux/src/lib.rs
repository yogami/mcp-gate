//! Linux platform adapters for mcp-gate: capsule launch, Landlock, seccomp, inotify, and procfs.

pub mod canary_plant;
pub mod entropy;
pub mod guard;
pub mod launcher;
pub mod probe;
pub mod rundir;
pub mod self_harden;
pub mod shutdown;
pub mod workspace;
