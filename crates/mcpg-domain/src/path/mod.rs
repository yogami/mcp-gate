//! Path resolution, containment, and canonicalization.

pub mod contain;
pub mod proc_map;
pub mod resolve;

pub use contain::is_within;
pub use proc_map::ProcCtx;
pub use resolve::{resolve, EscapeKind, Resolution, ResolveError};
