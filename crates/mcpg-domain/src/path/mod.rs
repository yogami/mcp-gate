//! Path resolution, containment, and canonicalization.

pub mod contain;
pub mod resolve;

pub use contain::is_within;
pub use resolve::{resolve, EscapeKind, Resolution};
