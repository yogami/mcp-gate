//! Testing utilities for mcpg-domain.

pub mod fake_entropy;
pub mod fake_fs;

pub use fake_entropy::FakeEntropy;
pub use fake_fs::FakeFs;
