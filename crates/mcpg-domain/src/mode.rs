//! Operational mode of the capsule execution harness.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Operational mode of the capsule execution harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    Enforce,
    Observe,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enforce => write!(f, "enforce"),
            Self::Observe => write!(f, "observe"),
        }
    }
}
