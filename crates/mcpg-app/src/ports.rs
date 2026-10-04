//! Application port traits.

use std::fmt;
use std::process::Child;

pub use mcpg_domain::seed::EntropySource;

use crate::capsule_plan::CapsulePlan;

/// Handle to a running capsule child process.
#[derive(Debug)]
pub struct RunningCapsule {
    pub pid: u32,
    pub child: Child,
}

/// Errors occurring when launching a capsule.
#[derive(Debug)]
pub enum LaunchError {
    NotHardened,
    Io(std::io::Error),
    Failed(String),
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotHardened => write!(f, "runner process is not hardened"),
            Self::Io(e) => write!(f, "launch I/O error: {e}"),
            Self::Failed(s) => write!(f, "launch failed: {s}"),
        }
    }
}

impl std::error::Error for LaunchError {}

impl From<std::io::Error> for LaunchError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Port trait for launching test capsules.
pub trait CapsuleLauncher {
    fn launch(&self, plan: &CapsulePlan) -> Result<RunningCapsule, LaunchError>;
}
