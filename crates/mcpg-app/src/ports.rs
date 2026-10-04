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

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Port trait for launching test capsules.
pub trait CapsuleLauncher {
    fn launch(&self, plan: &CapsulePlan) -> Result<RunningCapsule, LaunchError>;
}

/// Clock abstraction for deterministic time testing and deadline tracking.
pub trait Clock: Send + Sync {
    /// Return the current instant according to this clock.
    fn now(&self) -> Instant;
}

impl<C: Clock + ?Sized> Clock for Arc<C> {
    fn now(&self) -> Instant {
        (**self).now()
    }
}

/// Standard monotonic system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Controllable clock for deterministic deadline testing.
#[derive(Debug)]
pub struct FakeClock {
    current: RwLock<Instant>,
}

impl FakeClock {
    /// Create a new fake clock initialized to an instant.
    pub fn new(start: Instant) -> Self {
        Self {
            current: RwLock::new(start),
        }
    }

    /// Advance fake clock time by the given duration.
    pub fn advance(&self, duration: Duration) {
        let mut cur = self.current.write().expect("lock poisoned");
        *cur += duration;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        *self.current.read().expect("lock poisoned")
    }
}
