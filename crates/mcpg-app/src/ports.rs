//! Application port traits.

use std::fmt;
use std::process::Child;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;

pub use mcpg_domain::seed::EntropySource;
use mcpg_domain::config::model::Config;
use mcpg_domain::seed::Seed;
use mcpg_domain::env::EnvOutcome;
use mcpg_domain::config::vars::VarTable;
use mcpg_domain::canary::registry::CanaryRegistry;
use mcpg_domain::verdict::ExitCode;
use mcpg_domain::policy::resolve::ResolvedPolicy;
use mcpg_domain::host::HostCaps;
use mcpg_domain::event::Event;
use crate::orchestrator::RunOptions;

use crate::capsule_plan::CapsulePlan;

/// Handle to a running capsule child process.
#[derive(Debug)]
pub struct RunningCapsule {
    pub pid: u32,
    pub child: Child,
    pub seccomp_listener_fd: Option<RawFd>,
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
    pub fn new(start: Instant) -> Self {
        Self {
            current: RwLock::new(start),
        }
    }

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

pub trait Sandbox {
    fn generate_seed(&self) -> Result<Seed, ExitCode>;
    fn probe_host_caps(&self) -> HostCaps;
    fn init(&self, cfg: &Config, seed: &Seed, opts: &RunOptions) -> Result<(VarTable, CanaryRegistry, EnvOutcome), ExitCode>;
    fn build_ruleset(&self, policy: &ResolvedPolicy, vars: &VarTable, cmd: &str, caps: &HostCaps) -> Result<Option<OwnedFd>, ExitCode>;
    fn setup_tripwire(&self, registry: &CanaryRegistry, phase: crate::phase::PhaseCursor) -> Result<Option<Box<dyn TripwireHandle>>, ExitCode>;
    fn teardown(&self, capsule: RunningCapsule, grace: Duration) -> Result<Vec<Event>, ExitCode>;
    fn create_launcher(&self, ruleset: Option<OwnedFd>) -> (Box<dyn CapsuleLauncher>, Option<RawFd>);
    fn disarm_guard(&self);
    fn arm_guard(&self, pid: i32, pids: Vec<u32>);
    fn start_observer_thread(
        &self,
        fd: RawFd,
        allow_network: bool,
        allowed_child_binaries: Vec<std::path::PathBuf>,
        root_command: Option<std::path::PathBuf>,
        allowed_unix_sockets: Vec<String>,
        capsule_pids: Vec<u32>,
        active_phase: Option<String>,
        events_tx: Option<std::sync::mpsc::Sender<Event>>,
        obs_tx: std::sync::mpsc::Sender<(String, String)>,
    ) -> std::thread::JoinHandle<()>;
}

pub trait TripwireHandle {
    fn stop(&mut self);
    fn join(self: Box<Self>) -> Result<Vec<(String, String)>, ()>;
}


