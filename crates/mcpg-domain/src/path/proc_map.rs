use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Target process classification for `/proc` path mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcTarget {
    Capsule,
    Foreign(u32),
}

/// Process table and descriptor context for resolving `/proc` and `/dev/fd` paths.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcCtx {
    pub capsule_pids: BTreeSet<u32>,
    pub fds: BTreeMap<(u32, i32), PathBuf>,
    pub current_pid: Option<u32>,
}

impl ProcCtx {
    pub fn new(capsule_pids: BTreeSet<u32>, fds: BTreeMap<(u32, i32), PathBuf>) -> Self {
        let current_pid = capsule_pids.iter().next().copied();
        Self {
            capsule_pids,
            fds,
            current_pid,
        }
    }

    pub fn with_current_pid(mut self, pid: u32) -> Self {
        self.current_pid = Some(pid);
        self
    }

    pub fn is_capsule_pid(&self, pid: u32) -> bool {
        self.capsule_pids.contains(&pid)
    }

    pub fn resolve_fd(&self, pid: Option<u32>, fd: i32) -> Option<&Path> {
        let target_pid = pid.or(self.current_pid)?;
        self.fds.get(&(target_pid, fd)).map(|p| p.as_path())
    }
}

fn is_self_alias(name: &str) -> bool {
    name == "self" || name == "thread-self"
}

/// Classify a component under `/proc` as capsule or foreign.
pub fn classify_proc_target(name: &str, ctx: &ProcCtx) -> Option<ProcTarget> {
    if is_self_alias(name) {
        return Some(ProcTarget::Capsule);
    }
    let pid: u32 = name.parse().ok()?;
    if ctx.is_capsule_pid(pid) {
        return Some(ProcTarget::Capsule);
    }
    Some(ProcTarget::Foreign(pid))
}

/// Parse an integer file descriptor.
pub fn parse_fd(s: &str) -> Option<i32> {
    s.parse().ok()
}

/// Construct the logical prefix for a `/proc` target.
pub fn build_proc_prefix(target: &ProcTarget) -> PathBuf {
    match target {
        ProcTarget::Capsule => PathBuf::from("proc:capsule"),
        ProcTarget::Foreign(pid) => PathBuf::from(format!("proc:foreign:{pid}")),
    }
}
