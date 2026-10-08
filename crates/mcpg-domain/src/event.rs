//! Event model for mcp-gate boundary observations.
//!
//! SPEC 3.3.2:
//! Events are captured by the observer, leak scanner, tripwire, and protocol drivers.
#![forbid(unsafe_code)]

use crate::canary::catalogue::CanaryKind;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Event categories observed across capsule boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventKind {
    #[serde(rename = "fs.open")]
    FsOpen,
    #[serde(rename = "fs.mutate")]
    FsMutate,
    #[serde(rename = "fs.stat")]
    FsStat,
    #[serde(rename = "proc.exec")]
    ProcExec,
    #[serde(rename = "proc.spawn")]
    ProcSpawn,
    #[serde(rename = "proc.exit")]
    ProcExit,
    #[serde(rename = "proc.orphan")]
    ProcOrphan,
    #[serde(rename = "net.socket")]
    NetSocket,
    #[serde(rename = "net.connect")]
    NetConnect,
    #[serde(rename = "net.send")]
    NetSend,
    #[serde(rename = "net.bind")]
    NetBind,
    #[serde(rename = "unix.connect")]
    UnixConnect,
    #[serde(rename = "signal.send")]
    SignalSend,
    #[serde(rename = "tamper.denied")]
    TamperDenied,
    #[serde(rename = "canary.inotify")]
    CanaryInotify,
    #[serde(rename = "leak.match")]
    LeakMatch,
    #[serde(rename = "proto.violation")]
    ProtoViolation,
}

/// Access mode requested by an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessKind {
    Read,
    Write,
}

/// Observation source reporting the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventSource {
    SeccompNotify,
    Inotify,
    LeakScanner,
    Protocol,
}

/// Harness policy enforcement decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allowed,
    Denied,
}

/// Final outcome of the system call or operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Succeeded,
    Failed,
    Blocked,
    Unknown,
}

/// Raw system call arguments captured prior to kernel execution.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct RawSyscallData {
    pub dirfd: Option<String>,
    pub path: Option<String>,
    pub flags: Option<String>,
}

/// Canonical event structure representing an observed boundary action.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Event {
    pub v: u32,
    pub seq: u64,
    pub t_mono_ns: u64,
    pub phase: String,
    pub pid: u32,
    pub tid: u32,
    pub exe: PathBuf,
    pub kind: EventKind,
    pub syscall: Option<String>,
    pub raw: Option<RawSyscallData>,
    pub resolved: Option<PathBuf>,
    pub access: Option<AccessKind>,
    pub source: EventSource,
    pub decision: Decision,
    pub outcome: Outcome,
    pub dev_ino: Option<(u64, u64)>,
    pub canary_kind: Option<CanaryKind>,
    pub message: Option<String>,
    pub target: Option<String>,
    pub escaped_via: Option<String>,
}

impl Event {
    /// Return a fluent builder for constructing events.
    pub fn builder(kind: EventKind, phase: impl Into<String>) -> EventBuilder {
        EventBuilder::new(kind, phase.into())
    }
}

/// Fluent builder for constructing `Event` instances cleanly in tests and adapters.
#[derive(Debug, Clone)]
pub struct EventBuilder {
    event: Event,
}

impl EventBuilder {
    pub fn new(kind: EventKind, phase: String) -> Self {
        Self {
            event: Event {
                v: 1,
                seq: 0,
                t_mono_ns: 0,
                phase,
                pid: 1000,
                tid: 1000,
                exe: PathBuf::from("/usr/bin/server"),
                kind,
                syscall: None,
                raw: None,
                resolved: None,
                access: None,
                source: EventSource::SeccompNotify,
                decision: Decision::Allowed,
                outcome: Outcome::Unknown,
                dev_ino: None,
                canary_kind: None,
                message: None,
                target: None,
                escaped_via: None,
            },
        }
    }

    pub fn seq(mut self, seq: u64) -> Self {
        self.event.seq = seq;
        self
    }

    pub fn pid(mut self, pid: u32) -> Self {
        self.event.pid = pid;
        self
    }

    pub fn tid(mut self, tid: u32) -> Self {
        self.event.tid = tid;
        self
    }

    pub fn exe(mut self, exe: impl Into<PathBuf>) -> Self {
        self.event.exe = exe.into();
        self
    }

    pub fn syscall(mut self, syscall: impl Into<String>) -> Self {
        self.event.syscall = Some(syscall.into());
        self
    }

    pub fn resolved(mut self, resolved: impl Into<PathBuf>) -> Self {
        self.event.resolved = Some(resolved.into());
        self
    }

    pub fn access(mut self, access: AccessKind) -> Self {
        self.event.access = Some(access);
        self
    }

    pub fn source(mut self, source: EventSource) -> Self {
        self.event.source = source;
        self
    }

    pub fn decision(mut self, decision: Decision) -> Self {
        self.event.decision = decision;
        self
    }

    pub fn outcome(mut self, outcome: Outcome) -> Self {
        self.event.outcome = outcome;
        self
    }

    pub fn dev_ino(mut self, dev: u64, ino: u64) -> Self {
        self.event.dev_ino = Some((dev, ino));
        self
    }

    pub fn canary_kind(mut self, kind: CanaryKind) -> Self {
        self.event.canary_kind = Some(kind);
        self
    }

    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.event.message = Some(msg.into());
        self
    }

    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.event.target = Some(target.into());
        self
    }

    pub fn escaped_via(mut self, esc: impl Into<String>) -> Self {
        self.event.escaped_via = Some(esc.into());
        self
    }

    pub fn build(self) -> Event {
        self.event
    }
}
