//! Canary registry and observation records.
//!
//! SPEC 3.2.3 (REQ-CAN-005):
//! Planting returns a CanaryRegistry: for each canary, its ID, kind, tier,
//! path, (st_dev, st_ino), the secret substrings, and a fingerprint (sha256(value)[0..12]).
//! Access matching compares (dev, ino) as well as path.

use std::path::{Path, PathBuf};

use crate::canary::catalogue::{CanaryKind, CanaryTier};
use crate::canary::render::Secret;

/// An individual planted canary record in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryRecord {
    pub id: String,
    pub kind: CanaryKind,
    pub tier: CanaryTier,
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub fp: String,
    pub secrets: Vec<Secret>,
}

/// Registry of all planted canaries for a run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CanaryRegistry {
    pub records: Vec<CanaryRecord>,
}

impl CanaryRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a record to the registry.
    pub fn add(&mut self, record: CanaryRecord) {
        self.records.push(record);
    }

    /// Find a matching canary record by device and inode.
    pub fn find_by_dev_ino(&self, dev: u64, ino: u64) -> Option<&CanaryRecord> {
        self.records.iter().find(|r| r.dev == dev && r.ino == ino)
    }

    /// Find a matching canary record by filesystem path.
    pub fn find_by_path(&self, path: &Path) -> Option<&CanaryRecord> {
        self.records.iter().find(|r| r.path == path)
    }
}
