//! EnforcementSet and EvaluationSet separation.
//!
//! SPEC 2.4 (REQ-POL-007):
//! EnforcementSet = policy ∪ baseline ∪ CAPSULE_TMP(rw) ∪ CAPSULE_HOME(ro)
//! EvaluationSet  = policy ∪ baseline ∪ CAPSULE_TMP(rw)

use std::path::{Path, PathBuf};

use crate::config::vars::VarTable;
use crate::path::contain::is_within;
use crate::policy::resolve::{PathEntry, ResolvedPolicy};

fn matches_any_entry(path: &Path, entries: &[PathEntry]) -> bool {
    entries.iter().any(|entry| match entry {
        PathEntry::Dir(d) => is_within(path, d),
        PathEntry::File(f) => path == f,
    })
}

/// The sandbox enforcement set applied to process sandboxing (Landlock).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementSet {
    pub read_paths: Vec<PathEntry>,
    pub write_paths: Vec<PathEntry>,
    pub capsule_home: PathBuf,
    pub capsule_tmp: PathBuf,
}

impl EnforcementSet {
    /// Build the enforcement set from a resolved policy and variable table.
    pub fn from_policy(policy: &ResolvedPolicy, vars: &VarTable) -> Self {
        let mut read_paths = policy.read_paths.clone();
        for bp in &policy.baseline_paths {
            if !read_paths.contains(bp) {
                read_paths.push(bp.clone());
            }
        }
        let write_paths = policy.write_paths.clone();

        Self {
            read_paths,
            write_paths,
            capsule_home: vars.capsule_home.clone(),
            capsule_tmp: vars.capsule_tmp.clone(),
        }
    }

    /// Check if path is contained in either read or write permissions.
    pub fn contains(&self, path: &Path) -> bool {
        self.is_read_allowed(path) || self.is_write_allowed(path)
    }

    /// Check if path is allowed for reading (including decoy zone).
    pub fn is_read_allowed(&self, path: &Path) -> bool {
        is_within(path, &self.capsule_home)
            || is_within(path, &self.capsule_tmp)
            || matches_any_entry(path, &self.read_paths)
    }

    /// Check if path is allowed for writing.
    pub fn is_write_allowed(&self, path: &Path) -> bool {
        is_within(path, &self.capsule_tmp) || matches_any_entry(path, &self.write_paths)
    }
}

/// The policy evaluation set used to determine security findings.
///
/// Excludes the decoy zone (`CAPSULE_HOME`) so canary access produces findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationSet {
    pub read_paths: Vec<PathEntry>,
    pub write_paths: Vec<PathEntry>,
    pub capsule_tmp: PathBuf,
}

impl EvaluationSet {
    /// Build the evaluation set from a resolved policy and variable table.
    pub fn from_policy(policy: &ResolvedPolicy, vars: &VarTable) -> Self {
        let mut read_paths = policy.read_paths.clone();
        for bp in &policy.baseline_paths {
            if !read_paths.contains(bp) {
                read_paths.push(bp.clone());
            }
        }
        let write_paths = policy.write_paths.clone();

        Self {
            read_paths,
            write_paths,
            capsule_tmp: vars.capsule_tmp.clone(),
        }
    }

    /// Check if path is contained in evaluation permissions.
    pub fn contains(&self, path: &Path) -> bool {
        self.is_read_allowed(path) || self.is_write_allowed(path)
    }

    /// Check if path is allowed for reading (strictly excludes decoy zone).
    pub fn is_read_allowed(&self, path: &Path) -> bool {
        is_within(path, &self.capsule_tmp) || matches_any_entry(path, &self.read_paths)
    }

    /// Check if path is allowed for writing.
    pub fn is_write_allowed(&self, path: &Path) -> bool {
        is_within(path, &self.capsule_tmp) || matches_any_entry(path, &self.write_paths)
    }
}
