//! Capability policy resolution and canonicalization.

use std::path::{Path, PathBuf};

use crate::config::model::PolicyConfig;
use crate::config::vars::{expand, VarError, VarTable};
use crate::fs_view::{FileType, FsView};
use crate::path::contain::is_within;
use crate::path::resolve::resolve;

/// Typed policy entry: a file or a directory granting its whole subtree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathEntry {
    File(PathBuf),
    Dir(PathBuf),
}

impl PathEntry {
    pub fn path(&self) -> &Path {
        match self {
            Self::File(p) | Self::Dir(p) => p,
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Dir(_))
    }
}

/// Errors occurring during policy resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Var(VarError),
    Missing(PathBuf),
    Loop(PathBuf),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Var(e) => write!(f, "variable expansion error: {e}"),
            Self::Missing(p) => write!(f, "policy path entry does not exist: {}", p.display()),
            Self::Loop(p) => write!(f, "symlink loop resolving policy path: {}", p.display()),
        }
    }
}

impl std::error::Error for PolicyError {}

impl From<VarError> for PolicyError {
    fn from(err: VarError) -> Self {
        Self::Var(err)
    }
}

enum PolicyItem {
    Existing(PathEntry),
    ToCreate(PathBuf),
}

fn is_creatable(path: &Path, vars: &VarTable) -> bool {
    is_within(path, &vars.workspace) || is_within(path, &vars.capsule_tmp)
}

fn classify_existing(path: &Path, fs: &dyn FsView) -> PathEntry {
    let is_dir = fs
        .lstat(path)
        .map(|m| m.file_type == FileType::Dir)
        .unwrap_or(false);
    if is_dir {
        PathEntry::Dir(path.to_path_buf())
    } else {
        PathEntry::File(path.to_path_buf())
    }
}

fn resolve_single_entry(
    raw: &str,
    vars: &VarTable,
    fs: &dyn FsView,
) -> Result<PolicyItem, PolicyError> {
    let expanded = expand(raw, vars)?;
    let res = resolve(
        fs,
        Path::new("/"),
        Path::new("/"),
        expanded.as_os_str().as_encoded_bytes(),
        true,
        None,
    );
    if res.is_eloop() {
        return Err(PolicyError::Loop(expanded));
    }
    if res.exists {
        return Ok(PolicyItem::Existing(classify_existing(&res.resolved, fs)));
    }
    if is_creatable(&res.resolved, vars) {
        return Ok(PolicyItem::ToCreate(res.resolved));
    }
    Err(PolicyError::Missing(res.resolved))
}

fn resolve_path_list(
    raw_paths: &[String],
    vars: &VarTable,
    fs: &dyn FsView,
    to_create: &mut Vec<PathBuf>,
) -> Result<Vec<PathEntry>, PolicyError> {
    let mut entries = Vec::new();
    for raw in raw_paths {
        let item = resolve_single_entry(raw, vars, fs)?;
        match item {
            PolicyItem::Existing(entry) => entries.push(entry),
            PolicyItem::ToCreate(path) => {
                if !to_create.contains(&path) {
                    to_create.push(path.clone());
                }
                entries.push(PathEntry::Dir(path));
            }
        }
    }
    Ok(entries)
}

/// Fully canonicalized capability policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub read_paths: Vec<PathEntry>,
    pub write_paths: Vec<PathEntry>,
    pub allowed_child_binaries: Vec<String>,
    pub allow_network: bool,
    pub allowed_unix_sockets: Vec<String>,
    pub to_create: Vec<PathBuf>,
}

impl ResolvedPolicy {
    /// Canonicalize a `PolicyConfig` against the filesystem view and variable table.
    pub fn from_config(
        policy: &PolicyConfig,
        vars: &VarTable,
        fs: &dyn FsView,
    ) -> Result<Self, PolicyError> {
        let mut to_create = Vec::new();
        let read_paths = resolve_path_list(&policy.read_paths, vars, fs, &mut to_create)?;
        let write_paths = resolve_path_list(&policy.write_paths, vars, fs, &mut to_create)?;

        Ok(Self {
            read_paths,
            write_paths,
            allowed_child_binaries: policy.allowed_child_binaries.clone(),
            allow_network: policy.allow_network,
            allowed_unix_sockets: policy.allowed_unix_sockets.clone(),
            to_create,
        })
    }
}
