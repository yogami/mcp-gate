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
    BinaryNotFound(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Var(e) => write!(f, "variable expansion error: {e}"),
            Self::Missing(p) => write!(f, "policy path entry does not exist: {}", p.display()),
            Self::Loop(p) => write!(f, "symlink loop resolving policy path: {}", p.display()),
            Self::BinaryNotFound(b) => write!(f, "binary not found in PATH: {b}"),
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

fn is_file_or_symlink(path: &Path, fs: &dyn FsView) -> bool {
    fs.lstat(path)
        .map(|m| m.file_type != FileType::Dir)
        .unwrap_or(false)
}

fn check_candidate(candidate: &str, fs: &dyn FsView) -> Option<PathBuf> {
    let res = resolve(
        fs,
        Path::new("/"),
        Path::new("/"),
        candidate.as_bytes(),
        true,
        None,
    );
    if res.exists && is_file_or_symlink(&res.resolved, fs) {
        Some(res.resolved)
    } else {
        None
    }
}

fn search_path_dirs(name: &str, capsule_path: &str, fs: &dyn FsView) -> Option<PathBuf> {
    capsule_path
        .split(':')
        .filter(|d| !d.is_empty())
        .find_map(|dir| check_candidate(&format!("{dir}/{name}"), fs))
}

/// Resolve a binary name to its canonical executable path.
///
/// If `name` contains a slash, it is resolved directly. Otherwise, it is
/// searched across the directories in `capsule_path` (REQ-POL-004).
pub fn resolve_binary(
    name: &str,
    capsule_path: &str,
    fs: &dyn FsView,
) -> Result<PathBuf, PolicyError> {
    let found = if name.contains('/') {
        check_candidate(name, fs)
    } else {
        search_path_dirs(name, capsule_path, fs)
    };
    found.ok_or_else(|| PolicyError::BinaryNotFound(name.to_string()))
}

fn resolve_child_binaries(
    raw_binaries: &[String],
    capsule_path: &str,
    fs: &dyn FsView,
) -> Result<Vec<PathBuf>, PolicyError> {
    let mut resolved = Vec::new();
    for raw in raw_binaries {
        let bin = resolve_binary(raw, capsule_path, fs)?;
        if !resolved.contains(&bin) {
            resolved.push(bin);
        }
    }
    Ok(resolved)
}

fn merge_write_into_read(read_paths: &mut Vec<PathEntry>, write_paths: &[PathEntry]) {
    for wp in write_paths {
        if !read_paths.contains(wp) {
            read_paths.push(wp.clone());
        }
    }
}

/// Fully canonicalized capability policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub read_paths: Vec<PathEntry>,
    pub write_paths: Vec<PathEntry>,
    pub allowed_child_binaries: Vec<PathBuf>,
    pub allow_network: bool,
    pub allowed_unix_sockets: Vec<String>,
    pub to_create: Vec<PathBuf>,
}

impl ResolvedPolicy {
    /// Canonicalize a `PolicyConfig` against the filesystem view and variable table using default PATH.
    pub fn from_config(
        policy: &PolicyConfig,
        vars: &VarTable,
        fs: &dyn FsView,
    ) -> Result<Self, PolicyError> {
        Self::from_config_with_path(policy, vars, "/usr/local/bin:/usr/bin:/bin", fs)
    }

    /// Canonicalize a `PolicyConfig` using an explicit capsule PATH string.
    pub fn from_config_with_path(
        policy: &PolicyConfig,
        vars: &VarTable,
        capsule_path: &str,
        fs: &dyn FsView,
    ) -> Result<Self, PolicyError> {
        let mut to_create = Vec::new();
        let mut read_paths = resolve_path_list(&policy.read_paths, vars, fs, &mut to_create)?;
        let write_paths = resolve_path_list(&policy.write_paths, vars, fs, &mut to_create)?;

        // REQ-POL-003: write_paths implies read on the same paths
        merge_write_into_read(&mut read_paths, &write_paths);

        // REQ-POL-004: allowed_child_binaries resolved through capsule PATH
        let allowed_child_binaries =
            resolve_child_binaries(&policy.allowed_child_binaries, capsule_path, fs)?;

        Ok(Self {
            read_paths,
            write_paths,
            allowed_child_binaries,
            allow_network: policy.allow_network,
            allowed_unix_sockets: policy.allowed_unix_sockets.clone(),
            to_create,
        })
    }

    /// Check if reading `path` is permitted by any read path entry.
    pub fn is_read_allowed(&self, path: &Path) -> bool {
        self.read_paths.iter().any(|entry| match entry {
            PathEntry::Dir(d) => is_within(path, d),
            PathEntry::File(f) => path == f,
        })
    }

    /// Check if writing `path` is permitted by any write path entry.
    pub fn is_write_allowed(&self, path: &Path) -> bool {
        self.write_paths.iter().any(|entry| match entry {
            PathEntry::Dir(d) => is_within(path, d),
            PathEntry::File(f) => path == f,
        })
    }

    /// Check if executing `binary` is permitted. Root process is always permitted (REQ-POL-004).
    pub fn is_exec_allowed(&self, binary: &Path, is_root: bool) -> bool {
        if is_root {
            return true;
        }
        self.allowed_child_binaries.iter().any(|b| b == binary)
    }
}
