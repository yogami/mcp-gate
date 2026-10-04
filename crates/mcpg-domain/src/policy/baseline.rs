//! Baseline path definitions for language runtimes.
//!
//! SPEC 2.4 (REQ-POL-005): Selected baseline adds read-only paths that language
//! runtimes need. The expanded list is filtered through `FsView` so absent paths
//! (for example `/lib64` on arm64) are dropped. `none` adds nothing.

use std::path::Path;

use crate::config::model::Baseline;
use crate::fs_view::{FileType, FsView};
use crate::path::resolve::resolve;
use crate::policy::resolve::PathEntry;

const MINIMAL_PATHS: &[&str] = &[
    "/dev/null",
    "/dev/urandom",
    "/dev/zero",
    "/etc/ld.so.cache",
    "/etc/localtime",
    "/etc/ssl/certs",
    "/lib",
    "/lib64",
    "/usr",
    "/bin",
];

const PYTHON_PATHS: &[&str] = &[
    "/dev/null",
    "/dev/urandom",
    "/dev/zero",
    "/etc/ld.so.cache",
    "/etc/localtime",
    "/etc/ssl/certs",
    "/lib",
    "/lib64",
    "/usr",
    "/bin",
    "/etc/python3",
    "/usr/lib/python3",
    "/usr/local/lib/python3",
];

const NODE_PATHS: &[&str] = &[
    "/dev/null",
    "/dev/urandom",
    "/dev/zero",
    "/etc/ld.so.cache",
    "/etc/localtime",
    "/etc/ssl/certs",
    "/lib",
    "/lib64",
    "/usr",
    "/bin",
    "/usr/lib/node_modules",
    "/usr/local/lib/node_modules",
];

fn classify_candidate(raw: &str, fs: &dyn FsView) -> Option<PathEntry> {
    let res = resolve(
        fs,
        Path::new("/"),
        Path::new("/"),
        raw.as_bytes(),
        true,
        None,
    );
    if !res.exists {
        return None;
    }
    let is_dir = fs
        .lstat(&res.resolved)
        .map(|m| m.file_type == FileType::Dir)
        .unwrap_or(false);
    if is_dir {
        Some(PathEntry::Dir(res.resolved))
    } else {
        Some(PathEntry::File(res.resolved))
    }
}

fn raw_baseline_paths(baseline: Baseline) -> &'static [&'static str] {
    match baseline {
        Baseline::None => &[],
        Baseline::Minimal => MINIMAL_PATHS,
        Baseline::Python => PYTHON_PATHS,
        Baseline::Node => NODE_PATHS,
    }
}

/// Expand a runtime baseline into canonical, deduplicated `PathEntry` items.
///
/// Any paths that do not exist on the current filesystem view are silently dropped.
pub fn expand_baseline(baseline: Baseline, fs: &dyn FsView) -> Vec<PathEntry> {
    let candidates = raw_baseline_paths(baseline);
    let mut entries = Vec::new();
    for &cand in candidates {
        if let Some(entry) = classify_candidate(cand, fs) {
            if !entries.contains(&entry) {
                entries.push(entry);
            }
        }
    }
    entries
}
