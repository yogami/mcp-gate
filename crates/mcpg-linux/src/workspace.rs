//! Workspace preparation and isolation.
//!
//! SPEC 3.1.2, 3.5.1 (REQ-POL-002):
//! Prepares the capsule workspace by either:
//! - Copying from source to <run-dir>/workspace, excluding .git and configured excludes.
//!   Symlinks are preserved without being followed.
//!   Plants fixture link: ${WORKSPACE}/mcpg-link -> ${CAPSULE_HOME}/.ssh.
//! - InPlace mode: returns the source path directly.

use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use mcpg_domain::config::model::{WorkspaceConfig, WorkspaceMode};

use crate::rundir::RunDir;

fn is_excluded(name: &str, exclude: &[String]) -> bool {
    exclude.iter().any(|ex| ex == name)
}

fn copy_entry(src: &Path, dst: &Path, exclude: &[String]) -> io::Result<()> {
    let name = match src.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return Ok(()),
    };

    if is_excluded(name, exclude) {
        return Ok(());
    }

    let meta = fs::symlink_metadata(src)?;
    if meta.file_type().is_symlink() {
        #[cfg(unix)]
        {
            let target = fs::read_link(src)?;
            symlink(&target, dst)?;
        }
        #[cfg(not(unix))]
        {
            fs::copy(src, dst)?;
        }
    } else if meta.is_dir() {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let child_src = entry.path();
            let child_dst = dst.join(entry.file_name());
            copy_entry(&child_src, &child_dst, exclude)?;
        }
    } else {
        fs::copy(src, dst)?;
    }

    Ok(())
}

/// Prepare the workspace directory for capsule execution.
pub fn prepare(cfg: &WorkspaceConfig, run_dir: &RunDir) -> io::Result<PathBuf> {
    match cfg.mode {
        WorkspaceMode::InPlace => Ok(PathBuf::from(&cfg.source)),
        WorkspaceMode::Copy => {
            let src = Path::new(&cfg.source);
            let dst = run_dir.workspace();

            if src.exists() {
                for entry in fs::read_dir(src)? {
                    let entry = entry?;
                    let child_src = entry.path();
                    let child_dst = dst.join(entry.file_name());
                    copy_entry(&child_src, &child_dst, &cfg.exclude)?;
                }
            }

            // Payload 07 fixture link: ${WORKSPACE}/mcpg-link -> ${CAPSULE_HOME}/.ssh
            let mcpg_link = dst.join("mcpg-link");
            let ssh_target = run_dir.home().join(".ssh");
            #[cfg(unix)]
            if !mcpg_link.exists() && fs::symlink_metadata(&mcpg_link).is_err() {
                symlink(&ssh_target, &mcpg_link)?;
            }

            Ok(dst.to_path_buf())
        }
    }
}
