//! Disposable run directory management.
//!
//! SPEC 3.1.2:
//! Run directory layout:
//! <run-dir>/
//! ├── home/       (${CAPSULE_HOME})
//! ├── workspace/  (${WORKSPACE})
//! └── tmp/        (${CAPSULE_TMP})

use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use mcpg_app::ports::EntropySource;

/// Disposable directory tree containing capsule home, workspace, and tmp.
#[derive(Debug)]
pub struct RunDir {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
    tmp: PathBuf,
    keep: bool,
}

impl RunDir {
    /// Create a new disposable run directory with 0700 permissions.
    pub fn create(base: &Path, keep: bool, entropy: &dyn EntropySource) -> io::Result<Self> {
        let mut random_bytes = [0u8; 8];
        entropy.fill_bytes(&mut random_bytes)?;
        let hex_id = random_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        let root = base.join(format!("mcpg-{hex_id}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&root)?;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(&root)?;
        }

        let home = root.join("home");
        let workspace = root.join("workspace");
        let tmp = root.join("tmp");

        for sub in [&home, &workspace, &tmp] {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new().recursive(true).mode(0o700).create(sub)?;
            }
            #[cfg(not(unix))]
            {
                fs::create_dir_all(sub)?;
            }
        }

        Ok(Self {
            root,
            home,
            workspace,
            tmp,
            keep,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn tmp(&self) -> &Path {
        &self.tmp
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        if !self.keep && self.root.exists() {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
