//! Canary planting into the disposable run directory.
//!
//! SPEC 3.2.2, 3.2.3:
//! Plants canary files with 0600 mode and creates parent directories with 0700 mode.
//! Records device, inode, secrets, and sha256(value)[0..12] fingerprint into CanaryRegistry.

use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use mcpg_domain::canary::catalogue::CanaryKind;
use mcpg_domain::canary::registry::{CanaryRecord, CanaryRegistry};
use mcpg_domain::canary::render::{CanaryPlan, Secret};
use sha2::{Digest, Sha256};

use crate::rundir::RunDir;

fn compute_fingerprint(secrets: &[Secret], content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    if let Some(first_secret) = secrets.first() {
        hasher.update(first_secret.value.as_bytes());
    } else {
        hasher.update(content);
    }
    let full = format!("{:x}", hasher.finalize());
    full[..12].to_string()
}

fn set_dirs_mode_0700(mut dir: &std::path::Path, stop_at: &std::path::Path) -> io::Result<()> {
    while dir != stop_at && dir.starts_with(stop_at) {
        #[cfg(unix)]
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        match dir.parent() {
            Some(p) => dir = p,
            None => break,
        }
    }
    Ok(())
}

/// Plant all planned files from a CanaryPlan into the run directory.
pub fn plant(plan: &CanaryPlan, run_dir: &RunDir) -> io::Result<CanaryRegistry> {
    let mut registry = CanaryRegistry::new();

    for (i, planned) in plan.files.iter().enumerate() {
        let target_path = if planned.kind == CanaryKind::Dotenv {
            run_dir.root().join(&planned.path)
        } else {
            run_dir.home().join(&planned.path)
        };

        if let Some(parent) = target_path.parent() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)?;
            }
            #[cfg(not(unix))]
            {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }
        }

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(planned.mode)
                .open(&target_path)?;
            f.write_all(&planned.content)?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&target_path, &planned.content)?;
        }

        let meta = fs::metadata(&target_path)?;
        #[cfg(unix)]
        let (dev, ino) = (meta.dev(), meta.ino());
        #[cfg(not(unix))]
        let (dev, ino) = (1, (i + 1) as u64);

        let secrets: Vec<_> = plan
            .secrets
            .iter()
            .filter(|s| s.kind == planned.kind)
            .cloned()
            .collect();

        let fp = compute_fingerprint(&secrets, &planned.content);

        registry.add(CanaryRecord {
            id: format!("{}_{i}", planned.kind as u8),
            kind: planned.kind,
            tier: planned.tier,
            path: target_path,
            dev,
            ino,
            fp,
            secrets,
        });
    }

    Ok(registry)
}
