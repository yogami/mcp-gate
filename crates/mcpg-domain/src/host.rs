use serde::{Deserialize, Serialize};

/// Optional host features that can be requested via `--require`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Feature {
    Landlock,
    LandlockNet,
}

impl std::str::FromStr for Feature {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "landlock" => Ok(Feature::Landlock),
            "landlock-net" => Ok(Feature::LandlockNet),
            _ => Err(format!("unknown feature: {s}")),
        }
    }
}

/// Landlock capabilities on the host kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandlockCaps {
    pub available: bool,
    pub abi: u32,
}

/// Seccomp capabilities on the host kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeccompCaps {
    pub filter: bool,
    pub user_notif: bool,
    pub notif_continue: bool,
    pub wait_killable_recv: bool,
}

/// Host support assessment result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assessment {
    pub supported: bool,
    pub missing: Vec<String>,
}

/// Host capabilities detected by the runner probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCaps {
    pub kernel: String,
    pub arch: String,
    pub landlock: LandlockCaps,
    pub seccomp: SeccompCaps,
    pub inotify: bool,
    pub proc_mem_readable: bool,
    pub supported: bool,
    pub missing: Vec<String>,
}

fn check_base_requirements(caps: &HostCaps, missing: &mut Vec<String>) {
    let checks = [
        (!caps.seccomp.user_notif, "seccomp.user_notif"),
        (!caps.seccomp.notif_continue, "seccomp.notif_continue"),
        (!caps.inotify, "inotify"),
        (!caps.proc_mem_readable, "proc_mem_readable"),
    ];
    for (failed, name) in checks {
        if failed {
            missing.push(name.to_string());
        }
    }
}

fn landlock_net_missing(caps: &HostCaps) -> bool {
    !caps.landlock.available || caps.landlock.abi < 4
}

fn check_feature_requirement(caps: &HostCaps, feature: Feature, missing: &mut Vec<String>) {
    match feature {
        Feature::Landlock => {
            if !caps.landlock.available {
                missing.push("landlock".to_string());
            }
        }
        Feature::LandlockNet => {
            if landlock_net_missing(caps) {
                missing.push("landlock-net".to_string());
            }
        }
    }
}

impl HostCaps {
    /// Assess whether this host meets all base requirements and required features.
    pub fn assess(&self, require: &[Feature]) -> Assessment {
        let mut missing = Vec::new();
        check_base_requirements(self, &mut missing);
        for &feature in require {
            check_feature_requirement(self, feature, &mut missing);
        }
        let supported = missing.is_empty();
        Assessment { supported, missing }
    }
}
