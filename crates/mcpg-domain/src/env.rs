//! Environment scrubbing and construction for the test capsule.
//!
//! Under REQ-ENV-001, the child environment is built from scratch, never by
//! filtering the host environment in place.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use crate::config::model::EnvConfig;

/// Fixed environment variables supplied to the capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedEnv {
    pub home: PathBuf,
    pub tmpdir: PathBuf,
    pub path: String,
    pub lang: String,
}

impl Default for FixedEnv {
    fn default() -> Self {
        Self {
            home: PathBuf::from("/tmp"),
            tmpdir: PathBuf::from("/tmp"),
            path: "/usr/local/bin:/usr/bin:/bin".to_string(),
            lang: "C.UTF-8".to_string(),
        }
    }
}

/// Errors occurring during environment variable scrubbing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvError {
    Forbidden(String),
    SecretPassthrough(String),
    InvalidSet(String),
}

impl std::fmt::Display for EnvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forbidden(s) => write!(f, "forbidden environment variable: {s}"),
            Self::SecretPassthrough(s) => {
                write!(f, "secret-shaped passthrough variable disallowed: {s}")
            }
            Self::InvalidSet(s) => write!(f, "invalid set environment variable: {s}"),
        }
    }
}

impl std::error::Error for EnvError {}

fn add_fixed_vars(env: &mut BTreeMap<OsString, OsString>, fixed: &FixedEnv) {
    env.insert(OsString::from("HOME"), OsString::from(&fixed.home));
    env.insert(OsString::from("LANG"), OsString::from(&fixed.lang));
    env.insert(OsString::from("PATH"), OsString::from(&fixed.path));
    env.insert(OsString::from("TMPDIR"), OsString::from(&fixed.tmpdir));
}

fn matches_passthrough_pattern(pattern: &str, candidate: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        candidate.starts_with(prefix)
    } else {
        candidate == pattern
    }
}

fn matches_ci_prefix(name: &str) -> bool {
    name.starts_with("GITHUB_") || name.starts_with("RUNNER_") || name.starts_with("ACTIONS_")
}

fn is_ci_deny_var(name: &str) -> bool {
    if name == "CI" {
        return true;
    }
    matches_ci_prefix(name)
}

fn is_forbidden_token(name: &str) -> bool {
    name == "ACTIONS_RUNTIME_TOKEN" || name.starts_with("ACTIONS_ID_TOKEN_REQUEST")
}

fn check_forbidden_passthrough(passthrough: &[String]) -> Result<(), EnvError> {
    for pat in passthrough {
        if is_forbidden_token(pat) {
            return Err(EnvError::Forbidden(pat.clone()));
        }
    }
    Ok(())
}

fn add_passthrough_vars(
    env: &mut BTreeMap<OsString, OsString>,
    host: &[(OsString, OsString)],
    passthrough: &[String],
) {
    for (k, v) in host {
        let key_str = k.to_string_lossy();
        if is_ci_deny_var(&key_str) {
            continue;
        }
        let matches = passthrough
            .iter()
            .any(|pat| matches_passthrough_pattern(pat, &key_str));
        if matches {
            env.insert(k.clone(), v.clone());
        }
    }
}

fn add_set_vars(env: &mut BTreeMap<OsString, OsString>, set: &BTreeMap<String, String>) {
    for (k, v) in set {
        env.insert(OsString::from(k), OsString::from(v));
    }
}

fn add_decoy_vars(env: &mut BTreeMap<OsString, OsString>, decoys: &[(OsString, OsString)]) {
    for (k, v) in decoys {
        if !env.contains_key(k) {
            env.insert(k.clone(), v.clone());
        }
    }
}

/// Build the scrubbed capsule environment from host environment, configuration, and decoys.
pub fn build_env(
    host: &[(OsString, OsString)],
    cfg: &EnvConfig,
    fixed: &FixedEnv,
    decoys: &[(OsString, OsString)],
) -> Result<Vec<(OsString, OsString)>, EnvError> {
    check_forbidden_passthrough(&cfg.passthrough)?;

    let mut env = BTreeMap::new();

    add_fixed_vars(&mut env, fixed);
    add_passthrough_vars(&mut env, host, &cfg.passthrough);
    add_set_vars(&mut env, &cfg.set);
    add_decoy_vars(&mut env, decoys);

    Ok(env.into_iter().collect())
}
