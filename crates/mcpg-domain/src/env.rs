//! Environment scrubbing and construction for the test capsule.
//!
//! Under REQ-ENV-001, the child environment is built from scratch, never by
//! filtering the host environment in place.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

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

/// The outcome of scrubbing environment variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvOutcome {
    pub vars: Vec<(OsString, OsString)>,
    pub warnings: Vec<String>,
}

/// Errors occurring during environment variable scrubbing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvError {
    Forbidden(String),
    SecretNeedsOptIn(String),
    InvalidSet(String),
}

impl std::fmt::Display for EnvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forbidden(s) => write!(f, "forbidden environment variable: {s}"),
            Self::SecretNeedsOptIn(s) => {
                write!(
                    f,
                    "secret-shaped passthrough variable disallowed without allow_secret_passthrough: {s}"
                )
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

fn contains_secret_word(name: &str) -> bool {
    name.contains("TOKEN") || name.contains("SECRET") || name.contains("PASSWORD")
}

fn matches_secret_affix(name: &str) -> bool {
    name.ends_with("_KEY") || name.starts_with("AWS_")
}

fn is_secret_shaped(name: &str) -> bool {
    let clean = name.strip_suffix('*').unwrap_or(name);
    contains_secret_word(clean) || matches_secret_affix(clean)
}

fn validate_secret_key(key: &str, allow: bool, warnings: &mut Vec<String>) -> Result<(), EnvError> {
    if !is_secret_shaped(key) {
        return Ok(());
    }
    if !allow {
        return Err(EnvError::SecretNeedsOptIn(key.to_string()));
    }
    let msg = format!("secret-shaped passthrough variable allowed: {key}");
    if !warnings.contains(&msg) {
        warnings.push(msg);
    }
    Ok(())
}

fn check_secret_passthrough(
    passthrough: &[String],
    allow: bool,
    warnings: &mut Vec<String>,
) -> Result<(), EnvError> {
    for pat in passthrough {
        if !is_ci_deny_var(pat) {
            validate_secret_key(pat, allow, warnings)?;
        }
    }
    Ok(())
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
    allow: bool,
    warnings: &mut Vec<String>,
) -> Result<(), EnvError> {
    for (k, v) in host {
        let key_str = k.to_string_lossy();
        if is_ci_deny_var(&key_str) {
            continue;
        }
        // B-09: Passthrough must not overwrite fixed vars.
        if key_str == "HOME" || key_str == "TMPDIR" || key_str == "PATH" || key_str == "LANG" {
            continue;
        }

        let matches = passthrough
            .iter()
            .any(|pat| matches_passthrough_pattern(pat, &key_str));
        if matches {
            validate_secret_key(&key_str, allow, warnings)?;
            env.insert(k.clone(), v.clone());
        }
    }
    Ok(())
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

fn validate_path_entries(val: &str, is_reachable: &dyn Fn(&Path) -> bool) -> Result<(), EnvError> {
    for part in val.split(':') {
        if part.is_empty() || !is_reachable(Path::new(part)) {
            return Err(EnvError::InvalidSet("PATH".to_string()));
        }
    }
    Ok(())
}

fn validate_set_entry(
    key: &str,
    val: &str,
    is_reachable: &dyn Fn(&Path) -> bool,
) -> Result<(), EnvError> {
    if key == "HOME" || key == "TMPDIR" || key == "LANG" {
        return Err(EnvError::InvalidSet(key.to_string()));
    }
    if key == "PATH" {
        validate_path_entries(val, is_reachable)?;
    }
    Ok(())
}

fn validate_set(
    set: &BTreeMap<String, String>,
    is_reachable: &dyn Fn(&Path) -> bool,
) -> Result<(), EnvError> {
    for (k, v) in set {
        validate_set_entry(k, v, is_reachable)?;
    }
    Ok(())
}

/// Build the scrubbed capsule environment from host environment, configuration, and decoys.
pub fn build_env(
    host: &[(OsString, OsString)],
    cfg: &EnvConfig,
    fixed: &FixedEnv,
    decoys: &[(OsString, OsString)],
    is_reachable: &dyn Fn(&Path) -> bool,
) -> Result<EnvOutcome, EnvError> {
    check_forbidden_passthrough(&cfg.passthrough)?;
    validate_set(&cfg.set, is_reachable)?;

    let mut warnings = Vec::new();
    check_secret_passthrough(
        &cfg.passthrough,
        cfg.allow_secret_passthrough,
        &mut warnings,
    )?;

    let mut env = BTreeMap::new();

    add_fixed_vars(&mut env, fixed);

    // B-08: validate secret keys on the host keys actually matched.
    add_passthrough_vars(
        &mut env,
        host,
        &cfg.passthrough,
        cfg.allow_secret_passthrough,
        &mut warnings,
    )?;

    // add_set_vars can override PATH, but not HOME/TMPDIR/LANG (prevented by validate_set_entry)
    add_set_vars(&mut env, &cfg.set);

    add_decoy_vars(&mut env, decoys);

    Ok(EnvOutcome {
        vars: env.into_iter().collect(),
        warnings,
    })
}
