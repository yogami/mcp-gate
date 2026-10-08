//! Pre-spawn plan builder for the test capsule.
//!
//! SPEC 3.1.4: Pre-builds command line arguments and environment variables
//! as CString arrays before fork to ensure async-signal-safety in child.

use std::ffi::{CString, OsStr, OsString};
use std::fmt;
use std::path::PathBuf;

use mcpg_domain::config::model::Config;
use mcpg_domain::config::vars::{expand, VarTable};
use mcpg_domain::env::EnvOutcome;
pub use mcpg_domain::mode::Mode;

/// Errors occurring during capsule plan construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    InteriorNul(String),
    VarExpansion(String),
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InteriorNul(s) => write!(f, "interior NUL byte in argument or variable: {s}"),
            Self::VarExpansion(s) => write!(f, "variable expansion failed: {s}"),
        }
    }
}

impl std::error::Error for PlanError {}

/// Fully prepared execution plan for starting a capsule process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsulePlan {
    pub program: CString,
    pub argv: Vec<CString>,
    pub envp: Vec<CString>,
    pub cwd: PathBuf,
    pub mode: Mode,
}

fn to_cstring(s: &str) -> Result<CString, PlanError> {
    CString::new(s).map_err(|e| PlanError::InteriorNul(e.to_string()))
}

fn expand_string(raw: &str, vars: &VarTable) -> Result<String, PlanError> {
    if raw.contains("${") {
        let path = expand(raw, vars).map_err(|e| PlanError::VarExpansion(e.to_string()))?;
        let s = path.to_string_lossy().into_owned();
        if s.contains("..") {
            if let Ok(canon) = std::fs::canonicalize(&path) {
                return Ok(canon.to_string_lossy().into_owned());
            }
        }
        Ok(s)
    } else {
        Ok(raw.to_string())
    }
}

fn append_expanded_arg(
    argv: &mut Vec<CString>,
    raw: &str,
    vars: &VarTable,
) -> Result<(), PlanError> {
    let expanded = expand_string(raw, vars)?;
    let cstr = to_cstring(&expanded)?;
    argv.push(cstr);
    Ok(())
}

fn build_argv(cmd: &str, args: &[String], vars: &VarTable) -> Result<Vec<CString>, PlanError> {
    let mut argv = Vec::with_capacity(1 + args.len());
    append_expanded_arg(&mut argv, cmd, vars)?;
    for arg in args {
        append_expanded_arg(&mut argv, arg, vars)?;
    }
    Ok(argv)
}

#[cfg(unix)]
fn env_pair_to_cstring(k: &OsStr, v: &OsStr) -> Result<CString, PlanError> {
    use std::os::unix::ffi::OsStrExt;
    let mut bytes = Vec::with_capacity(k.len() + 1 + v.len());
    bytes.extend_from_slice(k.as_bytes());
    bytes.push(b'=');
    bytes.extend_from_slice(v.as_bytes());
    CString::new(bytes).map_err(|e| PlanError::InteriorNul(e.to_string()))
}

#[cfg(not(unix))]
fn env_pair_to_cstring(k: &OsStr, v: &OsStr) -> Result<CString, PlanError> {
    let s = format!("{}={}", k.to_string_lossy(), v.to_string_lossy());
    to_cstring(&s)
}

fn build_envp(vars: &[(OsString, OsString)]) -> Result<Vec<CString>, PlanError> {
    vars.iter()
        .map(|(k, v)| env_pair_to_cstring(k.as_os_str(), v.as_os_str()))
        .collect()
}

impl CapsulePlan {
    /// Build an immutable, pre-allocated CapsulePlan from configuration and environment.
    pub fn build(
        cfg: &Config,
        outcome: &EnvOutcome,
        vars: &VarTable,
        mode: Mode,
    ) -> Result<Self, PlanError> {
        let argv = build_argv(&cfg.server.command, &cfg.server.args, vars)?;
        let program = argv[0].clone();
        let envp = build_envp(&outcome.vars)?;

        Ok(Self {
            program,
            argv,
            envp,
            cwd: vars.workspace.clone(),
            mode,
        })
    }
}
