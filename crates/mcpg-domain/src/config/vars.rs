//! Path variable expansion for mcp-gate configuration.
//!
//! Under SPEC 2.2, only four specific variables expand, and only at the start
//! of path values. Host environment variables are never interpolated.

use std::path::{Path, PathBuf};

/// Table of allowed path expansion variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarTable {
    pub workspace: PathBuf,
    pub capsule_home: PathBuf,
    pub capsule_tmp: PathBuf,
    pub config_dir: PathBuf,
}

/// Errors occurring during path variable expansion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarError {
    VariableNotAtStart(String),
    UnknownVariable(String),
    UnclosedVariable(String),
    NotAbsolute(PathBuf),
}

impl std::fmt::Display for VarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VariableNotAtStart(s) => write!(f, "variable not at start of path: {s}"),
            Self::UnknownVariable(s) => write!(f, "unknown variable: {s}"),
            Self::UnclosedVariable(s) => write!(f, "unclosed variable in path: {s}"),
            Self::NotAbsolute(p) => write!(f, "path is not absolute: {}", p.display()),
        }
    }
}

impl std::error::Error for VarError {}

/// Expand path variables in a raw path string according to SPEC 2.2.
///
/// Only `${WORKSPACE}`, `${CAPSULE_HOME}`, `${CAPSULE_TMP}`, and `${CONFIG_DIR}`
/// are expanded, and only at the start of the string.
pub fn expand(raw: &str, vars: &VarTable) -> Result<PathBuf, VarError> {
    let result = if let Some(dollar_idx) = raw.find("${") {
        if dollar_idx != 0 {
            return Err(VarError::VariableNotAtStart(raw.to_string()));
        }

        let close_idx = raw
            .find('}')
            .ok_or_else(|| VarError::UnclosedVariable(raw.to_string()))?;

        let var_name = &raw[2..close_idx];
        let rest = &raw[close_idx + 1..];

        if rest.contains("${") {
            return Err(VarError::VariableNotAtStart(raw.to_string()));
        }

        let base: &Path = match var_name {
            "WORKSPACE" => &vars.workspace,
            "CAPSULE_HOME" => &vars.capsule_home,
            "CAPSULE_TMP" => &vars.capsule_tmp,
            "CONFIG_DIR" => &vars.config_dir,
            _ => return Err(VarError::UnknownVariable(var_name.to_string())),
        };

        if rest.is_empty() {
            base.to_path_buf()
        } else {
            let relative = rest.strip_prefix('/').unwrap_or(rest);
            base.join(relative)
        }
    } else {
        PathBuf::from(raw)
    };

    if !result.is_absolute() {
        return Err(VarError::NotAbsolute(result));
    }

    Ok(result)
}
