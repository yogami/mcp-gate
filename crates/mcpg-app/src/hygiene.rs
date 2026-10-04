//! CI hygiene checks for runner and workspace state.
//!
//! SPEC 1.4, REQ-CI-002:
//! Detects persisted credentials in checkout git configuration
//! and warns developers to configure persist-credentials: false.

use std::fmt;
use std::fs;
use std::path::Path;

/// Warning produced by CI hygiene inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub message: String,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

fn has_extraheader(content: &str) -> bool {
    content.lines().any(|line| {
        line.trim_start()
            .to_ascii_lowercase()
            .starts_with("extraheader")
    })
}

/// Inspect raw git configuration content for persisted authorization headers.
pub fn checkout_hint(git_config: Option<&str>) -> Option<Warning> {
    let content = git_config?;
    if has_extraheader(content) {
        Some(Warning {
            message: "workspace .git/config contains extraheader credential; recommend setting persist-credentials: false in actions/checkout".to_string(),
        })
    } else {
        None
    }
}

/// Read .git/config from source root and check for persisted credentials.
pub fn check_source_checkout_hint(source: &Path) -> Option<Warning> {
    let config_path = source.join(".git").join("config");
    let content = fs::read_to_string(config_path).ok();
    checkout_hint(content.as_deref())
}
