//! Pure in-memory configuration loader for mcp-gate.

use mcpg_domain::config::Config;

/// Errors produced during configuration loading, parsing, and validation.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Yaml(String),
    Schema(String),
    Semantic(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Yaml(msg) => write!(f, "YAML parse error: {msg}"),
            Self::Schema(msg) => write!(f, "schema validation error: {msg}"),
            Self::Semantic(msg) => write!(f, "semantic configuration error: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parse a YAML configuration string into a typed domain `Config`.
pub fn load_str(src: &str) -> Result<Config, ConfigError> {
    serde_yml::from_str(src).map_err(|e| ConfigError::Yaml(e.to_string()))
}
