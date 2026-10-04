//! Pure in-memory configuration loader for mcp-gate.

use mcpg_domain::config::Config;

use crate::config::schema::{validate_json_value, validate_semantics};

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
///
/// Follows the pipeline:
/// 1. Parse YAML into a generic JSON representation.
/// 2. Validate against the embedded JSON schema (REQ-CFG-002, REQ-SEED-001).
/// 3. Deserialize into the typed domain `Config`.
/// 4. Run semantic validation checks (REQ-POL-001).
pub fn load_str(src: &str) -> Result<Config, ConfigError> {
    let json_val: serde_json::Value =
        serde_yml::from_str(src).map_err(|e| ConfigError::Yaml(e.to_string()))?;

    validate_json_value(&json_val)?;

    let config: Config =
        serde_json::from_value(json_val).map_err(|e| ConfigError::Yaml(e.to_string()))?;

    validate_semantics(&config)?;

    Ok(config)
}
