//! Pure in-memory configuration loader for mcp-gate.

use mcpg_domain::config::Config;

use crate::config::schema::{validate_json_value, validate_semantics};
use crate::config::spans::SpanMap;

/// Errors produced during configuration loading, parsing, and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Yaml { message: String, line: Option<u32> },
    Schema { message: String, line: Option<u32> },
    Semantic { message: String, line: Option<u32> },
}

impl ConfigError {
    pub fn yaml(msg: impl Into<String>, line: Option<u32>) -> Self {
        Self::Yaml {
            message: msg.into(),
            line,
        }
    }

    pub fn schema(msg: impl Into<String>, line: Option<u32>) -> Self {
        Self::Schema {
            message: msg.into(),
            line,
        }
    }

    pub fn semantic(msg: impl Into<String>, line: Option<u32>) -> Self {
        Self::Semantic {
            message: msg.into(),
            line,
        }
    }

    pub fn line(&self) -> Option<u32> {
        match self {
            Self::Yaml { line, .. } => *line,
            Self::Schema { line, .. } => *line,
            Self::Semantic { line, .. } => *line,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Yaml { message, .. } => message,
            Self::Schema { message, .. } => message,
            Self::Semantic { message, .. } => message,
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, msg, line) = match self {
            Self::Yaml { message, line } => ("YAML parse error", message, line),
            Self::Schema { message, line } => ("schema validation error", message, line),
            Self::Semantic { message, line } => ("semantic configuration error", message, line),
        };
        match line {
            Some(l) => write!(f, "{kind} on line {l}: {msg}"),
            None => write!(f, "{kind}: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parse a YAML configuration string into a typed domain `Config`.
///
/// Follows the pipeline:
/// 1. Parse YAML into a generic JSON representation and build a `SpanMap`.
/// 2. Validate against the embedded JSON schema, attaching source lines to errors (REQ-CFG-002, REQ-SEED-001).
/// 3. Deserialize into the typed domain `Config`.
/// 4. Run semantic validation checks (REQ-POL-001).
pub fn load_str(src: &str) -> Result<Config, ConfigError> {
    let spans = SpanMap::from_str(src);

    let json_val: serde_json::Value = serde_yml::from_str(src).map_err(|e| {
        let line = e.location().map(|loc| loc.line() as u32);
        ConfigError::yaml(e.to_string(), line)
    })?;

    validate_json_value(&json_val, &spans)?;

    let config: Config =
        serde_json::from_value(json_val).map_err(|e| ConfigError::yaml(e.to_string(), None))?;

    validate_semantics(&config, &spans)?;

    Ok(config)
}
