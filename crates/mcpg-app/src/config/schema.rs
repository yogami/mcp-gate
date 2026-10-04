//! JSON schema validation and semantic policy checks.

use crate::config::load::ConfigError;
use mcpg_domain::config::Config;

pub static CONFIG_SCHEMA_JSON: &str = include_str!("../../../../schema/mcp-gate.config.v1.json");

/// Validate a JSON value against the vendored JSON Schema.
pub fn validate_json_value(value: &serde_json::Value) -> Result<(), ConfigError> {
    let schema: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA_JSON)
        .map_err(|e| ConfigError::Schema(format!("invalid embedded schema: {e}")))?;

    let validator = jsonschema::validator_for(&schema)
        .map_err(|e| ConfigError::Schema(format!("failed to compile schema: {e}")))?;

    let mut errors = Vec::new();
    for error in validator.iter_errors(value) {
        errors.push(format!("{}: {}", error.instance_path(), error));
    }

    if !errors.is_empty() {
        return Err(ConfigError::Schema(errors.join("; ")));
    }

    Ok(())
}

/// Perform semantic validation checks that extend beyond JSON schema syntax.
///
/// Under REQ-POL-001, each path entry is a file or directory. Globs (*, ?, [)
/// are strictly forbidden.
pub fn validate_semantics(config: &Config) -> Result<(), ConfigError> {
    let check_path = |path: &str, field: &str| -> Result<(), ConfigError> {
        if path.contains('*') || path.contains('?') || path.contains('[') {
            return Err(ConfigError::Semantic(format!(
                "path '{path}' in {field} contains forbidden glob pattern (*, ?, [): REQ-POL-001 forbids globs"
            )));
        }
        Ok(())
    };

    check_path(&config.server.workspace.source, "server.workspace.source")?;
    for p in &config.policy.read_paths {
        check_path(p, "policy.read_paths")?;
    }
    for p in &config.policy.write_paths {
        check_path(p, "policy.write_paths")?;
    }
    for p in &config.policy.allowed_child_binaries {
        check_path(p, "policy.allowed_child_binaries")?;
    }
    for p in &config.policy.allowed_unix_sockets {
        check_path(p, "policy.allowed_unix_sockets")?;
    }

    Ok(())
}
