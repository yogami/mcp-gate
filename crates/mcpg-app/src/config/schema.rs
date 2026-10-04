//! JSON schema validation and semantic policy checks.

use crate::config::load::ConfigError;
use crate::config::spans::SpanMap;
use mcpg_domain::config::Config;

pub static CONFIG_SCHEMA_JSON: &str = include_str!("../../../../schema/mcp-gate.config.v1.json");

/// Convert a JSON Pointer path (e.g. `/scenarios/1/id`) into a SpanMap dotted path (`scenarios[1].id`).
pub fn json_pointer_to_span_path(pointer: &str) -> String {
    let trimmed = pointer.trim_start_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    let parts: Vec<&str> = trimmed.split('/').collect();
    let mut res = String::new();
    for part in parts {
        if let Ok(idx) = part.parse::<usize>() {
            res.push_str(&format!("[{idx}]"));
        } else {
            if !res.is_empty() && !res.ends_with(']') {
                res.push('.');
            }
            res.push_str(part);
        }
    }
    res
}

/// Validate a JSON value against the vendored JSON Schema, annotating errors with source lines.
pub fn validate_json_value(value: &serde_json::Value, spans: &SpanMap) -> Result<(), ConfigError> {
    let schema: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA_JSON)
        .map_err(|e| ConfigError::schema(format!("invalid embedded schema: {e}"), None))?;

    let validator = jsonschema::validator_for(&schema)
        .map_err(|e| ConfigError::schema(format!("failed to compile schema: {e}"), None))?;

    let mut first_error: Option<ConfigError> = None;
    for error in validator.iter_errors(value) {
        let instance_path = error.instance_path().to_string();
        let base_path = json_pointer_to_span_path(&instance_path);

        let (lookup_path, line) = match error.kind() {
            jsonschema::error::ValidationErrorKind::AdditionalProperties { unexpected } => {
                let first = unexpected.first().map(|s| s.as_str()).unwrap_or("");
                let full = if base_path.is_empty() {
                    first.to_string()
                } else {
                    format!("{base_path}.{first}")
                };
                let line = spans.line_of(&full).or_else(|| spans.line_of(&base_path));
                (full, line)
            }
            _ => {
                let line = spans.line_of(&base_path);
                (base_path, line)
            }
        };

        let msg = if lookup_path.is_empty() {
            error.to_string()
        } else {
            format!("{lookup_path}: {error}")
        };

        let cfg_err = ConfigError::schema(msg, line);
        if first_error.is_none() {
            first_error = Some(cfg_err);
        }
    }

    if let Some(err) = first_error {
        return Err(err);
    }

    Ok(())
}

/// Perform semantic validation checks that extend beyond JSON schema syntax.
///
/// Under REQ-POL-001, each path entry is a file or directory. Globs (*, ?, [)
/// are strictly forbidden.
pub fn validate_semantics(config: &Config, spans: &SpanMap) -> Result<(), ConfigError> {
    let check_path = |path: &str, field: &str, lookup: &str| -> Result<(), ConfigError> {
        if path.contains('*') || path.contains('?') || path.contains('[') {
            let line = spans.line_of(lookup).or_else(|| spans.line_of(field));
            return Err(ConfigError::semantic(
                format!(
                    "path '{path}' in {field} contains forbidden glob pattern (*, ?, [): REQ-POL-001 forbids globs"
                ),
                line,
            ));
        }
        Ok(())
    };

    check_path(
        &config.server.workspace.source,
        "server.workspace.source",
        "server.workspace.source",
    )?;
    for (i, p) in config.policy.read_paths.iter().enumerate() {
        check_path(p, "policy.read_paths", &format!("policy.read_paths[{i}]"))?;
    }
    for (i, p) in config.policy.write_paths.iter().enumerate() {
        check_path(p, "policy.write_paths", &format!("policy.write_paths[{i}]"))?;
    }
    for (i, p) in config.policy.allowed_child_binaries.iter().enumerate() {
        check_path(
            p,
            "policy.allowed_child_binaries",
            &format!("policy.allowed_child_binaries[{i}]"),
        )?;
    }
    for (i, p) in config.policy.allowed_unix_sockets.iter().enumerate() {
        check_path(
            p,
            "policy.allowed_unix_sockets",
            &format!("policy.allowed_unix_sockets[{i}]"),
        )?;
    }

    Ok(())
}
