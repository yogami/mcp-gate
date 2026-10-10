//! Implementation of `mcp-gate explain <RULE_ID>`.
//!
//! SPEC 2.1, 3.4.4.

use mcpg_domain::rules::{RULES};
use mcpg_domain::verdict::ExitCode;

/// Execute `mcp-gate explain <RULE_ID>`.
pub fn execute(rule_query: &str) -> ExitCode {
    let query_norm = rule_query.trim().to_ascii_uppercase();
    let found = RULES
        .iter()
        .find(|r| r.id == query_norm || r.name.eq_ignore_ascii_case(rule_query.trim()));

    let Some(info) = found else {
        eprintln!("Error: unknown rule ID '{rule_query}'");
        return ExitCode::Usage;
    };

    println!("Rule: {}", info.id);
    println!("Name: {}", info.name);
    let level_str = match info.default_level {
        mcpg_domain::rules::FindingLevel::Note => "note",
        mcpg_domain::rules::FindingLevel::Warning => "warning",
        mcpg_domain::rules::FindingLevel::Error => "error",
    };
    println!("Default Level: {}", level_str);
    println!("Security Severity: {}", info.security_severity);
    println!("CWE: {}", info.cwe);
    println!("Description: {}", info.description);

    ExitCode::Pass
}
