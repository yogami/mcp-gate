use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

#[test]
fn explain_rule_mcpg005_success() {
    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate binary exists");
    cmd.current_dir(workspace_root());
    cmd.args(["explain", "MCPG005"]);
    cmd.assert()
        .code(0)
        .stdout(predicate::str::contains("Rule: MCPG005"))
        .stdout(predicate::str::contains("Name: path-traversal-escape"))
        .stdout(predicate::str::contains("Default Level: error"))
        .stdout(predicate::str::contains("Security Severity: 8.5"))
        .stdout(predicate::str::contains("CWE: CWE-22"));
}

#[test]
fn explain_all_spec_rules_exit_0() {
    let rules = [
        "MCPG001", "MCPG002", "MCPG003", "MCPG004", "MCPG005", "MCPG006", "MCPG007", "MCPG008",
        "MCPG009", "MCPG010", "MCPG011", "MCPG012", "MCPG900",
    ];

    for rule_id in rules {
        let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate binary exists");
        cmd.current_dir(workspace_root());
        cmd.args(["explain", rule_id]);
        cmd.assert()
            .code(0)
            .stdout(predicate::str::contains(format!("Rule: {rule_id}")));
    }
}

#[test]
fn explain_lowercase_rule_id_succeeds() {
    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate binary exists");
    cmd.current_dir(workspace_root());
    cmd.args(["explain", "mcpg002"]);
    cmd.assert()
        .code(0)
        .stdout(predicate::str::contains("Rule: MCPG002"))
        .stdout(predicate::str::contains("canary-value-leak"));
}

#[test]
fn explain_unknown_rule_exits_64() {
    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate binary exists");
    cmd.current_dir(workspace_root());
    cmd.args(["explain", "NONEXISTENT999"]);
    cmd.assert()
        .code(64)
        .stderr(predicate::str::contains("unknown rule ID 'NONEXISTENT999'"));
}
