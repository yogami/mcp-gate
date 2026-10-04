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
fn validate_valid_exits_0() {
    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate binary exists");
    cmd.current_dir(workspace_root());
    cmd.args(["validate", "--config", "tests/configs/valid/annotated.yaml"]);
    cmd.assert().code(0).stdout(predicate::str::contains(
        "OK: tests/configs/valid/annotated.yaml",
    ));
}

#[test]
fn validate_invalid_exits_64_with_line() {
    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate binary exists");
    cmd.current_dir(workspace_root());
    cmd.args([
        "validate",
        "--config",
        "tests/configs/invalid/unknown_key.yaml",
    ]);
    cmd.assert()
        .code(64)
        .stderr(predicate::str::contains("line 7"));
}
