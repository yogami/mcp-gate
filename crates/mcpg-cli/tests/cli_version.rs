use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn version_prints_semver_and_protocols() {
    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate binary exists");
    cmd.arg("version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("mcp-gate 0.1.0"))
        .stdout(predicate::str::contains("2025-06-18"));
}
