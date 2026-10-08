use assert_cmd::Command;
use std::path::Path;

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

#[test]
fn parses_version() {
    let mut cmd = Command::cargo_bin("mcp-gate").unwrap();
    cmd.arg("version").assert().success();
}

#[test]
fn validates_valid_and_invalid_configs() {
    let valid_path = workspace_root().join("tests/configs/valid/annotated.yaml");
    let mut cmd_valid = Command::cargo_bin("mcp-gate").unwrap();
    cmd_valid
        .args(["validate", "--config", valid_path.to_str().unwrap()])
        .assert()
        .success();

    let invalid_path = workspace_root().join("tests/configs/invalid/unknown_key.yaml");
    let mut cmd_invalid = Command::cargo_bin("mcp-gate").unwrap();
    cmd_invalid
        .args(["validate", "--config", invalid_path.to_str().unwrap()])
        .assert()
        .code(64); // ExitCode::Usage

    let mut cmd_missing = Command::cargo_bin("mcp-gate").unwrap();
    cmd_missing
        .args(["validate", "--config", "non_existent_config.yaml"])
        .assert()
        .code(64); // ExitCode::Usage
}
