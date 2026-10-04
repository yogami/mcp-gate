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
fn p1_seed_04_cli_bad_seed_exits_64() {
    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate binary exists");
    cmd.current_dir(workspace_root());
    cmd.args([
        "run",
        "--config",
        "tests/configs/valid/minimal.yaml",
        "--seed",
        "abc",
    ]);
    cmd.assert()
        .code(64)
        .stderr(predicate::str::contains("error"));
}
