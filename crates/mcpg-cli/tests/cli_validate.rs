use std::fs;
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
fn validate_benign_exits_0() {
    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate binary exists");
    cmd.current_dir(workspace_root());
    cmd.args(["validate", "--config", "tests/configs/valid/benign.yaml"]);
    cmd.assert().code(0).stdout(predicate::str::contains(
        "OK: tests/configs/valid/benign.yaml",
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

#[test]
fn validate_missing_policy_path_exits_64() {
    let tmp = tempfile_helper::TempDir::new("test_val_missing_path");
    let cfg_content = r#"version: 1
server:
  name: test-server
  command: /usr/bin/python3
  workspace:
    source: .
policy:
  read_paths:
    - /nonexistent_path_outside_workspace/for_mcpg_test
  write_paths: []
  allowed_child_binaries: []
  allow_network: false
"#;
    let cfg_path = tmp.path().join("missing_path.yaml");
    fs::write(&cfg_path, cfg_content).expect("write temp config");

    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate binary exists");
    cmd.current_dir(workspace_root());
    cmd.args(["validate", "--config", cfg_path.to_str().unwrap()]);
    cmd.assert()
        .code(64)
        .stderr(predicate::str::contains("policy path resolution error"))
        .stderr(predicate::str::contains("policy path entry does not exist"));
}

#[test]
fn validate_missing_child_binary_exits_64() {
    let tmp = tempfile_helper::TempDir::new("test_val_missing_bin");
    let cfg_content = r#"version: 1
server:
  name: test-server
  command: /usr/bin/python3
  workspace:
    source: .
policy:
  read_paths: []
  write_paths: []
  allowed_child_binaries:
    - /usr/bin/definitely_not_a_real_binary_name_xyz
  allow_network: false
"#;
    let cfg_path = tmp.path().join("missing_bin.yaml");
    fs::write(&cfg_path, cfg_content).expect("write temp config");

    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate binary exists");
    cmd.current_dir(workspace_root());
    cmd.args(["validate", "--config", cfg_path.to_str().unwrap()]);
    cmd.assert()
        .code(64)
        .stderr(predicate::str::contains("policy path resolution error"))
        .stderr(predicate::str::contains("binary not found"));
}

mod tempfile_helper {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(prefix: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let p = std::env::temp_dir().join(format!("mcpg_val_{prefix}_{nanos}"));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
