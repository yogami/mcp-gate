use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let count = COUNTER.fetch_add(1, Ordering::SeqCst);
        let name = format!("{prefix}_{}_{}", std::process::id(), count);
        let path = std::env::temp_dir().join(name);
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn init_creates_mcp_gate_yaml() {
    let dir = TempDir::new("mcpg_test_init");
    let mut cmd = Command::cargo_bin("mcp-gate").unwrap();
    cmd.current_dir(dir.path()).arg("init");

    cmd.assert().success();

    let config_path = dir.path().join("mcp-gate.yaml");
    assert!(config_path.exists());

    let content = fs::read_to_string(&config_path).unwrap();
    let expected = r#"version: 1

server:
  name: my-mcp-server
  command: /bin/sh
  args: []
  protocol_versions: ["2024-11-05"]
  workspace:
    source: .
    mode: copy

policy:
  read_paths:
    - ${WORKSPACE}
  write_paths:
    - ${WORKSPACE}
  allowed_child_binaries: []
  allow_network: false
  allowed_unix_sockets: []

canaries:
  enabled: true
  kinds: [ssh, aws]

scenarios: []
"#;
    assert_eq!(content, expected);
}

#[test]
fn init_warns_on_npx() {
    let dir = TempDir::new("mcpg_test_init_npx");
    let mut cmd = Command::cargo_bin("mcp-gate").unwrap();
    cmd.current_dir(dir.path())
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin/npx")
        .arg("init");

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Warning: Detected npx"));
}

#[test]
fn init_warns_on_uvx() {
    let dir = TempDir::new("mcpg_test_init_uvx");
    let mut cmd = Command::cargo_bin("mcp-gate").unwrap();
    cmd.current_dir(dir.path())
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin/uvx")
        .arg("init");

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Warning: Detected uvx"));
}

#[test]
fn init_generated_file_passes_validate() {
    let dir = TempDir::new("mcpg_test_init_validate");
    let mut init_cmd = Command::cargo_bin("mcp-gate").unwrap();
    init_cmd.current_dir(dir.path()).arg("init");
    init_cmd.assert().success();

    let mut val_cmd = Command::cargo_bin("mcp-gate").unwrap();
    val_cmd
        .current_dir(dir.path())
        .args(["validate", "--config", "mcp-gate.yaml"]);
    val_cmd.assert().success();
}

#[test]
fn init_warns_if_file_exists() {
    let dir = TempDir::new("mcpg_test_init_exist");
    let config_path = dir.path().join("mcp-gate.yaml");
    fs::write(&config_path, "dummy").unwrap();

    let mut cmd = Command::cargo_bin("mcp-gate").unwrap();
    cmd.current_dir(dir.path()).arg("init");

    cmd.assert()
        .failure()
        .code(64)
        .stderr(predicates::str::contains("already exists"));

    let content = fs::read_to_string(&config_path).unwrap();
    assert_eq!(content, "dummy");
}
