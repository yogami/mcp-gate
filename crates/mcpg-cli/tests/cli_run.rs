#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

mod tempfile_helper {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        pub fn new(prefix: &str) -> Self {
            let count = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("{prefix}_{count}_{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create test dir");
            Self { path }
        }

        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn list_mcpg_dirs() -> std::collections::HashSet<PathBuf> {
    let mut dirs = std::collections::HashSet::new();
    if let Ok(entries) = fs::read_dir("/tmp") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("mcpg-") && name_str.len() == 21 {
                dirs.insert(entry.path());
            }
        }
    }
    dirs
}

static RUN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn run_benign_exits_0() {
    let _lock = RUN_LOCK.lock().unwrap();
    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd.current_dir(workspace_root());
    cmd.args(["run", "--config", "tests/configs/valid/benign.yaml"]);
    cmd.assert().code(0);
}

#[test]
fn run_prints_seed_line() {
    let _lock = RUN_LOCK.lock().unwrap();
    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd.current_dir(workspace_root());
    cmd.args(["run", "--config", "tests/configs/valid/benign.yaml"]);
    let pattern = r"mcp-gate: seed [0-9a-f]{64} \(replay with --seed [0-9a-f]{64}\)";
    cmd.assert()
        .code(0)
        .stdout(predicate::str::is_match(pattern).unwrap());
}

#[test]
fn run_with_same_seed_gives_same_canary_fps() {
    let _lock = RUN_LOCK.lock().unwrap();
    let seed_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let tmp = tempfile_helper::TempDir::new("test_same_seed");
    let out1 = tmp.path().join("run1");
    let out2 = tmp.path().join("run2");

    let mut cmd1 = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd1.current_dir(workspace_root())
        .args([
            "run",
            "--config",
            "tests/configs/valid/benign.yaml",
            "--seed",
            seed_hex,
            "--out-dir",
            out1.to_str().unwrap(),
        ])
        .assert()
        .code(0);

    let mut cmd2 = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd2.current_dir(workspace_root())
        .args([
            "run",
            "--config",
            "tests/configs/valid/benign.yaml",
            "--seed",
            seed_hex,
            "--out-dir",
            out2.to_str().unwrap(),
        ])
        .assert()
        .code(0);

    let ev1 = fs::read_to_string(out1.join("evidence.ndjson")).expect("evidence 1");
    let ev2 = fs::read_to_string(out2.join("evidence.ndjson")).expect("evidence 2");

    let line1 = ev1.lines().next().expect("header 1");
    let line2 = ev2.lines().next().expect("header 2");

    let header1: serde_json::Value = serde_json::from_str(line1).expect("json 1");
    let header2: serde_json::Value = serde_json::from_str(line2).expect("json 2");

    assert_eq!(header1["canary_fps"], header2["canary_fps"]);
    assert!(!header1["canary_fps"].as_array().unwrap().is_empty());
}

#[test]
fn run_without_seed_gives_different_fps() {
    let _lock = RUN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("test_diff_seed");
    let out1 = tmp.path().join("run1");
    let out2 = tmp.path().join("run2");

    let mut cmd1 = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd1.current_dir(workspace_root())
        .args([
            "run",
            "--config",
            "tests/configs/valid/benign.yaml",
            "--out-dir",
            out1.to_str().unwrap(),
        ])
        .assert()
        .code(0);

    let mut cmd2 = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd2.current_dir(workspace_root())
        .args([
            "run",
            "--config",
            "tests/configs/valid/benign.yaml",
            "--out-dir",
            out2.to_str().unwrap(),
        ])
        .assert()
        .code(0);

    let ev1 = fs::read_to_string(out1.join("evidence.ndjson")).expect("evidence 1");
    let ev2 = fs::read_to_string(out2.join("evidence.ndjson")).expect("evidence 2");

    let line1 = ev1.lines().next().expect("header 1");
    let line2 = ev2.lines().next().expect("header 2");

    let header1: serde_json::Value = serde_json::from_str(line1).expect("json 1");
    let header2: serde_json::Value = serde_json::from_str(line2).expect("json 2");

    assert_ne!(header1["seed"], header2["seed"]);
    assert_ne!(header1["canary_fps"], header2["canary_fps"]);
}

#[test]
fn run_dir_deleted_unless_keep_capsule() {
    let _lock = RUN_LOCK.lock().unwrap();
    for dir in list_mcpg_dirs() {
        let _ = fs::remove_dir_all(dir);
    }
    let before_keep = list_mcpg_dirs();
    let mut cmd_keep = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd_keep
        .current_dir(workspace_root())
        .args([
            "run",
            "--config",
            "tests/configs/valid/benign.yaml",
            "--keep-capsule",
        ])
        .assert()
        .code(0);
    let after_keep = list_mcpg_dirs();
    let diff_keep: Vec<_> = after_keep.difference(&before_keep).cloned().collect();
    assert_eq!(
        diff_keep.len(),
        1,
        "expected 1 retained capsule directory with --keep-capsule"
    );
    let retained = &diff_keep[0];
    assert!(retained.exists());
    let _ = fs::remove_dir_all(retained);

    let before_clean = list_mcpg_dirs();
    let mut cmd_clean = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd_clean
        .current_dir(workspace_root())
        .args(["run", "--config", "tests/configs/valid/benign.yaml"])
        .assert()
        .code(0);
    let after_clean = list_mcpg_dirs();
    let diff_clean: Vec<_> = after_clean.difference(&before_clean).cloned().collect();
    assert!(
        diff_clean.is_empty(),
        "run directory must be deleted when --keep-capsule is omitted, found: {:?}",
        diff_clean
    );
}

#[test]
fn failed_expectation_exits_2() {
    let _lock = RUN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("test_failed_expect");
    let server_path = workspace_root().join("fixtures/servers/benign/server.py");
    let base_cfg = fs::read_to_string(workspace_root().join("tests/configs/valid/benign.yaml"))
        .expect("read benign config");
    let modified_cfg = base_cfg
        .replace(
            "${CONFIG_DIR}/../../../fixtures/servers/benign/server.py",
            server_path.to_str().unwrap(),
        )
        .replace(
            "${CONFIG_DIR}/../../../fixtures/servers/benign",
            server_path.parent().unwrap().to_str().unwrap(),
        )
        .replace(
            r#"arguments: { path: "hello.txt", body: "world" }"#,
            r#"arguments: { path: "hello.txt", body: "different_content" }"#,
        );
    let cfg_path = tmp.path().join("failed_expect.yaml");
    fs::write(&cfg_path, modified_cfg).expect("write modified config");

    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd.current_dir(workspace_root())
        .args(["run", "--config", cfg_path.to_str().unwrap()])
        .assert()
        .code(2);
}

#[test]
fn server_exits_during_handshake_exits_3() {
    let _lock = RUN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("test_handshake_crash");
    let server_path = workspace_root().join("fixtures/servers/benign/server.py");
    let base_cfg = fs::read_to_string(workspace_root().join("tests/configs/valid/benign.yaml"))
        .expect("read benign config");
    let modified_cfg = base_cfg
        .replace(
            "${CONFIG_DIR}/../../../fixtures/servers/benign/server.py",
            server_path.to_str().unwrap(),
        )
        .replace(
            "${CONFIG_DIR}/../../../fixtures/servers/benign",
            server_path.parent().unwrap().to_str().unwrap(),
        )
        .replace(
            r#"--root", "${WORKSPACE}""#,
            r#"--root", "${WORKSPACE}", "--bad-flag-causes-exit-immediately""#,
        );
    let cfg_path = tmp.path().join("crash.yaml");
    fs::write(&cfg_path, modified_cfg).expect("write crash config");

    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd.current_dir(workspace_root())
        .args(["run", "--config", cfg_path.to_str().unwrap()])
        .assert()
        .code(3);
}

#[test]
fn reports_written_for_exit_2_and_3() {
    let _lock = RUN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("test_reports_2_3");
    let server_path = workspace_root().join("fixtures/servers/benign/server.py");
    let base_cfg = fs::read_to_string(workspace_root().join("tests/configs/valid/benign.yaml"))
        .expect("read benign config");

    let fail_cfg = base_cfg
        .replace(
            "${CONFIG_DIR}/../../../fixtures/servers/benign/server.py",
            server_path.to_str().unwrap(),
        )
        .replace(
            "${CONFIG_DIR}/../../../fixtures/servers/benign",
            server_path.parent().unwrap().to_str().unwrap(),
        )
        .replace(
            r#"arguments: { path: "hello.txt", body: "world" }"#,
            r#"arguments: { path: "hello.txt", body: "mismatched_content" }"#,
        );
    let fail_path = tmp.path().join("fail.yaml");
    fs::write(&fail_path, fail_cfg).expect("write fail config");

    let out2 = tmp.path().join("out2");
    let mut cmd2 = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd2.current_dir(workspace_root())
        .args([
            "run",
            "--config",
            fail_path.to_str().unwrap(),
            "--out-dir",
            out2.to_str().unwrap(),
        ])
        .assert()
        .code(2);

    let ev2_content =
        fs::read_to_string(out2.join("evidence.ndjson")).expect("evidence for exit 2");
    assert!(ev2_content.contains(r#""verdict":"FAIL_FUNCTIONAL""#));

    let crash_cfg = base_cfg
        .replace(
            "${CONFIG_DIR}/../../../fixtures/servers/benign/server.py",
            server_path.to_str().unwrap(),
        )
        .replace(
            "${CONFIG_DIR}/../../../fixtures/servers/benign",
            server_path.parent().unwrap().to_str().unwrap(),
        )
        .replace(
            r#"--root", "${WORKSPACE}""#,
            r#"--root", "${WORKSPACE}", "--crash-on-start""#,
        );
    let crash_path = tmp.path().join("crash.yaml");
    fs::write(&crash_path, crash_cfg).expect("write crash config");

    let out3 = tmp.path().join("out3");
    let mut cmd3 = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd3.current_dir(workspace_root())
        .args([
            "run",
            "--config",
            crash_path.to_str().unwrap(),
            "--out-dir",
            out3.to_str().unwrap(),
        ])
        .assert()
        .code(3);

    let ev3_content =
        fs::read_to_string(out3.join("evidence.ndjson")).expect("evidence for exit 3");
    assert!(ev3_content.contains(r#""verdict":"INCONCLUSIVE""#));
}

#[test]
fn run_enforce_denies_read_outside_policy() {
    // Only run on Linux when Landlock is actually available.
    // We add a switch or just skip if missing, but bug_report says "with a switch that makes Landlock unavailable a failure in CI".
    // We'll use mcpg_linux::landlock::get_landlock_abi().
    #[cfg(target_os = "linux")]
    {
        if mcpg_linux::landlock::get_landlock_abi() == 0 {
            if std::env::var("CI").is_ok() {
                panic!("Landlock is required in CI but unavailable on this host");
            }
            return;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        return;
    }

    let ws = tempfile_helper::TempDir::new("mcpg_cli_ws");
    let outside = tempfile_helper::TempDir::new("mcpg_cli_outside");
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, "secret data").unwrap();

    let cfg_path = ws.path().join("mcpg.yaml");
    std::fs::write(
        &cfg_path,
        format!(
            "version: 1\npolicy:\n  read_paths: []\n  write_paths: []\n  allowed_child_binaries: []\n  allow_network: false\n  allowed_unix_sockets: []\nscenarios: []\nserver:\n  name: \"test-server\"\n  command: \"cat\"\n  args: [\"{}\"]\n  workspace:\n    source: ./fixtures/workspace\n    mode: copy\n",
            secret.display()
        ),
    )
    .unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    cmd.current_dir(ws.path())
        .arg("run")
        .arg("--config")
        .arg(&cfg_path)
        .arg("--mode")
        .arg("enforce") // Use enforce mode
        .assert()
        // `cat` should fail to read the file and exit non-zero.
        // mcp-gate will capture this non-zero exit from the server handshake or execution and exit 3.
        .code(3);
}

#[test]
fn run_invalid_fail_on_exits_64() {
    let _lock = RUN_LOCK.lock().unwrap();
    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd.current_dir(workspace_root())
        .args([
            "run",
            "--config",
            "tests/configs/valid/benign.yaml",
            "--fail-on",
            "not_a_valid_level",
        ])
        .assert()
        .code(64);
}

#[test]
fn run_evidence_include_values_in_ci_exits_64() {
    let _lock = RUN_LOCK.lock().unwrap();
    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd.current_dir(workspace_root())
        .env("CI", "true")
        .args([
            "run",
            "--config",
            "tests/configs/valid/benign.yaml",
            "--evidence-include-values",
        ])
        .assert()
        .code(64);
}

#[test]
fn run_evidence_include_values_without_ci_writes_raw_secrets() {
    let _lock = RUN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("test_ev_values");
    let out_dir = tmp.path().join("out");

    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd.current_dir(workspace_root())
        .env_remove("CI")
        .args([
            "run",
            "--config",
            "tests/configs/valid/benign.yaml",
            "--out-dir",
            out_dir.to_str().unwrap(),
            "--evidence-include-values",
        ])
        .assert()
        .code(0);

    let ev_content =
        fs::read_to_string(out_dir.join("evidence.ndjson")).expect("evidence.ndjson exists");

    assert!(
        ev_content.contains("AKIA"),
        "evidence.ndjson must contain raw AWS canary secret when --evidence-include-values is enabled"
    );
    assert!(
        ev_content.contains(r#""type":"canary_secret""#)
            || ev_content.contains(r#""canary_values""#),
        "evidence.ndjson must record canary values structure"
    );

    let out_clean = tmp.path().join("out_clean");
    let mut cmd_clean = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd_clean
        .current_dir(workspace_root())
        .env_remove("CI")
        .args([
            "run",
            "--config",
            "tests/configs/valid/benign.yaml",
            "--out-dir",
            out_clean.to_str().unwrap(),
        ])
        .assert()
        .code(0);

    let clean_ev = fs::read_to_string(out_clean.join("evidence.ndjson")).expect("clean evidence");
    assert!(
        !clean_ev.contains("AKIA"),
        "raw secret must not appear in evidence when --evidence-include-values is omitted"
    );
}

#[test]
fn run_quiet_flag_suppresses_console_summary() {
    let _lock = RUN_LOCK.lock().unwrap();
    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd.current_dir(workspace_root())
        .args(["run", "--config", "tests/configs/valid/benign.yaml", "-q"])
        .assert()
        .code(0)
        .stdout(predicate::str::is_empty());
}

#[test]
fn run_timeout_flag_overrides_limits() {
    let _lock = RUN_LOCK.lock().unwrap();
    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd.current_dir(workspace_root())
        .args([
            "run",
            "--config",
            "tests/configs/valid/benign.yaml",
            "--timeout",
            "0",
        ])
        .assert()
        .code(3);
}

#[test]
fn p2_launch_06_cli_extraheader_warns() {
    let _lock = RUN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("test_extraheader");
    let ws_source = tmp.path().join("source");
    fs::create_dir_all(ws_source.join(".git")).unwrap();
    fs::write(
        ws_source.join(".git/config"),
        "[http]\n    extraheader = AUTHORIZATION: basic xyz\n",
    )
    .unwrap();

    let server_path = workspace_root().join("fixtures/servers/benign/server.py");
    let base_cfg = fs::read_to_string(workspace_root().join("tests/configs/valid/benign.yaml"))
        .expect("read benign config");
    let modified_cfg = base_cfg
        .replace(
            "${CONFIG_DIR}/../../../fixtures/servers/benign/server.py",
            server_path.to_str().unwrap(),
        )
        .replace(
            "${CONFIG_DIR}/../../../fixtures/servers/benign",
            server_path.parent().unwrap().to_str().unwrap(),
        )
        .replace(
            "source: ./fixtures/workspace",
            &format!("source: {}", ws_source.display()),
        );
    let cfg_path = tmp.path().join("extraheader.yaml");
    fs::write(&cfg_path, modified_cfg).unwrap();

    let mut cmd = Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    cmd.current_dir(workspace_root())
        .args(["run", "--config", cfg_path.to_str().unwrap()]);
    cmd.assert()
        .code(0)
        .stderr(predicate::str::contains("persist-credentials: false"));
}
