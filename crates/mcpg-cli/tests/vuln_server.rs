use std::fs;
use std::path::{Path, PathBuf};

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

static VULN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn make_vuln_config(defect: &str, out_dir: &Path) -> PathBuf {
    let vuln_py = workspace_root().join("fixtures/servers/vulnerable/server.py");
    let ws = out_dir.join("workspace");
    let _ = fs::create_dir_all(&ws);

    let cfg_path = out_dir.join("mcp-gate.yaml");
    let content = format!(
        r#"version: 1
policy:
  read_paths: []
  write_paths: []
  allowed_child_binaries: []
  allow_network: false
  allowed_unix_sockets: []
scenarios:
  - id: test-call
    action: call_tool
    tool: read_file
    arguments:
      path: "../../../../../../../../../../../etc/passwd"
server:
  name: "vulnerable-server"
  command: "python3"
  args: ["{}", "--defect", "{}", "--root", "{}"]
  workspace:
    source: "{}"
    mode: in_place
"#,
        vuln_py.display(),
        defect,
        ws.display(),
        ws.display()
    );

    fs::write(&cfg_path, content).unwrap();
    cfg_path
}

fn assert_exit(assert: assert_cmd::assert::Assert, linux_expected: i32) {
    if cfg!(target_os = "linux") {
        assert.code(linux_expected);
    } else {
        assert.code(69);
    }
}

#[test]
fn p2_vuln_01_naive_read() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_01");
    let cfg = make_vuln_config("naive-read", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_02_naive_read_enforce() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_02");
    let cfg = make_vuln_config("naive-read", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args([
            "run",
            "--config",
            cfg.to_str().unwrap(),
            "--mode",
            "enforce",
        ])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_03_naive_write() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_03");
    let cfg = make_vuln_config("naive-write", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_04_startup_read() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_04");
    let cfg = make_vuln_config("startup-read", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_05_config_echo() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_05");
    let cfg = make_vuln_config("config-echo", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_06_env_echo() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_06");
    let cfg = make_vuln_config("env-echo", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_07_shell_out() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_07");
    let cfg = make_vuln_config("shell-out", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_08_shell_out_enforce() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_08");
    let cfg = make_vuln_config("shell-out", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args([
            "run",
            "--config",
            cfg.to_str().unwrap(),
            "--mode",
            "enforce",
        ])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_09_net_call() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_09");
    let cfg = make_vuln_config("net-call", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_10_unix_sock() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_10");
    let cfg = make_vuln_config("unix-sock", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_11_proc_peek() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_11");
    let cfg = make_vuln_config("proc-peek", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_12_daemon() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_12");
    let cfg = make_vuln_config("daemon", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_13_signal_parent() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_13");
    let cfg = make_vuln_config("signal-parent", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_14_symlink_follow() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_14");
    let cfg = make_vuln_config("symlink-follow", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_15_netrc_read_fail_on_error() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_15");
    let cfg = make_vuln_config("netrc-read", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args([
            "run",
            "--config",
            cfg.to_str().unwrap(),
            "--fail-on",
            "error",
        ])
        .assert();
    assert_exit(assert, 0);
}

#[test]
fn p2_vuln_16_netrc_read_fail_on_warning() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_16");
    let cfg = make_vuln_config("netrc-read", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args([
            "run",
            "--config",
            cfg.to_str().unwrap(),
            "--fail-on",
            "warning",
        ])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_17_all_defects() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_17");
    let cfg = make_vuln_config("all", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_18_same_seed_replay() {
    let _lock = VULN_LOCK.lock().unwrap();
    let seed = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    let tmp = tempfile_helper::TempDir::new("p2_vuln_18");
    let cfg = make_vuln_config("config-echo", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap(), "--seed", seed])
        .assert();
    assert_exit(assert, 1);
}

#[test]
fn p2_vuln_18a_replay_with_printed_seed() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_18a");
    let cfg = make_vuln_config("config-echo", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .assert();
    if cfg!(target_os = "linux") {
        let assert = assert.code(1);
        let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
        assert!(out.contains("mcp-gate: seed"));
    } else {
        assert.code(69);
    }
}

#[test]
fn p2_vuln_19_server_exits_during_handshake() {
    let _lock = VULN_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("p2_vuln_19");
    let cfg = make_vuln_config("naive-read", tmp.path());
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", cfg.to_str().unwrap(), "--timeout", "0"])
        .assert();
    assert_exit(assert, 3);
}

#[test]
fn p2_vuln_20_startup_read_then_crash() {
    let codes = vec![
        mcpg_domain::verdict::ExitCode::FailSecurity,
        mcpg_domain::verdict::ExitCode::Inconclusive,
    ];
    let final_code = mcpg_domain::verdict::combine(codes);
    assert_eq!(final_code, mcpg_domain::verdict::ExitCode::FailSecurity);
}
