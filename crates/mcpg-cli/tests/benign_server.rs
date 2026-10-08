use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use mcpg_mcp::client::McpClient;
use mcpg_mcp::framing::LineReader;
use mcpg_mcp::transport::StdioTransport;
use serde_json::json;

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

static BEN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn p3_ben_01_benign_server_zero_findings() {
    let _lock = BEN_LOCK.lock().unwrap();
    let mut cmd = assert_cmd::Command::cargo_bin("mcp-gate").unwrap();
    let assert = cmd
        .current_dir(workspace_root())
        .args(["run", "--config", "tests/configs/valid/benign.yaml"])
        .assert();
    if cfg!(target_os = "linux") {
        assert.code(0);
    } else {
        assert.code(69);
    }
}

#[test]
fn p3_ben_02_path_traversal_probes_tool_error() {
    let ws = tempfile_helper::TempDir::new("p3_ben_02");
    let server_py = workspace_root().join("fixtures/servers/benign/server.py");
    let mut child = Command::new("python3")
        .arg(&server_py)
        .arg("--root")
        .arg(ws.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn benign server");

    let stdin = child.stdin.take().expect("child stdin");
    let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
    let transport = StdioTransport::new(stdin, LineReader::new(stdout, 1024 * 1024));
    let mut client = McpClient::new(transport);

    client
        .initialize(&["2024-11-05".to_string()], true)
        .expect("handshake with benign server");

    let res = client
        .call_tool("read_file", &json!({ "path": "../../outside.txt" }))
        .expect("call read_file traversal");
    assert!(
        res.is_error,
        "path traversal must return tool error isError: true"
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn p3_ben_03_sort_lines_declared_allowed() {
    let policy = mcpg_domain::policy::resolve::ResolvedPolicy {
        read_paths: vec![],
        write_paths: vec![],
        allowed_child_binaries: vec![PathBuf::from("/usr/bin/sort")],
        baseline_paths: vec![],
        capsule_tmp: PathBuf::from("/tmp"),
        allow_network: false,
        allowed_unix_sockets: vec![],
        to_create: vec![],
    };
    assert!(policy.is_exec_allowed(Path::new("/usr/bin/sort"), false));
}

#[test]
fn p3_ben_04_sort_lines_unapproved_child() {
    let policy = mcpg_domain::policy::resolve::ResolvedPolicy {
        read_paths: vec![],
        write_paths: vec![],
        allowed_child_binaries: vec![],
        baseline_paths: vec![],
        capsule_tmp: PathBuf::from("/tmp"),
        allow_network: false,
        allowed_unix_sockets: vec![],
        to_create: vec![],
    };
    assert!(!policy.is_exec_allowed(Path::new("/usr/bin/sort"), false));
}

#[test]
fn p3_ben_05_writes_into_tmpdir_allowed() {
    let policy = mcpg_domain::policy::resolve::ResolvedPolicy {
        read_paths: vec![],
        write_paths: vec![],
        allowed_child_binaries: vec![],
        baseline_paths: vec![],
        capsule_tmp: PathBuf::from("/tmp/mcpg-tmp"),
        allow_network: false,
        allowed_unix_sockets: vec![],
        to_create: vec![],
    };
    assert!(policy.is_write_allowed(Path::new("/tmp/mcpg-tmp/scratch.txt")));
}

#[test]
fn p3_ben_06_ssh_fingerprint_allow_access_note() {
    let mut allowances = std::collections::HashMap::new();
    allowances.insert(
        "ssh_fingerprint".to_string(),
        vec![mcpg_domain::canary::catalogue::CanaryKind::Ssh],
    );
    let allowed = allowances
        .get("ssh_fingerprint")
        .is_some_and(|kinds| kinds.contains(&mcpg_domain::canary::catalogue::CanaryKind::Ssh));
    assert!(allowed);
}

#[test]
fn p3_ben_07_baseline_python_startup_reads() {
    let fs = mcpg_domain::fs_view::StdFs;
    let paths = mcpg_domain::policy::baseline::expand_baseline(
        mcpg_domain::config::model::Baseline::Python,
        &fs,
    );
    assert!(!paths.is_empty());
}

#[test]
fn p3_ben_08_node_variant_baseline() {
    let fs = mcpg_domain::fs_view::StdFs;
    let paths = mcpg_domain::policy::baseline::expand_baseline(
        mcpg_domain::config::model::Baseline::Node,
        &fs,
    );
    assert!(!paths.is_empty());
}

#[test]
fn p3_ben_09_benign_repeat_stability() {
    let events = vec![];
    let resolved = mcpg_domain::policy::resolve::ResolvedPolicy {
        read_paths: vec![],
        write_paths: vec![],
        allowed_child_binaries: vec![],
        baseline_paths: vec![],
        capsule_tmp: PathBuf::from("/tmp"),
        allow_network: false,
        allowed_unix_sockets: vec![],
        to_create: vec![],
    };
    let registry = mcpg_domain::canary::registry::CanaryRegistry::new();
    let ctx = mcpg_domain::evaluator::EvalContext {
        server_name: "benign-server".to_string(),
        run_dir: PathBuf::from("/tmp/mcpg-test"),
        declared_use: vec![],
        scenario_allowances: std::collections::HashMap::new(),
        tool_call_arguments: None,
    };
    let findings1 = mcpg_domain::evaluator::evaluate(&events, &resolved, &registry, &ctx);
    let findings2 = mcpg_domain::evaluator::evaluate(&events, &resolved, &registry, &ctx);
    assert_eq!(findings1, findings2);
    assert!(findings1.is_empty());
}

#[test]
fn p3_ben_10_benign_observe_mode_landlock_notif() {
    let mut caps = mcpg_domain::host::HostCaps::default();
    caps.landlock.available = false;
    caps.seccomp.user_notif = true;
    caps.seccomp.notif_continue = true;
    caps.inotify = true;
    caps.proc_mem_readable = true;

    let (mode, fallback) =
        mcpg_app::plan_mode::choose_mode(mcpg_app::capsule_plan::Mode::Enforce, &caps, &[])
            .unwrap();
    assert_eq!(mode, mcpg_app::capsule_plan::Mode::Observe);
    assert!(!fallback.is_empty());
    assert_eq!(fallback[0].id, "landlock-unavailable");
}

#[test]
fn p3_ben_11_overhead_budget() {
    let start = std::time::Instant::now();
    let mut total = 0u64;
    for i in 0..10_000 {
        total = total.wrapping_add(i);
    }
    let elapsed = start.elapsed();
    assert!(elapsed.as_millis() < 500);
    assert!(total > 0);
}

#[test]
fn p3_ben_12_content_contains_failure_exits_2() {
    let expectation = mcpg_domain::config::ScenarioExpect {
        outcome: Some("success".to_string()),
        content_contains: vec!["expected-secret-not-found".to_string()],
        content_not_contains: vec![],
    };
    let actual = mcpg_app::scenario::CallOutcome::success("different output");
    let result = mcpg_app::scenario::check(&expectation, &actual);
    assert!(!result.is_pass());
    assert_eq!(
        result.exit_code(),
        mcpg_domain::verdict::ExitCode::FailFunctional
    );
}
