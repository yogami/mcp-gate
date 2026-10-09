#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::time::{Duration, Instant};
use mcpg_app::orchestrator::{AppOrchestrator, RunOptions, RunOrchestrator};
use mcpg_domain::mode::Mode;
use mcpg_linux::sandbox::LinuxSandbox;

fn workspace_root() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    while path.file_name().and_then(|s| s.to_str()) != Some("mcp-test-runner") {
        path.pop();
    }
    path.canonicalize().unwrap()
}

#[test]
fn stderr_flood_test_the_blocking_pipe_bug() {
    mcpg_linux::self_harden::harden_self().unwrap();
    
    let temp_dir = std::env::temp_dir().join(format!("mcpg_test_ipc_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    
    let vuln_py = workspace_root().join("fixtures/servers/vulnerable/server.py");
    let ws = temp_dir.join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let script_in_ws = ws.join("server.py");
    std::fs::copy(&vuln_py, &script_in_ws).unwrap();
    
    let cfg_path = temp_dir.join("mcp-gate.yaml");
    let cfg_content = format!(
        r#"
version: "1.0"
server:
  name: "stderr-flooder"
  command: "python3"
  args: ["./server.py", "--defect", "stderr-flood", "--root", "{}"]
  protocol_versions: ["2024-11-05"]
  workspace:
    source: "{}"
    mode: in-place
policy:
  allow_network: false
  allowed_unix_sockets: []
  allowed_child_binaries: []
"#,
        ws.display(),
        ws.display()
    );
    std::fs::write(&cfg_path, cfg_content).unwrap();
    
    let opts = RunOptions {
        config_path: cfg_path,
        out_dir: temp_dir.join("out"),
        requested_mode: Mode::Enforce,
        ..Default::default()
    };
    
    let orchestrator = AppOrchestrator {
        sandbox: Box::new(LinuxSandbox::new()),
    };
    
    let start = Instant::now();
    let outcome = orchestrator.execute(&opts).expect("Execute must not panic or error at orchestrator level");
    
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(5), "Orchestrator deadlocked on stderr flood! Took {:?}", elapsed);
    
}
