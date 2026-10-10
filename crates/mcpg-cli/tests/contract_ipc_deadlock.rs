#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::time::{Duration, Instant};
use mcpg_app::orchestrator::{AppOrchestrator, RunOptions, RunOrchestrator};
use mcpg_domain::mode::Mode;
use mcpg_linux::sandbox::LinuxSandbox;

fn workspace_root() -> PathBuf {
    // Navigate up from mcpg-cli/tests to the repo root
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // pop mcpg-cli
    path.pop(); // pop crates
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
version: 1
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
  read_paths: []
  write_paths: []
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
    
    eprintln!("DEBUG: Starting orchestrator execute");
    let start = Instant::now();
    let outcome = orchestrator.execute(&opts).expect("Execute must not panic or error at orchestrator level");
    
    let elapsed = start.elapsed();
    eprintln!("DEBUG: Orchestrator execute finished in {:?}", elapsed);
    assert!(elapsed < Duration::from_secs(5), "Orchestrator deadlocked on stderr flood! Took {:?}", elapsed);
    
}

#[test]
fn high_frequency_canaries_inotify_queue() {
    mcpg_linux::self_harden::harden_self().unwrap();
    
    let temp_dir = std::env::temp_dir().join(format!("mcpg_test_hfcanary_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    
    let ws = temp_dir.join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    
    let script_in_ws = ws.join("server.py");
    // This script will quickly read 1000 canary files
    let script_code = r#"
import os, sys
files = sorted([f for f in os.listdir('.') if f.startswith('canary_')])
for f in files:
    try:
        with open(f, 'r') as fp:
            fp.read()
    except Exception:
        pass
"#;
    std::fs::write(&script_in_ws, script_code).unwrap();
    
    let cfg_path = temp_dir.join("mcp-gate.yaml");
    let cfg_content = format!(
        r#"
version: 1
server:
  name: "hf-canary"
  command: "python3"
  args: ["./server.py"]
  protocol_versions: ["2024-11-05"]
  workspace:
    source: "{}"
    mode: in-place
policy:
  allow_network: false
  allowed_unix_sockets: []
  allowed_child_binaries: []
  read_paths: []
  write_paths: []
"#,
        ws.display()
    );
    std::fs::write(&cfg_path, cfg_content).unwrap();

    // Plant 1000 canaries
    for i in 0..1000 {
        std::fs::write(ws.join(format!("canary_{:04}", i)), "secret").unwrap();
    }

    let opts = RunOptions {
        config_path: cfg_path,
        out_dir: temp_dir.join("out"),
        requested_mode: Mode::Enforce,
        ..Default::default()
    };
    
    let orchestrator = AppOrchestrator {
        sandbox: Box::new(LinuxSandbox::new()),
    };
    
    let outcome = orchestrator.execute(&opts).expect("Execute must not panic");
    
    // We should have a very large number of MCPG001 canary access events.
    let canary_events: Vec<_> = outcome.violations.iter().filter(|(k, _)| k == "MCPG001").collect();
    // At least 100 files accessed
    assert!(canary_events.len() > 50, "Expected a large number of canary access violations, got {}", canary_events.len());
}
