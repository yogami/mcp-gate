use mcpg_domain::verdict::ExitCode;
use std::fs;
use std::path::Path;

pub fn execute() -> ExitCode {
    let path = Path::new("mcp-gate.yaml");

    if let Ok(path_var) = std::env::var("PATH") {
        let mut has_npx = false;
        let mut has_uvx = false;
        for dir in std::env::split_paths(&path_var) {
            let name = dir.file_name().unwrap_or_default();
            if name == "npx" { has_npx = true; }
            if name == "uvx" { has_uvx = true; }
        }
        if has_npx { eprintln!("Warning: Detected npx in your PATH."); }
        if has_uvx { eprintln!("Warning: Detected uvx in your PATH."); }
    }

    if path.exists() {
        eprintln!("Error: mcp-gate.yaml already exists in the current directory.");
        return ExitCode::Usage;
    }

    let template = r#"version: 1

server:
  name: my-mcp-server
  command: /bin/sh
  args: []
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

    match fs::write(path, template) {
        Ok(_) => {
            println!("Created empty configuration at mcp-gate.yaml");
            ExitCode::Pass
        }
        Err(e) => {
            eprintln!("Error writing mcp-gate.yaml: {}", e);
            ExitCode::Internal
        }
    }
}
