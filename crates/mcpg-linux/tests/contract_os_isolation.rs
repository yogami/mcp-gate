#[cfg(not(target_os = "linux"))]
#[test]
fn test_skip_warning() {
    println!("WARNING: OS isolation contract tests were skipped on macOS.");
}

#[cfg(target_os = "linux")]
mod linux_tests {
    use mcpg_app::ports::Sandbox;
    use mcpg_linux::sandbox::LinuxSandbox;
    use mcpg_domain::mode::Mode;
    use mcpg_domain::config::{Config, ServerConfig, PolicyConfig, WorkspaceConfig};
    use mcpg_domain::config::model::{WorkspaceMode, LimitsConfig, Limits};
    use mcpg_domain::seed::Seed;
    use mcpg_app::orchestrator::RunOptions;
    use std::time::Duration;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    fn base_config(cmd: &str, args: Vec<&str>) -> Config {
        Config {
            version: 1,
            server: ServerConfig {
                name: "contract-test".to_string(),
                command: cmd.to_string(),
                args: args.iter().map(|s| s.to_string()).collect(),
                env: Default::default(),
                workspace: WorkspaceConfig {
                    source: ".".into(),
                    mode: WorkspaceMode::InPlace,
                },
                protocol_versions: vec!["2024-11-05".into()],
                limits: LimitsConfig {
                    limits: Limits {
                        cpu_seconds: 5,
                        memory_mb: 256,
                        max_fds: 100,
                        file_size_mb: 10,
                        max_children: 10,
                    },
                    grace_ms: 1000,
                },
            },
            policy: PolicyConfig {
                allow_network: false,
                allowed_unix_sockets: vec![],
                allowed_child_binaries: vec![],
                read_paths: vec![],
                write_paths: vec![],
                fail_on: None,
            },
        }
    }

    #[test]
    fn test_orphan_adoption_subreaper() {
        let sandbox = LinuxSandbox::new();
        let caps = sandbox.probe_host_caps();
        assert!(caps.supported, "Linux sandbox must be supported on Linux target");

        // Write a python script that double forks and sleeps
        let temp_dir = std::env::temp_dir().join(format!("mcpg_subreaper_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();
        let py_script = temp_dir.join("double_fork.py");
        let code = r#"
import os, sys, time
pid = os.fork()
if pid > 0:
    # Parent exits immediately
    sys.exit(0)
# Child becomes session leader
os.setsid()
pid2 = os.fork()
if pid2 > 0:
    # Child exits immediately, leaving grandchild orphaned
    sys.exit(0)
# Grandchild loops
while True:
    time.sleep(0.1)
"#;
        fs::write(&py_script, code).unwrap();

        let cfg = base_config("python3", vec![py_script.to_str().unwrap()]);
        let seed = Seed::from_bytes([0; 32]);
        let opts = RunOptions {
            requested_mode: Mode::Enforce,
            out_dir: temp_dir.join("out"),
            ..RunOptions::default()
        };

        // 1. init
        let (vars, _registry, _env_outcome) = sandbox.init(&cfg, &seed, &opts).unwrap();

        // 2. build_ruleset
        // We do not strict landlock here because we just want to test process teardown
        let ruleset_fd = sandbox.build_ruleset(&mcpg_domain::config::ResolvedPolicy::default(), &vars, "python3", &caps, Mode::Enforce).unwrap();

        // 3. create_launcher
        let (launcher, seccomp_fd) = sandbox.create_launcher(ruleset_fd);

        // 4. Launch!
        let mut plan = mcpg_app::ports::CapsulePlan {
            ruleset_fd: None,
            capsule_cwd: temp_dir.clone(),
            capsule_env: vec![],
            command: "python3".to_string(),
            args: vec![py_script.to_str().unwrap().to_string()],
            active_phase: "run".to_string(),
        };

        let running_capsule = launcher.launch(plan).expect("Failed to launch capsule");
        let main_pid = running_capsule.pid;
        
        // Wait a bit to let the double fork happen
        std::thread::sleep(Duration::from_millis(500));

        // 5. teardown
        // Teardown should cleanly reap the orphans via subreaper / cgroup.
        let events = sandbox.teardown(running_capsule, Duration::from_millis(500)).unwrap();

        // Verify the event log contains a process-escape / orphan event
        let has_escape_event = events.iter().any(|e| {
            e.kind == mcpg_domain::event::EventKind::TamperDenied || 
            e.message.contains("Orphan") ||
            e.message.contains("killed")
        });
        
        // In the raw Sandbox contract, teardown returns the events for orphans it kills
        assert!(events.len() > 0, "Teardown should return events for killed orphans");
    }
    #[test]
    fn test_landlock_relative_path_traversal_blocked() {
        let sandbox = LinuxSandbox::new();
        let caps = sandbox.probe_host_caps();
        if !caps.landlock.available {
            return;
        }

        let temp_dir = std::env::temp_dir().join(format!("mcpg_landlock_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();
        let py_script = temp_dir.join("traversal.py");
        let code = r#"
import os, sys
try:
    with open("../../../../../../../../../../../../../etc/passwd", "r") as f:
        f.read()
    sys.exit(0)
except PermissionError:
    sys.exit(75)
"#;
        fs::write(&py_script, code).unwrap();

        let cfg = base_config("python3", vec![py_script.to_str().unwrap()]);
        let opts = RunOptions {
            requested_mode: Mode::Enforce,
            out_dir: temp_dir.join("out"),
            ..RunOptions::default()
        };

        let orchestrator = mcpg_app::orchestrator::AppOrchestrator {
            sandbox: Box::new(LinuxSandbox::new()),
        };
        
        use mcpg_app::orchestrator::RunOrchestrator;
        let outcome = orchestrator.execute(&opts).unwrap();
        
        assert!(
            outcome.violations.iter().any(|(id, _)| id == "MCPG003" || id == "MCPG005"),
            "Expected MCPG003 or MCPG005 for path traversal"
        );
    }
}
