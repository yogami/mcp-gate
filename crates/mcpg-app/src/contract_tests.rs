#[cfg(test)]
mod tests {
    use crate::capsule_plan::CapsulePlan;
    use crate::orchestrator::{AppOrchestrator, RunOptions, RunOrchestrator};
    use crate::ports::{CapsuleLauncher, RunningCapsule, Sandbox, TripwireHandle};
    use mcpg_domain::canary::registry::CanaryRegistry;
    use mcpg_domain::config::model::Config;
    use mcpg_domain::config::vars::VarTable;
    use mcpg_domain::env::EnvOutcome;
    use mcpg_domain::event::Event;
    use mcpg_domain::host::{HostCaps, LandlockCaps, SeccompCaps};
    use mcpg_domain::policy::resolve::ResolvedPolicy;
    use mcpg_domain::seed::Seed;
    use mcpg_domain::verdict::ExitCode;
    use std::os::fd::{OwnedFd, RawFd};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    struct MockLauncher;
    impl CapsuleLauncher for MockLauncher {
        fn launch(&self, _plan: &CapsulePlan) -> Result<RunningCapsule, crate::ports::LaunchError> {
            Ok(RunningCapsule {
                pid: 1234,
                child: std::process::Command::new("true")
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .unwrap(),
                seccomp_listener_fd: Some(42),
            })
        }
    }

    struct MockSandbox {
        pub method_calls: Arc<Mutex<Vec<String>>>,
    }

    impl Sandbox for MockSandbox {
        fn generate_seed(&self) -> Result<Seed, ExitCode> {
            self.method_calls
                .lock()
                .unwrap()
                .push("generate_seed".into());
            Ok(Seed::from_bytes([0; 32]))
        }
        fn probe_host_caps(&self) -> HostCaps {
            self.method_calls
                .lock()
                .unwrap()
                .push("probe_host_caps".into());
            HostCaps {
                kernel: "Linux".to_string(),
                arch: "x86_64".to_string(),
                landlock: LandlockCaps {
                    available: true,
                    abi: 3,
                },
                seccomp: SeccompCaps {
                    filter: true,
                    user_notif: true,
                    notif_continue: true,
                    wait_killable_recv: true,
                },
                inotify: true,
                proc_mem_readable: true,
                supported: true,
                missing: vec![],
            }
        }
        fn init(
            &self,
            _cfg: &Config,
            _seed: &Seed,
            _opts: &RunOptions,
        ) -> Result<(VarTable, CanaryRegistry, EnvOutcome), ExitCode> {
            self.method_calls.lock().unwrap().push("init".into());
            Ok((
                VarTable {
                    workspace: std::path::PathBuf::from(""),
                    capsule_home: std::path::PathBuf::from(""),
                    capsule_tmp: std::path::PathBuf::from(""),
                    config_dir: std::path::PathBuf::from(""),
                },
                CanaryRegistry::default(),
                EnvOutcome {
                    vars: vec![],
                    warnings: vec![],
                },
            ))
        }
        fn build_ruleset(
            &self,
            _policy: &ResolvedPolicy,
            _vars: &VarTable,
            _cmd: &str,
            _caps: &HostCaps,
            _mode: mcpg_domain::mode::Mode,
        ) -> Result<Option<OwnedFd>, ExitCode> {
            self.method_calls
                .lock()
                .unwrap()
                .push("build_ruleset".into());
            Ok(None)
        }
        fn setup_tripwire(
            &self,
            _registry: &CanaryRegistry,
            _phase: crate::phase::PhaseCursor,
        ) -> Result<Option<Box<dyn TripwireHandle>>, ExitCode> {
            self.method_calls
                .lock()
                .unwrap()
                .push("setup_tripwire".into());
            Ok(None)
        }
        fn teardown(
            &self,
            _capsule: RunningCapsule,
            _grace: Duration,
        ) -> Result<Vec<Event>, ExitCode> {
            self.method_calls.lock().unwrap().push("teardown".into());
            Ok(vec![])
        }
        fn create_launcher(
            &self,
            _ruleset: Option<OwnedFd>,
        ) -> (Box<dyn CapsuleLauncher>, Option<RawFd>) {
            self.method_calls
                .lock()
                .unwrap()
                .push("create_launcher".into());
            (Box::new(MockLauncher), Some(42))
        }
        fn disarm_guard(&self) {
            self.method_calls
                .lock()
                .unwrap()
                .push("disarm_guard".into());
        }
        fn arm_guard(&self, _pid: i32, _pids: Vec<u32>) {
            self.method_calls.lock().unwrap().push("arm_guard".into());
        }
        fn start_observer_thread(
            &self,
            _fd: RawFd,
            _allow_network: bool,
            _allowed_child_binaries: Vec<std::path::PathBuf>,
            _root_command: Option<std::path::PathBuf>,
            _allowed_unix_sockets: Vec<String>,
            _capsule_pids: Vec<u32>,
            _active_phase: Option<String>,
            _events_tx: Option<std::sync::mpsc::Sender<Event>>,
            _obs_tx: std::sync::mpsc::Sender<(String, String)>,
        ) -> std::thread::JoinHandle<()> {
            self.method_calls
                .lock()
                .unwrap()
                .push("start_observer_thread".into());
            std::thread::spawn(|| {})
        }
    }

    #[test]
    fn test_orchestrator_sandbox_contract_sequence() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let sandbox = Box::new(MockSandbox {
            method_calls: calls.clone(),
        });

        let orch = AppOrchestrator { sandbox };

        let temp_dir = std::env::temp_dir();
        let cfg_path = temp_dir.join("test_gate_sequence.yaml");
        let cfg_content = r#"
version: 1
server:
  name: test
  command: "true"
  args: []
  workspace:
    source: .
    mode: copy
policy:
  read_paths: []
  write_paths: []
  allowed_child_binaries: []
  allow_network: false
  allowed_unix_sockets: []
"#;
        std::fs::write(&cfg_path, cfg_content).unwrap();

        let opts = RunOptions {
            config_path: cfg_path.clone(),
            ..RunOptions::default()
        };

        let _ = orch.execute(&opts);

        let executed = calls.lock().unwrap().clone();

        // Assert the presence and rough order of critical calls
        assert!(
            executed.contains(&"probe_host_caps".to_string()),
            "probe_host_caps not called"
        );
        assert!(
            executed.contains(&"generate_seed".to_string()),
            "generate_seed not called"
        );
        assert!(executed.contains(&"init".to_string()), "init not called");
        assert!(
            executed.contains(&"build_ruleset".to_string()),
            "build_ruleset not called"
        );
        assert!(
            executed.contains(&"create_launcher".to_string()),
            "create_launcher not called"
        );
        assert!(
            executed.contains(&"start_observer_thread".to_string()),
            "start_observer_thread not called"
        );
        assert!(
            executed.contains(&"setup_tripwire".to_string()),
            "setup_tripwire not called"
        );
        assert!(
            executed.contains(&"teardown".to_string()),
            "teardown not called"
        );

        // Order verifications: init -> ruleset -> tripwire -> launcher -> observer -> teardown
        let pos_init = executed.iter().position(|x| x == "init").unwrap();
        let pos_ruleset = executed.iter().position(|x| x == "build_ruleset").unwrap();
        let pos_tripwire = executed.iter().position(|x| x == "setup_tripwire").unwrap();
        let pos_launcher = executed
            .iter()
            .position(|x| x == "create_launcher")
            .unwrap();
        let pos_observer = executed
            .iter()
            .position(|x| x == "start_observer_thread")
            .unwrap();
        let pos_teardown = executed.iter().position(|x| x == "teardown").unwrap();

        assert!(pos_init < pos_ruleset, "init must be before build_ruleset");
        assert!(
            pos_ruleset < pos_launcher,
            "build_ruleset must be before create_launcher"
        );
        assert!(
            pos_launcher < pos_observer,
            "launcher creation must be before starting observer thread"
        );
        assert!(
            pos_observer < pos_teardown,
            "observer thread must start before teardown"
        );
        assert!(
            pos_tripwire < pos_teardown,
            "tripwire must setup before teardown"
        );
    }
}
