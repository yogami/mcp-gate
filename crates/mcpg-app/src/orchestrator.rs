//! Run orchestrator types and options.
//!
//! SPEC 1.3, 3.0: High-level test run configuration and execution tracking.

use std::path::PathBuf;

use mcpg_domain::config::model::FailOnLevel;
use mcpg_domain::host::Feature;
use mcpg_domain::mode::Mode;
use mcpg_domain::seed::Seed;
use mcpg_domain::verdict::{ExitCode, Verdict};

/// Level of console verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verbosity {
    Quiet,
    #[default]
    Normal,
    Verbose,
}

/// Options controlling capsule run execution.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub config_path: PathBuf,
    pub out_dir: PathBuf,
    pub sarif_path: Option<String>,
    pub junit_path: Option<String>,
    pub evidence_path: Option<String>,
    pub requested_mode: Mode,
    pub require: Vec<Feature>,
    pub fail_on: Option<FailOnLevel>,
    pub seed: Option<Seed>,
    pub timeout: Option<u64>,
    pub keep_capsule: bool,
    pub evidence_include_values: bool,
    pub no_annotations: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub verbosity: Verbosity,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            config_path: PathBuf::from("./mcp-gate.yaml"),
            out_dir: PathBuf::from("./mcp-gate-results"),
            sarif_path: None,
            junit_path: None,
            evidence_path: None,
            requested_mode: Mode::Enforce,
            require: Vec::new(),
            fail_on: None,
            seed: None,
            timeout: None,
            keep_capsule: false,
            evidence_include_values: false,
            no_annotations: false,
            quiet: false,
            verbose: false,
            verbosity: Verbosity::Normal,
        }
    }
}

/// Final summary outcome produced by run orchestration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    pub verdict: Verdict,
    pub exit_code: ExitCode,
    pub seed: Seed,
    pub registry: mcpg_domain::canary::registry::CanaryRegistry,
    pub violations: Vec<(String, String)>,
}

/// Port trait for executing a configured capsule run.
pub trait RunOrchestrator {
    /// Execute the run using the provided options and return the final process exit code.
    fn execute(&self, options: &RunOptions) -> Result<RunOutcome, ExitCode>;
}

use crate::phase::PhaseCursor;
use crate::ports::{CapsuleLauncher, Sandbox};
use crate::run_planner::RunPlanner;
use std::sync::Arc;

pub struct AppOrchestrator {
    pub sandbox: Box<dyn Sandbox>,
}

impl RunOrchestrator for AppOrchestrator {
    fn execute(&self, opts: &RunOptions) -> Result<RunOutcome, ExitCode> {
        let (cfg, mode, seed, caps) = match self.init_base(opts) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        let (vars, registry, env_outcome) = match self.sandbox.init(&cfg, &seed, opts) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        let capsule_path = env_outcome
            .vars
            .iter()
            .find(|(k, _)| k == "PATH")
            .and_then(|(_, v)| v.to_str())
            .unwrap_or("/usr/local/bin:/usr/bin:/bin");

        let resolved = match RunPlanner::resolve_policy(&cfg, &vars, capsule_path) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        let plan = match RunPlanner::create_plan(&cfg, &env_outcome, &vars, mode) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        let ruleset = if mode == Mode::Enforce {
            match self
                .sandbox
                .build_ruleset(&resolved, &vars, &cfg.server.command, &caps)
            {
                Ok(v) => v,
                Err(e) => return Err(e),
            }
        } else {
            None
        };

        let phase = PhaseCursor::new();

        let _tripwire_handle = match self.sandbox.setup_tripwire(&registry, phase.clone()) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        let _scanner = if !registry.records.is_empty() {
            Some(Arc::new(mcpg_domain::leak::LeakScanner::from_registry(
                &registry,
            )))
        } else {
            None
        };

        let (exec_verdict, exec_code, proto_errs) = {
            let (launcher, handover) = self.sandbox.create_launcher(ruleset);
            let (obs_tx, obs_rx) = std::sync::mpsc::channel();

            let mut _obs_handle = None;
            if let Some(fd) = handover {
                _obs_handle = Some(
                    self.sandbox.start_observer_thread(
                        fd,
                        cfg.policy.allow_network,
                        cfg.policy
                            .allowed_child_binaries
                            .iter()
                            .map(std::path::PathBuf::from)
                            .collect(),
                        Some(cfg.server.command.clone().into()),
                        cfg.policy.allowed_unix_sockets.clone(),
                        vec![],
                        None,
                        None,
                        obs_tx,
                    ),
                );
            }

            let mut cap = match launcher.launch(&plan) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("launch error: {:?}", e);
                    return Err(ExitCode::Internal);
                }
            };

            let transport = mcpg_mcp::transport::StdioTransport::new(
                cap.child.stdin.take().unwrap(),
                mcpg_mcp::framing::LineReader::new(
                    std::io::BufReader::new(cap.child.stdout.take().unwrap()),
                    1024 * 1024,
                ),
            );
            let mut client = mcpg_mcp::client::McpClient::new(transport)
                .with_workspace_uri(format!("file://{}", vars.workspace.display()));
            let tracker = mcpg_mcp::deadline::DeadlineTracker::new(
                std::sync::Arc::new(mcpg_mcp::deadline::SystemClock),
                cfg.limits.clone(),
            );
            client.set_deadline_tracker(tracker.clone());

            let (exec_verdict, exec_code, mut proto_errs) =
                crate::session::drive_session(client, &cfg, &tracker, &phase);

            let _ = self
                .sandbox
                .teardown(cap, std::time::Duration::from_millis(1500));

            while let Ok(v) = obs_rx.try_recv() {
                proto_errs.push(v);
            }

            (exec_verdict, exec_code, proto_errs)
        };

        Ok(RunOutcome {
            verdict: exec_verdict,
            exit_code: exec_code,
            seed,
            registry,
            violations: proto_errs,
        })
    }
}

impl AppOrchestrator {
    fn init_base(
        &self,
        opts: &RunOptions,
    ) -> Result<
        (
            mcpg_domain::config::model::Config,
            Mode,
            Seed,
            mcpg_domain::host::HostCaps,
        ),
        ExitCode,
    > {
        let caps = self.sandbox.probe_host_caps(); // Need to abstract this later if needed.
        let mut cfg = RunPlanner::load_config(&opts.config_path)?;
        if let Some(timeout) = opts.timeout {
            cfg.limits.total_timeout_s = timeout;
        }
        let (mode, _) = crate::plan_mode::choose_mode(opts.requested_mode, &caps, &opts.require)?;
        let seed = match opts.seed {
            Some(s) => s,
            None => self.sandbox.generate_seed().map_err(|e| {
                eprintln!("failed to generate seed: {:?}", e);
                ExitCode::Internal
            })?,
        };
        Ok((cfg, mode, seed, caps))
    }
}
