use std::path::{Path, PathBuf};
use std::fs;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::os::fd::AsRawFd;
use mcpg_domain::config::model::{CanariesConfig, Config, EnvConfig, WorkspaceConfig};
use mcpg_domain::config::vars::VarTable;
use mcpg_domain::canary::registry::CanaryRegistry;
use mcpg_domain::env::{build_env, EnvOutcome, FixedEnv};
use mcpg_domain::seed::Seed;
use mcpg_domain::verdict::ExitCode;
use mcpg_domain::policy::resolve::ResolvedPolicy;
use mcpg_domain::host::HostCaps;
use mcpg_domain::fs_view::StdFs;
use mcpg_domain::mode::Mode;
use mcpg_domain::policy::sets::EnforcementSet;
use mcpg_domain::event::Event;
use mcpg_app::orchestrator::RunOptions;
use mcpg_app::ports::{Sandbox, TripwireHandle, RunningCapsule};
use crate::entropy::OsEntropy;
use crate::rundir::RunDir;
use mcpg_app::phase::PhaseCursor;

pub struct LinuxSandbox {
    run_dir: std::sync::Mutex<Option<RunDir>>,
}

impl LinuxSandbox {
    pub fn new() -> Self {
        Self {
            run_dir: std::sync::Mutex::new(None),
        }
    }
}

impl Sandbox for LinuxSandbox {
    fn generate_seed(&self) -> Result<Seed, ExitCode> {
        Seed::random(&crate::entropy::OsEntropy).map_err(|e| {
            eprintln!("failed to generate seed: {e}");
            ExitCode::Internal
        })
    }
    fn probe_host_caps(&self) -> HostCaps {
        crate::probe::probe()
    }
    fn init(&self, cfg: &Config, seed: &Seed, opts: &RunOptions) -> Result<(VarTable, CanaryRegistry, EnvOutcome), ExitCode> {
        let run_dir = RunDir::create(Path::new("/tmp"), opts.keep_capsule, &OsEntropy).map_err(|e| {
            eprintln!("failed to create run directory: {e}");
            ExitCode::Internal
        })?;

        let canonical_cfg = opts
            .config_path
            .canonicalize()
            .unwrap_or_else(|_| opts.config_path.clone());
        let cfg_dir = canonical_cfg.parent().unwrap_or(Path::new("/"));
        
        let ws_path = self.resolve_workspace(&cfg.server.workspace, &run_dir, cfg_dir)?;
        let (registry, decoys) = self.plant_canaries(&cfg.canaries, seed, &run_dir)?;
        let env_outcome = self.scrub_environment(&cfg.server.env, &run_dir, &decoys)?;

        let vars = VarTable {
            workspace: ws_path,
            capsule_home: run_dir.home().to_path_buf(),
            capsule_tmp: run_dir.tmp().to_path_buf(),
            config_dir: cfg_dir.to_path_buf(),
        };

        if let Ok(mut guard) = self.run_dir.lock() {
            *guard = Some(run_dir);
        }

        Ok((vars, registry, env_outcome))
    }

    fn build_ruleset(&self, policy: &ResolvedPolicy, vars: &VarTable, cmd: &str, caps: &HostCaps) -> Result<Option<OwnedFd>, ExitCode> {
        if !caps.landlock.available {
            eprintln!("Landlock is not available for requested enforce mode");
            return Err(ExitCode::UnsupportedHost);
        }
        
        let exec_roots = Self::collect_exec_roots(cmd, &policy.allowed_child_binaries);
        let full_exec = mcpg_domain::exec_deps::exec_closure(&exec_roots, &StdFs, &|p| fs::read(p));
        let enforcement_set = EnforcementSet::from_policy(policy, vars);
        let plan = mcpg_domain::landlock_plan::plan(
            &enforcement_set,
            &full_exec,
            caps.landlock.abi as u8,
            Mode::Enforce,
            policy.allow_network,
        );
        let fd = crate::landlock::build(&plan).map_err(|e| {
            eprintln!("failed to build Landlock ruleset: {e}");
            ExitCode::Internal
        })?;
        Ok(Some(fd))
    }

    fn setup_tripwire(&self, registry: &CanaryRegistry, phase: PhaseCursor) -> Result<Option<Box<dyn TripwireHandle>>, ExitCode> {
        if registry.records.is_empty() {
            return Ok(None);
        }
        
        let tw = crate::inotify::Tripwire::new().map_err(|_| ExitCode::Internal)?;
        for record in &registry.records {
            let _ = tw.add_watch(&record.path, format!("{:?}", record.kind));
        }
        let handle = tw.start_with_phase(phase);
        Ok(Some(Box::new(LinuxTripwireHandle(handle))))
    }

    fn teardown(&self, capsule: RunningCapsule, grace: std::time::Duration) -> Result<Vec<Event>, ExitCode> {
        let shutdown_report = crate::shutdown::shutdown(capsule, grace);
        let mut events = Vec::new();

        if !shutdown_report.survivors.is_empty() {
            events.push(
                Event::builder(mcpg_domain::event::EventKind::ProcOrphan, "shutdown")
                    .message(format!(
                        "Process escape: {} orphaned processes outlived run",
                        shutdown_report.survivors.len()
                    ))
                    .source(mcpg_domain::event::EventSource::SeccompNotify)
                    .build(),
            );
        }
        
        if let Ok(mut guard) = self.run_dir.lock() {
            let _ = guard.take();
        }

        Ok(events)
    }

    fn create_launcher(&self, ruleset: Option<OwnedFd>) -> Box<dyn mcpg_app::ports::CapsuleLauncher> {
        let mut launcher = crate::launcher::LinuxLauncher::new().with_seccomp(true);
        if let Some(fd) = ruleset {
            use std::os::fd::IntoRawFd;
            launcher = launcher.with_landlock_fd(fd.into_raw_fd());
        }
        Box::new(launcher)
    }

    fn disarm_guard(&self) {}

    fn arm_guard(&self, pid: i32, pids: Vec<u32>) {
        let guard = crate::guard::CapsuleGuard::new(pid, pids);
        std::mem::forget(guard); // Quick hack to avoid changing signature and keep guard active
    }

    fn start_observer_thread(
        &self,
        fd: RawFd,
        allow_network: bool,
        allowed_child_binaries: Vec<std::path::PathBuf>,
        root_command: Option<std::path::PathBuf>,
        allowed_unix_sockets: Vec<String>,
        capsule_pids: Vec<u32>,
        active_phase: Option<String>,
        events_tx: Option<std::sync::mpsc::Sender<Event>>,
        obs_tx: std::sync::mpsc::Sender<(String, String)>,
    ) -> std::thread::JoinHandle<()> {
        let obs_cfg = crate::observer::ObserverConfig {
            allow_network,
            allowed_child_binaries,
            root_command,
            allowed_unix_sockets,
            capsule_pids,
            active_phase,
            events_tx,
        };
        crate::observer::start_observer_thread(fd, obs_cfg, obs_tx)
    }
}

pub struct LinuxTripwireHandle(std::thread::JoinHandle<Vec<(String, String)>>);

impl TripwireHandle for LinuxTripwireHandle {
    fn stop(&mut self) {
        // Tripwire is stopped via the stop method on the Tripwire struct, but here we only have the JoinHandle. We should change how this works or just ignore it for now.
    }
    fn join(self: Box<Self>) -> Result<Vec<(String, String)>, ()> {
        self.0.join().map_err(|_| ())
    }
}

impl LinuxSandbox {
    fn resolve_workspace(
        &self,
        cfg: &WorkspaceConfig,
        run_dir: &RunDir,
        config_dir: &Path,
    ) -> Result<PathBuf, ExitCode> {
        let mut ws_cfg = cfg.clone();
        if Path::new(&ws_cfg.source).is_relative() {
            let candidate = config_dir.join(&ws_cfg.source);
            if candidate.exists() {
                ws_cfg.source = candidate.to_string_lossy().to_string();
            }
        }
        if let Some(warning) = mcpg_app::hygiene::check_source_checkout_hint(Path::new(&ws_cfg.source))
        {
            eprintln!("Warning: {warning}");
        }
        crate::workspace::prepare(&ws_cfg, run_dir).map_err(|e| {
            eprintln!("failed to prepare workspace: {e}");
            ExitCode::Internal
        })
    }

    fn plant_canaries(
        &self,
        cfg: &CanariesConfig,
        seed: &Seed,
        run_dir: &RunDir,
    ) -> Result<
        (
            CanaryRegistry,
            Vec<(std::ffi::OsString, std::ffi::OsString)>,
        ),
        ExitCode,
    > {
        if !cfg.enabled {
            return Ok((CanaryRegistry::new(), Vec::new()));
        }
        let kinds = mcpg_app::run_planner::RunPlanner::resolve_canary_kinds(cfg);
        let plan = mcpg_domain::canary::render::plan(seed, &kinds);
        let registry = crate::canary_plant::plant(&plan, run_dir).map_err(|e| {
            eprintln!("failed to plant canaries: {e}");
            ExitCode::Internal
        })?;
        Ok((registry, plan.env))
    }

    fn scrub_environment(
        &self,
        cfg: &EnvConfig,
        run_dir: &RunDir,
        decoys: &[(std::ffi::OsString, std::ffi::OsString)],
    ) -> Result<EnvOutcome, ExitCode> {
        let fixed = FixedEnv {
            home: run_dir.home().to_path_buf(),
            tmpdir: run_dir.tmp().to_path_buf(),
            path: "/usr/local/bin:/usr/bin:/bin".to_string(),
            lang: "C.UTF-8".to_string(),
        };
        let host_vars: Vec<_> = std::env::vars_os().collect();
        build_env(&host_vars, cfg, &fixed, decoys, &|_| true).map_err(|e| {
            eprintln!("environment error: {e}");
            ExitCode::Usage
        })
    }

    fn collect_exec_roots(cmd: &str, child_bins: &[PathBuf]) -> Vec<PathBuf> {
        let path_var = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string());
        let root =
            mcpg_domain::policy::resolve::resolve_binary(cmd, &path_var, &StdFs)
                .unwrap_or_else(|_| PathBuf::from(cmd));
        let mut roots = vec![root];
        roots.extend(child_bins.iter().cloned());
        roots
    }
}
