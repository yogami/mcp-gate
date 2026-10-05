//! Implementation of `mcp-gate run`.
//!
//! SPEC 1.3, 3.1: Orchestrates capsule execution, MCP driver lifecycle,
//! expectation checking, and report generation.

use std::fs;
use std::io::BufReader;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mcpg_app::capsule_plan::CapsulePlan;
use mcpg_app::config::load_str;
use mcpg_app::orchestrator::{RunOptions, RunOrchestrator};
use mcpg_app::phase::PhaseCursor;
use mcpg_app::ports::{CapsuleLauncher, SystemClock};
use mcpg_app::scenario::CallOutcome;
use mcpg_domain::canary::catalogue::all_catalogue_entries;
use mcpg_domain::canary::registry::CanaryRegistry;
use mcpg_domain::config::model::{
    CanariesConfig, Config, EnvConfig, ScenarioConfig, WorkspaceConfig,
};
use mcpg_domain::config::vars::VarTable;
use mcpg_domain::env::{build_env, EnvOutcome, FixedEnv};
use mcpg_domain::fs_view::StdFs;
use mcpg_domain::host::HostCaps;
use mcpg_domain::mode::Mode;
use mcpg_domain::policy::resolve::ResolvedPolicy;
use mcpg_domain::policy::sets::EnforcementSet;
use mcpg_domain::seed::Seed;
use mcpg_domain::verdict::{ExitCode, Verdict};
use mcpg_linux::entropy::OsEntropy;
use mcpg_linux::launcher::LinuxLauncher;
use mcpg_linux::rundir::RunDir;
use mcpg_mcp::client::{DriverError, McpClient};
use mcpg_mcp::deadline::DeadlineTracker;
use mcpg_mcp::framing::LineReader;
use mcpg_mcp::transport::{McpTransport, StdioTransport};
use mcpg_report::{ConsoleWriter, EvidenceWriter, ReportWriter, RunRecord};

fn check_platform() -> Result<(), ExitCode> {
    if !cfg!(target_os = "linux") {
        eprintln!("Error: mcp-gate run requires Linux (exit 69)");
        return Err(ExitCode::UnsupportedHost);
    }
    Ok(())
}

fn load_config(path: &Path) -> Result<Config, ExitCode> {
    let content = fs::read_to_string(path).map_err(|e| {
        eprintln!("error reading config file {}: {e}", path.display());
        ExitCode::Usage
    })?;
    load_str(&content).map_err(|e| {
        eprintln!("{e}");
        ExitCode::Usage
    })
}

fn resolve_seed(seed_opt: Option<Seed>) -> Result<Seed, ExitCode> {
    match seed_opt {
        Some(s) => Ok(s),
        None => Seed::random(&OsEntropy).map_err(|e| {
            eprintln!("failed to generate seed: {e}");
            ExitCode::Internal
        }),
    }
}

fn resolve_workspace(
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
    mcpg_linux::workspace::prepare(&ws_cfg, run_dir).map_err(|e| {
        eprintln!("failed to prepare workspace: {e}");
        ExitCode::Internal
    })
}

fn resolve_canary_kinds(cfg: &CanariesConfig) -> Vec<mcpg_domain::canary::catalogue::CanaryKind> {
    if cfg.kinds.is_empty() {
        all_catalogue_entries().iter().map(|e| e.kind).collect()
    } else {
        cfg.kinds.iter().map(|&k| k.into()).collect()
    }
}

fn plant_canaries(
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
    let kinds = resolve_canary_kinds(cfg);
    let plan = mcpg_domain::canary::render::plan(seed, &kinds);
    let registry = mcpg_linux::canary_plant::plant(&plan, run_dir).map_err(|e| {
        eprintln!("failed to plant canaries: {e}");
        ExitCode::Internal
    })?;
    Ok((registry, plan.env))
}

fn scrub_environment(
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

fn resolve_policy_paths(cfg: &Config, vars: &VarTable) -> Result<ResolvedPolicy, ExitCode> {
    let resolved = ResolvedPolicy::from_config(&cfg.policy, vars, &StdFs).map_err(|e| {
        eprintln!("policy resolution error: {e}");
        ExitCode::Usage
    })?;
    for p in &resolved.to_create {
        let _ = fs::create_dir_all(p);
    }
    Ok(resolved)
}

fn collect_exec_roots(cmd: &str, child_bins: &[PathBuf]) -> Vec<PathBuf> {
    let root =
        mcpg_domain::policy::resolve::resolve_binary(cmd, "/usr/local/bin:/usr/bin:/bin", &StdFs)
            .unwrap_or_else(|_| PathBuf::from(cmd));
    let mut roots = vec![root];
    roots.extend(child_bins.iter().cloned());
    roots
}

fn build_landlock_ruleset(
    policy: &ResolvedPolicy,
    vars: &VarTable,
    cmd: &str,
    caps: &HostCaps,
) -> Option<std::os::fd::OwnedFd> {
    let exec_roots = collect_exec_roots(cmd, &policy.allowed_child_binaries);
    let full_exec = mcpg_domain::exec_deps::exec_closure(&exec_roots, &StdFs, &|p| fs::read(p));
    let enforcement_set = EnforcementSet::from_policy(policy, vars);
    let plan = mcpg_domain::landlock_plan::plan(
        &enforcement_set,
        &full_exec,
        caps.landlock.abi as u8,
        Mode::Enforce,
        policy.allow_network,
    );
    mcpg_linux::landlock::build(&plan).ok()
}

fn execute_single_scenario<T: McpTransport>(
    client: &mut McpClient<T>,
    _tracker: &DeadlineTracker,
    scenario: &ScenarioConfig,
    phase: &PhaseCursor,
    tools: &std::collections::HashMap<String, mcpg_mcp::tools::ToolDef>,
) -> Result<bool, DriverError> {
    let _ = phase.start_scenario(&scenario.id);
    let outcome = if let Some(tool_def) = tools.get(&scenario.tool) {
        let is_valid = if tool_def.input_schema.is_null() {
            true
        } else if let Ok(validator) = jsonschema::validator_for(&tool_def.input_schema) {
            validator.is_valid(&scenario.arguments)
        } else {
            false
        };
        if is_valid {
            match client.call_tool_with_timeout(
                &scenario.tool,
                &scenario.arguments,
                scenario.timeout_s,
            ) {
                Ok(res) => CallOutcome::from(res),
                Err(DriverError::Protocol(msg)) => CallOutcome::protocol_error(msg),
                Err(e) => return Err(e),
            }
        } else {
            CallOutcome::tool_error("arguments failed schema validation")
        }
    } else {
        CallOutcome::tool_error("tool not found in tools/list")
    };
    let expect = scenario.expect.clone().unwrap_or_default();
    let passed = mcpg_app::scenario::check(&expect, &outcome).passed;
    let _ = phase.end_scenario();
    Ok(passed)
}

fn handle_scenario_step<T: McpTransport>(
    client: &mut McpClient<T>,
    tracker: &DeadlineTracker,
    scenario: &ScenarioConfig,
    phase: &PhaseCursor,
    has_failure: &mut bool,
    tools: &std::collections::HashMap<String, mcpg_mcp::tools::ToolDef>,
) -> bool {
    match execute_single_scenario(client, tracker, scenario, phase, tools) {
        Ok(passed) => {
            if !passed {
                *has_failure = true;
            }
            true
        }
        Err(_) => false,
    }
}

fn drive_scenarios_loop<T: McpTransport>(
    client: &mut McpClient<T>,
    tracker: &DeadlineTracker,
    scenarios: &[ScenarioConfig],
    phase: &PhaseCursor,
    tools: &std::collections::HashMap<String, mcpg_mcp::tools::ToolDef>,
) -> (Verdict, ExitCode) {
    let mut codes = vec![ExitCode::Pass];
    for scenario in scenarios {
        if tracker.is_total_expired() {
            codes.push(ExitCode::Inconclusive);
            break;
        }
        let mut has_failure = false;
        let ok = handle_scenario_step(client, tracker, scenario, phase, &mut has_failure, tools);
        if has_failure {
            codes.push(ExitCode::FailFunctional);
        }
        if !ok {
            codes.push(ExitCode::Inconclusive);
            break;
        }
    }
    let final_code = mcpg_domain::verdict::combine(codes);
    let final_verdict = match final_code {
        ExitCode::Pass => Verdict::Pass,
        ExitCode::FailFunctional => Verdict::FailFunctional,
        ExitCode::FailSecurity => Verdict::FailSecurity,
        _ => Verdict::Inconclusive,
    };
    (final_verdict, final_code)
}

fn drive_session<T: McpTransport>(
    mut client: McpClient<T>,
    cfg: &Config,
    tracker: &DeadlineTracker,
    phase: &PhaseCursor,
) -> (Verdict, ExitCode, Vec<(String, String)>) {
    let _ = phase.advance_to_handshake();
    if client
        .initialize(&cfg.server.protocol_versions, cfg.server.client.roots)
        .is_err()
    {
        return (
            Verdict::Inconclusive,
            ExitCode::Inconclusive,
            client
                .take_violations()
                .into_iter()
                .map(|v| (v.reason, v.raw))
                .collect(),
        );
    }

    let tools_list = match client.list_tools() {
        Ok(t) => t,
        Err(_) => {
            return (
                Verdict::Inconclusive,
                ExitCode::Inconclusive,
                client
                    .take_violations()
                    .into_iter()
                    .map(|v| (v.reason, v.raw))
                    .collect(),
            );
        }
    };
    let mut tools = std::collections::HashMap::new();
    for t in tools_list {
        tools.insert(t.name.clone(), t);
    }

    let (v, e) = drive_scenarios_loop(&mut client, tracker, &cfg.scenarios, phase, &tools);
    (
        v,
        e,
        client
            .take_violations()
            .into_iter()
            .map(|v| (v.reason, v.raw))
            .collect(),
    )
}

fn execute_capsule_run(
    plan: &CapsulePlan,
    ruleset: Option<&std::os::fd::OwnedFd>,
    cfg: &Config,
    vars: &VarTable,
) -> (Verdict, ExitCode, Vec<(String, String)>) {
    let mut launcher = LinuxLauncher::new();
    if let Some(ruleset) = ruleset {
        launcher = launcher.with_landlock_fd(ruleset.as_raw_fd());
    }
    let mut cap = match launcher.launch(plan) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("launch error: {e}");
            return (Verdict::Inconclusive, ExitCode::Internal, Vec::new());
        }
    };

    let stdout = cap.child.stdout.take().expect("piped stdout");
    let stdin = cap.child.stdin.take().expect("piped stdin");
    let stderr_drain = cap.child.stderr.take().map(|mut stderr| {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
        })
    });
    let reader = LineReader::new(BufReader::new(stdout), cfg.limits.max_stdout_line_bytes);
    let transport = StdioTransport::new(stdin, reader);

    let mut client = McpClient::new(transport)
        .with_workspace_uri(format!("file://{}", vars.workspace.display()));
    let tracker = DeadlineTracker::new(Arc::new(SystemClock), cfg.limits);
    client.set_deadline_tracker(tracker.clone());

    let phase = PhaseCursor::new();
    let result = drive_session(client, cfg, &tracker, &phase);

    let _ = phase.advance_to_shutdown();
    let grace = Duration::from_secs(cfg.limits.shutdown_grace_s);
    let _ = mcpg_linux::shutdown::shutdown(cap, grace);
    if let Some(drain) = stderr_drain {
        let _ = drain.join();
    }

    result
}

fn write_run_reports(
    record: &RunRecord,
    out_dir: &Path,
    evidence_path_opt: Option<&str>,
) -> Result<(), ExitCode> {
    let _ = ConsoleWriter.write(record, &mut std::io::stdout());
    let _ = fs::create_dir_all(out_dir);
    let ev_path = match evidence_path_opt {
        Some("-") => return Ok(()),
        Some(p) => PathBuf::from(p),
        None => out_dir.join("evidence.ndjson"),
    };
    if let Some(parent) = ev_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = fs::File::create(&ev_path) {
        let _ = EvidenceWriter.write(record, &mut file);
    }
    Ok(())
}

struct RunContext {
    cfg: Config,
    mode: Mode,
    seed: Seed,
    _run_dir: RunDir,
    vars: VarTable,
    registry: CanaryRegistry,
    env_outcome: EnvOutcome,
    caps: HostCaps,
}

fn init_base(opts: &RunOptions) -> Result<(Config, Mode, Seed, HostCaps), ExitCode> {
    let _ = mcpg_linux::self_harden::harden_self();
    let caps = mcpg_linux::probe::probe();
    let mut cfg = load_config(&opts.config_path)?;
    if let Some(timeout) = opts.timeout {
        cfg.limits.total_timeout_s = timeout;
    }
    let (mode, _) = mcpg_app::plan_mode::choose_mode(opts.requested_mode, &caps, &opts.require)?;
    let seed = resolve_seed(opts.seed)?;
    Ok((cfg, mode, seed, caps))
}

fn init_sandbox(
    cfg: &Config,
    seed: &Seed,
    opts: &RunOptions,
) -> Result<(RunDir, VarTable, CanaryRegistry, EnvOutcome), ExitCode> {
    let run_dir =
        RunDir::create(Path::new("/tmp"), opts.keep_capsule, &OsEntropy).map_err(|e| {
            eprintln!("failed to create run directory: {e}");
            ExitCode::Internal
        })?;

    let canonical_cfg = opts
        .config_path
        .canonicalize()
        .unwrap_or_else(|_| opts.config_path.clone());
    let cfg_dir = canonical_cfg.parent().unwrap_or(Path::new("/"));
    let ws_path = resolve_workspace(&cfg.server.workspace, &run_dir, cfg_dir)?;
    let (registry, decoys) = plant_canaries(&cfg.canaries, seed, &run_dir)?;
    let env_outcome = scrub_environment(&cfg.server.env, &run_dir, &decoys)?;

    let vars = VarTable {
        workspace: ws_path,
        capsule_home: run_dir.home().to_path_buf(),
        capsule_tmp: run_dir.tmp().to_path_buf(),
        config_dir: cfg_dir.to_path_buf(),
    };

    Ok((run_dir, vars, registry, env_outcome))
}

fn prepare_context(opts: &RunOptions) -> Result<RunContext, ExitCode> {
    let (cfg, mode, seed, caps) = init_base(opts)?;
    let (run_dir, vars, registry, env_outcome) = init_sandbox(&cfg, &seed, opts)?;
    Ok(RunContext {
        cfg,
        mode,
        seed,
        _run_dir: run_dir,
        vars,
        registry,
        env_outcome,
        caps,
    })
}

fn prepare_plan(ctx: &RunContext) -> Result<(CapsulePlan, Option<std::os::fd::OwnedFd>), ExitCode> {
    let resolved = resolve_policy_paths(&ctx.cfg, &ctx.vars)?;
    let plan =
        CapsulePlan::build(&ctx.cfg, &ctx.env_outcome, &ctx.vars, ctx.mode).map_err(|e| {
            eprintln!("plan error: {e}");
            ExitCode::Usage
        })?;
    let ruleset = if ctx.mode == Mode::Enforce && ctx.caps.landlock.available {
        build_landlock_ruleset(&resolved, &ctx.vars, &ctx.cfg.server.command, &ctx.caps)
    } else {
        None
    };
    Ok((plan, ruleset))
}

fn run_pipeline(opts: &RunOptions) -> Result<ExitCode, ExitCode> {
    let ctx = prepare_context(opts)?;
    let (plan, ruleset) = prepare_plan(&ctx)?;
    let (exec_verdict, exec_code, violations) =
        execute_capsule_run(&plan, ruleset.as_ref(), &ctx.cfg, &ctx.vars);

    let mut final_code = exec_code;
    let mut final_verdict = exec_verdict;

    let effective_fail_on = opts
        .fail_on
        .or(ctx.cfg.report.fail_on)
        .unwrap_or(mcpg_domain::config::model::FailOnLevel::Error);

    if !violations.is_empty()
        && effective_fail_on.should_fail(mcpg_domain::config::model::FailOnLevel::Warning)
    {
        final_code = mcpg_domain::verdict::combine(vec![final_code, ExitCode::FailSecurity]);
        if final_code == ExitCode::FailSecurity {
            final_verdict = Verdict::FailSecurity;
        }
    }

    let record = RunRecord::new(ctx.seed, final_verdict, ctx.registry, violations);
    write_run_reports(&record, &opts.out_dir, opts.evidence_path.as_deref())?;
    Ok(final_code)
}

/// Linux run orchestrator implementation.
pub struct LinuxOrchestrator;

impl RunOrchestrator for LinuxOrchestrator {
    fn execute(&self, opts: &RunOptions) -> ExitCode {
        if let Err(code) = check_platform() {
            return code;
        }
        match run_pipeline(opts) {
            Ok(code) | Err(code) => code,
        }
    }
}

pub fn execute(opts: &RunOptions) -> ExitCode {
    LinuxOrchestrator.execute(opts)
}
