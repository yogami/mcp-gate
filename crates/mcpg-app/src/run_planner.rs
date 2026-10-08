use crate::capsule_plan::{CapsulePlan, Mode};
use mcpg_domain::canary::catalogue::{all_catalogue_entries, CanaryKind};
use mcpg_domain::canary::render::CanaryPlan;
use mcpg_domain::config::model::{CanariesConfig, Config};
use mcpg_domain::config::vars::VarTable;
use mcpg_domain::env::EnvOutcome;
use mcpg_domain::fs_view::StdFs;
use mcpg_domain::policy::resolve::ResolvedPolicy;
use mcpg_domain::seed::Seed;
use mcpg_domain::verdict::ExitCode;
use std::path::Path;

pub struct RunPlanner;

impl RunPlanner {
    pub fn load_config(path: &Path) -> Result<Config, ExitCode> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            eprintln!("error reading config file {}: {e}", path.display());
            ExitCode::Usage
        })?;
        crate::config::load_str(&content).map_err(|e| {
            eprintln!("{e}");
            ExitCode::Usage
        })
    }

    pub fn resolve_canary_kinds(cfg: &CanariesConfig) -> Vec<CanaryKind> {
        if cfg.kinds.is_empty() {
            all_catalogue_entries().iter().map(|e| e.kind).collect()
        } else {
            cfg.kinds.iter().map(|&k| k.into()).collect()
        }
    }

    pub fn plan_canaries(seed: &Seed, cfg: &CanariesConfig) -> CanaryPlan {
        let kinds = Self::resolve_canary_kinds(cfg);
        mcpg_domain::canary::render::plan(seed, &kinds)
    }

    pub fn resolve_policy(
        cfg: &Config,
        vars: &VarTable,
        capsule_path: &str,
    ) -> Result<ResolvedPolicy, ExitCode> {
        let resolved =
            ResolvedPolicy::from_config_with_path(&cfg.policy, vars, capsule_path, &StdFs)
                .map_err(|e| {
                    eprintln!("policy resolution error: {e}");
                    ExitCode::Usage
                })?;
        for p in &resolved.to_create {
            let _ = std::fs::create_dir_all(p);
        }
        Ok(resolved)
    }

    pub fn create_plan(
        cfg: &Config,
        env_outcome: &EnvOutcome,
        vars: &VarTable,
        mode: Mode,
    ) -> Result<CapsulePlan, ExitCode> {
        CapsulePlan::build(cfg, env_outcome, vars, mode).map_err(|e| {
            eprintln!("plan error: {e}");
            ExitCode::Usage
        })
    }
}
