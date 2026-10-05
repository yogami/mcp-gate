//! Implementation of `mcp-gate validate`.

use std::fs;
use std::path::{Path, PathBuf};

use mcpg_app::config::load_str;
use mcpg_domain::config::vars::VarTable;
use mcpg_domain::fs_view::StdFs;
use mcpg_domain::policy::resolve::ResolvedPolicy;
use mcpg_domain::verdict::ExitCode;

/// Validate a configuration file against JSON schema, semantic rules, and path resolution.
pub fn execute(config_path: &Path) -> ExitCode {
    let content = match fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error reading config file {}: {e}", config_path.display());
            return ExitCode::Usage;
        }
    };

    let cfg = match load_str(&content) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::Usage;
        }
    };

    let canonical_cfg = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf());
    let cfg_dir = canonical_cfg
        .parent()
        .unwrap_or(Path::new("/"))
        .to_path_buf();
    let vars = VarTable {
        workspace: PathBuf::from("/capsule/workspace"),
        capsule_home: PathBuf::from("/capsule/home"),
        capsule_tmp: PathBuf::from("/capsule/tmp"),
        config_dir: cfg_dir,
    };

    if let Err(err) = ResolvedPolicy::from_config(&cfg.policy, &vars, &StdFs) {
        eprintln!("policy path resolution error: {err}");
        return ExitCode::Usage;
    }

    println!("OK: {}", config_path.display());
    ExitCode::Pass
}
