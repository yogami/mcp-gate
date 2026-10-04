//! Implementation of `mcp-gate validate`.

use std::fs;
use std::path::Path;

use mcpg_app::config::load_str;
use mcpg_domain::verdict::ExitCode;

/// Validate a configuration file against the JSON schema and semantic rules.
pub fn execute(config_path: &Path) -> ExitCode {
    let content = match fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error reading config file {}: {e}", config_path.display());
            return ExitCode::Usage;
        }
    };

    match load_str(&content) {
        Ok(_) => {
            println!("OK: {}", config_path.display());
            ExitCode::Pass
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::Usage
        }
    }
}
