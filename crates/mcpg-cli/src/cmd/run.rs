use std::path::Path;

use mcpg_domain::seed::Seed;
use mcpg_domain::verdict::ExitCode;

pub fn execute(_config: &Path, _seed: Option<Seed>) -> ExitCode {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Error: mcp-gate run requires Linux (exit 69)");
        ExitCode::UnsupportedHost
    }
    #[cfg(target_os = "linux")]
    {
        eprintln!("Error: mcp-gate run not implemented yet (exit 70)");
        ExitCode::Internal
    }
}
