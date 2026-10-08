use mcpg_app::orchestrator::{AppOrchestrator, RunOptions, RunOrchestrator};
use mcpg_linux::sandbox::LinuxSandbox;
use mcpg_report::reporter::DefaultReporter;
use mcpg_domain::verdict::ExitCode;
use mcpg_report::RunRecord;

pub fn execute(opts: &RunOptions) -> ExitCode {
    if !cfg!(target_os = "linux") {
        eprintln!("Error: mcp-gate run requires Linux (exit 69)");
        return ExitCode::UnsupportedHost;
    }
    
    let orchestrator = AppOrchestrator {
        sandbox: Box::new(LinuxSandbox::new()),
    };

    match orchestrator.execute(opts) {
        Ok(outcome) => {
            let record = RunRecord::new(
                outcome.seed,
                outcome.verdict,
                outcome.registry,
                outcome.violations,
            );
            let reporter = DefaultReporter;
            if let Err(e) = reporter.write_reports(&record, opts) {
                return e;
            }
            outcome.exit_code
        }
        Err(e) => e,
    }
}
