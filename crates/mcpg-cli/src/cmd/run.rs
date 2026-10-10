use mcpg_app::orchestrator::{AppOrchestrator, RunOptions, RunOrchestrator};
use mcpg_domain::verdict::ExitCode;
use mcpg_linux::sandbox::LinuxSandbox;
use mcpg_report::reporter::DefaultReporter;
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
        Ok(mut outcome) => {
            // Apply fail_on logic for security violations
            let mut fail = false;
            let fail_on_level = opts.fail_on.unwrap_or(mcpg_domain::config::model::FailOnLevel::Error);

            for (rule_id, _) in &outcome.violations {
                let default_level = mcpg_domain::rules::get_rule(rule_id)
                    .map(|r| r.default_level)
                    .unwrap_or(mcpg_domain::rules::FindingLevel::Warning);

                if fail_on_level.admits(default_level) {
                    fail = true;
                    break;
                }
            }

            if fail {
                let codes = vec![outcome.exit_code, ExitCode::FailSecurity];
                let final_code = mcpg_domain::verdict::combine(codes);
                outcome.exit_code = final_code;
                if final_code == ExitCode::FailSecurity {
                    outcome.verdict = mcpg_domain::verdict::Verdict::FailSecurity;
                }
            }

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
