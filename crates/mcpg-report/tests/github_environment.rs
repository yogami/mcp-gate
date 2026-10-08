use std::process::Command;

use mcpg_domain::canary::registry::CanaryRegistry;
use mcpg_domain::seed::Seed;
use mcpg_domain::verdict::Verdict;
use mcpg_report::{GithubWriter, ReportWriter, RunRecord};

fn record() -> RunRecord {
    RunRecord::new(
        Seed::from_bytes([7; 32]),
        Verdict::Pass,
        CanaryRegistry::new(),
        vec![],
    )
}

/// Environment-sensitive assertions run in a separate process, avoiding
/// set_var/remove_var races with other tests in the report test harness.
#[test]
fn github_writer_is_silent_outside_actions() {
    for value in [None, Some("false")] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "helper_github_writer_is_silent",
            "--ignored",
            "--nocapture",
        ]);
        command.env("MCPG_GITHUB_SILENCE_HELPER", "1");
        command.env(
            "GITHUB_STEP_SUMMARY",
            "/nonexistent/mcpg-must-not-open-summary/report.md",
        );
        match value {
            Some(value) => {
                command.env("GITHUB_ACTIONS", value);
            }
            None => {
                command.env_remove("GITHUB_ACTIONS");
            }
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "helper failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[ignore]
fn helper_github_writer_is_silent() {
    assert_eq!(
        std::env::var("MCPG_GITHUB_SILENCE_HELPER").as_deref(),
        Ok("1")
    );
    let mut output = Vec::new();
    GithubWriter.write(&record(), &mut output).unwrap();
    assert!(output.is_empty(), "unexpected GitHub console output");
}
