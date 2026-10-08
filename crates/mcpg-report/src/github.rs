use std::env;
use std::fs::OpenOptions;
use std::io::{self, Write};

use crate::{ReportWriter, RunRecord};

pub struct GithubWriter;

fn escape_data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn escape_property(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
        .replace(':', "%3A")
        .replace(',', "%2C")
}

impl ReportWriter for GithubWriter {
    fn name(&self) -> &'static str {
        "github"
    }

    fn write(&self, run: &RunRecord, out: &mut dyn Write) -> io::Result<()> {
        let in_github_actions = env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true");

        if !in_github_actions {
            return Ok(());
        }

        // Print inline annotations with sanitized special characters
        for (rule, msg) in &run.protocol_violations {
            let escaped_rule = escape_property(rule);
            let escaped_msg = escape_data(msg);
            writeln!(
                out,
                "::error file=mcp-gate.yaml,title={escaped_rule}::{escaped_msg}"
            )?;
        }
        writeln!(out, "::notice title=mcp-gate Seed::{}", run.seed)?;
        writeln!(out, "::notice title=mcp-gate Claim::{}", run.claim)?;

        // Append to step summary if available
        if let Ok(summary_path) = env::var("GITHUB_STEP_SUMMARY") {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(summary_path)?;

            writeln!(file, "### mcp-gate: {}", run.verdict.as_str())?;
            writeln!(file, "Seed: `{}`", run.seed)?;
            writeln!(file)?;
            if !run.protocol_violations.is_empty() {
                writeln!(file, "| Rule | Message |")?;
                writeln!(file, "|---|---|")?;
                for (rule, msg) in &run.protocol_violations {
                    writeln!(file, "| {} | {} |", rule, msg)?;
                }
            }
        }

        Ok(())
    }
}
