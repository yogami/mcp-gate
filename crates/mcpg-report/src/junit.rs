//! JUnit XML report writer implementation.

use std::io::{self, Write};

use crate::{ReportWriter, RunRecord};

/// Report writer producing JUnit XML output for CI test runner integration.
#[derive(Debug, Clone, Copy, Default)]
pub struct JunitWriter;

impl ReportWriter for JunitWriter {
    fn name(&self) -> &'static str {
        "junit"
    }

    fn write(&self, run: &RunRecord, out: &mut dyn Write) -> io::Result<()> {
        let failures_count = run.protocol_violations.len();
        writeln!(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
        writeln!(
            out,
            "<testsuites name=\"mcp-gate\" tests=\"{}\" failures=\"{}\" errors=\"0\" time=\"0.000\">",
            1 + failures_count,
            failures_count
        )?;
        writeln!(
            out,
            "  <testsuite name=\"mcp-gate\" tests=\"{}\" failures=\"{}\" errors=\"0\" time=\"0.000\">",
            1 + failures_count,
            failures_count
        )?;
        writeln!(out, "    <properties>")?;
        writeln!(
            out,
            "      <property name=\"verdict\" value=\"{}\"/>",
            run.verdict.as_str()
        )?;
        writeln!(
            out,
            "      <property name=\"seed\" value=\"{}\"/>",
            run.seed
        )?;
        let escaped_claim = run
            .claim
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;");
        writeln!(
            out,
            "      <property name=\"claim\" value=\"{}\"/>",
            escaped_claim
        )?;
        writeln!(out, "    </properties>")?;
        writeln!(
            out,
            "    <testcase classname=\"mcpgate.lifecycle\" name=\"execution\" time=\"0.000\"/>"
        )?;

        for (rule_id, detail) in &run.protocol_violations {
            let escaped_detail = detail
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&apos;");
            writeln!(
                out,
                "    <testcase classname=\"mcpgate.violation\" name=\"{}\" time=\"0.000\">",
                rule_id
            )?;
            writeln!(
                out,
                "      <failure type=\"{}\" message=\"{}\">{}</failure>",
                rule_id, escaped_detail, escaped_detail
            )?;
            writeln!(out, "    </testcase>")?;
        }

        writeln!(out, "  </testsuite>")?;
        writeln!(out, "</testsuites>")?;
        Ok(())
    }
}
