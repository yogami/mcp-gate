//! Evidence NDJSON report writer.
//!
//! SPEC 3.6.3, REQ-SEED-002, REQ-CLAIM-001, REQ-CAN-005.

use std::io::{self, Write};

use serde::Serialize;

use crate::{ReportWriter, RunRecord};

/// Writes NDJSON evidence trace. Currently produces header and footer lines.
#[derive(Debug, Default, Clone, Copy)]
pub struct EvidenceWriter;

#[derive(Serialize)]
struct EvidenceHeader<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    seed: String,
    claim: &'a str,
    tool_name: &'static str,
}

#[derive(Serialize)]
struct EvidenceFooter<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    verdict: &'a str,
    findings_count: usize,
}

impl ReportWriter for EvidenceWriter {
    fn name(&self) -> &'static str {
        "evidence"
    }

    fn write(&self, run: &RunRecord, out: &mut dyn Write) -> io::Result<()> {
        let header = EvidenceHeader {
            record_type: "header",
            seed: run.seed.to_string(),
            claim: run.claim,
            tool_name: "mcp-gate",
        };
        serde_json::to_writer(&mut *out, &header).map_err(io::Error::other)?;
        writeln!(out)?;

        let footer = EvidenceFooter {
            record_type: "footer",
            verdict: run.verdict.as_str(),
            findings_count: 0,
        };
        serde_json::to_writer(&mut *out, &footer).map_err(io::Error::other)?;
        writeln!(out)?;

        Ok(())
    }
}
