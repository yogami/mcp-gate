//! Console summary report writer.
//!
//! SPEC 1.4, REQ-SEED-002, REQ-CLAIM-001, REQ-CAN-005.

use std::io::{self, Write};

use crate::{ReportWriter, RunRecord};

/// Writes human-readable run summary to standard console stream.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConsoleWriter;

impl ReportWriter for ConsoleWriter {
    fn name(&self) -> &'static str {
        "console"
    }

    fn write(&self, run: &RunRecord, out: &mut dyn Write) -> io::Result<()> {
        let seed_hex = run.seed.to_string();
        writeln!(
            out,
            "mcp-gate: seed {seed_hex} (replay with --seed {seed_hex})"
        )?;
        writeln!(out, "verdict: {}", run.verdict)?;
        writeln!(out, "claim: {}", run.claim)?;
        writeln!(out, "canaries: {} planted", run.registry.records.len())?;
        Ok(())
    }
}
