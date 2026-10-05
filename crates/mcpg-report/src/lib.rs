//! Reporting adapters: SARIF 2.1.0, JUnit XML, NDJSON evidence, and console summary.
#![forbid(unsafe_code)]

use std::io::{self, Write};

use mcpg_domain::canary::registry::CanaryRegistry;
use mcpg_domain::seed::Seed;
use mcpg_domain::verdict::Verdict;

pub mod console;
pub mod evidence;

pub use console::ConsoleWriter;
pub use evidence::EvidenceWriter;

/// The normative claim sentence required on every report by REQ-CLAIM-001.
pub const CLAIM_SENTENCE: &str =
    "No finding at or above the configured threshold was observed in the scenarios that ran, with the observer coverage listed in the report.";

/// Complete outcome record of an mcp-gate run passed to report writers.
#[derive(Debug, Clone)]
pub struct RunRecord {
    pub seed: Seed,
    pub verdict: Verdict,
    pub registry: CanaryRegistry,
    pub claim: &'static str,
    pub protocol_violations: Vec<(String, String)>,
}

impl RunRecord {
    /// Construct a new RunRecord with the default claim sentence.
    pub fn new(
        seed: Seed,
        verdict: Verdict,
        registry: CanaryRegistry,
        protocol_violations: Vec<(String, String)>,
    ) -> Self {
        Self {
            seed,
            verdict,
            registry,
            claim: CLAIM_SENTENCE,
            protocol_violations,
        }
    }
}

/// Interface for generating run reports.
pub trait ReportWriter: Send + Sync {
    /// Returns the canonical name of the report writer.
    fn name(&self) -> &'static str;

    /// Render the run record to the given output stream.
    fn write(&self, run: &RunRecord, out: &mut dyn Write) -> io::Result<()>;
}

/// Returns a list of all active report writers.
pub fn all_writers() -> Vec<Box<dyn ReportWriter>> {
    vec![Box::new(ConsoleWriter), Box::new(EvidenceWriter::default())]
}
