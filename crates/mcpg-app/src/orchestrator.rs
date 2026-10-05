//! Run orchestrator types and options.
//!
//! SPEC 1.3, 3.0: High-level test run configuration and execution tracking.

use std::path::PathBuf;

use mcpg_domain::config::model::FailOnLevel;
use mcpg_domain::host::Feature;
use mcpg_domain::mode::Mode;
use mcpg_domain::seed::Seed;
use mcpg_domain::verdict::{ExitCode, Verdict};

/// Level of console verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verbosity {
    Quiet,
    #[default]
    Normal,
    Verbose,
}

/// Options controlling capsule run execution.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub config_path: PathBuf,
    pub out_dir: PathBuf,
    pub sarif_path: Option<String>,
    pub junit_path: Option<String>,
    pub evidence_path: Option<String>,
    pub requested_mode: Mode,
    pub require: Vec<Feature>,
    pub fail_on: Option<FailOnLevel>,
    pub seed: Option<Seed>,
    pub timeout: Option<u64>,
    pub keep_capsule: bool,
    pub evidence_include_values: bool,
    pub no_annotations: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub verbosity: Verbosity,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            config_path: PathBuf::from("./mcp-gate.yaml"),
            out_dir: PathBuf::from("./mcp-gate-results"),
            sarif_path: None,
            junit_path: None,
            evidence_path: None,
            requested_mode: Mode::Enforce,
            require: Vec::new(),
            fail_on: None,
            seed: None,
            timeout: None,
            keep_capsule: false,
            evidence_include_values: false,
            no_annotations: false,
            quiet: false,
            verbose: false,
            verbosity: Verbosity::Normal,
        }
    }
}

/// Final summary outcome produced by run orchestration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    pub verdict: Verdict,
    pub exit_code: ExitCode,
    pub seed: Seed,
}

/// Port trait for executing a configured capsule run.
pub trait RunOrchestrator {
    /// Execute the run using the provided options and return the final process exit code.
    fn execute(&self, options: &RunOptions) -> ExitCode;
}
