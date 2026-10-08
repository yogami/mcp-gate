use crate::RunRecord;
use crate::{ConsoleWriter, EvidenceWriter, GithubWriter, JunitWriter, ReportWriter, SarifWriter};
use mcpg_app::orchestrator::RunOptions;
use mcpg_domain::verdict::ExitCode;
use std::fs;
use std::path::PathBuf;

pub struct DefaultReporter;

impl DefaultReporter {
    pub fn write_reports(&self, record: &RunRecord, opts: &RunOptions) -> Result<(), ExitCode> {
        if !opts.quiet {
            ConsoleWriter
                .write(record, &mut std::io::stdout())
                .map_err(|e| {
                    eprintln!("console write error: {e}");
                    ExitCode::Internal
                })?;
        }

        if !opts.no_annotations {
            GithubWriter
                .write(record, &mut std::io::stdout())
                .map_err(|e| {
                    eprintln!("github annotations write error: {e}");
                    ExitCode::Internal
                })?;
        }

        fs::create_dir_all(&opts.out_dir).map_err(|e| {
            eprintln!(
                "failed to create output dir {}: {e}",
                opts.out_dir.display()
            );
            ExitCode::Internal
        })?;

        // Evidence
        let ev_path = match opts.evidence_path.as_deref() {
            Some("-") => None,
            Some(p) => Some(PathBuf::from(p)),
            None => Some(opts.out_dir.join("evidence.ndjson")),
        };
        if let Some(p) = ev_path {
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    eprintln!("failed to create evidence parent dir: {e}");
                    ExitCode::Internal
                })?;
            }
            let mut file = fs::File::create(&p).map_err(|e| {
                eprintln!("failed to create evidence file {}: {e}", p.display());
                ExitCode::Internal
            })?;
            let writer = EvidenceWriter::new(opts.evidence_include_values);
            writer.write(record, &mut file).map_err(|e| {
                eprintln!("failed to write evidence {}: {e}", p.display());
                ExitCode::Internal
            })?;
        }

        // SARIF
        let sarif_path = match opts.sarif_path.as_deref() {
            Some("-") => None,
            Some(p) => Some(PathBuf::from(p)),
            None => Some(opts.out_dir.join("mcp-gate.sarif")),
        };
        if let Some(p) = sarif_path {
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    eprintln!("failed to create sarif parent dir: {e}");
                    ExitCode::Internal
                })?;
            }
            let mut file = fs::File::create(&p).map_err(|e| {
                eprintln!("failed to create sarif file {}: {e}", p.display());
                ExitCode::Internal
            })?;
            SarifWriter.write(record, &mut file).map_err(|e| {
                eprintln!("failed to write sarif {}: {e}", p.display());
                ExitCode::Internal
            })?;
        }

        // JUnit
        let junit_path = match opts.junit_path.as_deref() {
            Some("-") => None,
            Some(p) => Some(PathBuf::from(p)),
            None => Some(opts.out_dir.join("mcp-gate.junit.xml")),
        };
        if let Some(p) = junit_path {
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    eprintln!("failed to create junit parent dir: {e}");
                    ExitCode::Internal
                })?;
            }
            let mut file = fs::File::create(&p).map_err(|e| {
                eprintln!("failed to create junit file {}: {e}", p.display());
                ExitCode::Internal
            })?;
            JunitWriter.write(record, &mut file).map_err(|e| {
                eprintln!("failed to write junit {}: {e}", p.display());
                ExitCode::Internal
            })?;
        }

        Ok(())
    }
}
