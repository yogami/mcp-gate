//! Evidence NDJSON report writer.
//!
//! SPEC 3.6.3, REQ-SEED-002, REQ-CLAIM-001, REQ-CAN-005.

use std::io::{self, Write};

use mcpg_domain::canary::catalogue::CanaryKind;
use serde::Serialize;

use crate::{ReportWriter, RunRecord};

/// Writes NDJSON evidence trace. Produces header, finding, and footer lines.
#[derive(Debug, Default, Clone, Copy)]
pub struct EvidenceWriter {
    pub include_values: bool,
}

impl EvidenceWriter {
    /// Construct a new EvidenceWriter specifying whether raw canary secrets are included.
    pub fn new(include_values: bool) -> Self {
        Self { include_values }
    }
}

#[derive(Serialize)]
struct EvidenceHeader<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    seed: String,
    claim: &'a str,
    tool_name: &'static str,
    canary_fps: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    canary_values: Option<Vec<CanarySecretEvidence<'a>>>,
}

#[derive(Serialize)]
struct CanarySecretEvidence<'a> {
    canary_id: &'a str,
    kind: &'static str,
    field: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
struct EvidenceCanaryRecord<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    canary_id: &'a str,
    kind: &'static str,
    field: &'a str,
    value: &'a str,
    fp: &'a str,
}

#[derive(Serialize)]
struct EvidenceFinding<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    rule_id: &'static str,
    reason: &'a str,
    raw: &'a str,
}

#[derive(Serialize)]
struct EvidenceFooter<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    verdict: &'a str,
    findings_count: usize,
}

fn kind_to_str(k: CanaryKind) -> &'static str {
    match k {
        CanaryKind::Ssh => "ssh",
        CanaryKind::Aws => "aws",
        CanaryKind::Gcloud => "gcloud",
        CanaryKind::Kube => "kube",
        CanaryKind::Docker => "docker",
        CanaryKind::GitCredentials => "git_credentials",
        CanaryKind::GhCli => "gh_cli",
        CanaryKind::Netrc => "netrc",
        CanaryKind::Npmrc => "npmrc",
        CanaryKind::Pypirc => "pypirc",
        CanaryKind::Dotenv => "dotenv",
        CanaryKind::Env => "env",
    }
}

impl ReportWriter for EvidenceWriter {
    fn name(&self) -> &'static str {
        "evidence"
    }

    fn write(&self, run: &RunRecord, out: &mut dyn Write) -> io::Result<()> {
        let canary_fps: Vec<&str> = run.registry.records.iter().map(|r| r.fp.as_str()).collect();

        let canary_values = if self.include_values {
            let mut list = Vec::new();
            for r in &run.registry.records {
                let k = kind_to_str(r.kind);
                for s in &r.secrets {
                    list.push(CanarySecretEvidence {
                        canary_id: r.id.as_str(),
                        kind: k,
                        field: s.field.as_str(),
                        value: s.value.as_str(),
                    });
                }
            }
            Some(list)
        } else {
            None
        };

        let header = EvidenceHeader {
            record_type: "header",
            seed: run.seed.to_string(),
            claim: run.claim,
            tool_name: "mcp-gate",
            canary_fps,
            canary_values,
        };
        serde_json::to_writer(&mut *out, &header).map_err(io::Error::other)?;
        writeln!(out)?;

        if self.include_values {
            for r in &run.registry.records {
                let k = kind_to_str(r.kind);
                for s in &r.secrets {
                    let entry = EvidenceCanaryRecord {
                        record_type: "canary_secret",
                        canary_id: r.id.as_str(),
                        kind: k,
                        field: s.field.as_str(),
                        value: s.value.as_str(),
                        fp: r.fp.as_str(),
                    };
                    serde_json::to_writer(&mut *out, &entry).map_err(io::Error::other)?;
                    writeln!(out)?;
                }
            }
        }

        for v in &run.protocol_violations {
            let finding = EvidenceFinding {
                record_type: "finding",
                rule_id: "MCPG900",
                reason: &v.0,
                raw: &v.1,
            };
            serde_json::to_writer(&mut *out, &finding).map_err(io::Error::other)?;
            writeln!(out)?;
        }

        let footer = EvidenceFooter {
            record_type: "footer",
            verdict: run.verdict.as_str(),
            findings_count: run.protocol_violations.len(),
        };
        serde_json::to_writer(&mut *out, &footer).map_err(io::Error::other)?;
        writeln!(out)?;

        Ok(())
    }
}
