//! SARIF 2.1.0 report writer implementation.

use serde_json::json;
use std::io::{self, Write};

use crate::{ReportWriter, RunRecord};

/// Report writer producing OASIS SARIF 2.1.0 output for GitHub Code Scanning integration.
#[derive(Debug, Clone, Copy, Default)]
pub struct SarifWriter;

impl ReportWriter for SarifWriter {
    fn name(&self) -> &'static str {
        "sarif"
    }

    fn write(&self, run: &RunRecord, out: &mut dyn Write) -> io::Result<()> {
        let rules: Vec<serde_json::Value> = mcpg_domain::rules::RULES
            .iter()
            .map(|r| {
                let level_str = match r.default_level {
                    mcpg_domain::rules::FindingLevel::Note => "note",
                    mcpg_domain::rules::FindingLevel::Warning => "warning",
                    mcpg_domain::rules::FindingLevel::Error => "error",
                };
                let mut props = serde_json::Map::new();
                props.insert("security-severity".to_string(), json!(r.security_severity));
                if r.cwe != "n/a" {
                    props.insert("tags".to_string(), json!([r.cwe]));
                }
                json!({
                    "id": r.id,
                    "name": r.name,
                    "shortDescription": { "text": r.description },
                    "defaultConfiguration": { "level": level_str },
                    "properties": props
                })
            })
            .collect();

        let max_results = 5000;
        let truncated = run.protocol_violations.len() > max_results;
        let notifications = if truncated {
            vec![json!({
                "message": { "text": "Results truncated to maximum of 5,000 entries" },
                "level": "warning"
            })]
        } else {
            vec![]
        };

        let results: Vec<serde_json::Value> = run
            .protocol_violations
            .iter()
            .take(max_results)
            .map(|(rule_id, detail)| {
                let level = mcpg_domain::rules::get_rule(rule_id.as_str())
                    .map(|r| match r.default_level {
                        mcpg_domain::rules::FindingLevel::Note => "note",
                        mcpg_domain::rules::FindingLevel::Warning => "warning",
                        mcpg_domain::rules::FindingLevel::Error => "error",
                    })
                    .unwrap_or("warning");
                let mut hasher = sha2::Sha256::new();
                use sha2::Digest;
                hasher.update(b"mcpGate/v1:");
                hasher.update(rule_id.as_bytes());
                hasher.update(b":");
                hasher.update(detail.as_bytes());
                let fp_hash = format!("{:x}", hasher.finalize());

                let mut res = json!({
                    "ruleId": rule_id,
                    "level": level,
                    "message": { "text": detail },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "mcp-gate.yaml",
                                "uriBaseId": "SRCROOT"
                            },
                            "region": {
                                "startLine": 1
                            }
                        }
                    }],
                    "partialFingerprints": {
                        "mcpGate/v1": fp_hash
                    },
                    "properties": {
                        "occurrences": 1
                    }
                });
                if let Some(idx) = rules.iter().position(|r| r["id"] == *rule_id) {
                    res["ruleIndex"] = json!(idx);
                }
                res
            })
            .collect();

        let doc = json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "mcp-gate",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://github.com/mcp-gate/mcp-gate",
                        "rules": rules
                    }
                },
                "invocations": [{
                    "executionSuccessful": run.verdict != mcpg_domain::verdict::Verdict::Inconclusive,
                    "toolExecutionNotifications": notifications,
                    "properties": {
                        "verdict": run.verdict.as_str(),
                        "claim": run.claim,
                        "seed": run.seed.to_string()
                    }
                }],
                "results": results
            }]
        });

        let text = serde_json::to_string_pretty(&doc)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        out.write_all(text.as_bytes())?;
        out.write_all(b"\n")?;
        Ok(())
    }
}
