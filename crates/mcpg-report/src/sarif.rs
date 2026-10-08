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
        let rules = vec![
            json!({
                "id": "MCPG001",
                "name": "canary-file-access",
                "shortDescription": { "text": "Server process accessed a decoy canary file or triggered an inotify tripwire on planted credentials" },
                "defaultConfiguration": { "level": "error" },
                "properties": { "security-severity": "9.0", "tags": ["CWE-552"] }
            }),
            json!({
                "id": "MCPG002",
                "name": "canary-value-leak",
                "shortDescription": { "text": "Decoy canary secret value observed in stdout, stderr, written files, child process arguments, or network traffic" },
                "defaultConfiguration": { "level": "error" },
                "properties": { "security-severity": "9.5", "tags": ["CWE-200"] }
            }),
            json!({
                "id": "MCPG003",
                "name": "read-outside-policy",
                "shortDescription": { "text": "File read access outside declared policy read paths and runtime baseline" },
                "defaultConfiguration": { "level": "error" },
                "properties": { "security-severity": "7.5", "tags": ["CWE-284"] }
            }),
            json!({
                "id": "MCPG004",
                "name": "write-outside-policy",
                "shortDescription": { "text": "File write, creation, truncation, or mutation outside declared policy write paths" },
                "defaultConfiguration": { "level": "error" },
                "properties": { "security-severity": "8.0", "tags": ["CWE-284"] }
            }),
            json!({
                "id": "MCPG005",
                "name": "path-traversal-escape",
                "shortDescription": { "text": "Path traversal escape via relative components, symlinks, or absolute paths targeting files outside declared directories during a tool call" },
                "defaultConfiguration": { "level": "error" },
                "properties": { "security-severity": "8.5", "tags": ["CWE-22"] }
            }),
            json!({
                "id": "MCPG006",
                "name": "unapproved-child-process",
                "shortDescription": { "text": "Execution of a binary or child process not permitted by policy allowed child binaries" },
                "defaultConfiguration": { "level": "error" },
                "properties": { "security-severity": "8.0", "tags": ["CWE-78"] }
            }),
            json!({
                "id": "MCPG007",
                "name": "unapproved-network",
                "shortDescription": { "text": "Network activity while allow_network is disabled" },
                "defaultConfiguration": { "level": "error" },
                "properties": { "security-severity": "7.5", "tags": ["CWE-200"] }
            }),
            json!({
                "id": "MCPG008",
                "name": "foreign-proc-access",
                "shortDescription": { "text": "Access to foreign /proc entries outside the capsule process tree" },
                "defaultConfiguration": { "level": "error" },
                "properties": { "security-severity": "8.0", "tags": ["CWE-214"] }
            }),
            json!({
                "id": "MCPG009",
                "name": "unapproved-unix-socket",
                "shortDescription": { "text": "Connection to a Unix domain socket not listed in policy allowed_unix_sockets" },
                "defaultConfiguration": { "level": "error" },
                "properties": { "security-severity": "9.0", "tags": ["CWE-269"] }
            }),
            json!({
                "id": "MCPG010",
                "name": "harness-tamper-attempt",
                "shortDescription": { "text": "Attempt to tamper with harness execution, send disallowed signals, or invoke restricted system calls" },
                "defaultConfiguration": { "level": "warning" },
                "properties": { "security-severity": "6.0", "tags": ["CWE-693"] }
            }),
            json!({
                "id": "MCPG011",
                "name": "sensitive-path-probe",
                "shortDescription": { "text": "Existence probing or stat on sensitive paths such as user home directories or decoy credential zones" },
                "defaultConfiguration": { "level": "note" },
                "properties": { "security-severity": "3.0", "tags": ["CWE-200"] }
            }),
            json!({
                "id": "MCPG012",
                "name": "process-escape",
                "shortDescription": { "text": "Subprocess or orphaned daemon outliving the test run after shutdown signals" },
                "defaultConfiguration": { "level": "warning" },
                "properties": { "security-severity": "5.0", "tags": ["CWE-404"] }
            }),
            json!({
                "id": "MCPG900",
                "name": "protocol-violation",
                "shortDescription": { "text": "MCP JSON-RPC protocol violation or framing error" },
                "defaultConfiguration": { "level": "warning" },
                "properties": { "security-severity": "0.0" }
            }),
        ];

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
                let level = match rule_id.as_str() {
                    "MCPG001" | "MCPG002" | "MCPG003" | "MCPG004" | "MCPG005" | "MCPG006"
                    | "MCPG007" | "MCPG008" | "MCPG009" => "error",
                    "MCPG011" => "note",
                    _ => "warning",
                };
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
