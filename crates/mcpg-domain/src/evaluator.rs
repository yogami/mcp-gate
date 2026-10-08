//! Policy evaluator implementing the normative decision order from SPEC 3.4.
//!
//! Pure, deterministic evaluation of observed events into security findings.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::canary::catalogue::{CanaryKind, CanaryTier};
use crate::canary::registry::CanaryRegistry;
use crate::event::{AccessKind, Event, EventKind};
use crate::policy::resolve::ResolvedPolicy;

/// Finding severity level as defined in SPEC 3.4.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingLevel {
    Note,
    Warning,
    Error,
}

impl FindingLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Note => "note",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// A policy boundary violation finding produced by the evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub level: FindingLevel,
    pub message: String,
    pub normalized_target: String,
    pub phase_kind: String,
    pub fingerprint: String,
    pub occurrences: u32,
    pub primary_event: Option<Event>,
    pub canary_kind: Option<CanaryKind>,
    pub canary_fp: Option<String>,
}

/// Evaluation context providing run configuration and metadata.
#[derive(Debug, Clone)]
pub struct EvalContext {
    pub server_name: String,
    pub run_dir: PathBuf,
    pub declared_use: Vec<CanaryKind>,
    pub scenario_allowances: HashMap<String, Vec<CanaryKind>>,
    pub tool_call_arguments: Option<String>,
}

fn extract_phase_kind(phase: &str) -> String {
    phase.to_string()
}

fn normalize_target(target: &str, run_dir: &Path) -> String {
    let run_dir_str = run_dir.to_string_lossy();
    let res = if !run_dir_str.is_empty() && target.contains(&*run_dir_str) {
        target.replace(&*run_dir_str, "<CAPSULE>")
    } else {
        target.to_string()
    };

    if res.starts_with("proc:foreign:") {
        "proc:foreign:<PID>".to_string()
    } else {
        res
    }
}

fn compute_fingerprint(
    rule_id: &str,
    server_name: &str,
    normalized_target: &str,
    phase_kind: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mcpg/v1");
    hasher.update(rule_id.as_bytes());
    hasher.update(server_name.as_bytes());
    hasher.update(normalized_target.as_bytes());
    hasher.update(phase_kind.as_bytes());
    format!("{:x}", hasher.finalize())
}

struct RawFinding {
    rule_id: &'static str,
    level: FindingLevel,
    message: String,
    raw_target: String,
    canary_kind: Option<CanaryKind>,
    canary_fp: Option<String>,
}

fn evaluate_single_event(
    event: &Event,
    policy: &ResolvedPolicy,
    canaries: &CanaryRegistry,
    ctx: &EvalContext,
) -> Option<RawFinding> {
    // 1. leak.match produces MCPG002
    if event.kind == EventKind::LeakMatch {
        return Some(RawFinding {
            rule_id: "MCPG002",
            level: FindingLevel::Error,
            message: event
                .message
                .clone()
                .unwrap_or_else(|| "Canary secret value leak detected".to_string()),
            raw_target: event.target.clone().unwrap_or_else(|| "stream".to_string()),
            canary_kind: event.canary_kind,
            canary_fp: None,
        });
    }

    // 2. Event touches a canary or canary.inotify: MCPG001
    let matched_canary = if event.kind == EventKind::CanaryInotify {
        event
            .canary_kind
            .and_then(|k| canaries.records.iter().find(|r| r.kind == k))
    } else if let Some((dev, ino)) = event.dev_ino {
        canaries.find_by_dev_ino(dev, ino)
    } else if let Some(resolved) = &event.resolved {
        canaries.find_by_path(resolved)
    } else {
        None
    };

    if let Some(record) = matched_canary {
        let is_declared = ctx.declared_use.contains(&record.kind);
        let is_scenario_allowed = if let Some(scenario_id) = event.phase.strip_prefix("scenario:") {
            ctx.scenario_allowances
                .get(scenario_id)
                .is_some_and(|allowlist| allowlist.contains(&record.kind))
        } else {
            false
        };

        let level = if is_declared || is_scenario_allowed {
            FindingLevel::Note
        } else {
            match record.tier {
                CanaryTier::A | CanaryTier::EgressOnly => FindingLevel::Error,
                CanaryTier::B => FindingLevel::Warning,
            }
        };

        return Some(RawFinding {
            rule_id: "MCPG001",
            level,
            message: format!("Canary file access detected for {:?}", record.kind),
            raw_target: record.path.to_string_lossy().into_owned(),
            canary_kind: Some(record.kind),
            canary_fp: Some(record.fp.clone()),
        });
    }

    // 3. Path maps to proc:foreign:* produces MCPG008
    if let Some(resolved) = &event.resolved {
        let path_str = resolved.to_string_lossy();
        if path_str.starts_with("proc:foreign:") {
            return Some(RawFinding {
                rule_id: "MCPG008",
                level: FindingLevel::Error,
                message: format!("Access to foreign process entry: {path_str}"),
                raw_target: path_str.into_owned(),
                canary_kind: None,
                canary_fp: None,
            });
        }
    }

    // 4 & 5. File open / mutate
    if event.kind == EventKind::FsOpen || event.kind == EventKind::FsMutate {
        if let Some(resolved) = &event.resolved {
            let is_write =
                event.access == Some(AccessKind::Write) || event.kind == EventKind::FsMutate;
            let outside = if is_write {
                !policy.is_write_allowed(resolved)
            } else {
                !policy.is_read_allowed(resolved)
            };

            if outside {
                let is_traversal = event.escaped_via.is_some() || {
                    if let Some(args) = &ctx.tool_call_arguments {
                        let path_name = resolved
                            .file_name()
                            .map(|n| n.to_string_lossy())
                            .unwrap_or_default();
                        !path_name.is_empty() && args.contains(&*path_name)
                    } else {
                        false
                    }
                };

                let rule_id = if is_traversal {
                    "MCPG005"
                } else if is_write {
                    "MCPG004"
                } else {
                    "MCPG003"
                };

                return Some(RawFinding {
                    rule_id,
                    level: FindingLevel::Error,
                    message: format!(
                        "File {} outside declared policy: {}",
                        if is_write { "write" } else { "read" },
                        resolved.display()
                    ),
                    raw_target: resolved.to_string_lossy().into_owned(),
                    canary_kind: None,
                    canary_fp: None,
                });
            }
        }
    }

    // 6. proc.exec outside allowed_child_binaries: MCPG006
    if event.kind == EventKind::ProcExec {
        let is_allowed = policy.is_exec_allowed(&event.exe, false);
        if !is_allowed {
            return Some(RawFinding {
                rule_id: "MCPG006",
                level: FindingLevel::Error,
                message: format!("Unapproved child process executed: {}", event.exe.display()),
                raw_target: event.exe.to_string_lossy().into_owned(),
                canary_kind: None,
                canary_fp: None,
            });
        }
    }

    // 7. net.* with allow_network: false produces MCPG007
    if matches!(
        event.kind,
        EventKind::NetSocket | EventKind::NetConnect | EventKind::NetSend | EventKind::NetBind
    ) && !policy.allow_network
    {
        return Some(RawFinding {
            rule_id: "MCPG007",
            level: FindingLevel::Error,
            message: "Network activity attempted while allow_network is false".to_string(),
            raw_target: event
                .target
                .clone()
                .unwrap_or_else(|| "network".to_string()),
            canary_kind: None,
            canary_fp: None,
        });
    }

    // 8. unix.connect outside allowed_unix_sockets: MCPG009
    if event.kind == EventKind::UnixConnect {
        let path_str = event
            .resolved
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .or_else(|| event.target.clone())
            .unwrap_or_default();
        let allowed = policy.allowed_unix_sockets.iter().any(|s| s == &path_str);
        if !allowed {
            return Some(RawFinding {
                rule_id: "MCPG009",
                level: FindingLevel::Error,
                message: format!("Connection to unapproved Unix socket: {path_str}"),
                raw_target: path_str,
                canary_kind: None,
                canary_fp: None,
            });
        }
    }

    // 9. tamper.denied or signal.send to foreign target: MCPG010
    if event.kind == EventKind::TamperDenied || event.kind == EventKind::SignalSend {
        return Some(RawFinding {
            rule_id: "MCPG010",
            level: FindingLevel::Warning,
            message: event
                .message
                .clone()
                .unwrap_or_else(|| "Harness tamper attempt detected".to_string()),
            raw_target: "harness".to_string(),
            canary_kind: None,
            canary_fp: None,
        });
    }

    // 10. fs.stat on sensitive path: MCPG011
    if event.kind == EventKind::FsStat {
        let is_sensitive = event.resolved.as_ref().is_some_and(|p| {
            let s = p.to_string_lossy();
            s.contains("/.ssh") || s.contains("/.aws") || s.contains("/home")
        });
        if is_sensitive {
            return Some(RawFinding {
                rule_id: "MCPG011",
                level: FindingLevel::Note,
                message: "Sensitive path probe detected".to_string(),
                raw_target: event
                    .resolved
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                canary_kind: None,
                canary_fp: None,
            });
        }
    }

    // 11. proc.orphan: MCPG012
    if event.kind == EventKind::ProcOrphan {
        return Some(RawFinding {
            rule_id: "MCPG012",
            level: FindingLevel::Warning,
            message: "Process escape: orphan process survived run".to_string(),
            raw_target: "capsule".to_string(),
            canary_kind: None,
            canary_fp: None,
        });
    }

    // 12. proto.violation: MCPG900
    if event.kind == EventKind::ProtoViolation {
        return Some(RawFinding {
            rule_id: "MCPG900",
            level: FindingLevel::Warning,
            message: event
                .message
                .clone()
                .unwrap_or_else(|| "Protocol violation".to_string()),
            raw_target: "stdout".to_string(),
            canary_kind: None,
            canary_fp: None,
        });
    }

    None
}

/// Pure evaluation function mapping observed events to findings.
pub fn evaluate(
    events: &[Event],
    policy: &ResolvedPolicy,
    canaries: &CanaryRegistry,
    ctx: &EvalContext,
) -> Vec<Finding> {
    struct Group {
        raw: RawFinding,
        phase_kind: String,
        normalized_target: String,
        primary_event: Event,
        count: u32,
    }

    let mut groups: Vec<Group> = Vec::new();

    for ev in events {
        if let Some(raw) = evaluate_single_event(ev, policy, canaries, ctx) {
            let phase_kind = extract_phase_kind(&ev.phase);
            let normalized_target = normalize_target(&raw.raw_target, &ctx.run_dir);

            if let Some(existing) = groups.iter_mut().find(|g| {
                g.raw.rule_id == raw.rule_id
                    && g.phase_kind == phase_kind
                    && g.normalized_target == normalized_target
            }) {
                existing.count += 1;
            } else {
                groups.push(Group {
                    raw,
                    phase_kind,
                    normalized_target,
                    primary_event: ev.clone(),
                    count: 1,
                });
            }
        }
    }

    let mut findings: Vec<Finding> = groups
        .into_iter()
        .map(|g| {
            let fp = compute_fingerprint(
                g.raw.rule_id,
                &ctx.server_name,
                &g.normalized_target,
                &g.phase_kind,
            );
            Finding {
                rule_id: g.raw.rule_id.to_string(),
                level: g.raw.level,
                message: g.raw.message,
                normalized_target: g.normalized_target,
                phase_kind: g.phase_kind,
                fingerprint: fp,
                occurrences: g.count,
                primary_event: Some(g.primary_event),
                canary_kind: g.raw.canary_kind,
                canary_fp: g.raw.canary_fp,
            }
        })
        .collect();

    // Deterministic sorting: level (descending: Error > Warning > Note), then rule_id, then fingerprint
    findings.sort_by(|a, b| {
        b.level
            .cmp(&a.level)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.fingerprint.cmp(&b.fingerprint))
    });

    findings
}
