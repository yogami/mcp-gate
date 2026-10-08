use crate::phase::PhaseCursor;
use crate::scenario::CallOutcome;
use mcpg_domain::config::model::{Config, ScenarioConfig};
use mcpg_domain::leak::{LeakMatch, LeakScanner};
use mcpg_domain::verdict::{ExitCode, Verdict};
use mcpg_mcp::client::{DriverError, McpClient};
use mcpg_mcp::deadline::DeadlineTracker;
use mcpg_mcp::transport::McpTransport;
use std::io::{self, Read};
use std::sync::Mutex;

pub fn execute_single_scenario<T: McpTransport>(
    client: &mut McpClient<T>,
    _tracker: &DeadlineTracker,
    scenario: &ScenarioConfig,
    phase: &PhaseCursor,
    tools: &std::collections::HashMap<String, mcpg_mcp::tools::ToolDef>,
) -> Result<bool, DriverError> {
    let _ = phase.start_scenario(&scenario.id);
    let outcome = if let Some(tool_def) = tools.get(&scenario.tool) {
        let is_valid = if tool_def.input_schema.is_null() {
            true
        } else if let Ok(validator) = jsonschema::validator_for(&tool_def.input_schema) {
            validator.is_valid(&scenario.arguments)
        } else {
            false
        };
        if is_valid {
            match client.call_tool_with_timeout(
                &scenario.tool,
                &scenario.arguments,
                scenario.timeout_s,
            ) {
                Ok(res) => CallOutcome::from(res),
                Err(DriverError::Protocol(msg)) => CallOutcome::protocol_error(msg),
                Err(e) => {
                    let _ = phase.end_scenario();
                    return Err(e);
                }
            }
        } else {
            CallOutcome::protocol_error("arguments failed schema validation")
        }
    } else {
        CallOutcome::protocol_error("tool not found in tools/list")
    };
    let expect = scenario.expect.clone().unwrap_or_default();
    let passed = crate::scenario::check(&expect, &outcome).passed;
    let _ = phase.end_scenario();
    Ok(passed)
}

pub fn handle_scenario_step<T: McpTransport>(
    client: &mut McpClient<T>,
    tracker: &DeadlineTracker,
    scenario: &ScenarioConfig,
    phase: &PhaseCursor,
    has_failure: &mut bool,
    tools: &std::collections::HashMap<String, mcpg_mcp::tools::ToolDef>,
) -> bool {
    match execute_single_scenario(client, tracker, scenario, phase, tools) {
        Ok(passed) => {
            if !passed {
                *has_failure = true;
            }
            true
        }
        Err(_) => false,
    }
}

pub fn drive_scenarios_loop<T: McpTransport>(
    client: &mut McpClient<T>,
    tracker: &DeadlineTracker,
    scenarios: &[ScenarioConfig],
    phase: &PhaseCursor,
    tools: &std::collections::HashMap<String, mcpg_mcp::tools::ToolDef>,
) -> (Verdict, ExitCode) {
    let mut codes = vec![ExitCode::Pass];
    for scenario in scenarios {
        if tracker.is_total_expired() {
            codes.push(ExitCode::Inconclusive);
            break;
        }
        let mut has_failure = false;
        let ok = handle_scenario_step(client, tracker, scenario, phase, &mut has_failure, tools);
        if has_failure {
            codes.push(ExitCode::FailFunctional);
        }
        if !ok {
            codes.push(ExitCode::Inconclusive);
            break;
        }
    }
    let final_code = mcpg_domain::verdict::combine(codes);
    let final_verdict = match final_code {
        ExitCode::Pass => Verdict::Pass,
        ExitCode::FailFunctional => Verdict::FailFunctional,
        ExitCode::FailSecurity => Verdict::FailSecurity,
        _ => Verdict::Inconclusive,
    };
    (final_verdict, final_code)
}

pub fn drive_session<T: McpTransport>(
    mut client: McpClient<T>,
    cfg: &Config,
    tracker: &DeadlineTracker,
    phase: &PhaseCursor,
) -> (Verdict, ExitCode, Vec<(String, String)>) {
    let _ = phase.advance_to_handshake();
    if client
        .initialize(
            &cfg.server.protocol_versions,
            cfg.server.client.roots.clone(),
        )
        .is_err()
    {
        return (
            Verdict::Inconclusive,
            ExitCode::Inconclusive,
            client
                .take_violations()
                .into_iter()
                .map(|v| (v.reason, v.raw))
                .collect(),
        );
    }

    let tools_list = match client.list_tools() {
        Ok(t) => t,
        Err(_) => {
            return (
                Verdict::Inconclusive,
                ExitCode::Inconclusive,
                client
                    .take_violations()
                    .into_iter()
                    .map(|v| (v.reason, v.raw))
                    .collect(),
            );
        }
    };
    let mut tools = std::collections::HashMap::new();
    for t in tools_list {
        tools.insert(t.name.clone(), t);
    }

    let (v, e) = drive_scenarios_loop(&mut client, tracker, &cfg.scenarios, phase, &tools);
    (
        v,
        e,
        client
            .take_violations()
            .into_iter()
            .map(|v| (v.reason, v.raw))
            .collect(),
    )
}

pub struct ScanningReader<R> {
    inner: R,
    scanner: std::sync::Arc<LeakScanner>,
    channel_name: String,
    leaks: std::sync::Arc<Mutex<Vec<(LeakMatch, String)>>>,
    phase: PhaseCursor,
    tail: Vec<u8>,
}

impl<R> ScanningReader<R> {
    pub fn new(
        inner: R,
        scanner: std::sync::Arc<LeakScanner>,
        channel_name: &str,
        leaks: std::sync::Arc<Mutex<Vec<(LeakMatch, String)>>>,
        phase: PhaseCursor,
    ) -> Self {
        Self {
            inner,
            scanner,
            channel_name: channel_name.to_string(),
            leaks,
            phase,
            tail: Vec::new(),
        }
    }
}

impl<R: Read> Read for ScanningReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            let mut chunk = self.tail.clone();
            chunk.extend_from_slice(&buf[..n]);

            let hits = self.scanner.scan_bytes(&chunk, &self.channel_name);
            if !hits.is_empty() {
                if let Ok(mut guard) = self.leaks.lock() {
                    let current_phase = self.phase.current().to_string();
                    for hit in hits {
                        if !guard.iter().any(|(h, _)| h == &hit) {
                            guard.push((hit, current_phase.clone()));
                        }
                    }
                }
            }

            self.tail.clear();
            let start = chunk.len().saturating_sub(256);
            self.tail.extend_from_slice(&chunk[start..]);
        }
        Ok(n)
    }
}
