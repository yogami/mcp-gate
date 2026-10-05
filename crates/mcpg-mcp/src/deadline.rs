//! Deadline tracking and timeout enforcement.
//!
//! SPEC 2.2 and 2.5: Enforces startup, call, and total run timeouts.
//! Timeouts yield inconclusive verdicts and exit code 3.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mcpg_app::ports::Clock;
use mcpg_domain::config::{LimitsConfig, ScenarioConfig};
use mcpg_domain::verdict::{ExitCode, Verdict};

use crate::client::{DriverError, McpClient};
use crate::transport::McpTransport;

/// Monotonic deadline tracker for execution stages.
#[derive(Clone)]
pub struct DeadlineTracker {
    clock: Arc<dyn Clock>,
    limits: LimitsConfig,
    total_deadline: Instant,
}

impl DeadlineTracker {
    /// Create a deadline tracker from clock and limits configuration.
    pub fn new(clock: Arc<dyn Clock>, limits: LimitsConfig) -> Self {
        let now = clock.now();
        let total_deadline = now + Duration::from_secs(limits.total_timeout_s);
        Self {
            clock,
            limits,
            total_deadline,
        }
    }

    /// Access the underlying clock.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Access the configured limits.
    pub fn limits(&self) -> &LimitsConfig {
        &self.limits
    }

    /// Return the total deadline instant.
    pub fn total_deadline(&self) -> Instant {
        self.total_deadline
    }

    /// Verify startup did not exceed the startup timeout.
    pub fn check_startup(&self, start: Instant) -> Result<(), DriverError> {
        let elapsed = self.clock.now().saturating_duration_since(start);
        if elapsed >= Duration::from_secs(self.limits.startup_timeout_s) {
            return Err(DriverError::Inconclusive(format!(
                "startup timeout: exceeded {}s limit",
                self.limits.startup_timeout_s
            )));
        }
        Ok(())
    }

    /// Verify a tool call did not exceed the call timeout.
    pub fn check_call(&self, start: Instant, limit_s: Option<u64>) -> Result<(), DriverError> {
        let elapsed = self.clock.now().saturating_duration_since(start);
        let limit = limit_s.unwrap_or(self.limits.call_timeout_s);
        if elapsed >= Duration::from_secs(limit) {
            return Err(DriverError::Inconclusive(format!(
                "call timeout: exceeded {}s limit",
                limit
            )));
        }
        Ok(())
    }

    /// True if total execution duration exceeded total_timeout_s.
    pub fn is_total_expired(&self) -> bool {
        self.clock.now() >= self.total_deadline
    }

    /// Check whether total execution duration exceeded the limit.
    pub fn check_total(&self) -> Result<(), DriverError> {
        if self.is_total_expired() {
            return Err(DriverError::Inconclusive(format!(
                "total timeout: exceeded {}s limit",
                self.limits.total_timeout_s
            )));
        }
        Ok(())
    }
}

/// Outcome report from running a batch of scenarios under deadlines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenariosReport {
    pub completed: Vec<String>,
    pub skipped: Vec<String>,
    pub verdict: Verdict,
    pub exit_code: ExitCode,
}

fn execute_single_scenario<T: McpTransport>(
    client: &mut McpClient<T>,
    tracker: &DeadlineTracker,
    scenario: &ScenarioConfig,
) -> Result<bool, DriverError> {
    let call_start = tracker.clock().now();
    let outcome = match client.call_tool(&scenario.tool, &scenario.arguments) {
        Ok(res) => {
            tracker.check_call(call_start, scenario.timeout_s)?;
            mcpg_app::scenario::CallOutcome::from(res)
        }
        Err(DriverError::Protocol(msg)) => mcpg_app::scenario::CallOutcome::protocol_error(msg),
        Err(e) => return Err(e),
    };

    let expect = scenario.expect.as_ref().cloned().unwrap_or_default();
    let check_res = mcpg_app::scenario::check(&expect, &outcome);
    Ok(check_res.passed)
}

fn resolve_report_verdict(inconclusive: bool, failure: bool) -> (Verdict, ExitCode) {
    if inconclusive {
        (Verdict::Inconclusive, ExitCode::Inconclusive)
    } else if failure {
        (Verdict::FailFunctional, ExitCode::FailFunctional)
    } else {
        (Verdict::Pass, ExitCode::Pass)
    }
}

/// Run scenarios sequentially, honoring call deadlines and total run limits.
pub fn run_scenarios<T: McpTransport>(
    client: &mut McpClient<T>,
    tracker: &DeadlineTracker,
    scenarios: &[ScenarioConfig],
) -> ScenariosReport {
    let mut completed = Vec::new();
    let mut skipped = Vec::new();
    let mut has_failure = false;
    let mut is_inconclusive = false;

    for (i, scenario) in scenarios.iter().enumerate() {
        if tracker.is_total_expired() {
            for remaining in &scenarios[i..] {
                skipped.push(remaining.id.clone());
            }
            is_inconclusive = true;
            break;
        }

        completed.push(scenario.id.clone());
        match execute_single_scenario(client, tracker, scenario) {
            Ok(passed) => {
                if !passed {
                    has_failure = true;
                }
            }
            Err(_) => {
                is_inconclusive = true;
            }
        }
    }

    let (verdict, exit_code) = resolve_report_verdict(is_inconclusive, has_failure);
    ScenariosReport {
        completed,
        skipped,
        verdict,
        exit_code,
    }
}
