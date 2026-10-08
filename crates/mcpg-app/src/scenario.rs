//! Scenario expectation evaluation.
//!
//! SPEC 2.2 and REQ-EXIT-002: Evaluate tool call outcomes against declared
//! scenario expectations. Mismatches yield exit code 2 (FailFunctional).

use mcpg_domain::config::ScenarioExpect;
use mcpg_domain::verdict::ExitCode;
use serde::{Deserialize, Serialize};

/// Type alias for scenario expectations.
pub type Expect = ScenarioExpect;

/// Canonical tool invocation outcome classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    Success,
    ToolError,
    ProtocolError,
}

/// Observed result from invoking a tool scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallOutcome {
    pub kind: OutcomeKind,
    pub content: String,
}

impl CallOutcome {
    /// Create a successful outcome with content.
    pub fn success(content: impl Into<String>) -> Self {
        Self {
            kind: OutcomeKind::Success,
            content: content.into(),
        }
    }

    /// Create an outcome indicating a tool-level failure.
    pub fn tool_error(content: impl Into<String>) -> Self {
        Self {
            kind: OutcomeKind::ToolError,
            content: content.into(),
        }
    }

    /// Create an outcome indicating a protocol or JSON-RPC failure.
    pub fn protocol_error(content: impl Into<String>) -> Self {
        Self {
            kind: OutcomeKind::ProtocolError,
            content: content.into(),
        }
    }

    /// Map from is_error boolean flag to outcome kind.
    pub fn from_tool_result(is_error: bool, content: impl Into<String>) -> Self {
        if is_error {
            Self::tool_error(content)
        } else {
            Self::success(content)
        }
    }

    /// Map from a JSON-RPC error message.
    pub fn from_jsonrpc_error(message: impl Into<String>) -> Self {
        Self::protocol_error(message)
    }
}

/// Evaluation verdict for a single scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioResult {
    pub passed: bool,
    pub exit_code: ExitCode,
    pub reason: Option<String>,
}

impl ScenarioResult {
    /// Create a passing result.
    pub fn pass() -> Self {
        Self {
            passed: true,
            exit_code: ExitCode::Pass,
            reason: None,
        }
    }

    /// Create a failing functional result with a reason.
    pub fn fail(reason: impl Into<String>) -> Self {
        Self {
            passed: false,
            exit_code: ExitCode::FailFunctional,
            reason: Some(reason.into()),
        }
    }

    /// True if the scenario satisfied all expectations.
    pub fn is_pass(&self) -> bool {
        self.passed
    }

    /// Process exit code associated with this scenario outcome.
    pub fn exit_code(&self) -> ExitCode {
        self.exit_code
    }
}

fn outcome_matches(expected: Option<&str>, actual: OutcomeKind) -> bool {
    match expected {
        None | Some("success") => actual == OutcomeKind::Success,
        Some("tool_error") => actual == OutcomeKind::ToolError,
        Some("protocol_error") => actual == OutcomeKind::ProtocolError,
        Some("any") => true,
        Some(_) => false,
    }
}

fn check_contains(content: &str, substrings: &[String]) -> Result<(), String> {
    for needle in substrings {
        if !content.contains(needle) {
            return Err(format!("missing required content substring: {needle}"));
        }
    }
    Ok(())
}

fn check_not_contains(content: &str, substrings: &[String]) -> Result<(), String> {
    for needle in substrings {
        if content.contains(needle) {
            return Err(format!("unexpected content substring present: {needle}"));
        }
    }
    Ok(())
}

/// Check an observed tool outcome against scenario expectations.
pub fn check(expect: &Expect, outcome: &CallOutcome) -> ScenarioResult {
    if !outcome_matches(expect.outcome.as_deref(), outcome.kind) {
        return ScenarioResult::fail(format!(
            "outcome mismatch: expected {:?}, got {:?}",
            expect.outcome.as_deref().unwrap_or("success"),
            outcome.kind
        ));
    }

    if let Err(e) = check_contains(&outcome.content, &expect.content_contains) {
        return ScenarioResult::fail(e);
    }

    if let Err(e) = check_not_contains(&outcome.content, &expect.content_not_contains) {
        return ScenarioResult::fail(e);
    }

    ScenarioResult::pass()
}

impl From<mcpg_mcp::tools::ToolCallResult> for CallOutcome {
    fn from(res: mcpg_mcp::tools::ToolCallResult) -> Self {
        let text = res
            .content
            .into_iter()
            .filter_map(|c| {
                c.get("text")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .collect::<Vec<_>>()
            .join("\n");
        CallOutcome::from_tool_result(res.is_error, text)
    }
}
