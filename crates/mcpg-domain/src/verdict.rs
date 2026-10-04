//! Verdict evaluation and process exit code resolution.
//!
//! SPEC 2.5: Precedence order when several apply: `64 > 69 > 70 > 1 > 2 > 3 > 0`.
//! A security finding outranks a crash, because a crash after a canary read is still
//! a canary read (REQ-EXIT-002).

use serde::{Deserialize, Serialize};

/// Process exit codes produced by mcp-gate runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum ExitCode {
    /// No finding at or above fail_on, all scenarios met their expectations.
    Pass = 0,
    /// At least one finding at or above fail_on.
    FailSecurity = 1,
    /// No security finding, but a scenario expectation failed.
    FailFunctional = 2,
    /// Server crashed, handshake failed, or a timeout hit before all scenarios ran.
    Inconclusive = 3,
    /// Bad CLI arguments or invalid config (sysexits EX_USAGE).
    Usage = 64,
    /// Required host isolation features unavailable or unsupported platform (EX_UNAVAILABLE).
    UnsupportedHost = 69,
    /// Internal software error in mcp-gate (EX_SOFTWARE).
    Internal = 70,
}

impl ExitCode {
    /// Numeric exit code value as integer.
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Precedence rank for combining multiple outcomes. Higher rank dominates.
    /// SPEC 2.5: 64 > 69 > 70 > 1 > 2 > 3 > 0.
    const fn precedence(self) -> u8 {
        match self {
            Self::Usage => 7,
            Self::UnsupportedHost => 6,
            Self::Internal => 5,
            Self::FailSecurity => 4,
            Self::FailFunctional => 3,
            Self::Inconclusive => 2,
            Self::Pass => 1,
        }
    }
}

/// Combine multiple exit codes into one final exit code according to SPEC precedence rules.
pub fn combine(codes: impl IntoIterator<Item = ExitCode>) -> ExitCode {
    codes
        .into_iter()
        .max_by_key(|c| c.precedence())
        .unwrap_or(ExitCode::Pass)
}
