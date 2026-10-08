//! Deadline tracking and timeout enforcement.
//!
//! SPEC 2.2 and 2.5: Enforces startup, call, and total run timeouts.
//! Timeouts yield inconclusive verdicts and exit code 3.

use std::sync::Arc;
use std::time::{Duration, Instant};


pub trait Clock: Send + Sync {
    fn now(&self) -> std::time::Instant;
}
impl<C: Clock + ?Sized> Clock for std::sync::Arc<C> {
    fn now(&self) -> std::time::Instant {
        (**self).now()
    }
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> std::time::Instant { std::time::Instant::now() }
}

use mcpg_domain::config::LimitsConfig;

use crate::client::DriverError;

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
