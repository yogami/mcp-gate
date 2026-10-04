//! Orchestration phase cursor and event tagging.
//!
//! SPEC 1.5, 3.4.5, and REQ-ORCH-003: Phases advance in strict sequence:
//! startup -> handshake -> scenario:<id>... -> shutdown.
//! Scenarios run one at a time so events are attributed unambiguously.

use std::fmt;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

/// High-level execution phase.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Phase {
    Startup,
    Handshake,
    Scenario(String),
    Probe(String),
    Shutdown,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Startup => write!(f, "startup"),
            Self::Handshake => write!(f, "handshake"),
            Self::Scenario(id) => write!(f, "scenario:{id}"),
            Self::Probe(id) => write!(f, "probe:{id}"),
            Self::Shutdown => write!(f, "shutdown"),
        }
    }
}

/// Errors occurring during phase cursor management.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhaseError {
    ScenarioOverlap(String),
    InvalidTransition(String),
}

impl fmt::Display for PhaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScenarioOverlap(msg) => write!(f, "scenario overlap: {msg}"),
            Self::InvalidTransition(msg) => write!(f, "invalid phase transition: {msg}"),
        }
    }
}

impl std::error::Error for PhaseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CursorState {
    phase: Phase,
    scenario_active: bool,
}

/// Thread-safe phase cursor shared between test driver and observers.
#[derive(Debug, Clone)]
pub struct PhaseCursor {
    state: Arc<RwLock<CursorState>>,
}

impl Default for PhaseCursor {
    fn default() -> Self {
        Self::new()
    }
}

impl PhaseCursor {
    /// Create a new phase cursor initialized to the startup phase.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(CursorState {
                phase: Phase::Startup,
                scenario_active: false,
            })),
        }
    }

    /// Read the currently active execution phase.
    pub fn current(&self) -> Phase {
        self.state.read().expect("lock poisoned").phase.clone()
    }

    /// Advance cursor to the protocol handshake phase.
    pub fn advance_to_handshake(&self) -> Result<(), PhaseError> {
        let mut state = self.state.write().expect("lock poisoned");
        state.phase = Phase::Handshake;
        Ok(())
    }

    /// Enter a scenario phase. Returns error if another scenario is active.
    pub fn start_scenario(&self, id: &str) -> Result<(), PhaseError> {
        let mut state = self.state.write().expect("lock poisoned");
        if state.scenario_active {
            return Err(PhaseError::ScenarioOverlap(format!(
                "cannot start scenario '{id}': scenario '{}' is still active",
                state.phase
            )));
        }
        state.phase = Phase::Scenario(id.to_string());
        state.scenario_active = true;
        Ok(())
    }

    /// Leave the current scenario phase.
    pub fn end_scenario(&self) -> Result<(), PhaseError> {
        let mut state = self.state.write().expect("lock poisoned");
        state.scenario_active = false;
        Ok(())
    }

    /// Enter an active probe phase.
    pub fn start_probe(&self, id: &str) -> Result<(), PhaseError> {
        let mut state = self.state.write().expect("lock poisoned");
        if state.scenario_active {
            return Err(PhaseError::ScenarioOverlap(format!(
                "cannot start probe '{id}': scenario '{}' is still active",
                state.phase
            )));
        }
        state.phase = Phase::Probe(id.to_string());
        state.scenario_active = true;
        Ok(())
    }

    /// Leave the current probe phase.
    pub fn end_probe(&self) -> Result<(), PhaseError> {
        let mut state = self.state.write().expect("lock poisoned");
        state.scenario_active = false;
        Ok(())
    }

    /// Advance cursor to the final shutdown phase.
    pub fn advance_to_shutdown(&self) -> Result<(), PhaseError> {
        let mut state = self.state.write().expect("lock poisoned");
        state.scenario_active = false;
        state.phase = Phase::Shutdown;
        Ok(())
    }

    /// Attach the active phase to an event payload.
    pub fn tag<E>(&self, event: E) -> TaggedEvent<E> {
        let phase = self.current();
        TaggedEvent { phase, event }
    }
}

/// An observed event tagged with the phase active at reception.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaggedEvent<E> {
    pub phase: Phase,
    pub event: E,
}
