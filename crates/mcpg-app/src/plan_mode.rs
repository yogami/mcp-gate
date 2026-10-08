//! Operational mode selection and Landlock fallback logic.
//!
//! SPEC 3.1.5: When Landlock is absent on the host and not required,
//! the runner falls back to observe mode and emits a tool notification.

use mcpg_domain::host::{Feature, HostCaps};
use mcpg_domain::mode::Mode;
use mcpg_domain::verdict::ExitCode;
use serde::{Deserialize, Serialize};

/// Tool execution notification emitted during plan preparation or runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub message: String,
    pub level: String,
}

impl Notification {
    /// Create a new notification.
    pub fn new(
        id: impl Into<String>,
        message: impl Into<String>,
        level: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            message: message.into(),
            level: level.into(),
        }
    }
}

/// Choose the operational mode based on requested mode, host caps, and required features.
pub fn choose_mode(
    requested: Mode,
    caps: &HostCaps,
    require: &[Feature],
) -> Result<(Mode, Vec<Notification>), ExitCode> {
    if !caps.assess(require).supported {
        return Err(ExitCode::UnsupportedHost);
    }

    if requested == Mode::Observe {
        return Ok((Mode::Observe, Vec::new()));
    }

    if !caps.landlock.available {
        let notif = Notification::new(
            "landlock-unavailable",
            "Landlock is not available on this host; falling back to observe mode",
            "warning",
        );
        return Ok((Mode::Observe, vec![notif]));
    }

    Ok((Mode::Enforce, Vec::new()))
}
