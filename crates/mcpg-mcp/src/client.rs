//! High-level MCP client driver.
//!
//! SPEC 3.5: Implements protocol handshake, capabilities exchange,
//! and request-response lifecycle with subcommands.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::framing::JsonRpc;
use crate::transport::McpTransport;

/// Errors produced during MCP driver operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    Inconclusive(String),
    Protocol(String),
    Io(String),
    TransportClosed,
    Timeout(String),
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inconclusive(msg) => write!(f, "inconclusive: {msg}"),
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::TransportClosed => write!(f, "transport closed unexpectedly"),
            Self::Timeout(msg) => write!(f, "timeout: {msg}"),
        }
    }
}

impl std::error::Error for DriverError {}

/// Server information returned by the initialize handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub protocol_version: String,
    #[serde(default)]
    pub capabilities: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

fn build_init_params(version: &str, roots: bool) -> Value {
    let mut capabilities = serde_json::Map::new();
    if roots {
        capabilities.insert("roots".to_string(), json!({ "listChanged": false }));
    }
    json!({
        "protocolVersion": version,
        "clientInfo": {
            "name": "mcp-gate",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "capabilities": Value::Object(capabilities),
    })
}

fn extract_server_info(result: &Value, negotiated_version: &str) -> ServerInfo {
    let server_name = result
        .get("serverInfo")
        .and_then(|s| s.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("unknown")
        .to_string();

    let server_version = result
        .get("serverInfo")
        .and_then(|s| s.get("version"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let capabilities = result
        .get("capabilities")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let instructions = result
        .get("instructions")
        .and_then(|i| i.as_str())
        .map(String::from);

    ServerInfo {
        name: server_name,
        version: server_version,
        protocol_version: negotiated_version.to_string(),
        capabilities,
        instructions,
    }
}

fn validate_protocol_version(result: &Value, versions: &[String]) -> Result<String, DriverError> {
    let raw = result
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            DriverError::Protocol("initialize response missing protocolVersion".to_string())
        })?;

    if versions.iter().any(|v| v == raw) {
        Ok(raw.to_string())
    } else {
        Err(DriverError::Inconclusive(format!(
            "server requested unsupported protocol version: {raw}"
        )))
    }
}

/// Client driver executing MCP lifecycle stages against an McpTransport.
pub struct McpClient<T: McpTransport> {
    pub(crate) transport: T,
    pub(crate) next_id: u64,
    pub(crate) server_info: Option<ServerInfo>,
    pub(crate) workspace_uri: Option<String>,
    pub(crate) transcript: Vec<JsonRpc>,
    pub(crate) violations: Vec<crate::framing::ProtoViolation>,
    pub(crate) deadline_tracker: Option<crate::deadline::DeadlineTracker>,
}

impl<T: McpTransport> McpClient<T> {
    /// Create a new MCP client over a transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_id: 1,
            server_info: None,
            workspace_uri: None,
            transcript: Vec::new(),
            violations: Vec::new(),
            deadline_tracker: None,
        }
    }

    /// Take and return accumulated protocol violations.
    pub fn take_violations(&mut self) -> Vec<crate::framing::ProtoViolation> {
        std::mem::take(&mut self.violations)
    }

    /// Set deadline tracker on client builder.
    pub fn with_deadline_tracker(mut self, tracker: crate::deadline::DeadlineTracker) -> Self {
        self.deadline_tracker = Some(tracker);
        self
    }

    /// Set deadline tracker on client.
    pub fn set_deadline_tracker(&mut self, tracker: crate::deadline::DeadlineTracker) {
        self.deadline_tracker = Some(tracker);
    }

    /// Access configured deadline tracker if any.
    pub fn deadline_tracker(&self) -> Option<&crate::deadline::DeadlineTracker> {
        self.deadline_tracker.as_ref()
    }

    /// Set the workspace URI on client builder.
    pub fn with_workspace_uri(mut self, uri: impl Into<String>) -> Self {
        self.workspace_uri = Some(uri.into());
        self
    }

    /// Set the workspace URI on client.
    pub fn set_workspace_uri(&mut self, uri: impl Into<String>) {
        self.workspace_uri = Some(uri.into());
    }

    /// Get configured workspace URI if any.
    pub fn workspace_uri(&self) -> Option<&str> {
        self.workspace_uri.as_deref()
    }

    /// Get all received notifications and messages in transcript.
    pub fn transcript(&self) -> &[JsonRpc] {
        &self.transcript
    }

    /// Get all received notifications in transcript.
    pub fn notifications(&self) -> &[JsonRpc] {
        &self.transcript
    }

    /// Access the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Access the underlying transport mutably.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Access the negotiated server info if handshake completed.
    pub fn server_info(&self) -> Option<&ServerInfo> {
        self.server_info.as_ref()
    }

    /// Execute the initialize handshake with protocol version negotiation.
    pub fn initialize(
        &mut self,
        versions: &[String],
        roots: bool,
    ) -> Result<ServerInfo, DriverError> {
        let first_version = versions.first().ok_or_else(|| {
            DriverError::Inconclusive("no protocol versions configured".to_string())
        })?;

        let start = self.deadline_tracker.as_ref().map(|dt| dt.clock().now());
        let id = self.next_id;
        self.next_id += 1;

        let params = build_init_params(first_version, roots);
        let req = JsonRpc::request(id, "initialize", Some(params));
        self.transport
            .send(&req)
            .map_err(|e| DriverError::Io(e.to_string()))?;

        let startup_deadline = self.deadline_tracker.as_ref().map(|dt| {
            dt.clock().now() + std::time::Duration::from_secs(dt.limits().startup_timeout_s)
        });
        eprintln!("client - waiting for initialize response"); let result = self.wait_for_response_with_deadline(id, "initialize", startup_deadline)?; eprintln!("client - got initialize response");
        if let Some(start) = start {
            if let Some(dt) = &self.deadline_tracker {
                dt.check_startup(start)?;
            }
        }

        let negotiated_version = validate_protocol_version(&result, versions)?;
        let info = extract_server_info(&result, &negotiated_version);

        let notif = JsonRpc::notification("notifications/initialized", None);
        self.transport
            .send(&notif)
            .map_err(|e| DriverError::Io(e.to_string()))?;

        self.server_info = Some(info.clone());
        Ok(info)
    }
}
