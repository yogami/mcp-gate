//! Server-to-client request dispatch and notification recording.
//!
//! SPEC 3.5 steps 5 and 6: Answers server-to-client requests while waiting
//! for responses, and records received notifications in the transcript.

use serde_json::{json, Value};

use crate::client::{DriverError, McpClient};
use crate::framing::{FrameItem, JsonRpc};
use crate::transport::McpTransport;

const FALLBACK_TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

impl<T: McpTransport> McpClient<T> {
    /// Wait for a response with the expected request ID, dispatching incoming
    /// server requests and recording notifications along the way.
    pub fn wait_for_response(
        &mut self,
        expected_id: u64,
        context: &str,
    ) -> Result<Value, DriverError> {
        self.wait_for_response_with_deadline(expected_id, context, None)
    }

    /// Wait for a response with an optional per-call deadline.
    pub fn wait_for_response_with_deadline(
        &mut self,
        expected_id: u64,
        context: &str,
        call_deadline: Option<std::time::Instant>,
    ) -> Result<Value, DriverError> {
        loop {
            let total_deadline = self
                .deadline_tracker
                .as_ref()
                .map(|t| t.total_deadline())
                .unwrap_or_else(|| std::time::Instant::now() + FALLBACK_TOTAL_TIMEOUT);

            let deadline = match call_deadline {
                Some(cd) => std::cmp::min(total_deadline, cd),
                None => total_deadline,
            };

            let now = self
                .deadline_tracker
                .as_ref()
                .map(|t| t.clock().now())
                .unwrap_or_else(|| std::time::Instant::now());
            if now >= deadline {
                if let Some(cd) = call_deadline {
                    if now >= cd {
                        return Err(DriverError::Inconclusive(format!(
                            "{context} exceeded call deadline"
                        )));
                    }
                }
                return Err(DriverError::Inconclusive(format!(
                    "{context} exceeded total deadline"
                )));
            }

            let item = self
                .transport
                .receive(deadline)
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::TimedOut || e.to_string().contains("deadline") {
                        DriverError::Inconclusive(format!("{context} timeout: {e}"))
                    } else {
                        DriverError::Io(e.to_string())
                    }
                })?
                .ok_or(DriverError::TransportClosed)?;

            if let Some(res) = self.dispatch_item(item, expected_id, context)? {
                return res;
            }
        }
    }

    fn dispatch_item(
        &mut self,
        item: FrameItem,
        expected_id: u64,
        context: &str,
    ) -> Result<Option<Result<Value, DriverError>>, DriverError> {
        let msg = match item {
            FrameItem::Message(m) => m,
            FrameItem::Violation(v) => {
                self.violations.push(v);
                return Ok(None);
            }
        };

        if msg.id.is_none() {
            self.transcript.push(msg);
            return Ok(None);
        }

        if msg.method.is_some() {
            self.handle_server_request(&msg)?;
            return Ok(None);
        }

        if msg.id == Some(Value::from(expected_id)) {
            return Ok(Some(self.extract_result(msg, context)));
        }

        Ok(None)
    }

    fn extract_result(&self, msg: JsonRpc, context: &str) -> Result<Value, DriverError> {
        if let Some(err) = msg.error {
            if context == "initialize" {
                return Err(DriverError::Inconclusive(format!(
                    "server rejected initialize: {}",
                    err.message
                )));
            }
            return Err(DriverError::Protocol(format!(
                "{context} returned error {}: {}",
                err.code, err.message
            )));
        }

        msg.result
            .ok_or_else(|| DriverError::Protocol(format!("{context} response missing result")))
    }

    fn handle_server_request(&mut self, req: &JsonRpc) -> Result<(), DriverError> {
        let id = req.id.clone().unwrap_or_else(|| json!(0));
        let method = req.method.as_deref().unwrap_or("");

        let response = match method {
            "roots/list" => {
                let uri = self.workspace_uri.as_deref().unwrap_or("file:///workspace");
                JsonRpc::success(id, json!({ "roots": [{ "uri": uri }] }))
            }
            "ping" => JsonRpc::success(id, json!({})),
            _ => JsonRpc::error_response(Some(id), -32601, format!("Method not found: {method}")),
        };

        self.transport
            .send(&response)
            .map_err(|e| DriverError::Io(e.to_string()))
    }
}
