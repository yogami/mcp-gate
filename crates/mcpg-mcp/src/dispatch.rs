//! Server-to-client request dispatch and notification recording.
//!
//! SPEC 3.5 steps 5 and 6: Answers server-to-client requests while waiting
//! for responses, and records received notifications in the transcript.

use serde_json::{json, Value};

use crate::client::{DriverError, McpClient};
use crate::framing::{FrameItem, JsonRpc};
use crate::transport::McpTransport;

impl<T: McpTransport> McpClient<T> {
    /// Wait for a response with the expected request ID, dispatching incoming
    /// server requests and recording notifications along the way.
    pub fn wait_for_response(
        &mut self,
        expected_id: u64,
        context: &str,
    ) -> Result<Value, DriverError> {
        loop {
            let item = self
                .transport
                .receive()
                .map_err(|e| DriverError::Io(e.to_string()))?
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
                return Ok(Some(Err(DriverError::Protocol(format!(
                    "protocol violation reading {context} response: {}",
                    v.reason
                )))));
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
