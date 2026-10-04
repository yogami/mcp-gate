//! MCP tools discovery, pagination, and invocation.
//!
//! SPEC 3.5 step 3: Discovers tools via tools/list, following nextCursor
//! until all pages are retrieved, rejecting cursor loops as protocol violations.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::client::{DriverError, McpClient};
use crate::framing::{FrameItem, JsonRpc};
use crate::transport::McpTransport;

/// MCP tool definition returned by tools/list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema", default)]
    pub input_schema: Value,
}

fn parse_tool_entries(val: &Value) -> Result<Vec<ToolDef>, DriverError> {
    let tools_val = val
        .get("tools")
        .ok_or_else(|| DriverError::Protocol("tools/list missing tools field".to_string()))?;

    serde_json::from_value::<Vec<ToolDef>>(tools_val.clone())
        .map_err(|e| DriverError::Protocol(format!("failed to parse tool definitions: {e}")))
}

fn parse_page(result: Value) -> Result<(Vec<ToolDef>, Option<String>), DriverError> {
    let tools = parse_tool_entries(&result)?;
    let next_cursor = result
        .get("nextCursor")
        .and_then(|c| c.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);
    Ok((tools, next_cursor))
}

fn build_list_params(cursor: Option<&str>) -> Option<Value> {
    cursor.map(|c| json!({ "cursor": c }))
}

impl<T: McpTransport> McpClient<T> {
    fn request_page(&mut self, cursor: Option<&str>) -> Result<Value, DriverError> {
        let id = self.next_id;
        self.next_id += 1;

        let params = build_list_params(cursor);
        let req = JsonRpc::request(id, "tools/list", params);
        self.transport
            .send(&req)
            .map_err(|e| DriverError::Io(e.to_string()))?;

        let item = self
            .transport
            .receive()
            .map_err(|e| DriverError::Io(e.to_string()))?
            .ok_or(DriverError::TransportClosed)?;

        let msg = match item {
            FrameItem::Message(m) => m,
            FrameItem::Violation(v) => {
                return Err(DriverError::Protocol(format!(
                    "protocol violation reading tools/list response: {}",
                    v.reason
                )));
            }
        };

        if let Some(err) = msg.error {
            return Err(DriverError::Protocol(format!(
                "tools/list returned error {}: {}",
                err.code, err.message
            )));
        }

        msg.result
            .ok_or_else(|| DriverError::Protocol("tools/list response missing result".to_string()))
    }

    /// Retrieve all tool definitions by following pagination cursors.
    pub fn list_tools(&mut self) -> Result<Vec<ToolDef>, DriverError> {
        let mut all_tools = Vec::new();
        let mut seen_cursors = HashSet::new();
        let mut current_cursor: Option<String> = None;

        loop {
            let result = self.request_page(current_cursor.as_deref())?;
            let (tools, next_cursor) = parse_page(result)?;
            all_tools.extend(tools);

            match next_cursor {
                Some(cursor) => {
                    if !seen_cursors.insert(cursor.clone()) {
                        return Err(DriverError::Protocol(format!(
                            "repeated nextCursor detected: {cursor}"
                        )));
                    }
                    current_cursor = Some(cursor);
                }
                None => break,
            }
        }

        Ok(all_tools)
    }
}
