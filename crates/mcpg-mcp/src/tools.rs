//! MCP tools discovery, pagination, and invocation.
//!
//! SPEC 3.5 step 3 and 4: Discovers tools via tools/list, following nextCursor
//! until all pages are retrieved, rejecting cursor loops as protocol violations,
//! and invokes tools via tools/call.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::client::{DriverError, McpClient};
use crate::framing::JsonRpc;
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

/// Result of an MCP tools/call invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCallResult {
    #[serde(default)]
    pub content: Vec<Value>,
    #[serde(rename = "isError", default)]
    pub is_error: bool,
}

impl ToolCallResult {
    /// Extract joined text representation from content blocks.
    pub fn text_content(&self) -> String {
        let mut out = String::new();
        for item in &self.content {
            if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                out.push_str(text);
            } else if let Some(s) = item.as_str() {
                out.push_str(s);
            }
        }
        out
    }
}

impl From<ToolCallResult> for mcpg_app::scenario::CallOutcome {
    fn from(res: ToolCallResult) -> Self {
        let text = res.text_content();
        mcpg_app::scenario::CallOutcome::from_tool_result(res.is_error, text)
    }
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

        self.wait_for_response(id, "tools/list")
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

    /// Invoke a tool by name with arguments.
    pub fn call_tool(
        &mut self,
        name: &str,
        arguments: &Value,
    ) -> Result<ToolCallResult, DriverError> {
        let id = self.next_id;
        self.next_id += 1;

        let params = json!({
            "name": name,
            "arguments": arguments,
        });
        let req = JsonRpc::request(id, "tools/call", Some(params));
        self.transport
            .send(&req)
            .map_err(|e| DriverError::Io(e.to_string()))?;

        let result = self.wait_for_response(id, "tools/call")?;
        serde_json::from_value::<ToolCallResult>(result)
            .map_err(|e| DriverError::Protocol(format!("failed to parse tools/call result: {e}")))
    }
}
