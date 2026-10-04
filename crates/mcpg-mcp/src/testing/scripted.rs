//! Scripted test fake implementing McpTransport.

use std::collections::VecDeque;
use std::io;

use crate::framing::{FrameItem, JsonRpc};
use crate::transport::McpTransport;

/// Scripted MCP server for deterministic testing.
pub struct ScriptedServer {
    sent_by_client: Vec<JsonRpc>,
    canned_responses: VecDeque<FrameItem>,
}

impl Default for ScriptedServer {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptedServer {
    /// Create a new scripted server.
    pub fn new() -> Self {
        Self {
            sent_by_client: Vec::new(),
            canned_responses: VecDeque::new(),
        }
    }

    /// Enqueue a response item for the client to read.
    pub fn push_response(&mut self, item: FrameItem) {
        self.canned_responses.push_back(item);
    }

    /// Enqueue a JSON-RPC message response.
    pub fn push_json_message(&mut self, msg: JsonRpc) {
        self.canned_responses.push_back(FrameItem::Message(msg));
    }

    /// Get all messages sent by the client in arrival order.
    pub fn sent_messages(&self) -> &[JsonRpc] {
        &self.sent_by_client
    }
}

impl McpTransport for ScriptedServer {
    fn send(&mut self, msg: &JsonRpc) -> io::Result<()> {
        self.sent_by_client.push(msg.clone());
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Option<FrameItem>> {
        Ok(self.canned_responses.pop_front())
    }
}
