//! Scripted test fake implementing McpTransport.

use std::collections::VecDeque;
use std::io;

use mcpg_mcp::framing::{FrameItem, JsonRpc};
use mcpg_mcp::transport::McpTransport;

type SendCallback = Box<dyn FnMut(&JsonRpc) + Send>;

/// Scripted MCP server for deterministic testing.
pub struct ScriptedServer {
    sent_by_client: Vec<JsonRpc>,
    canned_responses: VecDeque<FrameItem>,
    on_send: Option<SendCallback>,
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
            on_send: None,
        }
    }

    /// Set a callback invoked whenever the client sends a message.
    pub fn set_on_send<F>(&mut self, f: F)
    where
        F: FnMut(&JsonRpc) + Send + 'static,
    {
        self.on_send = Some(Box::new(f));
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
        if let Some(f) = &mut self.on_send {
            f(msg);
        }
        Ok(())
    }

    fn receive(&mut self, _deadline: std::time::Instant) -> io::Result<Option<FrameItem>> {
        Ok(self.canned_responses.pop_front())
    }
}
