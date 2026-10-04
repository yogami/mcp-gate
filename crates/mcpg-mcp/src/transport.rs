//! Abstract transport interface for MCP JSON-RPC communication.

use std::io::{self, BufRead, Write};

use crate::framing::{write_msg, FrameItem, JsonRpc, LineReader};

/// Port trait abstracting bidirectional JSON-RPC message transport.
pub trait McpTransport {
    /// Send a JSON-RPC message across the transport.
    fn send(&mut self, msg: &JsonRpc) -> io::Result<()>;

    /// Receive the next framing item from the transport.
    fn receive(&mut self) -> io::Result<Option<FrameItem>>;
}

/// Standard I/O transport combining a buffered writer and capped line reader.
pub struct StdioTransport<W: Write, R: BufRead> {
    writer: W,
    reader: LineReader<R>,
}

impl<W: Write, R: BufRead> StdioTransport<W, R> {
    /// Create a new stdio transport.
    pub fn new(writer: W, reader: LineReader<R>) -> Self {
        Self { writer, reader }
    }
}

impl<W: Write, R: BufRead> McpTransport for StdioTransport<W, R> {
    fn send(&mut self, msg: &JsonRpc) -> io::Result<()> {
        write_msg(&mut self.writer, msg)
    }

    fn receive(&mut self) -> io::Result<Option<FrameItem>> {
        self.reader.next_frame()
    }
}
