//! Abstract transport interface for MCP JSON-RPC communication.

use std::io::{self, BufRead, Write};
use std::time::Instant;

use crate::framing::{write_msg, FrameItem, JsonRpc, LineReader};

/// Port trait abstracting bidirectional JSON-RPC message transport.
pub trait McpTransport {
    /// Send a JSON-RPC message across the transport.
    fn send(&mut self, msg: &JsonRpc) -> io::Result<()>;

    /// Receive the next framing item from the transport, timing out at deadline.
    fn receive(&mut self, deadline: Instant) -> io::Result<Option<FrameItem>>;
}

/// Standard I/O transport combining a buffered writer and capped line reader.
pub struct StdioTransport<W: Write> {
    writer: W,
    rx: std::sync::mpsc::Receiver<io::Result<Option<FrameItem>>>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

impl<W: Write> StdioTransport<W> {
    /// Create a new stdio transport by spawning a reader thread.
    pub fn new<R: BufRead + Send + 'static>(writer: W, mut reader: LineReader<R>) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(10);
        let thread_handle = std::thread::spawn(move || loop {
            let res = reader.next_frame();
            let is_err = res.is_err();
            let is_none = matches!(&res, Ok(None));
            if tx.send(res).is_err() {
                break;
            }
            if is_err || is_none {
                break;
            }
        });
        Self {
            writer,
            rx,
            thread_handle: Some(thread_handle),
        }
    }
}

impl<W: Write> Drop for StdioTransport<W> {
    fn drop(&mut self) {
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.thread().id();
        }
    }
}

impl<W: Write> McpTransport for StdioTransport<W> {
    fn send(&mut self, msg: &JsonRpc) -> io::Result<()> {
        write_msg(&mut self.writer, msg)
    }

    fn receive(&mut self, deadline: Instant) -> io::Result<Option<FrameItem>> {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline exceeded"));
        }
        match self.rx.recv_timeout(deadline.duration_since(now)) {
            Ok(res) => res,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                Err(io::Error::new(io::ErrorKind::TimedOut, "deadline exceeded"))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Ok(None),
        }
    }
}
