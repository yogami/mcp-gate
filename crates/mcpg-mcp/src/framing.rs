//! JSON-RPC stdio line framing and message serialization.
//!
//! SPEC 3.5: Implements newline-delimited JSON-RPC framing with byte-size limits.
//! Lines exceeding max_stdout_line_bytes or containing invalid JSON yield proto.violation.

use std::io::{self, BufRead, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Error payload in a JSON-RPC error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// JSON-RPC 2.0 message representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpc {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpc {
    /// Create a request message with id, method, and optional params.
    pub fn request(id: impl Into<Value>, method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: Some(id.into()),
            method: Some(method.into()),
            params,
            result: None,
            error: None,
        }
    }

    /// Create a notification message without id.
    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: Some(method.into()),
            params,
            result: None,
            error: None,
        }
    }

    /// Create a successful response message.
    pub fn success(id: impl Into<Value>, result: impl Into<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: Some(id.into()),
            method: None,
            params: None,
            result: Some(result.into()),
            error: None,
        }
    }

    /// Create an error response message.
    pub fn error_response(id: Option<Value>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            method: None,
            params: None,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// Protocol violation event emitted when framing or JSON validation fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtoViolation {
    pub event_kind: String,
    pub reason: String,
    pub raw: String,
}

/// Item returned by the framing reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameItem {
    Message(JsonRpc),
    Violation(ProtoViolation),
}

struct RawLine {
    bytes: Vec<u8>,
    is_oversized: bool,
}

fn append_capped(buf: &mut Vec<u8>, slice: &[u8], max_bytes: usize) {
    if buf.len() < max_bytes {
        let remaining = max_bytes - buf.len();
        let to_copy = remaining.min(slice.len());
        buf.extend_from_slice(&slice[..to_copy]);
    }
}

fn strip_cr(buf: &mut Vec<u8>) {
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
}

/// Buffered line reader enforcing maximum line length.
pub struct LineReader<R> {
    reader: R,
    max_bytes: usize,
}

impl<R: BufRead> LineReader<R> {
    /// Create a line reader wrapping a buffered stream.
    pub fn new(reader: R, max_bytes: usize) -> Self {
        Self { reader, max_bytes }
    }

    fn read_chunk(&mut self, buf: &mut Vec<u8>, total: &mut usize) -> io::Result<Option<bool>> {
        let available = self.reader.fill_buf()?;
        if available.is_empty() {
            return Ok(None);
        }

        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let slice = &available[..pos];
            *total += slice.len();
            append_capped(buf, slice, self.max_bytes);
            self.reader.consume(pos + 1);
            Ok(Some(true))
        } else {
            let len = available.len();
            *total += len;
            append_capped(buf, available, self.max_bytes);
            self.reader.consume(len);
            Ok(Some(false))
        }
    }

    fn read_raw_line(&mut self) -> io::Result<Option<RawLine>> {
        let mut buf = Vec::new();
        let mut total = 0;
        let mut saw_newline = false;

        loop {
            match self.read_chunk(&mut buf, &mut total)? {
                None => break,
                Some(true) => {
                    saw_newline = true;
                    break;
                }
                Some(false) => {}
            }
        }

        if buf.is_empty() && total == 0 && !saw_newline {
            return Ok(None);
        }

        strip_cr(&mut buf);
        let is_oversized = total > self.max_bytes;
        Ok(Some(RawLine {
            bytes: buf,
            is_oversized,
        }))
    }

    fn parse_line_text(&self, text: &str) -> FrameItem {
        match serde_json::from_str::<JsonRpc>(text) {
            Ok(msg) => FrameItem::Message(msg),
            Err(_) => FrameItem::Violation(ProtoViolation {
                event_kind: "proto.violation".to_string(),
                reason: "non_json".to_string(),
                raw: text.to_string(),
            }),
        }
    }

    /// Read the next framing item from the stream.
    pub fn next_frame(&mut self) -> io::Result<Option<FrameItem>> {
        loop {
            let raw = match self.read_raw_line()? {
                Some(r) => r,
                None => return Ok(None),
            };

            if raw.is_oversized {
                let text = String::from_utf8_lossy(&raw.bytes).into_owned();
                return Ok(Some(FrameItem::Violation(ProtoViolation {
                    event_kind: "proto.violation".to_string(),
                    reason: "oversized_line".to_string(),
                    raw: text,
                })));
            }

            let text = match std::str::from_utf8(&raw.bytes) {
                Ok(s) => s.trim(),
                Err(_) => {
                    return Ok(Some(FrameItem::Violation(ProtoViolation {
                        event_kind: "proto.violation".to_string(),
                        reason: "non_utf8".to_string(),
                        raw: String::from_utf8_lossy(&raw.bytes).into_owned(),
                    })));
                }
            };

            if !text.is_empty() {
                return Ok(Some(self.parse_line_text(text)));
            }
        }
    }
}

/// Write a compact JSON-RPC message followed by a newline.
pub fn write_msg<W: Write>(w: &mut W, msg: &JsonRpc) -> io::Result<()> {
    let json_bytes =
        serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    w.write_all(&json_bytes)?;
    w.write_all(b"\n")?;
    w.flush()?;
    Ok(())
}
