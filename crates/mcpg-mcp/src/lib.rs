//! MCP JSON-RPC 2.0 stdio protocol driver.
#![forbid(unsafe_code)]

pub mod client;
pub mod deadline;
pub mod dispatch;
pub mod framing;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod tools;
pub mod transport;
