use std::sync::Arc;
use std::time::{Duration, Instant};

use mcpg_mcp::deadline::Clock;

pub struct FakeClock(pub std::sync::RwLock<std::time::Instant>);
impl FakeClock {
    pub fn new(start: std::time::Instant) -> Self { Self(std::sync::RwLock::new(start)) }
    pub fn advance(&self, d: std::time::Duration) { *self.0.write().unwrap() += d; }
}
impl Clock for FakeClock {
    fn now(&self) -> std::time::Instant { *self.0.read().unwrap() }
}

use mcpg_domain::config::{LimitsConfig, ScenarioConfig};
use mcpg_domain::verdict::{ExitCode, Verdict};
use mcpg_mcp::client::{DriverError, McpClient};
use mcpg_mcp::deadline::{DeadlineTracker};
use mcpg_mcp::framing::JsonRpc;
use mcpg_mcp::testing::scripted::ScriptedServer;
use serde_json::json;

#[test]
fn startup_timeout_is_inconclusive() {
    let clock = Arc::new(FakeClock::new(Instant::now()));
    let limits = LimitsConfig {
        startup_timeout_s: 5,
        call_timeout_s: 10,
        total_timeout_s: 60,
        shutdown_grace_s: 1,
        max_processes: 10,
        max_stdout_line_bytes: 1024,
    };
    let tracker = DeadlineTracker::new(clock.clone(), limits);

    let mut server = ScriptedServer::new();
    server.push_json_message(JsonRpc::success(
        1,
        json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": { "name": "slow-server" }
        }),
    ));

    let clock_clone = clock.clone();
    server.set_on_send(move |_| {
        clock_clone.advance(Duration::from_secs(6));
    });

    let mut client = McpClient::new(server).with_deadline_tracker(tracker);

    let err = client
        .initialize(&["2024-11-05".to_string()], false)
        .expect_err("startup should time out");

    match err {
        DriverError::Inconclusive(msg) => {
            assert!(msg.contains("startup timeout"));
            assert!(msg.contains("5s"));
        }
        other => panic!("expected Inconclusive error, got: {other:?}"),
    }
}

#[test]
fn call_timeout_is_inconclusive() {
    let clock = Arc::new(FakeClock::new(Instant::now()));
    let limits = LimitsConfig {
        startup_timeout_s: 10,
        call_timeout_s: 5,
        total_timeout_s: 60,
        shutdown_grace_s: 1,
        max_processes: 10,
        max_stdout_line_bytes: 1024,
    };
    let tracker = DeadlineTracker::new(clock.clone(), limits);

    let mut server = ScriptedServer::new();
    server.push_json_message(JsonRpc::success(
        1,
        json!({
            "content": [{ "type": "text", "text": "result after delay" }],
            "isError": false
        }),
    ));

    let clock_clone = clock.clone();
    server.set_on_send(move |_| {
        clock_clone.advance(Duration::from_secs(6));
    });

    let mut client = McpClient::new(server).with_deadline_tracker(tracker);

    let err = client
        .call_tool("heavy_task", &json!({}))
        .expect_err("call should time out");

    match err {
        DriverError::Inconclusive(msg) => {
            assert!(msg.contains("exceeded call deadline"), "msg was: {}", msg);
        }
        other => panic!("expected Inconclusive error, got: {other:?}"),
    }
}

