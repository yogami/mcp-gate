use std::sync::Arc;
use std::time::{Duration, Instant};

use mcpg_app::ports::FakeClock;
use mcpg_domain::config::{LimitsConfig, ScenarioConfig};
use mcpg_domain::verdict::{ExitCode, Verdict};
use mcpg_mcp::client::{DriverError, McpClient};
use mcpg_mcp::deadline::{run_scenarios, DeadlineTracker};
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
            assert!(msg.contains("call timeout"));
            assert!(msg.contains("5s"));
        }
        other => panic!("expected Inconclusive error, got: {other:?}"),
    }
}

#[test]
fn total_timeout_skips_remaining_scenarios() {
    let clock = Arc::new(FakeClock::new(Instant::now()));
    let limits = LimitsConfig {
        startup_timeout_s: 10,
        call_timeout_s: 10,
        total_timeout_s: 15,
        shutdown_grace_s: 1,
        max_processes: 10,
        max_stdout_line_bytes: 1024,
    };
    let tracker = DeadlineTracker::new(clock.clone(), limits);

    let mut server = ScriptedServer::new();
    // First tool call succeeds
    server.push_json_message(JsonRpc::success(
        1,
        json!({
            "content": [{ "type": "text", "text": "scen 1 done" }],
            "isError": false
        }),
    ));

    let clock_clone = clock.clone();
    server.set_on_send(move |_| {
        // When client sends scenario 1 call, advance clock by 20 seconds
        clock_clone.advance(Duration::from_secs(20));
    });

    let mut client = McpClient::new(server);

    let scenarios = vec![
        ScenarioConfig {
            id: "scenario-1".to_string(),
            tool: "tool_a".to_string(),
            arguments: json!({}),
            canaries: None,
            expect: None,
            timeout_s: None,
        },
        ScenarioConfig {
            id: "scenario-2".to_string(),
            tool: "tool_b".to_string(),
            arguments: json!({}),
            canaries: None,
            expect: None,
            timeout_s: None,
        },
        ScenarioConfig {
            id: "scenario-3".to_string(),
            tool: "tool_c".to_string(),
            arguments: json!({}),
            canaries: None,
            expect: None,
            timeout_s: None,
        },
    ];

    let report = run_scenarios(&mut client, &tracker, &scenarios);

    assert_eq!(report.completed, vec!["scenario-1"]);
    assert_eq!(report.skipped, vec!["scenario-2", "scenario-3"]);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.exit_code, ExitCode::Inconclusive);
    assert_eq!(report.exit_code.as_i32(), 3);
}
