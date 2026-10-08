use mcpg_mcp::client::{DriverError, McpClient};
use mcpg_mcp::framing::JsonRpc;
use mcpg_mcp::testing::scripted::ScriptedServer;
use serde_json::json;

#[test]
fn sends_initialize_with_first_protocol_version() {
    let mut server = ScriptedServer::new();
    server.push_json_message(JsonRpc::success(
        1,
        json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "test-server", "version": "1.0"},
        }),
    ));

    let mut client = McpClient::new(server);
    let versions = vec!["2024-11-05".to_string(), "2024-10-07".to_string()];
    let info = client
        .initialize(&versions, true)
        .expect("handshake failed");

    assert_eq!(info.name, "test-server");
    assert_eq!(info.protocol_version, "2024-11-05");

    let sent = client.transport().sent_messages();
    assert_eq!(sent[0].method.as_deref(), Some("initialize"));
    let params = sent[0].params.as_ref().expect("params");
    assert_eq!(params["protocolVersion"], "2024-11-05");
    assert_eq!(params["clientInfo"]["name"], "mcp-gate");
}

#[test]
fn accepts_listed_version_from_server() {
    let mut server = ScriptedServer::new();
    server.push_json_message(JsonRpc::success(
        1,
        json!({
            "protocolVersion": "2024-10-07",
            "serverInfo": {"name": "legacy-server"},
        }),
    ));

    let mut client = McpClient::new(server);
    let versions = vec!["2024-11-05".to_string(), "2024-10-07".to_string()];
    let info = client
        .initialize(&versions, true)
        .expect("should accept second listed version");

    assert_eq!(info.protocol_version, "2024-10-07");
    assert_eq!(info.name, "legacy-server");
}

#[test]
fn unlisted_version_is_inconclusive() {
    let mut server = ScriptedServer::new();
    server.push_json_message(JsonRpc::success(
        1,
        json!({
            "protocolVersion": "1999-01-01",
            "serverInfo": {"name": "alien-server"},
        }),
    ));

    let mut client = McpClient::new(server);
    let versions = vec!["2024-11-05".to_string()];
    let err = client
        .initialize(&versions, true)
        .expect_err("should reject unlisted version");

    match err {
        DriverError::Inconclusive(msg) => {
            assert!(msg.contains("1999-01-01"));
        }
        other => panic!("expected Inconclusive, got: {other:?}"),
    }

    let sent = client.transport().sent_messages();
    assert_eq!(sent.len(), 1, "must not send notifications/initialized");
}

#[test]
fn sends_initialized_notification_after_response() {
    let mut server = ScriptedServer::new();
    server.push_json_message(JsonRpc::success(
        1,
        json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "test-server"},
        }),
    ));

    let mut client = McpClient::new(server);
    let versions = vec!["2024-11-05".to_string()];
    let _ = client
        .initialize(&versions, false)
        .expect("handshake failed");

    let sent = client.transport().sent_messages();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].method.as_deref(), Some("initialize"));
    assert_eq!(sent[1].method.as_deref(), Some("notifications/initialized"));
    assert_eq!(sent[1].id, None);
}

#[test]
fn advertises_roots_only_when_enabled() {
    // With roots enabled
    let mut s1 = ScriptedServer::new();
    s1.push_json_message(JsonRpc::success(
        1,
        json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "test"},
        }),
    ));
    let mut c1 = McpClient::new(s1);
    let _ = c1.initialize(&["2024-11-05".to_string()], true).unwrap();
    let p1 = c1.transport().sent_messages()[0].params.as_ref().unwrap();
    assert!(p1["capabilities"]["roots"].is_object());

    // With roots disabled
    let mut s2 = ScriptedServer::new();
    s2.push_json_message(JsonRpc::success(
        1,
        json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "test"},
        }),
    ));
    let mut c2 = McpClient::new(s2);
    let _ = c2.initialize(&["2024-11-05".to_string()], false).unwrap();
    let p2 = c2.transport().sent_messages()[0].params.as_ref().unwrap();
    assert!(p2["capabilities"]["roots"].is_null());
}
