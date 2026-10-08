use mcpg_mcp::client::McpClient;
use mcpg_mcp::framing::JsonRpc;
use mcpg_mcp::testing::scripted::ScriptedServer;
use serde_json::json;

#[test]
fn roots_list_returns_workspace_uri() {
    let mut server = ScriptedServer::new();
    // Server requests roots/list while client waits for tools/call
    server.push_json_message(JsonRpc::request(100, "roots/list", None));
    server.push_json_message(JsonRpc::success(
        1,
        json!({
            "content": [{ "type": "text", "text": "ok" }],
            "isError": false
        }),
    ));

    let mut client = McpClient::new(server).with_workspace_uri("file:///path/to/my/workspace");

    let result = client
        .call_tool("test_tool", &json!({}))
        .expect("tool call should succeed");
    assert_eq!(result.text_content(), "ok");

    let sent = client.transport().sent_messages();
    assert_eq!(sent.len(), 2);
    // First message sent was tools/call request
    assert_eq!(sent[0].method.as_deref(), Some("tools/call"));
    assert_eq!(sent[0].id, Some(json!(1)));
    // Second message sent was roots/list response
    assert_eq!(sent[1].id, Some(json!(100)));
    assert!(sent[1].method.is_none());
    let res = sent[1].result.as_ref().expect("result");
    let uri = res["roots"][0]["uri"]
        .as_str()
        .expect("workspace uri string");
    assert_eq!(uri, "file:///path/to/my/workspace");
}

#[test]
fn ping_returns_empty_object() {
    let mut server = ScriptedServer::new();
    // Server sends ping request while client waits for tools/call
    server.push_json_message(JsonRpc::request(200, "ping", None));
    server.push_json_message(JsonRpc::success(
        1,
        json!({
            "content": [{ "type": "text", "text": "pong-ok" }],
            "isError": false
        }),
    ));

    let mut client = McpClient::new(server);
    let result = client
        .call_tool("test_tool", &json!({}))
        .expect("tool call should succeed");
    assert_eq!(result.text_content(), "pong-ok");

    let sent = client.transport().sent_messages();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].id, Some(json!(200)));
    assert_eq!(sent[1].result, Some(json!({})));
    assert!(sent[1].error.is_none());
}

#[test]
fn sampling_gets_method_not_found() {
    let mut server = ScriptedServer::new();
    // Server requests sampling/createMessage while client waits for tools/call
    server.push_json_message(JsonRpc::request(
        300,
        "sampling/createMessage",
        Some(json!({ "messages": [] })),
    ));
    server.push_json_message(JsonRpc::success(
        1,
        json!({
            "content": [{ "type": "text", "text": "handled" }],
            "isError": false
        }),
    ));

    let mut client = McpClient::new(server);
    let result = client
        .call_tool("test_tool", &json!({}))
        .expect("tool call should succeed");
    assert_eq!(result.text_content(), "handled");

    let sent = client.transport().sent_messages();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].id, Some(json!(300)));
    let err = sent[1].error.as_ref().expect("error object expected");
    assert_eq!(err.code, -32601);
    assert!(err.message.contains("Method not found"));
}

#[test]
fn notifications_recorded_in_transcript() {
    let mut server = ScriptedServer::new();
    // Server sends notifications while client waits for tools/call
    server.push_json_message(JsonRpc::notification(
        "notifications/message",
        Some(json!({ "level": "info", "data": "syncing files" })),
    ));
    server.push_json_message(JsonRpc::notification(
        "notifications/progress",
        Some(json!({ "progress": 75 })),
    ));
    server.push_json_message(JsonRpc::success(
        1,
        json!({
            "content": [{ "type": "text", "text": "done" }],
            "isError": false
        }),
    ));

    let mut client = McpClient::new(server);
    let result = client
        .call_tool("test_tool", &json!({}))
        .expect("tool call should succeed");
    assert_eq!(result.text_content(), "done");

    let transcript = client.transcript();
    assert_eq!(transcript.len(), 2);
    assert_eq!(
        transcript[0].method.as_deref(),
        Some("notifications/message")
    );
    assert_eq!(
        transcript[1].method.as_deref(),
        Some("notifications/progress")
    );
}
