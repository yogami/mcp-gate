use mcpg_mcp::client::{DriverError, McpClient};
use mcpg_mcp::framing::JsonRpc;
use mcpg_mcp::testing::scripted::ScriptedServer;
use serde_json::json;

#[test]
fn follows_next_cursor_until_absent() {
    let mut server = ScriptedServer::new();
    // Enqueue 3 pages of tools
    server.push_json_message(JsonRpc::success(
        1,
        json!({
            "tools": [
                {
                    "name": "tool_one",
                    "description": "First tool",
                    "inputSchema": { "type": "object" }
                }
            ],
            "nextCursor": "page-2"
        }),
    ));
    server.push_json_message(JsonRpc::success(
        2,
        json!({
            "tools": [
                {
                    "name": "tool_two",
                    "description": "Second tool",
                    "inputSchema": { "type": "object" }
                }
            ],
            "nextCursor": "page-3"
        }),
    ));
    server.push_json_message(JsonRpc::success(
        3,
        json!({
            "tools": [
                {
                    "name": "tool_three",
                    "description": "Third tool",
                    "inputSchema": { "type": "object" }
                }
            ]
        }),
    ));

    let mut client = McpClient::new(server);
    let tools = client.list_tools().expect("list_tools should succeed");

    assert_eq!(tools.len(), 3);
    assert_eq!(tools[0].name, "tool_one");
    assert_eq!(tools[1].name, "tool_two");
    assert_eq!(tools[2].name, "tool_three");

    let sent = client.transport().sent_messages();
    assert_eq!(sent.len(), 3);
    assert_eq!(sent[0].method.as_deref(), Some("tools/list"));
    assert_eq!(sent[0].params, None);

    assert_eq!(sent[1].method.as_deref(), Some("tools/list"));
    assert_eq!(sent[1].params.as_ref().unwrap()["cursor"], "page-2");

    assert_eq!(sent[2].method.as_deref(), Some("tools/list"));
    assert_eq!(sent[2].params.as_ref().unwrap()["cursor"], "page-3");
}

#[test]
fn repeated_cursor_is_protocol_error() {
    let mut server = ScriptedServer::new();
    server.push_json_message(JsonRpc::success(
        1,
        json!({
            "tools": [{ "name": "tool_a", "inputSchema": {} }],
            "nextCursor": "loop-cursor"
        }),
    ));
    server.push_json_message(JsonRpc::success(
        2,
        json!({
            "tools": [{ "name": "tool_b", "inputSchema": {} }],
            "nextCursor": "loop-cursor"
        }),
    ));

    let mut client = McpClient::new(server);
    let err = client
        .list_tools()
        .expect_err("repeated cursor should fail");

    match err {
        DriverError::Protocol(msg) => {
            assert!(msg.contains("repeated nextCursor detected"));
            assert!(msg.contains("loop-cursor"));
        }
        other => panic!("expected Protocol error, got: {other:?}"),
    }
}
