use mcpg_mcp::framing::{write_msg, FrameItem, JsonRpc, LineReader};
use serde_json::json;

#[test]
fn one_message_per_line() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
    let mut reader = LineReader::new(&input[..], 1024);

    let item1 = reader.next_frame().unwrap().expect("first message");
    match item1 {
        FrameItem::Message(msg) => {
            assert_eq!(msg.method.as_deref(), Some("tools/list"));
            assert_eq!(msg.id, Some(json!(1)));
        }
        _ => panic!("expected Message"),
    }

    let item2 = reader.next_frame().unwrap().expect("second message");
    match item2 {
        FrameItem::Message(msg) => {
            assert_eq!(msg.method.as_deref(), Some("notifications/initialized"));
            assert_eq!(msg.id, None);
        }
        _ => panic!("expected Message"),
    }

    assert!(reader.next_frame().unwrap().is_none());
}

#[test]
fn oversized_line_truncated_and_flagged() {
    let long_line = "A".repeat(120);
    let input = format!("{long_line}\n{{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}}\n");
    let mut reader = LineReader::new(input.as_bytes(), 50);

    let item1 = reader.next_frame().unwrap().expect("first item violation");
    match item1 {
        FrameItem::Violation(v) => {
            assert_eq!(v.event_kind, "proto.violation");
            assert_eq!(v.reason, "oversized_line");
            assert_eq!(v.raw.len(), 50);
        }
        _ => panic!("expected Violation"),
    }

    let item2 = reader.next_frame().unwrap().expect("second item message");
    match item2 {
        FrameItem::Message(msg) => {
            assert_eq!(msg.method.as_deref(), Some("ping"));
        }
        _ => panic!("expected Message"),
    }
}

#[test]
fn non_json_line_flagged_and_skipped() {
    let input =
        b"Python runtime warning: unclosed socket\n{\"jsonrpc\":\"2.0\",\"method\":\"pong\"}\n";
    let mut reader = LineReader::new(&input[..], 1024);

    let item1 = reader.next_frame().unwrap().expect("first item violation");
    match item1 {
        FrameItem::Violation(v) => {
            assert_eq!(v.event_kind, "proto.violation");
            assert_eq!(v.reason, "non_json");
            assert!(v.raw.contains("Python runtime warning"));
        }
        _ => panic!("expected Violation"),
    }

    let item2 = reader.next_frame().unwrap().expect("second item message");
    match item2 {
        FrameItem::Message(msg) => {
            assert_eq!(msg.method.as_deref(), Some("pong"));
        }
        _ => panic!("expected Message"),
    }
}

#[test]
fn writes_compact_json_plus_newline() {
    let msg = JsonRpc::request(
        42,
        "tools/call",
        Some(json!({"name": "add", "arguments": {"a": 1, "b": 2}})),
    );
    let mut out = Vec::new();
    write_msg(&mut out, &msg).unwrap();

    let text = String::from_utf8(out).expect("utf8");
    assert!(text.ends_with('\n'), "must end with newline");
    assert_eq!(
        text.matches('\n').count(),
        1,
        "must have no embedded newlines"
    );

    let parsed: JsonRpc = serde_json::from_str(text.trim()).expect("valid json");
    assert_eq!(parsed, msg);
}

#[test]
fn stdio_transport_thread_handle_cleanup_on_drop() {
    use mcpg_mcp::transport::{McpTransport, StdioTransport};
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
    let reader = LineReader::new(&input[..], 1024);
    let writer = Vec::new();

    let mut transport = StdioTransport::new(writer, reader);
    let item = transport
        .receive(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .unwrap()
        .expect("item");
    assert!(matches!(item, FrameItem::Message(_)));

    drop(transport);
}
