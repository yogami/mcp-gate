use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mcpg_mcp::deadline::{Clock, SystemClock};

pub struct FakeClock(pub std::sync::RwLock<std::time::Instant>);
impl FakeClock {
    pub fn new(start: std::time::Instant) -> Self { Self(std::sync::RwLock::new(start)) }
    pub fn advance(&self, d: std::time::Duration) { *self.0.write().unwrap() += d; }
}
impl Clock for FakeClock {
    fn now(&self) -> std::time::Instant { *self.0.read().unwrap() }
}

use mcpg_domain::config::LimitsConfig;
use mcpg_mcp::client::{DriverError, McpClient};
use mcpg_mcp::deadline::DeadlineTracker;
use mcpg_mcp::framing::{FrameItem, JsonRpc};
use mcpg_mcp::transport::McpTransport;
use serde_json::json;

/// This fake checks the deadline given to the transport, rather than making
/// send advance time and relying on a post-response timeout check.
struct DeadlineAssertingTransport {
    expected_deadline: Instant,
    receives: usize,
}

impl McpTransport for DeadlineAssertingTransport {
    fn send(&mut self, _: &JsonRpc) -> io::Result<()> {
        Ok(())
    }

    fn receive(&mut self, deadline: Instant) -> io::Result<Option<FrameItem>> {
        assert_eq!(deadline, self.expected_deadline);
        self.receives += 1;
        Err(io::Error::new(io::ErrorKind::TimedOut, "silent server"))
    }
}

#[test]
fn startup_deadline_is_passed_to_receive_from_injected_clock() {
    // Intentionally far from the system clock: mixing clocks must fail.
    let start = Instant::now() + Duration::from_secs(3600);
    let clock = Arc::new(FakeClock::new(start));
    let limits = LimitsConfig {
        startup_timeout_s: 5,
        total_timeout_s: 60,
        ..Default::default()
    };
    let transport = DeadlineAssertingTransport {
        expected_deadline: start + Duration::from_secs(5),
        receives: 0,
    };
    let mut client =
        McpClient::new(transport).with_deadline_tracker(DeadlineTracker::new(clock, limits));
    let error = client
        .initialize(&["2024-11-05".into()], false)
        .unwrap_err();
    assert!(
        matches!(
            error,
            DriverError::Inconclusive(ref message) if message.contains("initialize timeout") || message.contains("startup timeout")
        ),
        "Actual error: {:?}", error
    );
    assert_eq!(client.transport().receives, 1);
}

#[test]
fn custom_call_deadline_uses_injected_clock() {
    let start = Instant::now() + Duration::from_secs(3600);
    let clock = Arc::new(FakeClock::new(start));
    let limits = LimitsConfig {
        call_timeout_s: 30,
        total_timeout_s: 60,
        ..Default::default()
    };
    let transport = DeadlineAssertingTransport {
        expected_deadline: start + Duration::from_secs(2),
        receives: 0,
    };
    let mut client =
        McpClient::new(transport).with_deadline_tracker(DeadlineTracker::new(clock, limits));
    assert!(matches!(
        client.call_tool_with_timeout("silent", &json!({}), Some(2)),
        Err(DriverError::Inconclusive(_))
    ));
    assert_eq!(client.transport().receives, 1);
}

#[test]
fn total_deadline_caps_startup_receive_deadline() {
    let start = Instant::now() + Duration::from_secs(3600);
    let clock = Arc::new(FakeClock::new(start));
    let limits = LimitsConfig {
        startup_timeout_s: 30,
        total_timeout_s: 3,
        ..Default::default()
    };
    let transport = DeadlineAssertingTransport {
        expected_deadline: start + Duration::from_secs(3),
        receives: 0,
    };
    let mut client =
        McpClient::new(transport).with_deadline_tracker(DeadlineTracker::new(clock, limits));
    assert!(client.initialize(&["2024-11-05".into()], false).is_err());
    assert_eq!(client.transport().receives, 1);
}

#[cfg(unix)]
#[test]
fn silent_real_stdio_server_times_out_during_startup_and_call() {
    use std::io::BufReader;
    use std::process::{Command, Stdio};

    use mcpg_mcp::framing::LineReader;
    use mcpg_mcp::transport::StdioTransport;

    // cat keeps stdin/stdout open but never returns a matching JSON-RPC
    // response: echoed requests are dispatched as server requests.
    for startup in [true, false] {
        let mut child = Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let transport = StdioTransport::new(stdin, LineReader::new(BufReader::new(stdout), 4096));
        let clock = Arc::new(SystemClock);
        let started = clock.now();
        let limits = LimitsConfig {
            startup_timeout_s: 1,
            call_timeout_s: 1,
            total_timeout_s: 30,
            ..Default::default()
        };
        let mut client =
            McpClient::new(transport).with_deadline_tracker(DeadlineTracker::new(clock, limits));

        let result = if startup {
            client.initialize(&["2024-11-05".into()], false).map(|_| ())
        } else {
            client.call_tool("silent", &json!({})).map(|_| ())
        };
        let elapsed = started.elapsed();

        // Always terminate and reap the real child before asserting.
        let _ = child.kill();
        let _ = child.wait();
        drop(client);

        assert!(
            matches!(result, Err(DriverError::Inconclusive(_))),
            "{result:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(900),
            "Elapsed: {elapsed:?}, Result: {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "startup/call timeout was not enforced: {elapsed:?}"
        );
    }
}
