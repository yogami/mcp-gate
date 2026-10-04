use std::fs;
use std::io::{BufReader, Read};
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mcpg_mcp::client::McpClient;
use mcpg_mcp::framing::LineReader;
use mcpg_mcp::transport::StdioTransport;
use serde_json::json;

static COUNTER: AtomicU64 = AtomicU64::new(100);

struct AutoCleanDir(PathBuf);

impl AutoCleanDir {
    fn new(prefix: &str) -> Self {
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("mcpg_{prefix}_{}_{}", std::process::id(), count));
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for AutoCleanDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct VulnProcess {
    child: Child,
    client: McpClient<StdioTransport<ChildStdin, BufReader<ChildStdout>>>,
}

impl VulnProcess {
    fn spawn(
        defect: &str,
        root: &Path,
        env_home: Option<&Path>,
        marker: Option<&Path>,
        socket: Option<&Path>,
        extra_env: Option<(&str, &str)>,
    ) -> Self {
        let server_py = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/servers/vulnerable/server.py")
            .canonicalize()
            .expect("find vulnerable server.py");

        let mut cmd = Command::new("python3");
        cmd.arg(&server_py)
            .arg("--defect")
            .arg(defect)
            .arg("--root")
            .arg(root);

        if let Some(m) = marker {
            cmd.arg("--marker-file").arg(m);
        }
        if let Some(s) = socket {
            cmd.arg("--socket-path").arg(s);
        }
        if let Some(home) = env_home {
            cmd.env("HOME", home);
        }
        if let Some((k, v)) = extra_env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());

        let mut child = cmd.spawn().expect("spawn vulnerable server.py");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
        let transport = StdioTransport::new(stdin, LineReader::new(stdout, 1024 * 1024));
        let mut client = McpClient::new(transport);

        client
            .initialize(&["2024-11-05".to_string()], true)
            .expect("handshake with vulnerable server");

        Self { child, client }
    }
}

impl Drop for VulnProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn vuln_naive_read() {
    let parent = AutoCleanDir::new("vuln_naive_read");
    let outside_file = parent.path().join("outside_secret.txt");
    fs::write(&outside_file, "secret-outside-content").unwrap();

    let ws = parent.path().join("workspace");
    fs::create_dir_all(&ws).unwrap();

    let mut proc = VulnProcess::spawn("naive-read", &ws, None, None, None, None);
    let res = proc
        .client
        .call_tool("read_file", &json!({ "path": "../outside_secret.txt" }))
        .expect("call read_file");

    assert!(!res.is_error);
    assert_eq!(res.text_content(), "secret-outside-content");
}

#[test]
fn vuln_naive_write() {
    let parent = AutoCleanDir::new("vuln_naive_write");
    let ws = parent.path().join("workspace");
    fs::create_dir_all(&ws).unwrap();

    let mut proc = VulnProcess::spawn("naive-write", &ws, None, None, None, None);
    let res = proc
        .client
        .call_tool(
            "write_file",
            &json!({ "path": "../escaped_write.txt", "body": "escaped-payload" }),
        )
        .expect("call write_file");

    assert!(!res.is_error);
    let written_file = parent.path().join("escaped_write.txt");
    assert!(written_file.exists());
    assert_eq!(fs::read_to_string(written_file).unwrap(), "escaped-payload");
}

#[test]
fn vuln_startup_read() {
    let temp = AutoCleanDir::new("vuln_startup_read");
    let marker = temp.path().join("marker.txt");
    let fake_home = temp.path().join("home");
    let aws_dir = fake_home.join(".aws");
    fs::create_dir_all(&aws_dir).unwrap();
    fs::write(aws_dir.join("credentials"), "aws_secret_key=xyz").unwrap();

    let server_py = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/servers/vulnerable/server.py")
        .canonicalize()
        .expect("find vulnerable server.py");

    let mut cmd = Command::new("python3");
    cmd.arg(&server_py)
        .arg("--defect")
        .arg("startup-read")
        .arg("--root")
        .arg(temp.path())
        .arg("--marker-file")
        .arg(&marker)
        .env("HOME", &fake_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn vulnerable server");
    // Wait up to 1 second for process startup code to execute before initialize
    for _ in 0..50 {
        if marker.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // Verify marker was touched before initialize
    assert!(
        marker.exists(),
        "marker file must be touched before initialize"
    );
    let marker_text = fs::read_to_string(&marker).unwrap();
    assert!(marker_text.contains("startup-read-executed"));

    let stdin = child.stdin.take().expect("child stdin");
    let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
    let transport = StdioTransport::new(stdin, LineReader::new(stdout, 1024 * 1024));
    let mut client = McpClient::new(transport);

    client
        .initialize(&["2024-11-05".to_string()], true)
        .expect("initialize succeeds");

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn vuln_config_echo() {
    let fake_home = AutoCleanDir::new("vuln_config_home");
    let aws_dir = fake_home.path().join(".aws");
    fs::create_dir_all(&aws_dir).unwrap();
    fs::write(
        aws_dir.join("credentials"),
        "aws_access_key_id = AKIA_LEAKED_CONFIG_TOKEN\n",
    )
    .unwrap();

    let ws = AutoCleanDir::new("vuln_config_ws");
    let mut proc = VulnProcess::spawn(
        "config-echo",
        ws.path(),
        Some(fake_home.path()),
        None,
        None,
        None,
    );

    let res = proc
        .client
        .call_tool("get_config", &json!({}))
        .expect("call get_config");

    assert!(!res.is_error);
    assert!(res.text_content().contains("AKIA_LEAKED_CONFIG_TOKEN"));
}

#[test]
fn vuln_env_echo() {
    let ws = AutoCleanDir::new("vuln_env_ws");
    let mut proc = VulnProcess::spawn(
        "env-echo",
        ws.path(),
        None,
        None,
        None,
        Some(("SECRET_CANARY_VAR", "super_confidential_canary_42")),
    );

    let res = proc
        .client
        .call_tool("debug_env", &json!({}))
        .expect("call debug_env");

    assert!(!res.is_error);
    assert!(res.text_content().contains("super_confidential_canary_42"));
}

#[test]
fn vuln_shell_out() {
    let ws = AutoCleanDir::new("vuln_shell_ws");
    let mut proc = VulnProcess::spawn("shell-out", ws.path(), None, None, None, None);

    let res = proc
        .client
        .call_tool("run_check", &json!({ "cmd": "echo shell_execution_ok" }))
        .expect("call run_check");

    assert!(!res.is_error);
    assert!(res.text_content().contains("shell_execution_ok"));
}

#[test]
fn vuln_net_call() {
    let ws = AutoCleanDir::new("vuln_net_ws");
    let mut proc = VulnProcess::spawn("net-call", ws.path(), None, None, None, None);

    let res = proc
        .client
        .call_tool("fetch", &json!({ "url": "http://127.0.0.1:9" }))
        .expect("call fetch");

    assert!(res.is_error);
    let msg = res.text_content();
    assert!(
        msg.contains("Connection refused")
            || msg.contains("connection failed")
            || msg.contains("ECONNREFUSED")
            || msg.contains("61")
            || msg.contains("111")
    );
}

#[test]
fn vuln_unix_sock() {
    let temp = AutoCleanDir::new("vuln_sock_dir");
    let sock_path = temp.path().join("test_vuln.sock");

    let listener = UnixListener::bind(&sock_path).expect("bind unix socket");

    let mut proc = VulnProcess::spawn("unix-sock", temp.path(), None, None, Some(&sock_path), None);

    let sock_str = sock_path.to_str().unwrap();
    let res = proc
        .client
        .call_tool("connect_socket", &json!({ "path": sock_str }))
        .expect("call connect_socket");
    assert!(!res.is_error);

    let (mut stream, _) = listener.accept().expect("accept connection from server");
    let mut buf = String::new();
    stream.read_to_string(&mut buf).expect("read from socket");
    assert!(buf.contains("ping from vulnerable server"));
}

#[test]
fn vuln_proc_peek() {
    let ws = AutoCleanDir::new("vuln_proc_ws");
    let mut proc = VulnProcess::spawn("proc-peek", ws.path(), None, None, None, None);

    let res = proc
        .client
        .call_tool("peek_proc", &json!({}))
        .expect("call peek_proc");

    let msg = res.text_content();
    assert!(msg.contains("/proc/") && msg.contains("environ"));
}

#[test]
fn vuln_symlink_follow() {
    let parent = AutoCleanDir::new("vuln_symlink_parent");
    let outside_target = parent.path().join("outside_id_ed25519");
    fs::write(&outside_target, "private_key_content").unwrap();

    let ws = parent.path().join("workspace");
    fs::create_dir_all(&ws).unwrap();

    let link_path = ws.join("mcpg-link");
    symlink(&outside_target, &link_path).expect("create symlink");

    let mut proc = VulnProcess::spawn("symlink-follow", &ws, None, None, None, None);
    let res = proc
        .client
        .call_tool("read_file", &json!({ "path": "mcpg-link" }))
        .expect("call read_file");

    assert!(!res.is_error);
    assert_eq!(res.text_content(), "private_key_content");
}

#[test]
fn vuln_netrc_read() {
    let fake_home = AutoCleanDir::new("vuln_netrc_home");
    let netrc_file = fake_home.path().join(".netrc");
    fs::write(
        &netrc_file,
        "machine api.github.com login token password secret_auth_token_xyz\n",
    )
    .unwrap();

    let ws = AutoCleanDir::new("vuln_netrc_ws");
    let mut proc = VulnProcess::spawn(
        "netrc-read",
        ws.path(),
        Some(fake_home.path()),
        None,
        None,
        None,
    );

    let res = proc
        .client
        .call_tool("read_netrc", &json!({}))
        .expect("call read_netrc");

    assert!(!res.is_error);
    assert!(res.text_content().contains("secret_auth_token_xyz"));
}
