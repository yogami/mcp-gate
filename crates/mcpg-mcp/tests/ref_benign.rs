use std::fs;
use std::io::BufReader;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use mcpg_mcp::client::McpClient;
use mcpg_mcp::framing::LineReader;
use mcpg_mcp::transport::StdioTransport;
use serde_json::json;

static COUNTER: AtomicU64 = AtomicU64::new(1);

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

struct BenignProcess {
    child: Child,
    client: McpClient<StdioTransport<ChildStdin, BufReader<ChildStdout>>>,
}

impl BenignProcess {
    fn spawn(root: &Path, env_home: Option<&Path>) -> Self {
        let server_py = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/servers/benign/server.py")
            .canonicalize()
            .expect("find server.py");

        let mut cmd = Command::new("python3");
        cmd.arg(&server_py).arg("--root").arg(root);
        if let Some(home) = env_home {
            cmd.env("HOME", home);
        }
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());

        let mut child = cmd.spawn().expect("spawn python3 server.py");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
        let transport = StdioTransport::new(stdin, LineReader::new(stdout, 1024 * 1024));
        let mut client = McpClient::new(transport);

        client
            .initialize(&["2024-11-05".to_string()], true)
            .expect("handshake with benign server");

        Self { child, client }
    }
}

impl Drop for BenignProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn benign_lists_six_tools() {
    let ws = AutoCleanDir::new("benign_ws");
    let mut proc = BenignProcess::spawn(ws.path(), None);

    let tools = proc.client.list_tools().expect("list tools");
    assert_eq!(tools.len(), 6);

    let names: Vec<String> = tools.into_iter().map(|t| t.name).collect();
    assert!(names.contains(&"read_file".to_string()));
    assert!(names.contains(&"write_file".to_string()));
    assert!(names.contains(&"list_dir".to_string()));
    assert!(names.contains(&"hash_file".to_string()));
    assert!(names.contains(&"sort_lines".to_string()));
    assert!(names.contains(&"ssh_fingerprint".to_string()));
}

#[test]
fn read_file_inside_ok() {
    let ws = AutoCleanDir::new("benign_read_ok");
    let file_path = ws.path().join("inside.txt");
    fs::write(&file_path, "contents of inside file").expect("write test file");

    let mut proc = BenignProcess::spawn(ws.path(), None);
    let res = proc
        .client
        .call_tool("read_file", &json!({ "path": "inside.txt" }))
        .expect("call read_file");

    assert!(!res.is_error);
    assert_eq!(res.text_content(), "contents of inside file");
}

#[test]
fn read_file_escape_is_tool_error() {
    let parent = AutoCleanDir::new("benign_escape_parent");
    let outside_file = parent.path().join("secret.txt");
    fs::write(&outside_file, "super-secret-password").expect("write outside file");

    let ws = parent.path().join("workspace");
    fs::create_dir_all(&ws).expect("create ws");

    let symlink_path = ws.join("symlink_outside");
    symlink(&outside_file, &symlink_path).expect("create symlink");

    let mut proc = BenignProcess::spawn(&ws, None);

    // 1. Relative dotdot escape
    let res_dotdot = proc
        .client
        .call_tool("read_file", &json!({ "path": "../secret.txt" }))
        .expect("call read_file dotdot");
    assert!(
        res_dotdot.is_error,
        "dotdot escape must return isError: true"
    );

    // 2. Absolute path escape
    let abs_str = outside_file.to_str().expect("valid utf8");
    let res_abs = proc
        .client
        .call_tool("read_file", &json!({ "path": abs_str }))
        .expect("call read_file absolute");
    assert!(
        res_abs.is_error,
        "absolute escape must return isError: true"
    );

    // 3. Symlink pointing outside
    let res_sym = proc
        .client
        .call_tool("read_file", &json!({ "path": "symlink_outside" }))
        .expect("call read_file symlink");
    assert!(res_sym.is_error, "symlink escape must return isError: true");
}

#[test]
fn write_file_inside_ok() {
    let ws = AutoCleanDir::new("benign_write_ok");
    let mut proc = BenignProcess::spawn(ws.path(), None);

    let res = proc
        .client
        .call_tool(
            "write_file",
            &json!({ "path": "created.txt", "body": "hello world from benign" }),
        )
        .expect("call write_file");

    assert!(!res.is_error);
    let disk_content =
        fs::read_to_string(ws.path().join("created.txt")).expect("read created file");
    assert_eq!(disk_content, "hello world from benign");
}

#[test]
fn sort_lines_uses_usr_bin_sort() {
    let ws = AutoCleanDir::new("benign_sort");
    let mut proc = BenignProcess::spawn(ws.path(), None);

    let lines = vec!["pear", "apple", "orange", "banana"];
    let res = proc
        .client
        .call_tool("sort_lines", &json!({ "lines": lines }))
        .expect("call sort_lines");

    assert!(!res.is_error);
    let sorted = res.text_content();
    let sorted_lines: Vec<&str> = sorted.lines().collect();
    assert_eq!(sorted_lines, vec!["apple", "banana", "orange", "pear"]);
}

#[test]
fn ssh_fingerprint_reads_pub_key() {
    let fake_home = AutoCleanDir::new("fake_home");
    let ssh_dir = fake_home.path().join(".ssh");
    fs::create_dir_all(&ssh_dir).expect("create .ssh dir");

    let key_content = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTesting user@test";
    fs::write(ssh_dir.join("id_ed25519.pub"), key_content).expect("write pub key");

    let ws = AutoCleanDir::new("benign_ssh_ws");
    let mut proc = BenignProcess::spawn(ws.path(), Some(fake_home.path()));

    let res = proc
        .client
        .call_tool("ssh_fingerprint", &json!({}))
        .expect("call ssh_fingerprint");

    assert!(!res.is_error);
    assert_eq!(res.text_content(), key_content);
}
