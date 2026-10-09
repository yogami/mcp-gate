use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use assert_cmd::Command as AssertCommand;
use serde_json::Value;

#[test]
fn test_env() {
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd.arg("env").assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert!(val.get("keys").is_some());
    let keys = val["keys"].as_array().expect("keys array");
    assert!(!keys.is_empty());
}

#[test]
fn test_fds() {
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd.arg("fds").assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert!(val.get("fds").is_some());
    let fds = val["fds"].as_array().expect("fds array");
    assert!(!fds.is_empty());
    let fd_nums: Vec<i64> = fds.iter().filter_map(|v| v.as_i64()).collect();
    assert!(fd_nums.contains(&0));
    assert!(fd_nums.contains(&1));
    assert!(fd_nums.contains(&2));
}

#[test]
fn test_cwd() {
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd.arg("cwd").assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert!(val.get("cwd").is_some());
    let cwd = val["cwd"].as_str().expect("cwd string");
    assert!(!cwd.is_empty());
}

#[test]
fn test_ids() {
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd.arg("ids").assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert!(val["pid"].as_i64().is_some());
    assert!(val["pgid"].as_i64().is_some());
    assert!(val["sid"].as_i64().is_some());
    assert!(val["umask"].as_i64().is_some());
    assert!(val["NoNewPrivs"].as_bool().is_some() || val["no_new_privs"].as_bool().is_some());
}

#[test]
fn test_read() {
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd.arg("read").arg("Cargo.toml").assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert_eq!(val["status"], "ok");

    let mut cmd_err = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert_err = cmd_err
        .arg("read")
        .arg("/nonexistent_path_probe")
        .assert()
        .success();
    let output_err = String::from_utf8(assert_err.get_output().stdout.clone()).unwrap();
    let val_err: Value = serde_json::from_str(output_err.trim()).expect("valid json line");
    assert_eq!(val_err["status"], "error");
    assert_eq!(val_err["error"], "ENOENT");
}

#[test]
fn test_write() {
    let tmp = std::env::temp_dir().join(format!("probe_write_{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);

    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd
        .arg("write")
        .arg(&tmp)
        .arg("hello probe")
        .assert()
        .success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert_eq!(val["status"], "ok");
    assert_eq!(val["ok"], true);
    assert_eq!(std::fs::read_to_string(&tmp).unwrap(), "hello probe");
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn test_exec() {
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd
        .arg("exec")
        .arg("/nonexistent_bin_probe")
        .assert()
        .success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert_eq!(val["status"], "error");
    assert_eq!(val["error"], "ENOENT");
}

#[test]
fn test_sleep() {
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd.arg("sleep").arg("0.01").assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert_eq!(val["status"], "slept");
}

#[test]
fn test_wait_stdin_eof() {
    let bin_path = assert_cmd::cargo::cargo_bin("syscall-probe");
    let mut child = Command::new(bin_path)
        .arg("wait-stdin-eof")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn child");

    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait output");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let val: Value = serde_json::from_str(text.trim()).expect("valid json line");
    assert_eq!(val["status"], "eof");
}

#[test]
fn test_ignore_sigterm() {
    let bin_path = assert_cmd::cargo::cargo_bin("syscall-probe");
    let mut child = Command::new(bin_path)
        .arg("ignore-sigterm")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn child");

    let pid = child.id() as i32;

    thread::sleep(Duration::from_millis(50));

    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }

    thread::sleep(Duration::from_millis(50));
    assert_eq!(
        unsafe { libc::kill(pid, 0) },
        0,
        "child should ignore SIGTERM"
    );

    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = child.wait();
}

#[test]
fn test_daemon() {
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd.arg("daemon").assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert!(val.get("pid").is_some());
    let grandchild_pid = val["pid"].as_i64().expect("grandchild pid") as i32;
    assert!(grandchild_pid > 0);

    assert_eq!(unsafe { libc::kill(grandchild_pid, 0) }, 0);

    unsafe {
        libc::kill(grandchild_pid, libc::SIGKILL);
    }
}

#[test]
fn test_openat_dirfd() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd
        .arg("openat-dirfd")
        .arg(manifest_dir)
        .arg("Cargo.toml")
        .assert()
        .success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert_eq!(val["status"], "ok");
    assert_eq!(val["ok"], true);
}

#[test]
fn test_openat2() {
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd.arg("openat2").arg("Cargo.toml").assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    #[cfg(target_os = "linux")]
    {
        assert_eq!(val["status"], "ok");
        assert_eq!(val["ok"], true);
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(val["status"], "error");
        assert_eq!(val["error"], "ENOSYS");
    }
}

#[test]
fn test_vfork_exec() {
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let bin = if cfg!(target_os = "linux") {
        "/bin/true"
    } else {
        "/usr/bin/true"
    };
    let assert = cmd.arg("vfork-exec").arg(bin).assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    #[cfg(target_os = "linux")]
    {
        assert_eq!(val["status"], "ok");
        assert_eq!(val["exit_code"], 0);
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(val["status"], "error");
        assert_eq!(val["error"], "ENOSYS");
    }
}

#[test]
fn test_clone_newuser() {
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd.arg("clone-newuser").assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert!(val.get("status").is_some());
}

#[test]
fn test_io_uring() {
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd.arg("io-uring").assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert!(val.get("status").is_some());
}

#[test]
fn test_x32_syscall() {
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd.arg("x32-syscall").assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert!(val.get("status").is_some());
}

#[test]
#[test]
fn test_threads_open() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd.arg("threads-open").arg(path).assert().success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert_eq!(val["status"], "ok");
    assert_eq!(val["count"], 8000);
}

#[test]
fn test_deep_symlink() {
    let tmp = std::env::temp_dir().join(format!("probe_deep_symlink_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd
        .arg("deep-symlink")
        .arg(tmp.to_str().unwrap())
        .assert()
        .success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert_eq!(val["status"], "error");
    assert_eq!(val["error"], "ELOOP");
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_execveat() {
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd
        .arg("execveat")
        .arg("/bin")
        .arg("true")
        .assert()
        .success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    if !output.trim().is_empty() {
        let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
        assert!(val.get("status").is_some());
    }

#[test]
fn test_sendto_addr() {
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    let mut cmd = AssertCommand::cargo_bin("syscall-probe").unwrap();
    let assert = cmd
        .arg("sendto-addr")
        .arg("127.0.0.1")
        .arg(port.to_string())
        .arg("hello-udp")
        .assert()
        .success();
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let val: Value = serde_json::from_str(output.trim()).expect("valid json line");
    assert_eq!(val["status"], "ok");
    assert_eq!(val["bytes"], 9);
}
