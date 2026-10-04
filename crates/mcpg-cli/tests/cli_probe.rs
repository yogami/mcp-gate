use std::process::Command;

#[test]
#[cfg(not(target_os = "linux"))]
fn run_on_non_linux_exits_69() {
    let bin = env!("CARGO_BIN_EXE_mcp-gate");
    let output = Command::new(bin)
        .arg("run")
        .output()
        .expect("failed to execute mcp-gate");

    assert_eq!(output.status.code(), Some(69));
}

#[test]
#[cfg(target_os = "linux")]
fn probe_json_has_spec_keys() {
    let bin = env!("CARGO_BIN_EXE_mcp-gate");
    let output = Command::new(bin)
        .arg("probe")
        .output()
        .expect("failed to execute mcp-gate");

    assert_eq!(output.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert!(v.get("kernel").is_some());
    assert!(v.get("arch").is_some());
    assert!(v.get("landlock").is_some());
    assert!(v.get("seccomp").is_some());
    assert!(v.get("inotify").is_some());
    assert!(v.get("proc_mem_readable").is_some());
    assert!(v.get("supported").is_some());
    assert!(v.get("missing").is_some());
    assert_eq!(v["supported"], true);
}
