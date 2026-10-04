#![cfg(target_os = "linux")]

use std::process::Command;

use mcpg_linux::self_harden::harden_self;

#[test]
fn harden_self_hides_environ_from_children() {
    let pid = std::process::id();
    let own_environ_path = format!("/proc/{pid}/environ");

    // Before hardening: readable by self
    let self_bytes = std::fs::read(&own_environ_path).expect("read own /proc/<pid>/environ");
    let self_str = String::from_utf8_lossy(&self_bytes);
    assert!(self_str.contains("PATH"), "own environ must contain PATH");

    // Harden current process
    harden_self().expect("harden_self must succeed");

    // After hardening: child cat cannot read /proc/<pid>/environ
    let output = Command::new("cat")
        .arg(&own_environ_path)
        .output()
        .expect("spawn cat command");

    assert!(
        !output.status.success(),
        "child cat should not be able to read hardened process environ"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("permission denied"),
        "stderr should mention permission denied, got: {stderr}"
    );
}
