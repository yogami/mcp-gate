#![cfg(target_os = "linux")]

use mcpg_linux::probe::probe;

#[test]
fn probe_detects_user_notif() {
    let caps = probe();
    assert!(caps.seccomp.user_notif);
}

#[test]
fn probe_proc_mem_readable() {
    let caps = probe();
    assert!(caps.proc_mem_readable);
}
