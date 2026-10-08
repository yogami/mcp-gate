//! Phase 0 runner probe tests (SPEC 4.1.1, TASKS Phase 0).
//!
//! Each test runs the compiled `runner-probe` binary and parses its JSON
//! report. Tests never `fork` inside the multi-threaded test harness.

use std::process::Command;

use serde_json::Value;

/// Run `runner-probe` with the given arguments and parse stdout as JSON.
fn probe(args: &[&str]) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_runner-probe"))
        .args(args)
        .output()
        .expect("runner-probe should start");
    assert!(
        out.status.success(),
        "runner-probe {:?} exited with {:?}, stderr: {}",
        args,
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("stdout should be valid JSON")
}

/// TASK-0.1: the envelope carries host fields and an empty `checks` object.
#[test]
fn p0_envelope_has_host_fields() {
    let report = probe(&["--check", "none", "--json"]);

    assert_eq!(report["schema"], "runner-probe/v1");

    let kernel = report["kernel"].as_str().expect("kernel is a string");
    assert!(!kernel.is_empty(), "kernel must not be empty");
    let uname = Command::new("uname")
        .arg("-r")
        .output()
        .expect("uname should run");
    assert_eq!(
        kernel,
        String::from_utf8_lossy(&uname.stdout).trim(),
        "kernel must match `uname -r`"
    );

    let arch = report["arch"].as_str().expect("arch is a string");
    assert!(!arch.is_empty(), "arch must not be empty");

    let checks = report["checks"].as_object().expect("checks is an object");
    assert!(checks.is_empty(), "`--check none` must report no checks");
}

/// TASK-0.3: P0-SPIKE-01, seccomp listener fd received by parent over SCM_RIGHTS.
#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "Linux only")]
fn p0_spike_01_listener_fd_received() {
    let report = probe(&["--check", "P0-SPIKE-01", "--json"]);
    let c = &report["checks"]["P0-SPIKE-01"];
    assert_eq!(
        c["status"], "pass",
        "P0-SPIKE-01 status must be pass, got: {:?}",
        c
    );
    let fd = c["detail"]["listener_fd"]
        .as_i64()
        .expect("listener_fd is integer");
    assert!(fd >= 3, "listener_fd must be >= 3, got {fd}");
}

/// TASK-0.4: P0-SPIKE-02, receive a notification and continue.
#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "Linux only")]
fn p0_spike_02_notification_continue() {
    let report = probe(&["--check", "P0-SPIKE-02", "--json"]);
    let c = &report["checks"]["P0-SPIKE-02"];
    assert_eq!(
        c["status"], "pass",
        "P0-SPIKE-02 status must be pass, got: {:?}",
        c
    );
    assert_eq!(
        c["detail"]["notifications"], 1,
        "must receive exactly 1 notification"
    );
    assert_eq!(
        c["detail"]["child_open_ok"], true,
        "child open must succeed"
    );
}

/// TASK-0.5: P0-SPIKE-03, read the child's path argument and verify NOTIF_ID_VALID.
#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "Linux only")]
fn p0_spike_03_read_path_arg() {
    let report = probe(&["--check", "P0-SPIKE-03", "--json"]);
    let c = &report["checks"]["P0-SPIKE-03"];
    assert_eq!(
        c["status"], "pass",
        "P0-SPIKE-03 status must be pass, got: {:?}",
        c
    );
    let path = c["detail"]["path"].as_str().expect("path is string");
    assert!(
        path == "/etc/hostname" || path == "/etc/hosts",
        "path read from /proc/<pid>/mem must match opened file, got: {path}"
    );
    assert_eq!(
        c["detail"]["id_valid"], true,
        "SECCOMP_IOCTL_NOTIF_ID_VALID must be true"
    );
}

/// TASK-0.6: P0-SPIKE-04, check WAIT_KILLABLE_RECV flag support.
#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "Linux only")]
fn p0_spike_04_wait_killable_recv() {
    let report = probe(&["--check", "P0-SPIKE-04", "--json"]);
    let c = &report["checks"]["P0-SPIKE-04"];
    assert!(
        c["status"] == "info" || c["status"] == "pass",
        "status must be info or pass, got: {:?}",
        c
    );
    assert!(
        c["detail"]["supported"].is_boolean(),
        "detail.supported must be boolean"
    );
}

/// TASK-0.7: P0-SPIKE-05, check Landlock ABI and restriction.
#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "Linux only")]
fn p0_spike_05_landlock_abi() {
    let report = probe(&["--check", "P0-SPIKE-05", "--json"]);
    let c = &report["checks"]["P0-SPIKE-05"];
    assert_eq!(
        c["status"], "pass",
        "P0-SPIKE-05 status must be pass, got: {:?}",
        c
    );
    let abi = c["detail"]["abi"].as_i64().expect("abi is integer");
    assert!(abi >= 1, "Landlock ABI must be >= 1, got: {abi}");
    assert_eq!(
        c["detail"]["enforced"], true,
        "Landlock restriction must be enforced"
    );
}

/// TASK-0.8: P0-SPIKE-06, Landlock plus seccomp in one child.
#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "Linux only")]
fn p0_spike_06_landlock_plus_seccomp() {
    let report = probe(&["--check", "P0-SPIKE-06", "--json"]);
    let c = &report["checks"]["P0-SPIKE-06"];
    assert_eq!(
        c["status"], "pass",
        "P0-SPIKE-06 status must be pass, got: {:?}",
        c
    );
    let notifs = c["detail"]["notifs_seen"]
        .as_i64()
        .expect("notifs_seen is integer");
    assert!(
        notifs >= 2,
        "must see at least 2 notifications, got: {notifs}"
    );
    assert_eq!(c["detail"]["allowed_ok"], true, "allowed open must succeed");
    assert_eq!(
        c["detail"]["denied_blocked"], true,
        "denied open must be blocked by Landlock"
    );
}

/// TASK-0.9: P0-SPIKE-07, inotify catches reads.
#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "Linux only")]
fn p0_spike_07_inotify_catches_reads() {
    let report = probe(&["--check", "P0-SPIKE-07", "--json"]);
    let c = &report["checks"]["P0-SPIKE-07"];
    assert_eq!(
        c["status"], "pass",
        "P0-SPIKE-07 status must be pass, got: {:?}",
        c
    );
    assert_eq!(c["detail"]["open_seen"], true, "IN_OPEN must be observed");
    assert_eq!(
        c["detail"]["access_seen"], true,
        "IN_ACCESS must be observed"
    );
}

/// TASK-0.10: P0-SPIKE-08, inotify on mmap read.
#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "Linux only")]
fn p0_spike_08_inotify_mmap_read() {
    let report = probe(&["--check", "P0-SPIKE-08", "--json"]);
    let c = &report["checks"]["P0-SPIKE-08"];
    assert_eq!(
        c["status"], "pass",
        "P0-SPIKE-08 status must be pass, got: {:?}",
        c
    );
    assert_eq!(
        c["detail"]["open_seen"], true,
        "IN_OPEN must be observed on mmap read"
    );
}

/// Run `runner-probe` with custom env vars.
fn probe_with_env(args: &[&str], envs: &[(&str, &str)]) -> Value {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_runner-probe"));
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("runner-probe should start");
    assert!(
        out.status.success(),
        "runner-probe {:?} exited with {:?}, stderr: {}",
        args,
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("stdout should be valid JSON")
}

/// TASK-0.11: P0-SPIKE-09, non-dumpable parent hides its environment.
#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "Linux only")]
fn p0_spike_09_dumpable_zero_hides_environ() {
    let report = probe_with_env(
        &["--check", "P0-SPIKE-09", "--json"],
        &[("MCPG_SPIKE_SECRET", "s3-canary-secret-12345")],
    );
    let c = &report["checks"]["P0-SPIKE-09"];
    assert_eq!(
        c["status"], "pass",
        "P0-SPIKE-09 status must be pass, got: {:?}",
        c
    );
    assert_eq!(
        c["detail"]["errno"], "EACCES",
        "detail.errno must be EACCES"
    );
    assert_eq!(
        c["detail"]["secret_seen"], false,
        "detail.secret_seen must be false"
    );
}

/// TASK-0.12: P0-SPIKE-10, notification overhead benchmark.
#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "Linux only")]
fn p0_spike_10_overhead_ratio() {
    let report = probe(&["--check", "P0-SPIKE-10", "--iterations", "10000", "--json"]);
    let c = &report["checks"]["P0-SPIKE-10"];
    assert_eq!(
        c["status"], "info",
        "P0-SPIKE-10 status must be info, got: {:?}",
        c
    );
    let ratio = c["detail"]["ratio"].as_f64().expect("ratio is a float");
    assert!(ratio.is_finite(), "ratio must be finite: {ratio}");
    assert!(ratio > 0.0, "ratio must be > 0: {ratio}");
}
