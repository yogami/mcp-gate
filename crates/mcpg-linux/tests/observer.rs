use std::path::PathBuf;
use std::sync::Arc;

use mcpg_app::capsule_plan::Mode;
use mcpg_domain::event::EventKind;
use mcpg_domain::host::{Feature, HostCaps};
use mcpg_domain::verdict::ExitCode;
use mcpg_linux::observer::{
    syscalls, MockMemoryReader, ObserverConfig, ObserverEngine, CLONE_NEWUSER,
    SECCOMP_USER_NOTIF_FLAG_CONTINUE, X32_SYSCALL_BIT,
};

#[test]
fn p2_obs_01_openat_dirfd() {
    let mut reader = MockMemoryReader::default();
    reader.links.insert(
        PathBuf::from("/proc/1000/fd/3"),
        PathBuf::from("/workspace/subdir"),
    );
    reader
        .strings
        .insert((1000, 0x1000), "target.txt".to_string());
    reader
        .strings
        .insert((1000, 0x2000), "../../outside.txt".to_string());

    let cfg = ObserverConfig::default();
    let engine = ObserverEngine::new(cfg, reader);

    // Valid relative path via dirfd 3
    let res = engine.handle_syscall(1000, syscalls::SYS_OPENAT, [3, 0x1000, 0, 0, 0, 0]);
    assert_eq!(res.flags, SECCOMP_USER_NOTIF_FLAG_CONTINUE);
    assert_eq!(res.error, 0);
    assert!(res.violation.is_none());
    let ev = res.event.expect("event emitted");
    assert_eq!(ev.kind, EventKind::FsOpen);
    assert_eq!(
        ev.resolved,
        Some(PathBuf::from("/workspace/subdir/target.txt"))
    );

    // Traversal attempting escape via ..
    let res_escape = engine.handle_syscall(1000, syscalls::SYS_OPENAT, [3, 0x2000, 0, 0, 0, 0]);
    assert_eq!(res_escape.flags, 0);
    assert_eq!(res_escape.error, -libc::EACCES);
    let vio = res_escape.violation.expect("violation emitted");
    assert_eq!(vio.0, "MCPG005");
    assert!(vio.1.contains("Path traversal detected"));
}

#[test]
fn p2_obs_02_openat2() {
    let mut reader = MockMemoryReader::default();
    reader
        .strings
        .insert((1000, 0x1000), "/workspace/data.json".to_string());

    let cfg = ObserverConfig::default();
    let engine = ObserverEngine::new(cfg, reader);

    let res = engine.handle_syscall(1000, syscalls::SYS_OPENAT2, [0, 0x1000, 0, 0, 0, 0]);
    assert_eq!(res.flags, SECCOMP_USER_NOTIF_FLAG_CONTINUE);
    assert_eq!(res.error, 0);
    assert!(res.violation.is_none());
    let ev = res.event.expect("event emitted");
    assert_eq!(ev.kind, EventKind::FsOpen);
    assert_eq!(ev.resolved, Some(PathBuf::from("/workspace/data.json")));
}

#[test]
fn p2_obs_03_vfork_exec() {
    let mut reader = MockMemoryReader::default();
    reader
        .strings
        .insert((1000, 0x1000), "/usr/bin/sort".to_string());
    reader
        .strings
        .insert((1000, 0x2000), "/usr/bin/curl".to_string());

    let cfg = ObserverConfig {
        root_command: Some(PathBuf::from("/usr/bin/python3")),
        allowed_child_binaries: vec![PathBuf::from("/usr/bin/sort")],
        ..Default::default()
    };
    let engine = ObserverEngine::new(cfg, reader);

    // Allowed child binary
    let res_allowed = engine.handle_syscall(1000, syscalls::SYS_EXECVE, [0x1000, 0, 0, 0, 0, 0]);
    assert_eq!(res_allowed.flags, SECCOMP_USER_NOTIF_FLAG_CONTINUE);
    assert_eq!(res_allowed.error, 0);
    assert!(res_allowed.violation.is_none());
    assert_eq!(
        res_allowed.event.unwrap().decision,
        mcpg_domain::event::Decision::Allowed
    );

    // Unapproved child binary
    let res_denied = engine.handle_syscall(1000, syscalls::SYS_EXECVE, [0x2000, 0, 0, 0, 0, 0]);
    assert_eq!(res_denied.flags, 0);
    assert_eq!(res_denied.error, -libc::EACCES);
    let vio = res_denied.violation.expect("violation emitted");
    assert_eq!(vio.0, "MCPG006");
    assert!(vio.1.contains("Unapproved child process"));
    assert_eq!(
        res_denied.event.unwrap().decision,
        mcpg_domain::event::Decision::Denied
    );
}

#[test]
fn p2_obs_04_clone_newuser() {
    let reader = MockMemoryReader::default();
    let cfg = ObserverConfig::default();
    let engine = ObserverEngine::new(cfg, reader);

    let res = engine.handle_syscall(1000, syscalls::SYS_CLONE, [CLONE_NEWUSER, 0, 0, 0, 0, 0]);
    assert_eq!(res.flags, 0);
    assert_eq!(res.error, -libc::EPERM);
    let vio = res.violation.expect("violation emitted");
    assert_eq!(vio.0, "MCPG010");
    assert!(vio.1.contains("CLONE_NEWUSER denial"));
    assert_eq!(res.event.unwrap().kind, EventKind::TamperDenied);
}

#[test]
fn p2_obs_05_io_uring() {
    let reader = MockMemoryReader::default();
    let cfg = ObserverConfig::default();
    let engine = ObserverEngine::new(cfg, reader);

    let res = engine.handle_syscall(1000, syscalls::SYS_IO_URING_SETUP, [0, 0, 0, 0, 0, 0]);
    assert_eq!(res.flags, 0);
    assert_eq!(res.error, -libc::ENOSYS);
    let vio = res.violation.expect("violation emitted");
    assert_eq!(vio.0, "MCPG010");
    assert!(vio.1.contains("io_uring denial"));
    assert_eq!(res.event.unwrap().kind, EventKind::TamperDenied);
}

#[test]
fn p2_obs_06_x32_syscall() {
    let reader = MockMemoryReader::default();
    let cfg = ObserverConfig::default();
    let engine = ObserverEngine::new(cfg, reader);

    let x32_nr = syscalls::SYS_OPENAT | X32_SYSCALL_BIT;
    let res = engine.handle_syscall(1000, x32_nr, [0, 0, 0, 0, 0, 0]);
    assert_eq!(res.flags, 0);
    assert_eq!(res.error, -libc::ENOSYS);
    let vio = res.violation.expect("violation emitted");
    assert_eq!(vio.0, "MCPG010");
    assert!(vio.1.contains("x32 ABI"));
    assert_eq!(res.event.unwrap().kind, EventKind::TamperDenied);
}

#[test]
fn p2_obs_07_kill_minus_one() {
    let reader = MockMemoryReader::default();
    let cfg = ObserverConfig {
        capsule_pids: vec![1000, 1001],
        ..Default::default()
    };
    let engine = ObserverEngine::new(cfg, reader);

    // Target -1 (broadcast kill)
    let res_all = engine.handle_syscall(1000, syscalls::SYS_KILL, [-1i64 as u64, 9, 0, 0, 0, 0]);
    assert_eq!(res_all.flags, 0);
    assert_eq!(res_all.error, -libc::EPERM);
    assert_eq!(res_all.violation.unwrap().0, "MCPG010");
    assert_eq!(res_all.event.unwrap().kind, EventKind::SignalSend);

    // Target foreign PID (9999 is outside capsule_pids)
    let res_foreign = engine.handle_syscall(1000, syscalls::SYS_KILL, [9999, 9, 0, 0, 0, 0]);
    assert_eq!(res_foreign.flags, 0);
    assert_eq!(res_foreign.error, -libc::EPERM);
    assert_eq!(res_foreign.violation.unwrap().0, "MCPG010");
    assert_eq!(res_foreign.event.unwrap().kind, EventKind::SignalSend);

    // Target intra-capsule PID (1001 is inside capsule_pids)
    let res_intra = engine.handle_syscall(1000, syscalls::SYS_KILL, [1001, 9, 0, 0, 0, 0]);
    assert_eq!(res_intra.flags, SECCOMP_USER_NOTIF_FLAG_CONTINUE);
    assert_eq!(res_intra.error, 0);
    assert!(res_intra.violation.is_none());
}

#[test]
fn p2_obs_08_threads_open() {
    let mut reader = MockMemoryReader::default();
    for tid in 0..16 {
        reader
            .strings
            .insert((1000 + tid, 0x1000), format!("file_{tid}.txt"));
        reader.links.insert(
            PathBuf::from(format!("/proc/{}/cwd", 1000 + tid)),
            PathBuf::from("/workspace"),
        );
    }

    let cfg = ObserverConfig::default();
    let engine = Arc::new(ObserverEngine::new(cfg, reader));

    let mut handles = Vec::new();
    for tid in 0..16 {
        let eng = engine.clone();
        handles.push(std::thread::spawn(move || {
            let res = eng.handle_syscall(
                1000 + tid,
                syscalls::SYS_OPENAT,
                [
                    mcpg_linux::observer::AT_FDCWD as i64 as u64,
                    0x1000,
                    0,
                    0,
                    0,
                    0,
                ],
            );
            assert_eq!(res.flags, SECCOMP_USER_NOTIF_FLAG_CONTINUE);
            assert_eq!(res.error, 0);
            let ev = res.event.expect("event emitted");
            assert_eq!(
                ev.resolved,
                Some(PathBuf::from(format!("/workspace/file_{tid}.txt")))
            );
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn p2_obs_09_unsupported_host_exit_69() {
    let mut caps = HostCaps::default();
    caps.seccomp.user_notif = false;
    let assess = caps.assess(&[]);
    assert!(!assess.supported);
    assert!(assess.missing.iter().any(|m| m == "seccomp.user_notif"));

    let res = mcpg_app::plan_mode::choose_mode(Mode::Observe, &caps, &[]);
    assert_eq!(res, Err(ExitCode::UnsupportedHost));
}

#[test]
fn p2_obs_10_no_landlock_observe_mode() {
    let mut caps = HostCaps::default();
    caps.landlock.available = false;
    caps.seccomp.user_notif = true;
    caps.seccomp.notif_continue = true;
    caps.inotify = true;
    caps.proc_mem_readable = true;

    let (mode, fallback) = mcpg_app::plan_mode::choose_mode(Mode::Enforce, &caps, &[]).unwrap();
    assert_eq!(mode, Mode::Observe);
    assert!(!fallback.is_empty());
}

#[test]
fn p2_obs_11_no_landlock_require_exits_69() {
    let mut caps = HostCaps::default();
    caps.landlock.available = false;

    let res = mcpg_app::plan_mode::choose_mode(Mode::Enforce, &caps, &[Feature::Landlock]);
    assert_eq!(res, Err(ExitCode::UnsupportedHost));
}
