    let deadline = Instant::now() + Duration::from_secs(30);
    let mut target_events = 0;
    loop {
        if capsule.child.try_wait().unwrap().is_some() {
            break;
        }
        assert!(Instant::now() < deadline, "notification loop deadlocked");
        let mut pfd = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a valid writable pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, 50) };
        assert!(rc >= 0);
        if rc == 0 || pfd.revents & libc::POLLIN == 0 {
            continue;
        }

        // SAFETY: zero is a valid initial state for the kernel ABI structure.
        let mut request: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: listener is owned and request is a writable notification.
        let rc = unsafe {
            libc::ioctl(
                listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_RECV,
                &mut request,
            )
        };
        if rc < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error();
            assert!(matches!(errno, Some(libc::ENOENT) | Some(libc::EINTR) | Some(libc::EAGAIN)));
            continue;
        }

        let result = engine.handle_syscall(request.pid, request.data.nr as i64, request.data.args);
        let mut id = request.id;
        // SAFETY: id is the notification ID just returned by the kernel.
        if unsafe {
            libc::ioctl(
                listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
                &mut id,
            )
        } < 0
        {
            continue;
        }

        if let Some(event) = result.event {
            if event.kind == EventKind::FsOpen && event.resolved.as_deref() == Some(target) {
                assert_eq!(event.access, Some(mcpg_domain::event::AccessKind::Read));
                target_events += 1;
            }
        }
        let response = libc::seccomp_notif_resp {
            id: request.id,
            val: result.val,
            error: result.error,
            flags: result.flags,
        };
        // SAFETY: response uses the ABI and ID of this notification.
        let rc = unsafe {
            libc::ioctl(
                listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_SEND,
                &response,
            )
        };
        if rc < 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOENT)
            );
        }
    }

    let output = capsule.child.wait_with_output().unwrap();
    guard.disarm();
    assert!(
        output.status.success(),
        "fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (
        serde_json::from_slice(&output.stdout).expect("real fixture JSON payload"),
        target_events,
    )
}

#[test]
fn real_launch_notification_contains_target_payload() {
    let target = Path::new("/dev/null");
    let (payload, count) = run_probe("read", target);
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["ok"], true);
    assert_eq!(count, 1, "exactly one notified open of the target");
}

#[test]
fn p2_obs_08_real_eight_threads_one_thousand_opens() {
    let (payload, count) = run_probe("threads-open", Path::new("/dev/null"));
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["count"], 8000, "all real OS opens must succeed");
    assert_eq!(
        count, 8000,
        "the kernel observer must capture every one of the 8,000 opens"
    );
}

#[test]
fn failed_exec_does_not_hang_or_return_unobserved_capsule() {
    mcpg_linux::self_harden::harden_self().unwrap();
    let missing = CString::new("/nonexistent/mcpg-launch-handshake").unwrap();
    let plan = CapsulePlan {
        program: missing.clone(),
        argv: vec![missing],
        envp: vec![],
        cwd: std::env::temp_dir(),
        mode: Mode::Observe,
    };
    let start = Instant::now();
    assert!(LinuxLauncher::new()
        .with_seccomp(true)
        .launch(&plan)
        .is_err());
    assert!(start.elapsed() < Duration::from_secs(6));
}
