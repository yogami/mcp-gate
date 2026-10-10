use std::time::{Duration, Instant};

fn dummy() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut target_events = 0;
    let mut loop_count = 0;
    loop {
        loop_count += 1;
        if loop_count % 1000 == 0 {
            eprintln!("DEBUG: Loop iteration {}, target_events={}", loop_count, target_events);
        }
        if capsule.child.try_wait().unwrap().is_some() {
            eprintln!("DEBUG: Child exited!");
            break;
        }
        assert!(Instant::now() < deadline, "notification loop deadlocked after 5s");
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
        let mut response = libc::seccomp_notif_resp {
            id: request.id,
            val: result.val,
            error: result.error,
            flags: result.flags,
        };
        // SAFETY: The response matches the ABI structure and references a valid notification ID.
        let rc = unsafe {
            libc::ioctl(
                listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_SEND,
                &mut response,
            )
        };
        if rc < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error();
            assert_eq!(errno, Some(libc::ENOENT));
        }
    }
}
