import re

with open("crates/mcpg-linux/tests/launch_handshake.rs", "r") as f:
    content = f.read()

replacement = """
    let (tx, rx) = std::sync::mpsc::channel();
    let ps = parent_sock.expect("parent sock");
    let obs_thread = std::thread::spawn(move || {
        let listener = unsafe {
            OwnedFd::from_raw_fd(mcpg_linux::seccomp::recv_fd(ps).expect("listener handover"))
        };
        unsafe {
            libc::close(ps);
            let flags = libc::fcntl(listener.as_raw_fd(), libc::F_GETFL, 0);
            libc::fcntl(listener.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let engine = ObserverEngine::new(
            ObserverConfig {
                root_command: Some(probe_binary()),
                capsule_pids: vec![],
                ..Default::default()
            },
            RealMemoryReader,
        );

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut target_events = 0;
        let mut loop_count = 0;
        loop {
            loop_count += 1;
            if loop_count % 1000 == 0 {
                eprintln!("DEBUG: Loop iteration {}, target_events={}", loop_count, target_events);
            }
            if let Ok(()) = rx.try_recv() {
                eprintln!("DEBUG: Child exited!");
                break;
            }
            assert!(std::time::Instant::now() < deadline, "notification loop deadlocked after 5s");
            let mut pfd = libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut pfd, 1, 50) };
            assert!(rc >= 0);
            if rc == 0 || pfd.revents & libc::POLLIN == 0 {
                continue;
            }
            let mut request: libc::seccomp_notif = unsafe { std::mem::zeroed() };
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
            if result.violation.is_some() {
                if request.data.nr == libc::SYS_openat as u64 {
                    target_events += 1;
                }
            }
            let mut resp: libc::seccomp_notif_resp = unsafe { std::mem::zeroed() };
            resp.id = request.id;
            resp.error = result.error;
            resp.val = result.val;
            resp.flags = result.flags;
            unsafe {
                libc::ioctl(listener.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_SEND, &mut resp);
            }
        }
        target_events
    });

    eprintln!("DEBUG: Calling launch");
    let mut capsule = launcher
        .launch(&launch_plan)
        .expect("real seccomp launch handshake");
    assert!(start.elapsed() < std::time::Duration::from_secs(6));
    eprintln!("DEBUG: launch returned");
    let guard = CapsuleGuard::new(capsule.pid as i32, vec![capsule.pid]);

    // Wait for child to exit
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        assert!(std::time::Instant::now() < deadline, "wait deadlocked");
        if capsule.child.try_wait().unwrap().is_some() {
            eprintln!("DEBUG: Child wait exited!");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let _ = tx.send(());
    let target_events = obs_thread.join().unwrap();
"""

pattern = re.compile(r'    let ps = parent_sock\.expect\("parent sock"\);.*?    \(serde_json::Value::Null, target_events\)\n\}', re.DOTALL)
new_content = pattern.sub(replacement + "    (serde_json::Value::Null, target_events)\n}", content)
with open("crates/mcpg-linux/tests/launch_handshake.rs", "w") as f:
    f.write(new_content)
