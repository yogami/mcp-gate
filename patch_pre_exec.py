import sys

with open("crates/mcpg-linux/src/launcher.rs", "r") as f:
    content = f.read()

# Fix close_extra_fds_except to take an array of fds to keep
old_close = """fn close_extra_fds_except(keep_fd: std::os::fd::RawFd) {"""
new_close = """fn close_extra_fds_except(keep_fds: &[std::os::fd::RawFd]) {"""
content = content.replace(old_close, new_close)

old_loop = """            for fd in start..max {
                if fd != keep_fd {
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                }
            }"""
new_loop = """            for fd in start..max {
                if !keep_fds.contains(&fd) {
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                }
            }"""
content = content.replace(old_loop, new_loop)

old_close_range = """        if keep_fd < 3 {
            let res = libc::syscall(libc::SYS_close_range, 3, !0u32, CLOSE_RANGE_CLOEXEC);
            if res < 0 {
                let max_fd = libc::sysconf(libc::_SC_OPEN_MAX).max(1024) as i32;
                set_cloexec_fallback(3, max_fd);
            }
        } else {
            let res1 = if keep_fd > 3 {
                libc::syscall(
                    libc::SYS_close_range,
                    3,
                    (keep_fd - 1) as u32,
                    CLOSE_RANGE_CLOEXEC,
                )
            } else {
                0
            };
            let res2 = libc::syscall(
                libc::SYS_close_range,
                (keep_fd + 1) as u32,
                !0u32,
                CLOSE_RANGE_CLOEXEC,
            );
            if res1 < 0 || res2 < 0 {
                let max_fd = libc::sysconf(libc::_SC_OPEN_MAX).max(1024) as i32;
                set_cloexec_fallback(3, max_fd);
            }
        }"""
new_close_range = """        let max_fd = libc::sysconf(libc::_SC_OPEN_MAX).max(1024) as i32;
        set_cloexec_fallback(3, max_fd);"""
content = content.replace(old_close_range, new_close_range)

# Now fix child_pre_exec
old_child = """        close_extra_fds_except(_landlock_fd);"""
new_child = """        let mut keep = vec![];
        if _landlock_fd >= 0 { keep.push(_landlock_fd); }
        if _child_sock >= 0 { keep.push(_child_sock); }
        close_extra_fds_except(&keep);"""
content = content.replace(old_child, new_child)

with open("crates/mcpg-linux/src/launcher.rs", "w") as f:
    f.write(content)

