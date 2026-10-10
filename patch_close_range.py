import sys

with open("crates/mcpg-linux/src/launcher.rs", "r") as f:
    content = f.read()

old_func = """#[allow(unused_variables)]
fn close_extra_fds_except(keep_fds: &[std::os::fd::RawFd]) {
    #[cfg(target_os = "linux")]
    unsafe {
        let max_fd = libc::sysconf(libc::_SC_OPEN_MAX).max(1024) as i32;
        for fd in 3..max_fd {
            if !keep_fds.contains(&fd) {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
        }
    }
}"""

new_func = """#[allow(unused_variables)]
fn close_extra_fds_except(keep_fds: &[std::os::fd::RawFd]) {
    #[cfg(target_os = "linux")]
    unsafe {
        const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;
        
        let mut start_fd = 3;
        // Since keep_fds is very small (max 2-3 items), we can just find the next one
        loop {
            // Find the smallest fd in keep_fds that is >= start_fd
            let mut next_keep = -1;
            for &fd in keep_fds {
                if fd >= start_fd {
                    if next_keep == -1 || fd < next_keep {
                        next_keep = fd;
                    }
                }
            }
            
            if next_keep == -1 {
                // No more fds to keep, close the rest
                let res = libc::syscall(libc::SYS_close_range, start_fd as u32, !0u32, CLOSE_RANGE_CLOEXEC);
                if res < 0 {
                    // Fallback to loop if close_range fails (e.g. old kernel)
                    let max_fd = libc::sysconf(libc::_SC_OPEN_MAX).max(1024).min(65536) as i32;
                    for fd in start_fd..max_fd {
                        if !keep_fds.contains(&fd) {
                            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                        }
                    }
                }
                break;
            } else {
                if next_keep > start_fd {
                    // close [start_fd, next_keep - 1]
                    let res = libc::syscall(libc::SYS_close_range, start_fd as u32, (next_keep - 1) as u32, CLOSE_RANGE_CLOEXEC);
                    if res < 0 {
                        // Fallback
                        let max_fd = (next_keep - 1).min(65536);
                        for fd in start_fd..=max_fd {
                            if !keep_fds.contains(&fd) {
                                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                            }
                        }
                    }
                }
                start_fd = next_keep + 1;
            }
        }
    }
}"""

content = content.replace(old_func, new_func)

with open("crates/mcpg-linux/src/launcher.rs", "w") as f:
    f.write(content)
