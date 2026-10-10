import sys

with open("crates/mcpg-linux/src/launcher.rs", "r") as f:
    content = f.read()

content = content.replace(
    "observe_seccomp: bool,",
    "observe_seccomp: bool,\n    pub(crate) handover_sock: Option<std::os::fd::RawFd>,"
)
content = content.replace(
    "observe_seccomp: false,",
    "observe_seccomp: false,\n            handover_sock: None,"
)

replacement = """    pub fn with_seccomp(mut self, observe: bool) -> Self {
        self.observe_seccomp = observe;
        self
    }
    
    pub fn with_handover_sock(mut self, fd: std::os::fd::RawFd) -> Self {
        self.handover_sock = Some(fd);
        self
    }"""

content = content.replace("""    pub fn with_seccomp(mut self, observe: bool) -> Self {
        self.observe_seccomp = observe;
        self
    }""", replacement)

# Now we need to use self.handover_sock in `launch` instead of creating the socketpair!
# Find the socketpair code in `launch`
sock_code = """        #[cfg(target_os = "linux")]
        let mut parent_sock = None;
        #[cfg(target_os = "linux")]
        let mut child_sock = None;

        let mut seccomp_filter: Vec<crate::seccomp::sock_filter> = vec![];
        #[cfg(target_os = "linux")]
        let mut seccomp_ptr = std::ptr::null();
        #[cfg(target_os = "linux")]
        let mut seccomp_len = 0;

        #[cfg(target_os = "linux")]
        if self.observe_seccomp {
            unsafe {
                let mut sv = [-1i32; 2];
                if libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    sv.as_mut_ptr(),
                ) == 0
                {
                    parent_sock = Some(sv[0]);
                    child_sock = Some(sv[1]);
                }
            }
            if let Some(cs) = child_sock {
                seccomp_filter = crate::seccomp::build_seccomp_filter_for_child(Some(cs));
                seccomp_ptr = seccomp_filter.as_ptr();
                seccomp_len = seccomp_filter.len();
            }
        }"""

new_sock_code = """        #[cfg(target_os = "linux")]
        let child_sock = self.handover_sock;

        let mut seccomp_filter: Vec<crate::seccomp::sock_filter> = vec![];
        #[cfg(target_os = "linux")]
        let mut seccomp_ptr = std::ptr::null();
        #[cfg(target_os = "linux")]
        let mut seccomp_len = 0;

        #[cfg(target_os = "linux")]
        if self.observe_seccomp {
            if let Some(cs) = child_sock {
                seccomp_filter = crate::seccomp::build_seccomp_filter_for_child(Some(cs));
                seccomp_ptr = seccomp_filter.as_ptr();
                seccomp_len = seccomp_filter.len();
            }
        }"""

content = content.replace(sock_code, new_sock_code)

# Remove the parent_sock reading at the end of launch
end_code = """        #[cfg(target_os = "linux")]
        let mut seccomp_listener_fd = None;
        #[cfg(not(target_os = "linux"))]
        let seccomp_listener_fd = None;
        #[cfg(target_os = "linux")]
        if let Some(ps) = parent_sock {
            if let Some(cs) = child_sock {
                unsafe {
                    libc::close(cs);
                }
            }
            if let Ok(fd) = crate::seccomp::recv_fd(ps) {
                seccomp_listener_fd = Some(fd);
            }
            unsafe {
                libc::close(ps);
            }
        }"""

new_end_code = """        #[cfg(target_os = "linux")]
        let seccomp_listener_fd = None;
        #[cfg(not(target_os = "linux"))]
        let seccomp_listener_fd = None;
        #[cfg(target_os = "linux")]
        if let Some(cs) = child_sock {
            unsafe {
                libc::close(cs);
            }
        }"""

content = content.replace(end_code, new_end_code)

with open("crates/mcpg-linux/src/launcher.rs", "w") as f:
    f.write(content)

