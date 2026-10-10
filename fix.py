import sys

with open("crates/mcpg-linux/src/launcher.rs", "r") as f:
    content = f.read()

bad_block = """        let mut child_sock = None;
        #[cfg(target_os = "linux")]
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
                    child_sock = Some(sv[1]);
                }
            }"""

good_block = """        let mut child_sock = self.handover_sock;
        #[cfg(target_os = "linux")]
        let mut seccomp_filter: Vec<crate::seccomp::sock_filter> = vec![];
        #[cfg(target_os = "linux")]
        let mut seccomp_ptr = std::ptr::null();
        #[cfg(target_os = "linux")]
        let mut seccomp_len = 0;

        #[cfg(target_os = "linux")]
        if self.observe_seccomp {"""

content = content.replace(bad_block, good_block)

with open("crates/mcpg-linux/src/launcher.rs", "w") as f:
    f.write(content)

