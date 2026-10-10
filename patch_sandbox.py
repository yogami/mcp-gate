import sys

with open("crates/mcpg-linux/src/sandbox.rs", "r") as f:
    content = f.read()

content = content.replace(
    "fn create_launcher(&self, ruleset: Option<OwnedFd>) -> Box<dyn mcpg_app::ports::CapsuleLauncher> {",
    "fn create_launcher(&self, ruleset: Option<OwnedFd>) -> (Box<dyn mcpg_app::ports::CapsuleLauncher>, Option<RawFd>) {"
)

replacement = """        let mut parent_sock = None;
        let mut child_sock = None;
        unsafe {
            let mut sv = [-1i32; 2];
            if libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) == 0 {
                parent_sock = Some(sv[0]);
                child_sock = Some(sv[1]);
            }
        }
        if let Some(cs) = child_sock {
            launcher = launcher.with_handover_sock(cs);
        }
        (Box::new(launcher), parent_sock)"""

content = content.replace("        Box::new(launcher)", replacement)

with open("crates/mcpg-linux/src/sandbox.rs", "w") as f:
    f.write(content)
