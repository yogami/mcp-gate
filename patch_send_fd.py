import sys

with open("crates/mcpg-linux/src/seccomp.rs", "r") as f:
    content = f.read()

old_send = """        let cmsg_space = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];

        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = cmsg_space as _;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::other("CMSG_FIRSTHDR returned null"));
        }"""

new_send = """        let cmsg_space = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as usize;
        // Allocate statically or on the stack. cmsg_space is small (around 24-32 bytes).
        let mut cmsg_buf = [0u8; 64];
        
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = cmsg_space as _;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }"""

if old_send in content:
    content = content.replace(old_send, new_send)
    with open("crates/mcpg-linux/src/seccomp.rs", "w") as f:
        f.write(content)
    print("Patched!")
else:
    print("Could not find the target code to patch in send_fd!")

