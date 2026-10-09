//! Seccomp BPF filter builder and user notification listener handover.
//!
//! SPEC 3.3.3 & 3.3.4:
//! Enforces architecture verification, denies tamper syscalls (io_uring, ptrace, bpf),
//! denies clone3 (so libc falls back to clone), routes monitored syscalls to USER_NOTIF,
//! and hands over the listener file descriptor via SCM_RIGHTS over a Unix domain socket.

use std::io;
use std::os::fd::RawFd;

pub const BPF_LD: u16 = 0x00;
pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_K: u16 = 0x00;
pub const BPF_RET: u16 = 0x06;

pub const SECCOMP_DATA_NR_OFFSET: u32 = 0;
pub const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

pub const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
pub const AUDIT_ARCH_AARCH64: u32 = 0xc00000b7;

#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH_NATIVE: u32 = AUDIT_ARCH_X86_64;
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH_NATIVE: u32 = AUDIT_ARCH_AARCH64;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const AUDIT_ARCH_NATIVE: u32 = 0;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
pub const SECCOMP_RET_ERRNO: u32 = 0x00050000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc00000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

pub const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 1 << 3;
pub const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: libc::c_uint = 1 << 5;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct sock_filter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
pub struct sock_fprog {
    pub len: u16,
    pub filter: *const sock_filter,
}

/// Filter action to return for a matching syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompAction {
    Allow,
    KillProcess,
    Errno(u16),
    UserNotif,
}

impl SeccompAction {
    pub fn to_return_code(self) -> u32 {
        match self {
            Self::Allow => SECCOMP_RET_ALLOW,
            Self::KillProcess => SECCOMP_RET_KILL_PROCESS,
            Self::Errno(e) => SECCOMP_RET_ERRNO | (e as u32),
            Self::UserNotif => SECCOMP_RET_USER_NOTIF,
        }
    }
}

fn stmt(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

#[cfg(target_os = "linux")]
fn append_syscall_rule(
    instrs: &mut Vec<sock_filter>,
    syscall_nr: libc::c_long,
    action: SeccompAction,
) {
    if syscall_nr < 0 {
        return;
    }
    // If nr == syscall_nr, proceed to next instruction (jt=0), else skip return (jf=1)
    instrs.push(jump(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr as u32, 0, 1));
    instrs.push(stmt(BPF_RET | BPF_K, action.to_return_code()));
}

/// Construct the complete seccomp BPF filter per SPEC Section 3.3.3.
pub fn build_seccomp_filter() -> Vec<sock_filter> {
    build_seccomp_filter_for_child(None)
}

/// Construct seccomp filter with an optional bypass for the handover socket during sendmsg.
pub fn build_seccomp_filter_for_child(_handover_sock: Option<RawFd>) -> Vec<sock_filter> {
    let mut instrs = Vec::with_capacity(64);

    // 1. Verify audit architecture matches native host
    instrs.push(stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
    instrs.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_NATIVE, 1, 0));
    instrs.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // 2. Load syscall number
    instrs.push(stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

    // 3. On x86_64, kill x32 ABI syscalls
    #[cfg(target_arch = "x86_64")]
    {
        instrs.push(jump(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1));
        instrs.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }

    // 4. clone3 returns ENOSYS so libc falls back to clone
    #[cfg(target_os = "linux")]
    append_syscall_rule(
        &mut instrs,
        libc::SYS_clone3,
        SeccompAction::Errno(libc::ENOSYS as u16),
    );

    // 5. Tamper group denials (io_uring returns ENOSYS, debug/priv returns EPERM)
    #[cfg(target_os = "linux")]
    add_tamper_rules(&mut instrs);

    // 6. Monitored boundary syscalls route to user notification
    #[cfg(target_os = "linux")]
    add_notif_rules(&mut instrs, _handover_sock);

    // 7. Default action: ALLOW
    instrs.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    instrs
}

#[cfg(target_os = "linux")]
fn add_tamper_rules(instrs: &mut Vec<sock_filter>) {
    let enosys = SeccompAction::Errno(libc::ENOSYS as u16);
    append_syscall_rule(instrs, libc::SYS_io_uring_setup, enosys);
    append_syscall_rule(instrs, libc::SYS_io_uring_enter, enosys);
    append_syscall_rule(instrs, libc::SYS_io_uring_register, enosys);

    let eperm = SeccompAction::Errno(libc::EPERM as u16);
    append_syscall_rule(instrs, libc::SYS_ptrace, eperm);
    append_syscall_rule(instrs, libc::SYS_bpf, eperm);
    append_syscall_rule(instrs, libc::SYS_perf_event_open, eperm);
    append_syscall_rule(instrs, libc::SYS_userfaultfd, eperm);
    append_syscall_rule(instrs, libc::SYS_process_vm_writev, eperm);
    append_syscall_rule(instrs, libc::SYS_setns, eperm);
    append_syscall_rule(instrs, libc::SYS_keyctl, eperm);
}

#[cfg(target_os = "linux")]
fn add_notif_rules(instrs: &mut Vec<sock_filter>, handover_sock: Option<RawFd>) {
    let notif = SeccompAction::UserNotif;

    // File operations
    append_syscall_rule(instrs, libc::SYS_openat, notif);
    append_syscall_rule(instrs, libc::SYS_openat2, notif);

    // Process execution & lifecycle
    // append_syscall_rule(instrs, libc::SYS_execve, notif);
    // append_syscall_rule(instrs, libc::SYS_execveat, notif);
    // append_syscall_rule(instrs, libc::SYS_clone, notif);

    // Network operations
    append_syscall_rule(instrs, libc::SYS_socket, notif);
    append_syscall_rule(instrs, libc::SYS_connect, notif);
    append_syscall_rule(instrs, libc::SYS_sendto, notif);
    append_sendmsg_rule(instrs, handover_sock);
    append_syscall_rule(instrs, libc::SYS_bind, notif);

    // Signals
    append_syscall_rule(instrs, libc::SYS_kill, notif);
    append_syscall_rule(instrs, libc::SYS_tkill, notif);
    append_syscall_rule(instrs, libc::SYS_tgkill, notif);

    // Mutations
    append_syscall_rule(instrs, libc::SYS_unlinkat, notif);
    append_syscall_rule(instrs, libc::SYS_mkdirat, notif);
}

#[cfg(target_os = "linux")]
fn append_sendmsg_rule(instrs: &mut Vec<sock_filter>, handover_sock: Option<RawFd>) {
    if let Some(sock) = handover_sock {
        // Check nr == SYS_sendmsg
        instrs.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::SYS_sendmsg as u32,
            0,
            4,
        ));
        // jt=0 -> load args[0] (low 32 bits at offset 16)
        instrs.push(stmt(BPF_LD | BPF_W | BPF_ABS, 16));
        // if args[0] == sock, return ALLOW
        instrs.push(jump(BPF_JMP | BPF_JEQ | BPF_K, sock as u32, 0, 1));
        instrs.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        // else return USER_NOTIF
        instrs.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));
    } else {
        append_syscall_rule(instrs, libc::SYS_sendmsg, SeccompAction::UserNotif);
    }
}

/// Apply seccomp filter and return the listener file descriptor.
pub fn install_seccomp_filter(filter: &[sock_filter]) -> io::Result<RawFd> {
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }

        let prog = sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };

        // Try NEW_LISTENER with WAIT_KILLABLE_RECV first
        let flags = SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
        let fd = libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &prog);
        if fd >= 0 {
            return Ok(fd as RawFd);
        }

        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINVAL) {
            let fallback_fd = libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &prog,
            );
            if fallback_fd >= 0 {
                return Ok(fallback_fd as RawFd);
            }
            return Err(io::Error::last_os_error());
        }
        Err(err)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = filter;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "seccomp user notifications require Linux",
        ))
    }
}

/// Send a file descriptor across a connected Unix domain socket using SCM_RIGHTS.
pub fn send_fd(sock: RawFd, fd_to_send: RawFd) -> io::Result<()> {
    #[cfg(unix)]
    unsafe {
        let mut dummy: [u8; 1] = *b"F";
        let mut iov = libc::iovec {
            iov_base: dummy.as_mut_ptr() as *mut _,
            iov_len: 1,
        };

        let cmsg_space = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as usize;
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
        }

        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;

        let data_ptr = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
        *data_ptr = fd_to_send;

        let res = libc::sendmsg(sock, &msg, 0);
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (sock, fd_to_send);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "send_fd requires Unix",
        ))
    }
}

/// Receive a file descriptor from a connected Unix domain socket using SCM_RIGHTS.
pub fn recv_fd(sock: RawFd) -> io::Result<RawFd> {
    #[cfg(unix)]
    unsafe {
        let mut dummy: [u8; 1] = [0];
        let mut iov = libc::iovec {
            iov_base: dummy.as_mut_ptr() as *mut _,
            iov_len: 1,
        };

        let cmsg_space = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];

        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = cmsg_space as _;

        let res = libc::recvmsg(sock, &mut msg, 0);
        if res <= 0 {
            return Err(io::Error::last_os_error());
        }

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing SCM_RIGHTS message",
            ));
        }

        let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::c_int;
        let fd = *data_ptr;
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "negative fd received",
            ));
        }
        Ok(fd)
    }
    #[cfg(not(unix))]
    {
        let _ = sock;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "recv_fd requires Unix",
        ))
    }
}
