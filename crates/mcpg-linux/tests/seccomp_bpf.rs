#![cfg(target_os = "linux")]

use mcpg_linux::seccomp::{
    build_seccomp_filter, build_seccomp_filter_for_child, install_seccomp_filter, recv_fd, send_fd,
    AUDIT_ARCH_NATIVE,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[test]
fn test_filter_builder_structure() {
    let filter = build_seccomp_filter();
    assert!(
        !filter.is_empty(),
        "filter instructions should not be empty"
    );

    // First instruction should be loading architecture
    assert_eq!(filter[0].code, 0x20); // BPF_LD | BPF_W | BPF_ABS
    assert_eq!(filter[0].k, 4); // SECCOMP_DATA_ARCH_OFFSET

    // Second instruction should check AUDIT_ARCH_NATIVE
    assert_eq!(filter[1].code, 0x15); // BPF_JMP | BPF_JEQ | BPF_K
    assert_eq!(filter[1].k, AUDIT_ARCH_NATIVE);
}

#[test]
fn test_filter_install_and_handover_over_socketpair() {
    let mut sv = [-1i32; 2];
    unsafe {
        let rc = libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        );
        assert_eq!(rc, 0, "socketpair failed");
    }

    let parent_sock = unsafe { OwnedFd::from_raw_fd(sv[0]) };
    let child_sock = unsafe { OwnedFd::from_raw_fd(sv[1]) };

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        // Child process
        drop(parent_sock);
        let filter = build_seccomp_filter_for_child(Some(child_sock.as_raw_fd()));
        let listener_fd = install_seccomp_filter(&filter).expect("install seccomp in child");
        send_fd(child_sock.as_raw_fd(), listener_fd).expect("send_fd");
        unsafe {
            libc::close(listener_fd);
            libc::_exit(0);
        }
    } else {
        // Parent process
        drop(child_sock);
        let received_fd = recv_fd(parent_sock.as_raw_fd()).expect("recv_fd");
        assert!(received_fd >= 0, "valid listener fd received");

        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
            libc::close(received_fd);
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}

#[test]
fn test_filter_contains_required_syscall_rules() {
    let filter = build_seccomp_filter();

    let has_syscall =
        |nr: libc::c_long| -> bool { filter.iter().any(|f| f.code == 0x15 && f.k == nr as u32) };

    assert!(has_syscall(libc::SYS_clone3), "must filter clone3");
    assert!(
        has_syscall(libc::SYS_io_uring_setup),
        "must filter io_uring_setup"
    );
    assert!(has_syscall(libc::SYS_ptrace), "must filter ptrace");
    assert!(has_syscall(libc::SYS_bpf), "must filter bpf");
    assert!(has_syscall(libc::SYS_openat), "must filter openat");
    assert!(has_syscall(libc::SYS_execve), "must filter execve");
    assert!(has_syscall(libc::SYS_socket), "must filter socket");
    assert!(has_syscall(libc::SYS_connect), "must filter connect");
}

#[test]
fn test_send_and_recv_fd_invalid() {
    assert!(send_fd(-1, 0).is_err());
    assert!(recv_fd(-1).is_err());
}

#[test]
fn test_build_filter_without_handover_bypass() {
    let f1 = build_seccomp_filter();
    let f2 = build_seccomp_filter_for_child(None);
    assert_eq!(f1, f2);

    // Empty filter install fails EINVAL
    let err = install_seccomp_filter(&[]);
    assert!(err.is_err());
}

#[test]
fn test_send_and_recv_fd_non_socket() {
    let file = std::fs::File::open("/dev/null").expect("open /dev/null");
    let fd = file.as_raw_fd();
    assert!(send_fd(fd, fd).is_err());
    assert!(recv_fd(fd).is_err());
}
