fn main() {
    unsafe {
        let prog = libc::sock_fprog { len: 0, filter: std::ptr::null() };
        let res = libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog
        );
        let err = std::io::Error::last_os_error();
        println!("res={}, err={:?}", res, err);
    }
}
