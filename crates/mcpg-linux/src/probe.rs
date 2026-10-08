#[cfg(not(target_os = "linux"))]
use mcpg_domain::host::{HostCaps, LandlockCaps, SeccompCaps};

#[cfg(not(target_os = "linux"))]
pub fn probe() -> HostCaps {
    let mut caps = HostCaps {
        kernel: "non-linux".to_string(),
        arch: std::env::consts::ARCH.to_string(),
        landlock: LandlockCaps {
            available: false,
            abi: 0,
        },
        seccomp: SeccompCaps {
            filter: false,
            user_notif: false,
            notif_continue: false,
            wait_killable_recv: false,
        },
        inotify: false,
        proc_mem_readable: false,
        supported: false,
        missing: Vec::new(),
    };
    let assessment = caps.assess(&[]);
    caps.supported = assessment.supported;
    caps.missing = assessment.missing;
    caps
}

#[cfg(target_os = "linux")]
pub use linux_impl::probe;

#[cfg(target_os = "linux")]
mod linux_impl {
    use mcpg_domain::host::{HostCaps, LandlockCaps, SeccompCaps};
    use std::ffi::CStr;
    use std::mem;
    use std::os::raw::{c_int, c_long, c_ushort};

    const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
    const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 8;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
    const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc00000;

    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct sock_filter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct sock_fprog {
        len: c_ushort,
        filter: *const sock_filter,
    }

    const SECCOMP_DATA_NR_OFFSET: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc00000b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const AUDIT_ARCH: u32 = 0;

    #[cfg(target_arch = "x86_64")]
    const SYS_OPENAT_NR: u32 = 257;
    #[cfg(target_arch = "aarch64")]
    const SYS_OPENAT_NR: u32 = 56;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const SYS_OPENAT_NR: u32 = 0;

    use crate::observer::{
        seccomp_notif, seccomp_notif_resp, SECCOMP_IOCTL_NOTIF_RECV,
        SECCOMP_IOCTL_NOTIF_SEND,
    };

    const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 0x00000001;

    const SYS_LANDLOCK_CREATE_RULESET: c_long = 444;
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

    fn host_uname() -> (String, String) {
        let mut u: libc::utsname = unsafe { mem::zeroed() };
        if unsafe { libc::uname(&mut u) } != 0 {
            return ("unknown".into(), "unknown".into());
        }
        let field = |p: &[libc::c_char]| {
            unsafe { CStr::from_ptr(p.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        };
        (field(&u.release), field(&u.machine))
    }

    fn probe_landlock() -> LandlockCaps {
        let res = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if res >= 1 {
            LandlockCaps {
                available: true,
                abi: res as u32,
            }
        } else {
            LandlockCaps {
                available: false,
                abi: 0,
            }
        }
    }

    fn probe_inotify() -> bool {
        unsafe {
            let fd = libc::inotify_init1(libc::IN_CLOEXEC);
            if fd >= 0 {
                libc::close(fd);
                true
            } else {
                false
            }
        }
    }

    fn read_proc_mem(pid: libc::pid_t, addr: u64, expected: &[u8]) -> bool {
        use std::os::unix::fs::FileExt;
        let Ok(file) = std::fs::File::open(format!("/proc/{pid}/mem")) else {
            return false;
        };
        let mut buf = vec![0u8; expected.len()];
        file.read_exact_at(&mut buf, addr).is_ok() && buf == expected
    }

    unsafe fn child_mem_server(sock: c_int) -> ! {
        libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
        libc::prctl(0x59616d61, libc::getppid() as libc::c_ulong, 0, 0, 0);
        let _ = libc::write(sock, b"R".as_ptr() as *const libc::c_void, 1);
        let mut byte = [0u8; 1];
        let _ = libc::read(sock, byte.as_mut_ptr() as *mut libc::c_void, 1);
        libc::close(sock);
        libc::_exit(0);
    }

    unsafe fn parent_check_child_mem(
        sock: c_int,
        pid: libc::pid_t,
        addr: usize,
        magic: [u8; 8],
    ) -> bool {
        let mut ready = [0u8; 1];
        let ok = libc::read(sock, ready.as_mut_ptr() as *mut libc::c_void, 1) == 1;
        let matches = ok && read_proc_mem(pid, addr as u64, &magic);
        let _ = libc::write(sock, b"D".as_ptr() as *const libc::c_void, 1);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        matches
    }

    fn probe_proc_mem() -> bool {
        unsafe {
            let mut sv: [c_int; 2] = [-1, -1];
            if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) != 0 {
                return false;
            }

            let magic: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
            let pid = libc::fork();
            match pid {
                -1 => {
                    libc::close(sv[0]);
                    libc::close(sv[1]);
                    false
                }
                0 => {
                    libc::close(sv[0]);
                    child_mem_server(sv[1]);
                }
                _ => {
                    libc::close(sv[1]);
                    let res = parent_check_child_mem(sv[0], pid, magic.as_ptr() as usize, magic);
                    libc::close(sv[0]);
                    res
                }
            }
        }
    }

    fn make_openat_filter() -> [sock_filter; 7] {
        [
            sock_filter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: SECCOMP_DATA_ARCH_OFFSET,
            },
            sock_filter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: AUDIT_ARCH,
            },
            sock_filter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
            sock_filter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: SECCOMP_DATA_NR_OFFSET,
            },
            sock_filter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 0,
                jf: 1,
                k: SYS_OPENAT_NR,
            },
            sock_filter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_USER_NOTIF,
            },
            sock_filter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
        ]
    }

    unsafe fn send_fd(sock: c_int, fd: c_int) -> bool {
        let mut dummy = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: dummy.as_mut_ptr() as *mut _,
            iov_len: 1,
        };
        let cmsg_space = libc::CMSG_SPACE(mem::size_of::<c_int>() as u32) as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = cmsg_space as _;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return false;
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<c_int>() as u32) as _;
        let data_ptr = libc::CMSG_DATA(cmsg) as *mut c_int;
        *data_ptr = fd;

        libc::sendmsg(sock, &msg, 0) >= 0
    }

    unsafe fn recv_fd(sock: c_int) -> Option<c_int> {
        let mut dummy = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: dummy.as_mut_ptr() as *mut _,
            iov_len: 1,
        };
        let cmsg_space = libc::CMSG_SPACE(mem::size_of::<c_int>() as u32) as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = cmsg_space as _;

        let res = libc::recvmsg(sock, &mut msg, 0);
        if res <= 0 {
            return None;
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return None;
        }
        let data_ptr = libc::CMSG_DATA(cmsg) as *const c_int;
        let fd = *data_ptr;
        if fd < 0 {
            None
        } else {
            Some(fd)
        }
    }

    unsafe fn child_install_seccomp(sock: c_int) -> ! {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            libc::_exit(1);
        }
        let filter = make_openat_filter();
        let prog = sock_fprog {
            len: filter.len() as c_ushort,
            filter: filter.as_ptr(),
        };
        let listener_fd = libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const sock_fprog,
        ) as c_int;
        if listener_fd < 0 {
            libc::_exit(2);
        }
        if !send_fd(sock, listener_fd) {
            libc::close(listener_fd);
            libc::_exit(3);
        }
        libc::close(listener_fd);

        let mut ack = [0u8; 1];
        if libc::read(sock, ack.as_mut_ptr() as *mut _, 1) != 1 {
            libc::_exit(4);
        }
        libc::close(sock);

        libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
        libc::prctl(0x59616d61, libc::getppid() as libc::c_ulong, 0, 0, 0);
        let mut fd = libc::openat(libc::AT_FDCWD, c"/etc/hostname".as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            fd = libc::openat(libc::AT_FDCWD, c"/etc/hosts".as_ptr(), libc::O_RDONLY);
        }
        if fd >= 0 {
            libc::close(fd);
            libc::_exit(0);
        }
        libc::_exit(5);
    }

    unsafe fn parent_handle_notif(listener_fd: c_int) -> (bool, bool) {
        let mut notif: seccomp_notif = mem::zeroed();
        if libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) != 0 {
            return (false, false);
        }
        let pid = notif.pid as libc::pid_t;
        let addr = notif.data.args[1];
        let mem_ok =
            read_proc_mem(pid, addr, b"/etc/hostname") || read_proc_mem(pid, addr, b"/etc/hosts");
        let mut resp: seccomp_notif_resp = mem::zeroed();
        resp.id = notif.id;
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        let cont_ok = libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) == 0;
        (cont_ok, mem_ok)
    }

    fn parse_kernel_version(release: &str) -> (u32, u32) {
        let mut parts = release.split('.').filter_map(|s| s.parse().ok());
        let major = parts.next().unwrap_or(0);
        let minor = parts.next().unwrap_or(0);
        (major, minor)
    }

    fn check_wait_killable(release: &str) -> bool {
        let (major, minor) = parse_kernel_version(release);
        major > 5 || (major == 5 && minor >= 19)
    }

    unsafe fn parent_supervise_seccomp(
        sock: c_int,
        pid: libc::pid_t,
        release: &str,
    ) -> (SeccompCaps, bool) {
        let fd_opt = recv_fd(sock);
        let mut user_notif = false;
        let mut notif_continue = false;
        let mut notif_mem_ok = false;
        if let Some(listener_fd) = fd_opt {
            user_notif = true;
            let _ = libc::write(sock, b"x".as_ptr() as *const libc::c_void, 1);
            let (cont, mem) = parent_handle_notif(listener_fd);
            notif_continue = cont;
            notif_mem_ok = mem;
            libc::close(listener_fd);
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);

        let wait_killable_recv = check_wait_killable(release);
        (
            SeccompCaps {
                filter: true,
                user_notif,
                notif_continue,
                wait_killable_recv,
            },
            notif_mem_ok,
        )
    }

    fn probe_seccomp(release: &str) -> (SeccompCaps, bool) {
        unsafe {
            let mut sv: [c_int; 2] = [-1, -1];
            if libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, sv.as_mut_ptr()) != 0 {
                return (
                    SeccompCaps {
                        filter: false,
                        user_notif: false,
                        notif_continue: false,
                        wait_killable_recv: false,
                    },
                    false,
                );
            }
            let pid = libc::fork();
            match pid {
                -1 => {
                    libc::close(sv[0]);
                    libc::close(sv[1]);
                    (
                        SeccompCaps {
                            filter: false,
                            user_notif: false,
                            notif_continue: false,
                            wait_killable_recv: false,
                        },
                        false,
                    )
                }
                0 => {
                    libc::close(sv[0]);
                    child_install_seccomp(sv[1]);
                }
                _ => {
                    libc::close(sv[1]);
                    let res = parent_supervise_seccomp(sv[0], pid, release);
                    libc::close(sv[0]);
                    res
                }
            }
        }
    }

    pub fn probe() -> HostCaps {
        let (kernel, arch) = host_uname();
        let landlock = probe_landlock();
        let inotify = probe_inotify();
        let (seccomp, notif_mem_ok) = probe_seccomp(&kernel);
        let proc_mem_readable = notif_mem_ok || probe_proc_mem();

        let mut caps = HostCaps {
            kernel,
            arch,
            landlock,
            seccomp,
            inotify,
            proc_mem_readable,
            supported: true,
            missing: Vec::new(),
        };
        let assessment = caps.assess(&[]);
        caps.supported = assessment.supported;
        caps.missing = assessment.missing;
        caps
    }
}
