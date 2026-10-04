//! Phase 0 spike: probe what an unprivileged process may do on a hosted CI
//! runner (seccomp user notifications, Landlock, inotify).
//!
//! Single-threaded on purpose. Raw `libc` calls, no abstractions. This crate
//! is deleted in Month 3 once `mcp-gate probe` covers the same ground
//! (see TASKS.md, Phase 0).
//!
//! Output is one JSON document on stdout:
//!
//! ```json
//! {"schema": "runner-probe/v1", "kernel": "...", "arch": "...", "checks": {}}
//! ```
//!
//! Each check writes `{"status": "pass"|"fail"|"info", "detail": {...}}` under
//! `checks["P0-SPIKE-NN"]`. A check that is not written yet reports
//! `"status": "not_implemented"`.

use std::ffi::CStr;
use std::process::ExitCode;

use serde_json::{json, Map, Value};

const SCHEMA: &str = "runner-probe/v1";

/// Every check the spike will eventually implement, in order.
const ALL_CHECKS: [&str; 10] = [
    "P0-SPIKE-01",
    "P0-SPIKE-02",
    "P0-SPIKE-03",
    "P0-SPIKE-04",
    "P0-SPIKE-05",
    "P0-SPIKE-06",
    "P0-SPIKE-07",
    "P0-SPIKE-08",
    "P0-SPIKE-09",
    "P0-SPIKE-10",
];

/// Which checks `--check` selected.
#[derive(Debug, PartialEq, Eq)]
enum Selection {
    None,
    All,
    One(String),
}

#[derive(Debug)]
struct Args {
    selection: Selection,
    /// Accepted for forward compatibility. `--json` is the only output format.
    json: bool,
    /// Loop count for the overhead check (P0-SPIKE-10).
    iterations: u64,
}

fn parse_args<I: Iterator<Item = String>>(mut it: I) -> Result<Args, String> {
    let mut args = Args {
        selection: Selection::All,
        json: false,
        iterations: 100_000,
    };
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--check" => {
                let v = it.next().ok_or("--check needs a value")?;
                args.selection = match v.as_str() {
                    "none" => Selection::None,
                    "all" => Selection::All,
                    id if ALL_CHECKS.contains(&id) => Selection::One(id.to_string()),
                    other => return Err(format!("unknown check: {other}")),
                };
            }
            "--json" => args.json = true,
            "--iterations" => {
                let v = it.next().ok_or("--iterations needs a value")?;
                args.iterations = v
                    .parse()
                    .map_err(|_| format!("--iterations: not a number: {v}"))?;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(args)
}

/// `uname -r` and `uname -m` through libc, so the report needs no subprocess.
fn host_info() -> Result<(String, String), String> {
    // SAFETY: `utsname` is plain old data; zeroed is a valid initial state and
    // `uname` fills it in.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `u` is a valid, writable `utsname`.
    if unsafe { libc::uname(&mut u) } != 0 {
        return Err(format!("uname failed: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: `uname` NUL-terminates every field.
    let field = |p: &[libc::c_char]| unsafe { CStr::from_ptr(p.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    Ok((field(&u.release), field(&u.machine)))
}

#[cfg(target_os = "linux")]
mod linux_probe {
    use std::mem;
    use std::os::raw::{c_int, c_ushort};
    use serde_json::{json, Value};

    // Constants from <linux/seccomp.h> and <linux/filter.h>
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
    const AUDIT_ARCH: u32 = 0xc000003e; // AUDIT_ARCH_X86_64
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc00000b7; // AUDIT_ARCH_AARCH64

    #[cfg(target_arch = "x86_64")]
    const SYS_OPENAT_NR: u32 = 257;
    #[cfg(target_arch = "aarch64")]
    const SYS_OPENAT_NR: u32 = 56;

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const AUDIT_ARCH: u32 = 0;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const SYS_OPENAT_NR: u32 = 0;

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct seccomp_data {
        nr: c_int,
        arch: u32,
        instruction_pointer: u64,
        args: [u64; 6],
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct seccomp_notif {
        id: u64,
        pid: u32,
        flags: u32,
        data: seccomp_data,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct seccomp_notif_resp {
        id: u64,
        val: i64,
        error: i32,
        flags: u32,
    }

    type IoctlReq = libc::c_ulong;

    const SECCOMP_IOCTL_NOTIF_RECV: IoctlReq = 0xc0502100;
    const SECCOMP_IOCTL_NOTIF_SEND: IoctlReq = 0xc0182101;
    const SECCOMP_IOCTL_NOTIF_ID_VALID: IoctlReq = 0x80082102;
    const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 0x00000001;

    fn make_openat_filter() -> Vec<sock_filter> {
        vec![
            // 0: [arch]
            sock_filter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: SECCOMP_DATA_ARCH_OFFSET,
            },
            // 1: if arch == AUDIT_ARCH jump to 3 (jt=1, jf=0)
            sock_filter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: AUDIT_ARCH,
            },
            // 2: kill process on arch mismatch
            sock_filter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
            // 3: [nr]
            sock_filter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: SECCOMP_DATA_NR_OFFSET,
            },
            // 4: if nr == SYS_OPENAT_NR jump to 5 (jt=0, jf=1)
            sock_filter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 0,
                jf: 1,
                k: SYS_OPENAT_NR,
            },
            // 5: return USER_NOTIF for openat
            sock_filter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_USER_NOTIF,
            },
            // 6: return ALLOW
            sock_filter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
        ]
    }

    unsafe fn send_fd(sock: c_int, fd: c_int) -> Result<(), String> {
        let mut dummy: [u8; 1] = [0];
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
        msg.msg_controllen = cmsg_space;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err("CMSG_FIRSTHDR failed".into());
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<c_int>() as u32) as _;

        let data_ptr = libc::CMSG_DATA(cmsg) as *mut c_int;
        *data_ptr = fd;

        let res = libc::sendmsg(sock, &msg, 0);
        if res < 0 {
            Err(format!("sendmsg failed: {}", std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    unsafe fn recv_fd(sock: c_int) -> Result<c_int, String> {
        let mut dummy: [u8; 1] = [0];
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
        msg.msg_controllen = cmsg_space;

        let res = libc::recvmsg(sock, &mut msg, 0);
        if res <= 0 {
            return Err(format!("recvmsg failed: {}", std::io::Error::last_os_error()));
        }

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err("recvmsg: no control message received".into());
        }
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err("recvmsg: unexpected control message type".into());
        }

        let data_ptr = libc::CMSG_DATA(cmsg) as *const c_int;
        let fd = *data_ptr;
        if fd < 0 {
            return Err("recvmsg: negative fd received".into());
        }
        Ok(fd)
    }

    pub fn check_listener() -> Value {
        unsafe {
            let mut sv: [c_int; 2] = [-1, -1];
            if libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, sv.as_mut_ptr()) != 0 {
                return json!({
                    "status": "fail",
                    "detail": {
                        "error": format!("socketpair failed: {}", std::io::Error::last_os_error())
                    }
                });
            }

            let pid = libc::fork();
            if pid < 0 {
                libc::close(sv[0]);
                libc::close(sv[1]);
                return json!({
                    "status": "fail",
                    "detail": {
                        "error": format!("fork failed: {}", std::io::Error::last_os_error())
                    }
                });
            }

            if pid == 0 {
                // Child process
                libc::close(sv[0]);

                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
                    libc::_exit(10 + (err & 0x7f));
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
                    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
                    libc::_exit(20 + (err & 0x7f));
                }

                if let Err(_) = send_fd(sv[1], listener_fd) {
                    libc::close(listener_fd);
                    libc::_exit(2);
                }

                libc::close(listener_fd);
                libc::close(sv[1]);
                libc::_exit(0);
            }

            // Parent process
            libc::close(sv[1]);

            let fd_res = recv_fd(sv[0]);
            libc::close(sv[0]);

            let mut status: c_int = 0;
            libc::waitpid(pid, &mut status, 0);

            if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
                let code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    -1
                };
                return json!({
                    "status": "fail",
                    "detail": {
                        "child_exit_code": code,
                        "error": format!("child exited abnormally: {code}")
                    }
                });
            }

            match fd_res {
                Ok(listener_fd) => {
                    libc::close(listener_fd);
                    json!({
                        "status": "pass",
                        "detail": {
                            "listener_fd": listener_fd
                        }
                    })
                }
                Err(e) => json!({
                    "status": "fail",
                    "detail": {
                        "error": e
                    }
                }),
            }
        }
    }

    pub fn check_continue() -> Value {
        unsafe {
            let mut sv: [c_int; 2] = [-1, -1];
            if libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, sv.as_mut_ptr()) != 0 {
                return json!({
                    "status": "fail",
                    "detail": {
                        "error": format!("socketpair failed: {}", std::io::Error::last_os_error())
                    }
                });
            }

            let pid = libc::fork();
            if pid < 0 {
                libc::close(sv[0]);
                libc::close(sv[1]);
                return json!({
                    "status": "fail",
                    "detail": {
                        "error": format!("fork failed: {}", std::io::Error::last_os_error())
                    }
                });
            }

            if pid == 0 {
                // Child process
                libc::close(sv[0]);

                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
                    libc::_exit(10 + (err & 0x7f));
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
                    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
                    libc::_exit(20 + (err & 0x7f));
                }

                if let Err(_) = send_fd(sv[1], listener_fd) {
                    libc::close(listener_fd);
                    libc::_exit(2);
                }
                libc::close(listener_fd);

                // Wait for parent ACK
                let mut ack: [u8; 1] = [0];
                if libc::read(sv[1], ack.as_mut_ptr() as *mut _, 1) != 1 {
                    libc::_exit(3);
                }
                libc::close(sv[1]);

                // Call openat on known file
                let mut fd = libc::openat(libc::AT_FDCWD, b"/etc/hostname\0".as_ptr() as *const _, libc::O_RDONLY);
                if fd < 0 {
                    fd = libc::openat(libc::AT_FDCWD, b"/etc/hosts\0".as_ptr() as *const _, libc::O_RDONLY);
                }

                if fd >= 0 {
                    libc::close(fd);
                    libc::_exit(0);
                } else {
                    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
                    libc::_exit(50 + (err & 0x7f));
                }
            }

            // Parent process
            libc::close(sv[1]);

            let listener_fd = match recv_fd(sv[0]) {
                Ok(fd) => fd,
                Err(e) => {
                    libc::close(sv[0]);
                    let mut st: c_int = 0;
                    libc::waitpid(pid, &mut st, 0);
                    return json!({
                        "status": "fail",
                        "detail": { "error": format!("recv_fd failed: {e}") }
                    });
                }
            };

            // Send ACK to child so it knows parent is listening
            let ack: [u8; 1] = [b'G'];
            libc::write(sv[0], ack.as_ptr() as *const _, 1);
            libc::close(sv[0]);

            let mut notifications = 0;
            let mut pfd = libc::pollfd {
                fd: listener_fd,
                events: libc::POLLIN,
                revents: 0,
            };

            // Wait up to 2000ms for notification
            let poll_res = libc::poll(&mut pfd, 1, 2000);
            if poll_res > 0 && (pfd.revents & libc::POLLIN) != 0 {
                let mut notif: seccomp_notif = mem::zeroed();
                if libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) == 0 {
                    notifications += 1;
                    // Send CONTINUE response
                    let mut resp = seccomp_notif_resp {
                        id: notif.id,
                        val: 0,
                        error: 0,
                        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
                    };
                    libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &mut resp);
                }
            }

            libc::close(listener_fd);

            let mut status: c_int = 0;
            libc::waitpid(pid, &mut status, 0);
            let child_ok = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;

            if notifications == 1 && child_ok {
                json!({
                    "status": "pass",
                    "detail": {
                        "notifications": notifications,
                        "child_open_ok": child_ok
                    }
                })
            } else {
                json!({
                    "status": "fail",
                    "detail": {
                        "notifications": notifications,
                        "child_open_ok": child_ok,
                        "child_exit_code": if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 }
                    }
                })
            }
        }
    }
}

/// Run one check. Checks are added here by TASK-0.3 to TASK-0.12.
fn run_check(id: &str, _args: &Args) -> Value {
    match id {
        #[cfg(target_os = "linux")]
        "P0-SPIKE-01" => linux_probe::check_listener(),
        #[cfg(target_os = "linux")]
        "P0-SPIKE-02" => linux_probe::check_continue(),
        #[cfg(not(target_os = "linux"))]
        "P0-SPIKE-01" | "P0-SPIKE-02" => json!({
            "status": "unsupported",
            "detail": { "reason": "seccomp is Linux-only" }
        }),
        _ => json!({ "status": "not_implemented", "detail": { "check": id } }),
    }
}

fn build_report(args: &Args) -> Result<Value, String> {
    let (kernel, arch) = host_info()?;
    let selected: Vec<&str> = match &args.selection {
        Selection::None => Vec::new(),
        Selection::All => ALL_CHECKS.to_vec(),
        Selection::One(id) => vec![id.as_str()],
    };
    let mut checks = Map::new();
    for id in selected {
        checks.insert(id.to_string(), run_check(id, args));
    }
    Ok(json!({
        "schema": SCHEMA,
        "kernel": kernel,
        "arch": arch,
        "checks": checks,
    }))
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("runner-probe: {e}");
            return ExitCode::from(64);
        }
    };
    match build_report(&args) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("runner-probe: {e}");
            ExitCode::from(70)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(v: &[&str]) -> Result<Args, String> {
        parse_args(v.iter().map(|s| s.to_string()))
    }

    #[test]
    fn defaults_to_all_checks() {
        assert_eq!(parse(&[]).unwrap().selection, Selection::All);
    }

    #[test]
    fn parses_single_check_and_iterations() {
        let a = parse(&["--check", "P0-SPIKE-03", "--iterations", "5"]).unwrap();
        assert_eq!(a.selection, Selection::One("P0-SPIKE-03".into()));
        assert_eq!(a.iterations, 5);
    }

    #[test]
    fn rejects_unknown_check() {
        assert!(parse(&["--check", "P0-SPIKE-99"]).is_err());
    }
}
