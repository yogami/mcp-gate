//! Capsule process launcher with pre_exec security hardening.
//!
//! SPEC 3.1.4: Prepares capsule child with unshared session, restricted fds,
//! NoNewPrivs, umask 077, disabled core dumps, and sanitized environment.

use std::ffi::{CString, OsStr};
use std::io;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use mcpg_app::capsule_plan::CapsulePlan;
use mcpg_app::ports::{CapsuleLauncher, LaunchError, RunningCapsule};

/// Linux capsule launcher implementing the CapsuleLauncher port.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxLauncher {
    landlock_fd: Option<std::os::fd::RawFd>,
    observe_seccomp: bool,
    pub(crate) handover_sock: Option<std::os::fd::RawFd>,
}

impl LinuxLauncher {
    /// Create a new Linux launcher and configure subreaper.
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        unsafe {
            let _ = libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
        }
        Self {
            landlock_fd: None,
            observe_seccomp: false,
            handover_sock: None,
        }
    }

    /// Attach a pre-built Landlock ruleset file descriptor to restrict the child.
    pub fn with_landlock_fd(mut self, fd: std::os::fd::RawFd) -> Self {
        self.landlock_fd = Some(fd);
        self
    }

    /// Enable seccomp observer filter installation in the child.
    pub fn with_seccomp(mut self, observe: bool) -> Self {
        self.observe_seccomp = observe;
        self
    }
    
    pub fn with_handover_sock(mut self, fd: std::os::fd::RawFd) -> Self {
        self.handover_sock = Some(fd);
        self
    }
}

fn apply_env_entry(cmd: &mut Command, item: &CString) {
    #[cfg(unix)]
    {
        let bytes = item.as_bytes();
        if let Some(pos) = bytes.iter().position(|&b| b == b'=') {
            let k = OsStr::from_bytes(&bytes[..pos]);
            let v = OsStr::from_bytes(&bytes[pos + 1..]);
            cmd.env(k, v);
        }
    }
    #[cfg(not(unix))]
    {
        let s = item.to_string_lossy();
        if let Some(pos) = s.find('=') {
            cmd.env(&s[..pos], &s[pos + 1..]);
        }
    }
}

fn apply_envp(cmd: &mut Command, envp: &[CString]) {
    cmd.env_clear();
    for item in envp {
        apply_env_entry(cmd, item);
    }
}

fn apply_argv(cmd: &mut Command, argv: &[CString]) {
    #[cfg(unix)]
    for arg in argv.iter().skip(1) {
        cmd.arg(OsStr::from_bytes(arg.as_bytes()));
    }
    #[cfg(not(unix))]
    for arg in argv.iter().skip(1) {
        cmd.arg(arg.to_string_lossy().as_ref());
    }
}

#[cfg(unix)]
fn close_extra_fds_except(keep_fds: &[std::os::fd::RawFd]) {
    #[cfg(target_os = "linux")]
    unsafe {
        const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;

        let set_cloexec_fallback = |start: i32, max: i32| {
            for fd in start..max {
                if !keep_fds.contains(&fd) {
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                }
            }
        };

        if keep_fd < 3 {
            let res = libc::syscall(libc::SYS_close_range, 3, !0u32, CLOSE_RANGE_CLOEXEC);
            if res < 0 {
                let max_fd = libc::sysconf(libc::_SC_OPEN_MAX).max(1024) as i32;
                set_cloexec_fallback(3, max_fd);
            }
        } else {
            let res1 = if keep_fd > 3 {
                libc::syscall(
                    libc::SYS_close_range,
                    3,
                    (keep_fd - 1) as u32,
                    CLOSE_RANGE_CLOEXEC,
                )
            } else {
                0
            };

            let res2 = libc::syscall(
                libc::SYS_close_range,
                (keep_fd + 1) as u32,
                !0u32,
                CLOSE_RANGE_CLOEXEC,
            );

            if res1 < 0 || res2 < 0 {
                let max_fd = libc::sysconf(libc::_SC_OPEN_MAX).max(1024) as i32;
                set_cloexec_fallback(3, max_fd);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    unsafe {
        let max_fd = libc::sysconf(libc::_SC_OPEN_MAX).max(1024) as i32;
        for fd in 3..max_fd {
            if !keep_fds.contains(&fd) {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn apply_landlock_in_child(fd: std::os::fd::RawFd) -> io::Result<()> {
    if fd >= 0 {
        let res = libc::syscall(crate::landlock::SYS_LANDLOCK_RESTRICT_SELF, fd, 0u32);
        libc::close(fd);
        if res != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn child_pre_exec(
    cwd_cstr: &CString,
    _runner_pid: libc::pid_t,
    _landlock_fd: std::os::fd::RawFd,
    _seccomp_ptr: *const crate::seccomp::sock_filter,
    _seccomp_len: usize,
    _child_sock: std::os::fd::RawFd,
) -> io::Result<()> {
    // SAFETY: Invokes only async-signal-safe syscalls without allocating.
    unsafe {
        if libc::setsid() < 0 {
            return Err(io::Error::last_os_error());
        }

        #[cfg(target_os = "linux")]
        {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != _runner_pid {
                libc::_exit(127);
            }
        }

        let mut keep = vec![];
        if _landlock_fd >= 0 { keep.push(_landlock_fd); }
        if _child_sock >= 0 { keep.push(_child_sock); }
        close_extra_fds_except(&keep);

        if libc::chdir(cwd_cstr.as_ptr()) < 0 {
            return Err(io::Error::last_os_error());
        }

        libc::umask(0o077);

        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &rlim) < 0 {
            return Err(io::Error::last_os_error());
        }

        #[cfg(target_os = "linux")]
        {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }

            if !_seccomp_ptr.is_null() && _seccomp_len > 0 && _child_sock >= 0 {
                let filter = std::slice::from_raw_parts(_seccomp_ptr, _seccomp_len);
                match crate::seccomp::install_seccomp_filter(filter) {
                    Ok(listener_fd) => {
                        let _ = crate::seccomp::send_fd(_child_sock, listener_fd);
                        libc::close(listener_fd);
                    }
                    Err(_) => {
                        libc::close(_child_sock);
                        return Err(io::Error::last_os_error());
                    }
                }
                libc::close(_child_sock);
            }

            apply_landlock_in_child(_landlock_fd)?;
        }

        Ok(())
    }
}

impl CapsuleLauncher for LinuxLauncher {
    fn launch(&self, plan: &CapsulePlan) -> Result<RunningCapsule, LaunchError> {
        #[cfg(target_os = "linux")]
        unsafe {
            let dumpable = libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0);
            if dumpable != 0 {
                return Err(LaunchError::NotHardened);
            }
        }

        #[cfg(unix)]
        let prog = OsStr::from_bytes(plan.program.as_bytes());
        #[cfg(not(unix))]
        let prog = plan.program.to_string_lossy();

        let mut cmd = Command::new(prog);
        apply_argv(&mut cmd, &plan.argv);
        apply_envp(&mut cmd, &plan.envp);

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        #[cfg(target_os = "linux")]
        let mut parent_sock = None;
        #[cfg(target_os = "linux")]
        let mut child_sock = None;
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
                    parent_sock = Some(sv[0]);
                    child_sock = Some(sv[1]);
                }
            }
            if let Some(cs) = child_sock {
                seccomp_filter = crate::seccomp::build_seccomp_filter_for_child(Some(cs));
                seccomp_ptr = seccomp_filter.as_ptr();
                seccomp_len = seccomp_filter.len();
            }
        }

        #[cfg(unix)]
        {
            let cwd_cstr = CString::new(plan.cwd.as_os_str().as_bytes())
                .map_err(|e| LaunchError::Failed(e.to_string()))?;
            let runner_pid = unsafe { libc::getpid() };
            let landlock_fd = self.landlock_fd.unwrap_or(-1);

            #[cfg(target_os = "linux")]
            let child_sock_raw = child_sock.unwrap_or(-1);
            #[cfg(not(target_os = "linux"))]
            let child_sock_raw = -1;

            #[cfg(target_os = "linux")]
            let s_ptr_usize = seccomp_ptr as usize;
            #[cfg(not(target_os = "linux"))]
            let s_ptr_usize = 0usize;

            #[cfg(target_os = "linux")]
            let s_len = seccomp_len;
            #[cfg(not(target_os = "linux"))]
            let s_len = 0;

            unsafe {
                cmd.pre_exec(move || {
                    let ptr = s_ptr_usize as *const crate::seccomp::sock_filter;
                    child_pre_exec(
                        &cwd_cstr,
                        runner_pid,
                        landlock_fd,
                        ptr,
                        s_len,
                        child_sock_raw,
                    )
                });
            }
        }

        let child = cmd.spawn()?;
        let pid = child.id();

        #[cfg(target_os = "linux")]
        let seccomp_listener_fd = None;
        #[cfg(not(target_os = "linux"))]
        let seccomp_listener_fd = None;
        #[cfg(target_os = "linux")]
        if let Some(cs) = child_sock {
            unsafe {
                libc::close(cs);
            }
        }

        Ok(RunningCapsule {
            pid,
            child,
            seccomp_listener_fd,
        })
    }
}
