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
#[allow(unused_variables)]
fn close_extra_fds_except(keep_fds: &[std::os::fd::RawFd]) {
    #[cfg(target_os = "linux")]
    unsafe {
        const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;

        let mut start_fd = 3;
        // Since keep_fds is very small (max 2-3 items), we can just find the next one
        loop {
            // Find the smallest fd in keep_fds that is >= start_fd
            let mut next_keep = -1;
            for &fd in keep_fds {
                if fd >= start_fd && (next_keep == -1 || fd < next_keep) {
                    next_keep = fd;
                }
            }

            if next_keep == -1 {
                // No more fds to keep, close the rest
                let res = libc::syscall(
                    libc::SYS_close_range,
                    start_fd as u32,
                    !0u32,
                    CLOSE_RANGE_CLOEXEC,
                );
                if res < 0 {
                    // Fallback to loop if close_range fails (e.g. old kernel)
                    // DO NOT use sysconf! It is not async-signal-safe and can deadlock!
                    let max_fd = 10240;
                    for fd in start_fd..max_fd {
                        if !keep_fds.contains(&fd) {
                            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                        }
                    }
                }
                break;
            } else {
                if next_keep > start_fd {
                    // close [start_fd, next_keep - 1]
                    let res = libc::syscall(
                        libc::SYS_close_range,
                        start_fd as u32,
                        (next_keep - 1) as u32,
                        CLOSE_RANGE_CLOEXEC,
                    );
                    if res < 0 {
                        // Fallback
                        let max_fd = (next_keep - 1).min(10240);
                        for fd in start_fd..=max_fd {
                            if !keep_fds.contains(&fd) {
                                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                            }
                        }
                    }
                }
                start_fd = next_keep + 1;
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
            libc::_exit(127);
        }

        #[cfg(target_os = "linux")]
        {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0 {
                libc::_exit(127);
            }
            if libc::getppid() != _runner_pid {
                libc::_exit(127);
            }
        }

        let mut keep = [-1; 2];
        let mut keep_len = 0;
        if _landlock_fd >= 0 {
            keep[keep_len] = _landlock_fd;
            keep_len += 1;
        }
        if _child_sock >= 0 {
            keep[keep_len] = _child_sock;
            keep_len += 1;
        }
        close_extra_fds_except(&keep[..keep_len]);

        if libc::chdir(cwd_cstr.as_ptr()) < 0 {
            libc::_exit(127);
        }

        libc::umask(0o077);

        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &rlim) < 0 {
            libc::_exit(127);
        }

        #[cfg(target_os = "linux")]
        {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                libc::_exit(127);
            }

            if !_seccomp_ptr.is_null() && _seccomp_len > 0 && _child_sock >= 0 {
                let filter = std::slice::from_raw_parts(_seccomp_ptr, _seccomp_len);
                match crate::seccomp::install_seccomp_filter(filter) {
                    Ok(listener_fd) => {
                        let _ = crate::seccomp::send_fd(_child_sock, listener_fd);
                        libc::close(listener_fd);
                    }
                    Err(_) => {
                        libc::_exit(127);
                    }
                }
                libc::close(_child_sock);
            }

            if apply_landlock_in_child(_landlock_fd).is_err() {
                libc::_exit(127);
            }
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
        let mut child_sock = self.handover_sock;
        #[cfg(target_os = "linux")]
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


        #[cfg(target_os = "linux")]
        let mut seccomp_listener_fd = None;
        #[cfg(not(target_os = "linux"))]
        let seccomp_listener_fd = None;

        #[cfg(target_os = "linux")]
        let thread = if self.observe_seccomp {
            if let Some(ps) = parent_sock {
                Some(std::thread::spawn(move || {
                    let listener = match crate::seccomp::recv_fd(ps) {
                        Ok(fd) => unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) },
                        Err(_) => {
                            unsafe { libc::close(ps); }
                            return None;
                        }
                    };
                    unsafe {
                        libc::close(ps);
                    }
                    
                    let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
                    let ret = unsafe { libc::ioctl(listener.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_RECV, &mut req) };
                    if ret >= 0 {
                        let mut resp: libc::seccomp_notif_resp = unsafe { std::mem::zeroed() };
                        resp.id = req.id;
                        resp.error = 0;
                        resp.val = 0;
                        resp.flags = 1; // SECCOMP_USER_NOTIF_FLAG_CONTINUE
                        unsafe {
                            libc::ioctl(listener.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_SEND, &mut resp);
                        }
                    }
                    Some(listener)
                }))
            } else {
                None
            }
        } else {
            None
        };

        let child = cmd.spawn()?;
        let pid = child.id();

        #[cfg(target_os = "linux")]
        {
            if let Some(cs) = child_sock {
                unsafe { libc::close(cs); }
            }
            if let Some(t) = thread {
                if let Ok(Some(listener)) = t.join() {
                    seccomp_listener_fd = Some(listener);
                }
            }
        }

        Ok(RunningCapsule {
            pid,
            child,
            seccomp_listener_fd,
        })
    }
}
