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
}

impl LinuxLauncher {
    /// Create a new Linux launcher and configure subreaper.
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        unsafe {
            let _ = libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
        }
        Self { landlock_fd: None }
    }

    /// Attach a pre-built Landlock ruleset file descriptor to restrict the child.
    pub fn with_landlock_fd(mut self, fd: std::os::fd::RawFd) -> Self {
        self.landlock_fd = Some(fd);
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
fn close_extra_fds_except(keep_fd: std::os::fd::RawFd) {
    #[cfg(target_os = "linux")]
    unsafe {
        const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;

        let set_cloexec_fallback = |start: i32, max: i32| {
            for fd in start..max {
                if fd != keep_fd {
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
            if fd != keep_fd {
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

        close_extra_fds_except(_landlock_fd);

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

        #[cfg(unix)]
        {
            let cwd_cstr = CString::new(plan.cwd.as_os_str().as_bytes())
                .map_err(|e| LaunchError::Failed(e.to_string()))?;
            let runner_pid = unsafe { libc::getpid() };
            let landlock_fd = self.landlock_fd.unwrap_or(-1);
            unsafe {
                cmd.pre_exec(move || child_pre_exec(&cwd_cstr, runner_pid, landlock_fd));
            }
        }

        let child = cmd.spawn()?;
        let pid = child.id();

        Ok(RunningCapsule { pid, child })
    }
}
