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
pub struct LinuxLauncher;

impl LinuxLauncher {
    /// Create a new Linux launcher.
    pub fn new() -> Self {
        Self
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
fn close_extra_fds() {
    #[cfg(target_os = "linux")]
    unsafe {
        let res = libc::syscall(libc::SYS_close_range, 3, !0u32, 0);
        if res < 0 {
            let max_fd = libc::sysconf(libc::_SC_OPEN_MAX).max(1024) as i32;
            for fd in 3..max_fd {
                libc::close(fd);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    unsafe {
        let max_fd = libc::sysconf(libc::_SC_OPEN_MAX).max(1024) as i32;
        for fd in 3..max_fd {
            libc::close(fd);
        }
    }
}

#[cfg(unix)]
fn child_pre_exec(cwd_cstr: &CString) -> io::Result<()> {
    // SAFETY: Invokes only async-signal-safe syscalls without allocating.
    unsafe {
        if libc::setsid() < 0 {
            return Err(io::Error::last_os_error());
        }

        close_extra_fds();

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
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
            return Err(io::Error::last_os_error());
        }

        // SeccompStep seam: Month 3 fills observer and landlock rules

        Ok(())
    }
}

impl CapsuleLauncher for LinuxLauncher {
    fn launch(&self, plan: &CapsulePlan) -> Result<RunningCapsule, LaunchError> {
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
            unsafe {
                cmd.pre_exec(move || child_pre_exec(&cwd_cstr));
            }
        }

        let child = cmd.spawn()?;
        let pid = child.id();

        Ok(RunningCapsule { pid, child })
    }
}
