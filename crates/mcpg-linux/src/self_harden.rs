//! Runner self-hardening.
//!
//! SPEC 1.4 (REQ-PROC-001):
//! The runner calls prctl(PR_SET_DUMPABLE, 0) on itself at startup.
//! That makes its own /proc/<pid>/environ and /proc/<pid>/mem unreadable
//! to same-UID child processes.

use std::io;

/// Harden the current process by clearing the dumpable flag.
pub fn harden_self() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let res = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if res != 0 {
            return Err(io::Error::last_os_error());
        }
        let check = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        if check != 0 {
            return Err(io::Error::other(
                "PR_GET_DUMPABLE check failed after hardening",
            ));
        }
    }
    Ok(())
}
