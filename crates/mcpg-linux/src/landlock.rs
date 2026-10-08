//! Landlock Linux security module ruleset builder.
//!
//! SPEC 3.1.5: Constructs a Landlock ruleset fd in the runner process
//! granting access paths and restricting execute and network privileges.

#[cfg(not(target_os = "linux"))]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::path::Path;

use mcpg_domain::landlock_plan::LandlockPlan;
#[cfg(target_os = "linux")]
use mcpg_domain::landlock_plan::{AccessFs, FsRule};
use mcpg_domain::mode::Mode;

#[cfg(target_os = "linux")]
pub const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
#[cfg(target_os = "linux")]
pub const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
#[cfg(target_os = "linux")]
pub const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

#[cfg(target_os = "linux")]
pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
#[cfg(target_os = "linux")]
pub const LANDLOCK_RULE_NET_PORT: u32 = 2;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[cfg(target_os = "linux")]
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[cfg(target_os = "linux")]
#[cfg(target_os = "linux")]
fn add_single_fs_rule(ruleset_fd: RawFd, path: &Path, allowed_access: u64) -> std::io::Result<()> {
    if path.is_relative() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Landlock path must be absolute",
        ));
    }
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains null bytes")
    })?;
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Err(std::io::Error::from_raw_os_error(libc::EACCES));
        }
        return Err(err);
    }
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    let is_dir = (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    let dir_rights: u64 = AccessFs::READ_DIR.bits()
        | AccessFs::REMOVE_DIR.bits()
        | AccessFs::MAKE_DIR.bits()
        | AccessFs::MAKE_CHAR.bits()
        | AccessFs::MAKE_REG.bits()
        | AccessFs::MAKE_SOCK.bits()
        | AccessFs::MAKE_FIFO.bits()
        | AccessFs::MAKE_BLOCK.bits()
        | AccessFs::MAKE_SYM.bits();

    let actual_access = if !is_dir {
        allowed_access & !dir_rights
    } else {
        allowed_access
    };

    if actual_access == 0 {
        unsafe {
            libc::close(fd);
        }
        return Ok(());
    }

    let beneath = LandlockPathBeneathAttr {
        allowed_access: actual_access,
        parent_fd: fd,
    };
    let res = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &beneath as *const LandlockPathBeneathAttr,
            0u32,
        )
    };
    unsafe {
        libc::close(fd);
    }
    if res != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn add_all_fs_rules(ruleset_fd: RawFd, rules: &[FsRule], handled: AccessFs) -> std::io::Result<()> {
    for rule in rules {
        let allowed = (rule.access & handled).bits();
        if allowed > 0 {
            add_single_fs_rule(ruleset_fd, &rule.path, allowed)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ruleset_attr_size(abi: u8) -> usize {
    if abi >= 6 {
        std::mem::size_of::<LandlockRulesetAttr>()
    } else if abi >= 4 {
        std::mem::size_of::<u64>() * 2
    } else {
        std::mem::size_of::<u64>()
    }
}

#[cfg(target_os = "linux")]
fn create_ruleset_fd(plan: &LandlockPlan) -> std::io::Result<OwnedFd> {
    let attr = LandlockRulesetAttr {
        handled_access_fs: plan.handled_access_fs.bits(),
        handled_access_net: plan.handled_access_net.bits(),
        scoped: plan.scopes.bits(),
    };
    let size = ruleset_attr_size(plan.abi);
    let raw = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const LandlockRulesetAttr,
            size,
            0u32,
        ) as i32
    };
    if raw < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}

#[cfg(target_os = "linux")]
fn build_linux(plan: &LandlockPlan) -> std::io::Result<OwnedFd> {
    let ruleset = create_ruleset_fd(plan)?;
    add_all_fs_rules(ruleset.as_raw_fd(), &plan.fs_rules, plan.handled_access_fs)?;
    Ok(ruleset)
}

/// Query the host kernel for its Landlock ABI version (0 if unsupported).
pub fn get_landlock_abi() -> u8 {
    #[cfg(target_os = "linux")]
    unsafe {
        let ver = libc::syscall(SYS_LANDLOCK_CREATE_RULESET, std::ptr::null::<()>(), 0, 1u32);
        if ver > 0 {
            ver as u8
        } else {
            0
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Build the Landlock ruleset fd in the runner from a plan.
pub fn build(plan: &LandlockPlan) -> std::io::Result<OwnedFd> {
    if plan.mode == Mode::Observe || plan.abi == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "observe mode or abi 0 has no landlock ruleset",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        build_linux(plan)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "landlock is only supported on linux",
        ))
    }
}
