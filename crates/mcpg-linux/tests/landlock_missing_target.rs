#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use mcpg_app::capsule_plan::CapsulePlan;
use mcpg_app::ports::CapsuleLauncher;
use mcpg_domain::fs_view::StdFs;
use mcpg_domain::landlock_plan::{AccessFs, FsRule};
use mcpg_domain::mode::Mode;
use mcpg_domain::policy::resolve::PathEntry;
use mcpg_domain::policy::sets::EnforcementSet;
use mcpg_linux::entropy::OsEntropy;
use mcpg_linux::launcher::LinuxLauncher;
use mcpg_linux::rundir::RunDir;

fn probe_binary() -> PathBuf {
    let path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("syscall-probe");
    assert!(
        path.is_file(),
        "build the real fixture first: cargo build -p syscall-probe"
    );
    path.canonicalize().unwrap()
}

/// REQ-POL-007 / SPEC 3.1.5 regression: a missing rule must not grant
/// access to a sibling through the nearest existing ancestor.
#[test]
fn missing_landlock_target_does_not_grant_read_or_write_to_sibling() {
    let abi = mcpg_linux::landlock::get_landlock_abi();
    if abi == 0 {
        eprintln!("Landlock unavailable: kernel enforcement regression not exercised");
        return;
    }
    mcpg_linux::self_harden::harden_self().unwrap();

    let run = RunDir::create(&std::env::temp_dir(), false, &OsEntropy).unwrap();
    let outside = run.root().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let sibling = outside.join("sibling.txt");
    std::fs::write(&sibling, "must remain unchanged").unwrap();
    let missing = outside.join("missing-target");

    let probe = probe_binary();
    let exec =
        mcpg_domain::exec_deps::exec_closure(std::slice::from_ref(&probe), &StdFs, &|path| {
            std::fs::read(path)
        });
    let mut read_paths = vec![PathEntry::File(probe.clone())];
    for path in ["/usr", "/lib", "/lib64", "/etc/ld.so.cache"] {
        let path = PathBuf::from(path);
        if path.exists() {
            read_paths.push(if path.is_dir() {
                PathEntry::Dir(path)
            } else {
                PathEntry::File(path)
            });
        }
    }
    let sets = EnforcementSet {
        read_paths,
        write_paths: vec![PathEntry::Dir(run.workspace().to_path_buf())],
        capsule_home: run.home().to_path_buf(),
        capsule_tmp: run.tmp().to_path_buf(),
    };
    let mut ll_plan = mcpg_domain::landlock_plan::plan(&sets, &exec, abi, Mode::Enforce, true);
    ll_plan.fs_rules.push(FsRule {
        path: missing,
        access: AccessFs::READ_FILE | AccessFs::WRITE_FILE,
    });
    let ruleset_err = mcpg_linux::landlock::build(&ll_plan).unwrap_err();
    assert_eq!(ruleset_err.raw_os_error(), Some(libc::EACCES));
}
