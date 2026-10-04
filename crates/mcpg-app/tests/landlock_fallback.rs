use std::path::PathBuf;

use mcpg_app::plan_mode::choose_mode;
use mcpg_domain::host::{Feature, HostCaps, LandlockCaps, SeccompCaps};
use mcpg_domain::landlock_plan::plan;
use mcpg_domain::mode::Mode;
use mcpg_domain::policy::resolve::PathEntry;
use mcpg_domain::policy::sets::EnforcementSet;
use mcpg_domain::verdict::ExitCode;

fn base_host_caps(landlock_available: bool, landlock_abi: u32) -> HostCaps {
    HostCaps {
        kernel: "6.8.0-generic".to_string(),
        arch: "x86_64".to_string(),
        landlock: LandlockCaps {
            available: landlock_available,
            abi: landlock_abi,
        },
        seccomp: SeccompCaps {
            filter: true,
            user_notif: true,
            notif_continue: true,
            wait_killable_recv: true,
        },
        inotify: true,
        proc_mem_readable: true,
        supported: true,
        missing: Vec::new(),
    }
}

fn sample_enforcement_set() -> EnforcementSet {
    EnforcementSet {
        read_paths: vec![PathEntry::Dir(PathBuf::from("/usr"))],
        write_paths: vec![PathEntry::Dir(PathBuf::from("/workspace"))],
        capsule_home: PathBuf::from("/capsule/home"),
        capsule_tmp: PathBuf::from("/capsule/tmp"),
    }
}

#[test]
fn no_landlock_falls_back_to_observe_with_notification() {
    let caps = base_host_caps(false, 0);
    let res = choose_mode(Mode::Enforce, &caps, &[]);
    let (mode, notifs) = res.expect("should fall back without failing");

    assert_eq!(mode, Mode::Observe);
    assert!(
        notifs.iter().any(|n| n.id == "landlock-unavailable"),
        "notifications should contain landlock-unavailable, got: {notifs:?}"
    );
}

#[test]
fn require_landlock_unmet_exits_69() {
    let caps = base_host_caps(false, 0);
    let err = choose_mode(Mode::Enforce, &caps, &[Feature::Landlock])
        .expect_err("should fail when required feature is missing");

    assert_eq!(err, ExitCode::UnsupportedHost);
    assert_eq!(err.as_i32(), 69);
}

#[test]
fn explicit_observe_mode_skips_fs_rules() {
    let caps = base_host_caps(true, 5);
    let (mode, notifs) =
        choose_mode(Mode::Observe, &caps, &[]).expect("explicit observe mode should succeed");

    assert_eq!(mode, Mode::Observe);
    assert!(notifs.is_empty());

    let sets = sample_enforcement_set();
    let exec = vec![PathBuf::from("/usr/bin/git")];
    let landlock_plan = plan(&sets, &exec, caps.landlock.abi as u8, mode, false);

    assert!(
        landlock_plan.fs_rules.is_empty(),
        "observe mode must have no filesystem rules"
    );
    assert!(
        landlock_plan.handled_access_fs.is_empty(),
        "observe mode must handle no filesystem rights"
    );
}
