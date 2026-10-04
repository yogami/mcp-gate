use mcpg_domain::host::{Feature, HostCaps, LandlockCaps, SeccompCaps};

fn base_caps() -> HostCaps {
    HostCaps {
        kernel: "6.8.0-test".to_string(),
        arch: "x86_64".to_string(),
        landlock: LandlockCaps {
            available: true,
            abi: 4,
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

#[test]
fn supported_when_notif_inotify_procmem_present() {
    let caps = base_caps();
    let assessment = caps.assess(&[]);
    assert!(assessment.supported);
    assert!(assessment.missing.is_empty());
}

#[test]
fn missing_user_notif_is_unsupported() {
    let mut caps = base_caps();
    caps.seccomp.user_notif = false;
    let assessment = caps.assess(&[]);
    assert!(!assessment.supported);
    assert_eq!(assessment.missing, vec!["seccomp.user_notif".to_string()]);
}

#[test]
fn landlock_absent_still_supported() {
    let mut caps = base_caps();
    caps.landlock.available = false;
    caps.landlock.abi = 0;
    let assessment = caps.assess(&[]);
    assert!(assessment.supported);
    assert!(assessment.missing.is_empty());
}

#[test]
fn require_landlock_unmet_is_unsupported() {
    let mut caps = base_caps();
    caps.landlock.available = false;
    caps.landlock.abi = 0;
    let assessment = caps.assess(&[Feature::Landlock]);
    assert!(!assessment.supported);
    assert_eq!(assessment.missing, vec!["landlock".to_string()]);
}
