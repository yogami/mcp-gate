use std::path::{Path, PathBuf};

use mcpg_domain::landlock_plan::{plan, AccessFs, AccessNet, Scope};
use mcpg_domain::mode::Mode;
use mcpg_domain::policy::resolve::PathEntry;
use mcpg_domain::policy::sets::EnforcementSet;

fn sample_enforcement_set() -> EnforcementSet {
    EnforcementSet {
        read_paths: vec![
            PathEntry::Dir(PathBuf::from("/usr")),
            PathEntry::File(PathBuf::from("/etc/hosts")),
        ],
        write_paths: vec![PathEntry::Dir(PathBuf::from("/workspace"))],
        capsule_home: PathBuf::from("/capsule/home"),
        capsule_tmp: PathBuf::from("/capsule/tmp"),
    }
}

#[test]
fn read_entries_get_read_rights() {
    let sets = sample_enforcement_set();
    let plan = plan(&sets, &[], 1, Mode::Enforce, true);

    let usr_rule = plan
        .fs_rules
        .iter()
        .find(|r| r.path == Path::new("/usr"))
        .expect("usr rule");
    assert_eq!(usr_rule.access, AccessFs::READ_FILE | AccessFs::READ_DIR);

    let hosts_rule = plan
        .fs_rules
        .iter()
        .find(|r| r.path == Path::new("/etc/hosts"))
        .expect("hosts rule");
    assert_eq!(hosts_rule.access, AccessFs::READ_FILE | AccessFs::READ_DIR);
}

#[test]
fn write_entries_add_write_rights() {
    let sets = sample_enforcement_set();
    let plan = plan(&sets, &[], 1, Mode::Enforce, true);

    let expected = AccessFs::READ_FILE
        | AccessFs::READ_DIR
        | AccessFs::WRITE_FILE
        | AccessFs::MAKE_REG
        | AccessFs::MAKE_DIR
        | AccessFs::MAKE_SYM
        | AccessFs::REMOVE_FILE
        | AccessFs::REMOVE_DIR;

    let ws_rule = plan
        .fs_rules
        .iter()
        .find(|r| r.path == Path::new("/workspace"))
        .expect("workspace rule");
    assert_eq!(ws_rule.access, expected);

    let tmp_rule = plan
        .fs_rules
        .iter()
        .find(|r| r.path == Path::new("/capsule/tmp"))
        .expect("tmp rule");
    assert_eq!(tmp_rule.access, expected);
}

#[test]
fn truncate_only_from_abi3() {
    let sets = sample_enforcement_set();

    let plan_abi2 = plan(&sets, &[], 2, Mode::Enforce, true);
    assert!(!plan_abi2.handled_access_fs.contains(AccessFs::TRUNCATE));
    let ws_rule_abi2 = plan_abi2
        .fs_rules
        .iter()
        .find(|r| r.path == Path::new("/workspace"))
        .expect("workspace rule");
    assert!(!ws_rule_abi2.access.contains(AccessFs::TRUNCATE));

    let plan_abi3 = plan(&sets, &[], 3, Mode::Enforce, true);
    assert!(plan_abi3.handled_access_fs.contains(AccessFs::TRUNCATE));
    let ws_rule_abi3 = plan_abi3
        .fs_rules
        .iter()
        .find(|r| r.path == Path::new("/workspace"))
        .expect("workspace rule");
    assert!(ws_rule_abi3.access.contains(AccessFs::TRUNCATE));
}

#[test]
fn decoy_zone_is_read_only() {
    let sets = sample_enforcement_set();
    let plan = plan(&sets, &[], 1, Mode::Enforce, true);

    let home_rule = plan
        .fs_rules
        .iter()
        .find(|r| r.path == Path::new("/capsule/home"))
        .expect("capsule home rule");
    assert_eq!(home_rule.access, AccessFs::READ_FILE | AccessFs::READ_DIR);
    assert!(!home_rule.access.contains(AccessFs::WRITE_FILE));
    assert!(!home_rule.access.contains(AccessFs::REMOVE_FILE));
}

#[test]
fn dev_nodes_get_ioctl_dev_from_abi5() {
    let sets = sample_enforcement_set();

    let plan_abi4 = plan(&sets, &[], 4, Mode::Enforce, true);
    assert!(!plan_abi4.handled_access_fs.contains(AccessFs::IOCTL_DEV));
    let null_rule_abi4 = plan_abi4
        .fs_rules
        .iter()
        .find(|r| r.path == Path::new("/dev/null"))
        .expect("dev null rule");
    assert!(!null_rule_abi4.access.contains(AccessFs::IOCTL_DEV));

    let plan_abi5 = plan(&sets, &[], 5, Mode::Enforce, true);
    assert!(plan_abi5.handled_access_fs.contains(AccessFs::IOCTL_DEV));
    let null_rule_abi5 = plan_abi5
        .fs_rules
        .iter()
        .find(|r| r.path == Path::new("/dev/null"))
        .expect("dev null rule");
    assert!(null_rule_abi5.access.contains(AccessFs::IOCTL_DEV));

    let urandom_rule = plan_abi5
        .fs_rules
        .iter()
        .find(|r| r.path == Path::new("/dev/urandom"))
        .expect("dev urandom rule");
    assert!(urandom_rule.access.contains(AccessFs::IOCTL_DEV));
}

#[test]
fn net_rules_when_network_denied_from_abi4() {
    let sets = sample_enforcement_set();

    let plan_denied = plan(&sets, &[], 4, Mode::Enforce, false);
    assert!(plan_denied
        .handled_access_net
        .contains(AccessNet::BIND_TCP | AccessNet::CONNECT_TCP));
    assert!(plan_denied.net_rules.is_empty());

    let plan_allowed = plan(&sets, &[], 4, Mode::Enforce, true);
    assert!(plan_allowed.handled_access_net.is_empty());
    assert!(plan_allowed.net_rules.is_empty());

    let plan_abi3 = plan(&sets, &[], 3, Mode::Enforce, false);
    assert!(plan_abi3.handled_access_net.is_empty());
}

#[test]
fn scopes_from_abi6() {
    let sets = sample_enforcement_set();

    let plan_abi5 = plan(&sets, &[], 5, Mode::Enforce, true);
    assert!(plan_abi5.scopes.is_empty());

    let plan_abi6 = plan(&sets, &[], 6, Mode::Enforce, true);
    assert!(plan_abi6
        .scopes
        .contains(Scope::ABSTRACT_UNIX_SOCKET | Scope::SIGNAL));
}

#[test]
fn observe_mode_has_no_fs_or_exec_rules() {
    let sets = sample_enforcement_set();
    let exec = vec![PathBuf::from("/usr/bin/git")];

    let plan = plan(&sets, &exec, 3, Mode::Observe, false);
    assert!(plan.fs_rules.is_empty());
    assert!(plan.handled_access_fs.is_empty());
}
