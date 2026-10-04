//! Pure domain model for Landlock rule planning.
//!
//! SPEC 3.1.5: Computes Landlock filesystem access rights, network restrictions,
//! and scope rules from the policy enforcement set based on the kernel ABI version.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::mode::Mode;
use crate::policy::resolve::PathEntry;
use crate::policy::sets::EnforcementSet;

/// Landlock filesystem access rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AccessFs(pub u64);

impl AccessFs {
    pub const EXECUTE: Self = Self(1 << 0);
    pub const WRITE_FILE: Self = Self(1 << 1);
    pub const READ_FILE: Self = Self(1 << 2);
    pub const READ_DIR: Self = Self(1 << 3);
    pub const REMOVE_DIR: Self = Self(1 << 4);
    pub const REMOVE_FILE: Self = Self(1 << 5);
    pub const MAKE_CHAR: Self = Self(1 << 6);
    pub const MAKE_DIR: Self = Self(1 << 7);
    pub const MAKE_REG: Self = Self(1 << 8);
    pub const MAKE_SOCK: Self = Self(1 << 9);
    pub const MAKE_FIFO: Self = Self(1 << 10);
    pub const MAKE_BLOCK: Self = Self(1 << 11);
    pub const MAKE_SYM: Self = Self(1 << 12);
    pub const REFER: Self = Self(1 << 13);
    pub const TRUNCATE: Self = Self(1 << 14);
    pub const IOCTL_DEV: Self = Self(1 << 15);

    pub const EMPTY: Self = Self(0);

    pub fn bits(&self) -> u64 {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    pub fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

impl std::ops::BitOr for AccessFs {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl std::ops::BitOrAssign for AccessFs {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for AccessFs {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        self.intersect(rhs)
    }
}

impl std::ops::Not for AccessFs {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

/// Landlock network access rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AccessNet(pub u64);

impl AccessNet {
    pub const BIND_TCP: Self = Self(1 << 0);
    pub const CONNECT_TCP: Self = Self(1 << 1);

    pub const EMPTY: Self = Self(0);

    pub fn bits(&self) -> u64 {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    pub fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl std::ops::BitOr for AccessNet {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl std::ops::BitOrAssign for AccessNet {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Landlock process isolation scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Scope(pub u64);

impl Scope {
    pub const ABSTRACT_UNIX_SOCKET: Self = Self(1 << 0);
    pub const SIGNAL: Self = Self(1 << 1);

    pub const EMPTY: Self = Self(0);

    pub fn bits(&self) -> u64 {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    pub fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl std::ops::BitOr for Scope {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl std::ops::BitOrAssign for Scope {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Filesystem access rule for a specific path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsRule {
    pub path: PathBuf,
    pub access: AccessFs,
}

/// Network access rule for a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetRule {
    pub port: u16,
    pub access: AccessNet,
}

/// Complete plan of Landlock rules to apply in the capsule child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockPlan {
    pub abi: u8,
    pub mode: Mode,
    pub handled_access_fs: AccessFs,
    pub handled_access_net: AccessNet,
    pub scopes: Scope,
    pub fs_rules: Vec<FsRule>,
    pub net_rules: Vec<NetRule>,
}

fn base_abi_fs() -> AccessFs {
    AccessFs::EXECUTE
        | AccessFs::WRITE_FILE
        | AccessFs::READ_FILE
        | AccessFs::READ_DIR
        | AccessFs::REMOVE_DIR
        | AccessFs::REMOVE_FILE
        | AccessFs::MAKE_CHAR
        | AccessFs::MAKE_DIR
        | AccessFs::MAKE_REG
        | AccessFs::MAKE_SOCK
        | AccessFs::MAKE_FIFO
        | AccessFs::MAKE_BLOCK
        | AccessFs::MAKE_SYM
}

fn extra_abi_fs(abi: u8) -> AccessFs {
    let mut flags = AccessFs::EMPTY;
    if abi >= 2 {
        flags |= AccessFs::REFER;
    }
    if abi >= 3 {
        flags |= AccessFs::TRUNCATE;
    }
    if abi >= 5 {
        flags |= AccessFs::IOCTL_DEV;
    }
    flags
}

fn handled_fs_for_abi(abi: u8) -> AccessFs {
    if abi == 0 {
        AccessFs::EMPTY
    } else {
        base_abi_fs() | extra_abi_fs(abi)
    }
}

fn handled_net_for_abi(abi: u8, allow_network: bool) -> AccessNet {
    if !allow_network && abi >= 4 {
        AccessNet::BIND_TCP | AccessNet::CONNECT_TCP
    } else {
        AccessNet::EMPTY
    }
}

fn scopes_for_abi(abi: u8) -> Scope {
    if abi >= 6 {
        Scope::ABSTRACT_UNIX_SOCKET | Scope::SIGNAL
    } else {
        Scope::EMPTY
    }
}

fn read_rights() -> AccessFs {
    AccessFs::READ_FILE | AccessFs::READ_DIR
}

fn write_rights_for_abi(abi: u8) -> AccessFs {
    let mut rights = AccessFs::READ_FILE
        | AccessFs::READ_DIR
        | AccessFs::WRITE_FILE
        | AccessFs::MAKE_REG
        | AccessFs::MAKE_DIR
        | AccessFs::MAKE_SYM
        | AccessFs::REMOVE_FILE
        | AccessFs::REMOVE_DIR;
    if abi >= 3 {
        rights |= AccessFs::TRUNCATE;
    }
    rights
}

fn dev_node_rights_for_abi(abi: u8) -> AccessFs {
    let mut rights = AccessFs::READ_FILE | AccessFs::WRITE_FILE;
    if abi >= 5 {
        rights |= AccessFs::IOCTL_DEV;
    }
    rights
}

fn add_path_rules(
    rules: &mut BTreeMap<PathBuf, AccessFs>,
    entries: &[PathEntry],
    access: AccessFs,
) {
    for entry in entries {
        *rules.entry(entry.path().to_path_buf()).or_default() |= access;
    }
}

fn add_single_rule(rules: &mut BTreeMap<PathBuf, AccessFs>, path: PathBuf, access: AccessFs) {
    *rules.entry(path).or_default() |= access;
}

fn add_dev_nodes(rules: &mut BTreeMap<PathBuf, AccessFs>, rights: AccessFs) {
    let dev_nodes = ["/dev/null", "/dev/zero", "/dev/urandom"];
    for node in dev_nodes {
        add_single_rule(rules, PathBuf::from(node), rights);
    }
}

fn add_exec_rules(rules: &mut BTreeMap<PathBuf, AccessFs>, exec: &[PathBuf]) {
    for path in exec {
        add_single_rule(rules, path.clone(), AccessFs::EXECUTE);
    }
}

fn build_fs_rules(sets: &EnforcementSet, exec: &[PathBuf], abi: u8) -> Vec<FsRule> {
    let mut rules = BTreeMap::new();
    let r_rights = read_rights();
    let w_rights = write_rights_for_abi(abi);

    add_path_rules(&mut rules, &sets.read_paths, r_rights);
    add_single_rule(&mut rules, sets.capsule_home.clone(), r_rights);
    add_path_rules(&mut rules, &sets.write_paths, w_rights);
    add_single_rule(&mut rules, sets.capsule_tmp.clone(), w_rights);
    add_dev_nodes(&mut rules, dev_node_rights_for_abi(abi));
    add_exec_rules(&mut rules, exec);

    rules
        .into_iter()
        .map(|(path, access)| FsRule { path, access })
        .collect()
}

/// Compute the complete Landlock plan for the capsule.
pub fn plan(
    sets: &EnforcementSet,
    exec: &[PathBuf],
    abi: u8,
    mode: Mode,
    allow_network: bool,
) -> LandlockPlan {
    if mode == Mode::Observe || abi == 0 {
        return LandlockPlan {
            abi,
            mode,
            handled_access_fs: AccessFs::EMPTY,
            handled_access_net: AccessNet::EMPTY,
            scopes: Scope::EMPTY,
            fs_rules: Vec::new(),
            net_rules: Vec::new(),
        };
    }

    LandlockPlan {
        abi,
        mode,
        handled_access_fs: handled_fs_for_abi(abi),
        handled_access_net: handled_net_for_abi(abi, allow_network),
        scopes: scopes_for_abi(abi),
        fs_rules: build_fs_rules(sets, exec, abi),
        net_rules: Vec::new(),
    }
}
