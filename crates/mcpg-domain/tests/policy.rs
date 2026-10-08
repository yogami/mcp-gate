use std::path::{Path, PathBuf};

use mcpg_domain::config::model::{Baseline, PolicyConfig};
use mcpg_domain::config::vars::VarTable;
use mcpg_domain::policy::resolve::{PathEntry, PolicyError, ResolvedPolicy};
use mcpg_domain::testing::FakeFs;

fn test_vars() -> VarTable {
    VarTable {
        workspace: PathBuf::from("/capsule/workspace"),
        capsule_home: PathBuf::from("/capsule/home"),
        capsule_tmp: PathBuf::from("/capsule/tmp"),
        config_dir: PathBuf::from("/repo/project"),
    }
}

fn empty_policy() -> PolicyConfig {
    PolicyConfig {
        baseline: Baseline::None,
        read_paths: Vec::new(),
        write_paths: Vec::new(),
        allowed_child_binaries: Vec::new(),
        allow_network: false,
        allowed_unix_sockets: Vec::new(),
    }
}

#[test]
fn pol_entries_canonicalized() {
    let mut fs = FakeFs::new();
    fs.add_dir("/real");
    fs.add_dir("/real/path");
    fs.add_dir("/real/path/data");
    fs.add_file("/real/file.txt", b"hello");

    fs.add_dir("/link");
    fs.add_symlink("/link/data", "/real/path/data");
    fs.add_symlink("/link/file.txt", "/real/file.txt");

    let vars = test_vars();
    let mut policy = empty_policy();
    policy.read_paths = vec!["/link/data".to_string()];
    policy.write_paths = vec!["/link/file.txt".to_string()];

    let resolved = ResolvedPolicy::from_config(&policy, &vars, &fs).expect("canonicalize policy");

    assert_eq!(
        resolved.read_paths,
        vec![
            PathEntry::Dir(PathBuf::from("/real/path/data")),
            PathEntry::File(PathBuf::from("/real/file.txt")),
        ]
    );
    assert_eq!(
        resolved.write_paths,
        vec![PathEntry::File(PathBuf::from("/real/file.txt"))]
    );
}

#[test]
fn pol_missing_entry_is_error() {
    let fs = FakeFs::new();
    let vars = test_vars();

    let mut policy = empty_policy();
    policy.read_paths = vec!["/nope".to_string()];

    let err =
        ResolvedPolicy::from_config(&policy, &vars, &fs).expect_err("/nope should return Missing");
    assert!(
        matches!(err, PolicyError::Missing(ref p) if p == Path::new("/nope")),
        "expected PolicyError::Missing(/nope), got {err:?}"
    );
}

#[test]
fn pol_missing_under_workspace_scheduled_for_creation() {
    let mut fs = FakeFs::new();
    fs.add_dir("/capsule");
    fs.add_dir("/capsule/workspace");
    fs.add_dir("/capsule/tmp");

    let vars = test_vars();
    let mut policy = empty_policy();
    policy.read_paths = vec!["${WORKSPACE}/notes".to_string()];
    policy.write_paths = vec!["${CAPSULE_TMP}/scratch".to_string()];

    let resolved = ResolvedPolicy::from_config(&policy, &vars, &fs)
        .expect("missing entries under workspace/tmp should succeed");

    assert_eq!(
        resolved.to_create,
        vec![
            PathBuf::from("/capsule/workspace/notes"),
            PathBuf::from("/capsule/tmp/scratch"),
        ]
    );
    assert_eq!(
        resolved.read_paths,
        vec![
            PathEntry::Dir(PathBuf::from("/capsule/workspace/notes")),
            PathEntry::Dir(PathBuf::from("/capsule/tmp/scratch")),
        ]
    );
    assert_eq!(
        resolved.write_paths,
        vec![PathEntry::Dir(PathBuf::from("/capsule/tmp/scratch"))]
    );
}

#[test]
fn path_entry_methods() {
    let dir = PathEntry::Dir(PathBuf::from("/data"));
    assert_eq!(dir.path(), Path::new("/data"));
    assert!(dir.is_dir());

    let file = PathEntry::File(PathBuf::from("/data/f.txt"));
    assert_eq!(file.path(), Path::new("/data/f.txt"));
    assert!(!file.is_dir());
}

#[test]
fn pol_symlink_loop_rejected() {
    let mut fs = FakeFs::new();
    fs.add_symlink("/loop1", "/loop2");
    fs.add_symlink("/loop2", "/loop1");

    let vars = test_vars();
    let mut policy = empty_policy();
    policy.read_paths = vec!["/loop1".to_string()];

    let err = ResolvedPolicy::from_config(&policy, &vars, &fs).expect_err("symlink loop must fail");
    assert!(matches!(err, PolicyError::Loop(_)));
}

#[test]
fn policy_error_display_and_conversions() {
    use mcpg_domain::config::vars::VarError;

    let e_missing = PolicyError::Missing(PathBuf::from("/nope"));
    assert_eq!(
        e_missing.to_string(),
        "policy path entry does not exist: /nope"
    );

    let e_loop = PolicyError::Loop(PathBuf::from("/loop"));
    assert_eq!(
        e_loop.to_string(),
        "symlink loop resolving policy path: /loop"
    );

    let var_err = VarError::UnknownVariable("UNKNOWN".into());
    let e_var: PolicyError = var_err.into();
    assert_eq!(
        e_var.to_string(),
        "variable expansion error: unknown variable: UNKNOWN"
    );
}

#[test]
fn p1_pol_01_write_path_grants_read() {
    let mut fs = FakeFs::new();
    fs.add_dir("/ws");
    fs.add_dir("/ws/out");
    fs.add_file("/ws/out/f", b"content");

    let vars = test_vars();
    let mut policy = empty_policy();
    policy.write_paths = vec!["/ws/out".to_string()];

    let resolved = ResolvedPolicy::from_config(&policy, &vars, &fs).expect("resolve policy");

    assert!(resolved
        .read_paths
        .contains(&PathEntry::Dir(PathBuf::from("/ws/out"))));
    assert!(resolved
        .write_paths
        .contains(&PathEntry::Dir(PathBuf::from("/ws/out"))));
    assert!(resolved.is_read_allowed(Path::new("/ws/out/f")));
}

#[test]
fn p1_pol_02_child_binary_name_resolved_via_path() {
    use mcpg_domain::policy::resolve::resolve_binary;

    let mut fs = FakeFs::new();
    fs.add_dir("/bin");
    fs.add_dir("/usr");
    fs.add_dir("/usr/bin");
    fs.add_file("/usr/bin/git-real", b"elf");
    fs.add_symlink("/usr/bin/git", "/usr/bin/git-real");

    let capsule_path = "/usr/local/bin:/usr/bin:/bin";
    let resolved = resolve_binary("git", capsule_path, &fs).expect("git should resolve");
    assert_eq!(resolved, PathBuf::from("/usr/bin/git-real"));

    let vars = test_vars();
    let mut policy = empty_policy();
    policy.allowed_child_binaries = vec!["git".to_string()];
    let pol = ResolvedPolicy::from_config_with_path(&policy, &vars, capsule_path, &fs)
        .expect("resolve policy with binary");
    assert_eq!(
        pol.allowed_child_binaries,
        vec![PathBuf::from("/usr/bin/git-real")]
    );
}

#[test]
fn root_command_always_executable() {
    let mut fs = FakeFs::new();
    fs.add_dir("/usr");
    fs.add_dir("/usr/bin");
    fs.add_file("/usr/bin/python3", b"elf");
    fs.add_file("/usr/bin/git", b"elf");

    let vars = test_vars();
    let mut policy = empty_policy();
    policy.allowed_child_binaries = vec!["/usr/bin/git".to_string()];

    let pol = ResolvedPolicy::from_config(&policy, &vars, &fs).expect("resolve policy");

    assert!(pol.is_exec_allowed(Path::new("/usr/bin/python3"), true));
    assert!(!pol.is_exec_allowed(Path::new("/usr/bin/python3"), false));
    assert!(pol.is_exec_allowed(Path::new("/usr/bin/git"), false));
}

#[test]
fn p1_pol_03_baseline_python_snapshot() {
    use mcpg_domain::policy::baseline::expand_baseline;

    let mut fs = FakeFs::new();
    fs.add_file("/dev/null", b"");
    fs.add_file("/dev/urandom", b"");
    fs.add_file("/dev/zero", b"");
    fs.add_file("/etc/ld.so.cache", b"");
    fs.add_file("/etc/localtime", b"");
    fs.add_dir("/etc/ssl/certs");
    fs.add_dir("/lib");
    fs.add_dir("/lib64");
    fs.add_dir("/usr");
    fs.add_dir("/bin");
    fs.add_dir("/etc/python3");
    fs.add_dir("/usr/lib/python3");
    fs.add_dir("/usr/local/lib/python3");

    let entries = expand_baseline(Baseline::Python, &fs);
    let str_entries: Vec<String> = entries
        .iter()
        .map(|e| match e {
            PathEntry::Dir(d) => format!("Dir({})", d.display()),
            PathEntry::File(f) => format!("File({})", f.display()),
        })
        .collect();

    insta::assert_yaml_snapshot!(str_entries);
}

#[test]
fn baseline_none_adds_nothing() {
    use mcpg_domain::policy::baseline::expand_baseline;

    let mut fs = FakeFs::new();
    fs.add_dir("/usr");
    let entries = expand_baseline(Baseline::None, &fs);
    assert!(entries.is_empty());
}

#[test]
fn pol_capsule_tmp_always_rw() {
    let mut fs = FakeFs::new();
    fs.add_dir("/capsule");
    fs.add_dir("/capsule/workspace");
    fs.add_dir("/capsule/tmp");

    let vars = test_vars();
    let policy = empty_policy();

    let resolved = ResolvedPolicy::from_config(&policy, &vars, &fs).expect("resolve policy");

    assert!(resolved.is_read_allowed(Path::new("/capsule/tmp/test.txt")));
    assert!(resolved.is_write_allowed(Path::new("/capsule/tmp/test.txt")));
}

#[test]
fn p1_pol_04_decoy_zone_enforced_not_evaluated() {
    use mcpg_domain::policy::sets::{EnforcementSet, EvaluationSet};

    let mut fs = FakeFs::new();
    fs.add_dir("/capsule");
    fs.add_dir("/capsule/workspace");
    fs.add_dir("/capsule/home");
    fs.add_dir("/capsule/home/.ssh");
    fs.add_file("/capsule/home/.ssh/id_ed25519", b"canary");
    fs.add_dir("/capsule/tmp");

    let vars = test_vars();
    let policy = empty_policy();

    let resolved = ResolvedPolicy::from_config(&policy, &vars, &fs).expect("resolve policy");
    let enforcement = EnforcementSet::from_policy(&resolved, &vars);
    let evaluation = EvaluationSet::from_policy(&resolved, &vars);

    let canary_path = Path::new("/capsule/home/.ssh/id_ed25519");

    // REQ-POL-007: Decoy zone is in EnforcementSet (readable) but NOT in EvaluationSet
    assert!(enforcement.is_read_allowed(canary_path));
    assert!(enforcement.contains(canary_path));

    assert!(!evaluation.is_read_allowed(canary_path));
    assert!(!evaluation.contains(canary_path));
}

#[test]
fn evaluation_set_excludes_capsule_home() {
    use mcpg_domain::policy::sets::{EnforcementSet, EvaluationSet};

    let mut fs = FakeFs::new();
    fs.add_dir("/capsule/home");
    fs.add_dir("/capsule/tmp");

    let vars = test_vars();
    let policy = empty_policy();

    let resolved = ResolvedPolicy::from_config(&policy, &vars, &fs).expect("resolve policy");
    let enforcement = EnforcementSet::from_policy(&resolved, &vars);
    let evaluation = EvaluationSet::from_policy(&resolved, &vars);

    assert!(enforcement.is_read_allowed(Path::new("/capsule/home")));
    assert!(enforcement.contains(Path::new("/capsule/home")));

    assert!(!evaluation.is_read_allowed(Path::new("/capsule/home")));
    assert!(!evaluation.contains(Path::new("/capsule/home")));
}
