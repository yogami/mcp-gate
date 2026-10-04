use std::ffi::OsString;
use std::path::PathBuf;

use mcpg_domain::config::model::EnvConfig;
use mcpg_domain::env::{build_env, EnvError, FixedEnv};

fn default_fixed() -> FixedEnv {
    FixedEnv {
        home: PathBuf::from("/capsule/home"),
        tmpdir: PathBuf::from("/capsule/tmp"),
        path: "/usr/local/bin:/usr/bin:/bin".to_string(),
        lang: "C.UTF-8".to_string(),
    }
}

fn make_host_vars() -> Vec<(OsString, OsString)> {
    let mut vars = Vec::new();
    for i in 0..40 {
        vars.push((
            OsString::from(format!("HOST_VAR_{i}")),
            OsString::from(format!("val_{i}")),
        ));
    }
    vars.push((OsString::from("USER"), OsString::from("alice")));
    vars.push((OsString::from("SHELL"), OsString::from("/bin/bash")));
    vars
}

fn allow_all(_: &std::path::Path) -> bool {
    true
}

#[test]
fn p1_env_01_empty_config_yields_only_fixed_vars() {
    let host = make_host_vars();
    let cfg = EnvConfig::default();
    let fixed = default_fixed();
    let decoys = [];

    let env = build_env(&host, &cfg, &fixed, &decoys, &allow_all)
        .expect("build_env succeeds")
        .vars;

    let keys: Vec<String> = env
        .iter()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();

    assert_eq!(
        keys,
        vec![
            "HOME".to_string(),
            "LANG".to_string(),
            "PATH".to_string(),
            "TMPDIR".to_string()
        ],
        "empty config must yield exactly the 4 fixed variables in sorted order"
    );

    assert_eq!(
        env.iter()
            .find(|(k, _)| k == "HOME")
            .unwrap()
            .1
            .to_string_lossy(),
        "/capsule/home"
    );
    assert_eq!(
        env.iter()
            .find(|(k, _)| k == "TMPDIR")
            .unwrap()
            .1
            .to_string_lossy(),
        "/capsule/tmp"
    );
    assert_eq!(
        env.iter()
            .find(|(k, _)| k == "PATH")
            .unwrap()
            .1
            .to_string_lossy(),
        "/usr/local/bin:/usr/bin:/bin"
    );
    assert_eq!(
        env.iter()
            .find(|(k, _)| k == "LANG")
            .unwrap()
            .1
            .to_string_lossy(),
        "C.UTF-8"
    );
}

#[test]
fn p1_env_02_passthrough_copies_value() {
    let mut host = make_host_vars();
    host.push((
        OsString::from("MY_CUSTOM_VAR"),
        OsString::from("custom_secret_123"),
    ));

    let cfg = EnvConfig {
        passthrough: vec!["MY_CUSTOM_VAR".to_string()],
        ..Default::default()
    };
    let fixed = default_fixed();
    let decoys = [];

    let env = build_env(&host, &cfg, &fixed, &decoys, &allow_all)
        .expect("build_env succeeds")
        .vars;

    let found = env
        .iter()
        .find(|(k, _)| k == "MY_CUSTOM_VAR")
        .expect("MY_CUSTOM_VAR should be present");
    assert_eq!(found.1.to_string_lossy(), "custom_secret_123");
}

#[test]
fn p1_env_03_absent_passthrough_is_omitted() {
    let host = make_host_vars();
    let cfg = EnvConfig {
        passthrough: vec!["NON_EXISTENT_VAR".to_string()],
        ..Default::default()
    };
    let fixed = default_fixed();
    let decoys = [];

    let env = build_env(&host, &cfg, &fixed, &decoys, &allow_all)
        .expect("build_env succeeds")
        .vars;

    assert!(
        !env.iter().any(|(k, _)| k == "NON_EXISTENT_VAR"),
        "absent passthrough variable must be omitted, not set to empty"
    );
}

#[test]
fn p1_env_04_trailing_wildcard_prefix_match() {
    let mut host = make_host_vars();
    host.push((OsString::from("LC_ALL"), OsString::from("en_US.UTF-8")));
    host.push((OsString::from("LC_TIME"), OsString::from("de_DE.UTF-8")));
    host.push((OsString::from("LCX"), OsString::from("should_not_match")));

    let cfg = EnvConfig {
        passthrough: vec!["LC_*".to_string()],
        ..Default::default()
    };
    let fixed = default_fixed();
    let decoys = [];

    let env = build_env(&host, &cfg, &fixed, &decoys, &allow_all)
        .expect("build_env succeeds")
        .vars;

    assert!(env.iter().any(|(k, v)| k == "LC_ALL" && v == "en_US.UTF-8"));
    assert!(env
        .iter()
        .any(|(k, v)| k == "LC_TIME" && v == "de_DE.UTF-8"));
    assert!(!env.iter().any(|(k, _)| k == "LCX"));
}

#[test]
fn p1_env_10_set_overrides_passthrough() {
    let mut host = make_host_vars();
    host.push((OsString::from("TARGET_VAR"), OsString::from("from_host")));

    let mut set = std::collections::BTreeMap::new();
    set.insert("TARGET_VAR".to_string(), "from_set".to_string());

    let cfg = EnvConfig {
        passthrough: vec!["TARGET_VAR".to_string()],
        set,
        ..Default::default()
    };
    let fixed = default_fixed();
    let decoys = [];

    let env = build_env(&host, &cfg, &fixed, &decoys, &allow_all)
        .expect("build_env succeeds")
        .vars;

    let found = env
        .iter()
        .find(|(k, _)| k == "TARGET_VAR")
        .expect("TARGET_VAR should be present");
    assert_eq!(found.1.to_string_lossy(), "from_set");
}

#[test]
fn p1_env_11_user_set_name_skips_decoy() {
    let host = make_host_vars();
    let mut set = std::collections::BTreeMap::new();
    set.insert(
        "AWS_SECRET_ACCESS_KEY".to_string(),
        "user_value".to_string(),
    );

    let cfg = EnvConfig {
        set,
        ..Default::default()
    };
    let fixed = default_fixed();
    let decoys = [(
        OsString::from("AWS_SECRET_ACCESS_KEY"),
        OsString::from("decoy_value"),
    )];

    let env = build_env(&host, &cfg, &fixed, &decoys, &allow_all)
        .expect("build_env succeeds")
        .vars;

    let found = env
        .iter()
        .find(|(k, _)| k == "AWS_SECRET_ACCESS_KEY")
        .expect("AWS_SECRET_ACCESS_KEY should be present");
    assert_eq!(found.1.to_string_lossy(), "user_value");
}

#[test]
fn p1_env_05_ci_vars_dropped() {
    let mut host = make_host_vars();
    host.push((
        OsString::from("GITHUB_TOKEN"),
        OsString::from("ghp_secret123"),
    ));
    host.push((OsString::from("CI"), OsString::from("true")));
    host.push((OsString::from("RUNNER_OS"), OsString::from("Linux")));
    host.push((
        OsString::from("ACTIONS_RUNNER_NAME"),
        OsString::from("runner-1"),
    ));

    let cfg = EnvConfig {
        passthrough: vec![
            "GITHUB_TOKEN".to_string(),
            "CI".to_string(),
            "RUNNER_OS".to_string(),
            "ACTIONS_RUNNER_NAME".to_string(),
        ],
        ..Default::default()
    };
    let fixed = default_fixed();
    let decoys = [];

    let env = build_env(&host, &cfg, &fixed, &decoys, &allow_all)
        .expect("build_env succeeds")
        .vars;

    assert!(!env.iter().any(|(k, _)| k == "GITHUB_TOKEN"));
    assert!(!env.iter().any(|(k, _)| k == "CI"));
    assert!(!env.iter().any(|(k, _)| k == "RUNNER_OS"));
    assert!(!env.iter().any(|(k, _)| k == "ACTIONS_RUNNER_NAME"));
}

#[test]
fn p1_env_06_actions_tokens_forbidden() {
    let host = make_host_vars();
    let cfg = EnvConfig {
        passthrough: vec!["ACTIONS_RUNTIME_TOKEN".to_string()],
        ..Default::default()
    };
    let fixed = default_fixed();
    let decoys = [];

    let err = build_env(&host, &cfg, &fixed, &decoys, &allow_all)
        .expect_err("ACTIONS_RUNTIME_TOKEN must be forbidden");
    assert_eq!(
        err,
        EnvError::Forbidden("ACTIONS_RUNTIME_TOKEN".to_string())
    );

    let cfg_id = EnvConfig {
        passthrough: vec!["ACTIONS_ID_TOKEN_REQUEST_URL".to_string()],
        ..Default::default()
    };
    let err_id = build_env(&host, &cfg_id, &fixed, &decoys, &allow_all)
        .expect_err("ACTIONS_ID_TOKEN_REQUEST_URL must be forbidden");
    assert_eq!(
        err_id,
        EnvError::Forbidden("ACTIONS_ID_TOKEN_REQUEST_URL".to_string())
    );
}

#[test]
fn p1_env_07_secret_name_needs_opt_in() {
    let host = make_host_vars();
    let cfg = EnvConfig {
        passthrough: vec!["MY_API_KEY".to_string()],
        allow_secret_passthrough: false,
        ..Default::default()
    };
    let fixed = default_fixed();
    let decoys = [];

    let err = build_env(&host, &cfg, &fixed, &decoys, &allow_all)
        .expect_err("MY_API_KEY must need opt-in");
    assert_eq!(err, EnvError::SecretNeedsOptIn("MY_API_KEY".to_string()));
}

#[test]
fn p1_env_08_opt_in_passes_with_warning() {
    let mut host = make_host_vars();
    host.push((OsString::from("MY_API_KEY"), OsString::from("key_12345")));

    let cfg = EnvConfig {
        passthrough: vec!["MY_API_KEY".to_string()],
        allow_secret_passthrough: true,
        ..Default::default()
    };
    let fixed = default_fixed();
    let decoys = [];

    let outcome = build_env(&host, &cfg, &fixed, &decoys, &allow_all).expect("build_env succeeds");
    assert_eq!(outcome.warnings.len(), 1);
    assert!(outcome.warnings[0].contains("MY_API_KEY"));
    let found = outcome
        .vars
        .iter()
        .find(|(k, _)| k == "MY_API_KEY")
        .expect("MY_API_KEY should be present");
    assert_eq!(found.1.to_string_lossy(), "key_12345");
}

#[test]
fn p1_env_09_reserved_names_rejected() {
    let host = make_host_vars();
    let fixed = default_fixed();
    let decoys = [];

    let mut set_home = std::collections::BTreeMap::new();
    set_home.insert("HOME".to_string(), "/root".to_string());
    let cfg_home = EnvConfig {
        set: set_home,
        ..Default::default()
    };
    let err_home = build_env(&host, &cfg_home, &fixed, &decoys, &|_| true)
        .expect_err("HOME in set must be rejected");
    assert_eq!(err_home, EnvError::InvalidSet("HOME".to_string()));

    let mut set_tmp = std::collections::BTreeMap::new();
    set_tmp.insert("TMPDIR".to_string(), "/x".to_string());
    let cfg_tmp = EnvConfig {
        set: set_tmp,
        ..Default::default()
    };
    let err_tmp = build_env(&host, &cfg_tmp, &fixed, &decoys, &|_| true)
        .expect_err("TMPDIR in set must be rejected");
    assert_eq!(err_tmp, EnvError::InvalidSet("TMPDIR".to_string()));
}

#[test]
fn path_set_requires_reachable_entries() {
    let host = make_host_vars();
    let fixed = default_fixed();
    let decoys = [];

    let mut set_bad = std::collections::BTreeMap::new();
    set_bad.insert("PATH".to_string(), "/usr/bin:/opt/evil".to_string());
    let cfg_bad = EnvConfig {
        set: set_bad,
        ..Default::default()
    };
    let is_reachable = |p: &std::path::Path| p != std::path::Path::new("/opt/evil");
    let err = build_env(&host, &cfg_bad, &fixed, &decoys, &is_reachable)
        .expect_err("unreachable PATH entry must be rejected");
    assert_eq!(err, EnvError::InvalidSet("PATH".to_string()));

    let mut set_good = std::collections::BTreeMap::new();
    set_good.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    let cfg_good = EnvConfig {
        set: set_good,
        ..Default::default()
    };
    let outcome = build_env(&host, &cfg_good, &fixed, &decoys, &is_reachable)
        .expect("reachable PATH entries must be accepted");
    let found = outcome
        .vars
        .iter()
        .find(|(k, _)| k == "PATH")
        .expect("PATH should be present");
    assert_eq!(found.1.to_string_lossy(), "/usr/bin:/bin");
}

#[test]
fn env_path_checked_against_enforcement_set() {
    use mcpg_domain::config::model::{Baseline, PolicyConfig};
    use mcpg_domain::config::vars::VarTable;
    use mcpg_domain::policy::resolve::ResolvedPolicy;
    use mcpg_domain::policy::sets::EnforcementSet;
    use mcpg_domain::testing::FakeFs;

    let mut fs = FakeFs::new();
    fs.add_dir("/usr");
    fs.add_dir("/usr/bin");
    fs.add_dir("/bin");
    fs.add_dir("/capsule");
    fs.add_dir("/capsule/home");
    fs.add_dir("/capsule/tmp");

    let vars = VarTable {
        workspace: std::path::PathBuf::from("/capsule/workspace"),
        capsule_home: std::path::PathBuf::from("/capsule/home"),
        capsule_tmp: std::path::PathBuf::from("/capsule/tmp"),
        config_dir: std::path::PathBuf::from("/repo"),
    };

    let policy = PolicyConfig {
        baseline: Baseline::Minimal,
        read_paths: vec!["/bin".to_string()],
        write_paths: Vec::new(),
        allowed_child_binaries: Vec::new(),
        allow_network: false,
        allowed_unix_sockets: Vec::new(),
    };

    let resolved = ResolvedPolicy::from_config(&policy, &vars, &fs).expect("resolve policy");
    let enforcement = EnforcementSet::from_policy(&resolved, &vars);

    let host = make_host_vars();
    let fixed = default_fixed();
    let decoys = [];

    let mut set_good = std::collections::BTreeMap::new();
    set_good.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    let cfg_good = EnvConfig {
        set: set_good,
        ..Default::default()
    };
    let outcome = build_env(&host, &cfg_good, &fixed, &decoys, &|p| {
        enforcement.contains(p)
    })
    .expect("enforcement set allows /usr/bin and /bin");
    assert!(outcome
        .vars
        .iter()
        .any(|(k, v)| k == "PATH" && v == "/usr/bin:/bin"));

    let mut set_bad = std::collections::BTreeMap::new();
    set_bad.insert("PATH".to_string(), "/usr/bin:/opt/evil".to_string());
    let cfg_bad = EnvConfig {
        set: set_bad,
        ..Default::default()
    };
    let err = build_env(&host, &cfg_bad, &fixed, &decoys, &|p| {
        enforcement.contains(p)
    })
    .expect_err("enforcement set must reject /opt/evil");
    assert_eq!(err, EnvError::InvalidSet("PATH".to_string()));
}

#[cfg(unix)]
#[test]
fn p1_env_12_values_preserved_byte_exact() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let mut host = make_host_vars();
    let val_newline = OsString::from("line1\nline2");
    let val_equals = OsString::from("key=value=more");
    let val_bytes = OsString::from_vec(vec![b'a', 0xff, b'b', 0xfe]);

    host.push((OsString::from("VAR_NEWLINE"), val_newline));
    host.push((OsString::from("VAR_EQUALS"), val_equals));
    host.push((OsString::from("VAR_NON_UTF8"), val_bytes));

    let cfg = EnvConfig {
        passthrough: vec![
            "VAR_NEWLINE".to_string(),
            "VAR_EQUALS".to_string(),
            "VAR_NON_UTF8".to_string(),
        ],
        ..Default::default()
    };
    let fixed = default_fixed();
    let decoys = [];

    let outcome = build_env(&host, &cfg, &fixed, &decoys, &allow_all).expect("build_env succeeds");

    let found_nl = outcome
        .vars
        .iter()
        .find(|(k, _)| k == "VAR_NEWLINE")
        .expect("VAR_NEWLINE should be present");
    assert_eq!(found_nl.1.as_bytes(), b"line1\nline2");

    let found_eq = outcome
        .vars
        .iter()
        .find(|(k, _)| k == "VAR_EQUALS")
        .expect("VAR_EQUALS should be present");
    assert_eq!(found_eq.1.as_bytes(), b"key=value=more");

    let found_non_utf8 = outcome
        .vars
        .iter()
        .find(|(k, _)| k == "VAR_NON_UTF8")
        .expect("VAR_NON_UTF8 should be present");
    assert_eq!(found_non_utf8.1.as_bytes(), &[b'a', 0xff, b'b', 0xfe]);
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(100))]
    #[test]
    fn p1_env_13_output_sorted_and_stable(weights in proptest::collection::vec(proptest::prelude::any::<u32>(), 40)) {
        let base_host = make_host_vars();
        let cfg = EnvConfig {
            passthrough: vec!["HOST_VAR_*".to_string()],
            ..Default::default()
        };
        let fixed = default_fixed();
        let decoys = [];

        let expected = build_env(&base_host, &cfg, &fixed, &decoys, &allow_all)
            .expect("build_env succeeds")
            .vars;

        let mut items: Vec<(u32, (OsString, OsString))> = weights
            .into_iter()
            .zip(base_host.into_iter().take(40))
            .collect();
        items.sort_by_key(|&(w, _)| w);
        let shuffled: Vec<(OsString, OsString)> = items.into_iter().map(|(_, item)| item).collect();

        let outcome = build_env(&shuffled, &cfg, &fixed, &decoys, &allow_all)
            .expect("build_env succeeds");

        proptest::prop_assert_eq!(outcome.vars, expected);
    }
}
