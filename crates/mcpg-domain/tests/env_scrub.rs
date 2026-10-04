use std::ffi::OsString;
use std::path::PathBuf;

use mcpg_domain::config::model::EnvConfig;
use mcpg_domain::env::{build_env, FixedEnv};

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

#[test]
fn p1_env_01_empty_config_yields_only_fixed_vars() {
    let host = make_host_vars();
    let cfg = EnvConfig::default();
    let fixed = default_fixed();
    let decoys = [];

    let env = build_env(&host, &cfg, &fixed, &decoys).expect("build_env succeeds");

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

    let env = build_env(&host, &cfg, &fixed, &decoys).expect("build_env succeeds");

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

    let env = build_env(&host, &cfg, &fixed, &decoys).expect("build_env succeeds");

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

    let env = build_env(&host, &cfg, &fixed, &decoys).expect("build_env succeeds");

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

    let env = build_env(&host, &cfg, &fixed, &decoys).expect("build_env succeeds");

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

    let env = build_env(&host, &cfg, &fixed, &decoys).expect("build_env succeeds");

    let found = env
        .iter()
        .find(|(k, _)| k == "AWS_SECRET_ACCESS_KEY")
        .expect("AWS_SECRET_ACCESS_KEY should be present");
    assert_eq!(found.1.to_string_lossy(), "user_value");
}
