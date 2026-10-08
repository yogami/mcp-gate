use std::fs;
use std::path::Path;

use mcpg_app::config::{load_str, ConfigError};

#[test]
fn p1_cfg_02_invalid_configs_rejected() {
    let invalid_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/configs/invalid");

    let expected_files = [
        "unknown_key.yaml",
        "bad_version.yaml",
        "missing_policy.yaml",
        "glob_in_path.yaml",
    ];

    for filename in &expected_files {
        let path = invalid_dir.join(filename);
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let res = load_str(&content);
        match res {
            Err(ConfigError::Schema { .. }) | Err(ConfigError::Semantic { .. }) => {
                // Expected rejection
            }
            Err(ConfigError::Yaml { message, .. }) => {
                panic!(
                    "expected Schema or Semantic error for {}, got Yaml error: {message}",
                    path.display()
                );
            }
            Ok(_) => {
                panic!(
                    "expected config rejection for {}, but it loaded successfully",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn p1_seed_02_seed_key_rejected() {
    let invalid_file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/configs/invalid/canaries_seed.yaml");

    let content = fs::read_to_string(&invalid_file)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", invalid_file.display()));

    let res = load_str(&content);
    match res {
        Err(ConfigError::Schema { message, .. }) => {
            assert!(
                message.contains("seed"),
                "expected schema error to name 'seed', got: {message}"
            );
        }
        other => {
            panic!(
                "expected ConfigError::Schema naming 'seed' for canaries_seed.yaml, got: {:?}",
                other
            );
        }
    }
}

#[test]
fn config_error_methods() {
    let err_yaml = ConfigError::yaml("bad yaml", Some(12));
    assert_eq!(err_yaml.line(), Some(12));
    assert_eq!(err_yaml.message(), "bad yaml");
    assert_eq!(
        err_yaml.to_string(),
        "YAML parse error on line 12: bad yaml"
    );

    let err_schema = ConfigError::schema("bad schema", None);
    assert_eq!(err_schema.line(), None);
    assert_eq!(err_schema.message(), "bad schema");
    assert_eq!(
        err_schema.to_string(),
        "schema validation error: bad schema"
    );

    let err_sem = ConfigError::semantic("bad semantics", Some(5));
    assert_eq!(err_sem.line(), Some(5));
    assert_eq!(err_sem.message(), "bad semantics");
    assert_eq!(
        err_sem.to_string(),
        "semantic configuration error on line 5: bad semantics"
    );
}
