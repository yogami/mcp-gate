use std::fs;
use std::path::Path;

use mcpg_app::config::{load_str, SpanMap};

#[test]
fn span_policy_key_line() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/configs/valid/annotated.yaml");
    let content = fs::read_to_string(&path).expect("read annotated.yaml");
    let map = SpanMap::from_str(&content);

    assert_eq!(map.line_of("policy"), Some(19));
}

#[test]
fn span_scenario_id_line() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/configs/valid/annotated.yaml");
    let content = fs::read_to_string(&path).expect("read annotated.yaml");
    let map = SpanMap::from_str(&content);

    assert_eq!(map.line_of("scenarios[1].id"), Some(52));
}

#[test]
fn span_unknown_key_error_names_line() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/configs/invalid/unknown_key.yaml");
    let content = fs::read_to_string(&path).expect("read unknown_key.yaml");
    let err = load_str(&content).expect_err("unknown_key.yaml must fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("line 7"),
        "error message should cite line 7, got: {err_str}"
    );
}
