use std::fs;
use std::path::Path;

use mcpg_app::config::load_str;

#[test]
fn p1_cfg_01_valid_configs_load() {
    let valid_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/configs/valid");

    let entries = fs::read_dir(&valid_dir).expect("tests/configs/valid exists");
    let mut tested = 0;

    for entry in entries {
        let entry = entry.expect("valid dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            let content = fs::read_to_string(&path).expect("read yaml content");
            let cfg = load_str(&content)
                .unwrap_or_else(|e| panic!("failed to load {}: {:?}", path.display(), e));
            assert!(
                !cfg.server.name.is_empty(),
                "server.name must not be empty in {}",
                path.display()
            );
            tested += 1;
        }
    }

    assert!(
        tested >= 2,
        "must test at least minimal and annotated configs, tested: {tested}"
    );
}
