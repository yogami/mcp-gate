#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use mcpg_linux::entropy::OsEntropy;
use mcpg_linux::rundir::RunDir;

#[test]
fn rundir_layout_and_mode_0700() {
    let entropy = OsEntropy;
    let base = std::env::temp_dir();
    let run_dir = RunDir::create(&base, false, &entropy).expect("create run dir");

    assert!(run_dir.root().exists(), "root must exist");
    assert!(run_dir.home().exists(), "home must exist");
    assert!(run_dir.workspace().exists(), "workspace must exist");
    assert!(run_dir.tmp().exists(), "tmp must exist");

    for dir in [
        run_dir.root(),
        run_dir.home(),
        run_dir.workspace(),
        run_dir.tmp(),
    ] {
        let meta = std::fs::metadata(dir).expect("metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "directory {:?} had mode {:o} instead of 0700",
            dir, mode
        );
    }
}

#[test]
fn rundir_id_is_16_hex() {
    let entropy = OsEntropy;
    let base = std::env::temp_dir();
    let run_dir = RunDir::create(&base, false, &entropy).expect("create run dir");

    let dir_name = run_dir
        .root()
        .file_name()
        .expect("dir name")
        .to_str()
        .expect("utf-8");

    let hex_id = dir_name
        .strip_prefix("mcpg-")
        .expect("dir name must start with mcpg-");

    assert_eq!(hex_id.len(), 16, "hex id must be 16 chars");
    assert!(
        hex_id.chars().all(|c| c.is_ascii_hexdigit()),
        "hex id must contain only hex digits"
    );
}

#[test]
fn rundir_removed_on_drop() {
    let entropy = OsEntropy;
    let base = std::env::temp_dir();
    let path = {
        let run_dir = RunDir::create(&base, false, &entropy).expect("create run dir");
        let root = run_dir.root().to_path_buf();
        assert!(root.exists());
        root
    };

    assert!(!path.exists(), "run dir must be deleted after drop");
}

#[test]
fn rundir_kept_with_keep_flag() {
    let entropy = OsEntropy;
    let base = std::env::temp_dir();
    let path = {
        let run_dir = RunDir::create(&base, true, &entropy).expect("create run dir");
        let root = run_dir.root().to_path_buf();
        assert!(root.exists());
        root
    };

    assert!(path.exists(), "run dir must be preserved with keep=true");
    let _ = std::fs::remove_dir_all(&path);
}
