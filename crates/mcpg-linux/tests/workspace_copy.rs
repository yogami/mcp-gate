#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use mcpg_domain::config::model::{WorkspaceConfig, WorkspaceMode};
use mcpg_linux::entropy::OsEntropy;
use mcpg_linux::rundir::RunDir;
use mcpg_linux::workspace::prepare;

fn create_test_source() -> (tempfile_helper::TempDir, WorkspaceConfig) {
    let base = std::env::temp_dir();
    let entropy = OsEntropy;
    let run_dir = RunDir::create(&base, false, &entropy).expect("create helper dir");
    let src = run_dir.workspace().to_path_buf();

    // Create source files
    fs::create_dir_all(src.join(".git")).expect("create .git");
    fs::write(src.join(".git/config"), "fake git config").expect("write git config");

    fs::create_dir_all(src.join("src")).expect("create src");
    fs::write(src.join("src/main.rs"), "fn main() {}").expect("write main.rs");

    fs::create_dir_all(src.join("build")).expect("create build");
    fs::write(src.join("build/artifact.bin"), b"binary").expect("write artifact");

    // Create a symlink to /etc
    symlink(Path::new("/etc"), src.join("etc_link")).expect("create etc_link");

    let cfg = WorkspaceConfig {
        source: src.to_string_lossy().into_owned(),
        mode: WorkspaceMode::Copy,
        exclude: vec![".git".to_string()],
    };

    (tempfile_helper::TempDir(run_dir), cfg)
}

mod tempfile_helper {
    #[allow(dead_code)]
    pub struct TempDir(pub mcpg_linux::rundir::RunDir);
}

#[test]
fn copy_excludes_git_by_default() {
    let entropy = OsEntropy;
    let base = std::env::temp_dir();
    let run_dir = RunDir::create(&base, false, &entropy).expect("create run dir");
    let (_guard, cfg) = create_test_source();

    let ws = prepare(&cfg, &run_dir).expect("prepare workspace");

    assert_eq!(ws, *run_dir.workspace());
    assert!(
        !ws.join(".git").exists(),
        ".git must be excluded by default"
    );
    assert!(
        ws.join("src/main.rs").exists(),
        "src/main.rs must be copied"
    );
}

#[test]
fn copy_honours_extra_excludes() {
    let entropy = OsEntropy;
    let base = std::env::temp_dir();
    let run_dir = RunDir::create(&base, false, &entropy).expect("create run dir");
    let (_guard, mut cfg) = create_test_source();
    cfg.exclude.push("build".to_string());

    let ws = prepare(&cfg, &run_dir).expect("prepare workspace");

    assert!(!ws.join(".git").exists(), ".git must be excluded");
    assert!(!ws.join("build").exists(), "build must be excluded");
    assert!(
        ws.join("src/main.rs").exists(),
        "src/main.rs must be copied"
    );
}

#[test]
fn copy_preserves_symlinks_without_following() {
    let entropy = OsEntropy;
    let base = std::env::temp_dir();
    let run_dir = RunDir::create(&base, false, &entropy).expect("create run dir");
    let (_guard, cfg) = create_test_source();

    let ws = prepare(&cfg, &run_dir).expect("prepare workspace");

    let link_path = ws.join("etc_link");
    let meta = fs::symlink_metadata(&link_path).expect("link metadata");
    assert!(
        meta.file_type().is_symlink(),
        "etc_link must remain a symlink"
    );
    let target = fs::read_link(&link_path).expect("read link");
    assert_eq!(target, Path::new("/etc"));
}

#[test]
fn in_place_mode_points_at_source() {
    let entropy = OsEntropy;
    let base = std::env::temp_dir();
    let run_dir = RunDir::create(&base, false, &entropy).expect("create run dir");
    let (_guard, mut cfg) = create_test_source();
    cfg.mode = WorkspaceMode::InPlace;

    let ws = prepare(&cfg, &run_dir).expect("prepare in-place");

    assert_eq!(ws, Path::new(&cfg.source));
}

#[test]
fn plants_mcpg_link_to_capsule_ssh() {
    let entropy = OsEntropy;
    let base = std::env::temp_dir();
    let run_dir = RunDir::create(&base, false, &entropy).expect("create run dir");
    let (_guard, cfg) = create_test_source();

    let ws = prepare(&cfg, &run_dir).expect("prepare workspace");

    let mcpg_link = ws.join("mcpg-link");
    let meta = fs::symlink_metadata(&mcpg_link).expect("mcpg-link metadata");
    assert!(meta.file_type().is_symlink(), "mcpg-link must be a symlink");
    let target = fs::read_link(&mcpg_link).expect("read mcpg-link target");
    assert_eq!(target, run_dir.home().join(".ssh"));
}
