#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use mcpg_domain::canary::catalogue::{all_catalogue_entries, CanaryKind};
use mcpg_domain::canary::render::plan;
use mcpg_domain::seed::Seed;
use mcpg_linux::canary_plant::plant;
use mcpg_linux::entropy::OsEntropy;
use mcpg_linux::rundir::RunDir;
use sha2::{Digest, Sha256};

fn compare_dirs_recursive(dir1: &Path, dir2: &Path) {
    let mut entries1: Vec<_> = std::fs::read_dir(dir1)
        .expect("read dir1")
        .map(|r| r.expect("entry1").path())
        .collect();
    let mut entries2: Vec<_> = std::fs::read_dir(dir2)
        .expect("read dir2")
        .map(|r| r.expect("entry2").path())
        .collect();

    entries1.sort();
    entries2.sort();

    assert_eq!(entries1.len(), entries2.len());

    for (p1, p2) in entries1.iter().zip(entries2.iter()) {
        assert_eq!(p1.file_name(), p2.file_name());
        let meta1 = std::fs::symlink_metadata(p1).expect("meta1");
        let meta2 = std::fs::symlink_metadata(p2).expect("meta2");

        if meta1.is_dir() {
            assert!(meta2.is_dir());
            compare_dirs_recursive(p1, p2);
        } else {
            assert!(meta1.is_file());
            assert!(meta2.is_file());
            let bytes1 = std::fs::read(p1).expect("read file1");
            let bytes2 = std::fs::read(p2).expect("read file2");
            assert_eq!(bytes1, bytes2, "file content mismatch at {:?}", p1);
        }
    }
}

#[test]
fn p1_can_01_plant_twice_byte_identical() {
    let entropy = OsEntropy;
    let temp_base = std::env::temp_dir();
    let run_dir1 = RunDir::create(&temp_base, false, &entropy).expect("create run dir 1");
    let run_dir2 = RunDir::create(&temp_base, false, &entropy).expect("create run dir 2");

    let seed = Seed::from_bytes([42u8; 32]);
    let kinds: Vec<CanaryKind> = all_catalogue_entries().iter().map(|e| e.kind).collect();
    let canary_plan = plan(&seed, &kinds);

    plant(&canary_plan, &run_dir1).expect("plant run dir 1");
    plant(&canary_plan, &run_dir2).expect("plant run dir 2");

    compare_dirs_recursive(run_dir1.home(), run_dir2.home());
}

#[test]
fn p1_can_05_file_and_dir_modes() {
    let entropy = OsEntropy;
    let temp_base = std::env::temp_dir();
    let run_dir = RunDir::create(&temp_base, false, &entropy).expect("create run dir");

    let seed = Seed::from_bytes([43u8; 32]);
    let kinds: Vec<CanaryKind> = all_catalogue_entries().iter().map(|e| e.kind).collect();
    let canary_plan = plan(&seed, &kinds);

    let registry = plant(&canary_plan, &run_dir).expect("plant run dir");

    // All planted files must have mode 0600
    for record in &registry.records {
        let meta = std::fs::metadata(&record.path).expect("metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "file {:?} had mode {:o} instead of 0600",
            record.path, mode
        );
    }

    // All directories in home must have mode 0700
    let mut dir_queue = vec![run_dir.home().to_path_buf()];
    while let Some(dir) = dir_queue.pop() {
        let meta = std::fs::metadata(&dir).expect("metadata for dir");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "directory {:?} had mode {:o} instead of 0700",
            dir, mode
        );
        for entry in std::fs::read_dir(&dir).expect("read dir") {
            let entry = entry.expect("entry");
            if entry.file_type().expect("file type").is_dir() {
                dir_queue.push(entry.path());
            }
        }
    }
}

#[test]
fn registry_records_dev_ino_and_fingerprint() {
    let entropy = OsEntropy;
    let temp_base = std::env::temp_dir();
    let run_dir = RunDir::create(&temp_base, false, &entropy).expect("create run dir");

    let seed = Seed::from_bytes([44u8; 32]);
    let kinds: Vec<CanaryKind> = all_catalogue_entries().iter().map(|e| e.kind).collect();
    let canary_plan = plan(&seed, &kinds);

    let registry = plant(&canary_plan, &run_dir).expect("plant run dir");

    assert!(!registry.records.is_empty());
    for record in &registry.records {
        assert!(record.dev > 0, "dev must be positive for {:?}", record.path);
        assert!(record.ino > 0, "ino must be positive for {:?}", record.path);
        assert_eq!(
            record.fp.len(),
            12,
            "fp length must be 12 for {:?}",
            record.path
        );
        assert!(
            record.fp.chars().all(|c| c.is_ascii_hexdigit()),
            "fp must be hex string"
        );

        if let Some(first_secret) = record.secrets.first() {
            let mut hasher = Sha256::new();
            hasher.update(first_secret.value.as_bytes());
            let full_hex = format!("{:x}", hasher.finalize());
            assert_eq!(
                record.fp,
                &full_hex[..12],
                "fp should match first 12 hex chars of sha256(secret)"
            );
        }
    }
}

#[test]
fn dotenv_planted_one_level_above_workspace() {
    let entropy = OsEntropy;
    let temp_base = std::env::temp_dir();
    let run_dir = RunDir::create(&temp_base, false, &entropy).expect("create run dir");

    let seed = Seed::from_bytes([45u8; 32]);
    let canary_plan = plan(&seed, &[CanaryKind::Dotenv]);

    let registry = plant(&canary_plan, &run_dir).expect("plant dotenv");
    let record = registry
        .records
        .iter()
        .find(|r| r.kind == CanaryKind::Dotenv)
        .expect("dotenv record found");

    let expected_path = run_dir.root().join(".env");
    assert_eq!(record.path, expected_path);

    // Workspace is inside root, so root is parent of workspace
    assert_eq!(
        run_dir.workspace().parent().expect("workspace parent"),
        run_dir.root()
    );
}
