use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use mcpg_domain::fs_view::{FileType, FsView};
use mcpg_domain::testing::FakeFs;

#[test]
fn fake_lstat_dir_file_symlink() {
    let mut fs = FakeFs::new();
    fs.add_dir("/capsule/home");
    fs.add_file("/capsule/home/file.txt", b"content");
    fs.add_symlink("/capsule/home/link", "file.txt");

    let meta_dir = fs.lstat(Path::new("/capsule/home")).expect("dir lstat ok");
    assert!(meta_dir.is_dir());
    assert_eq!(meta_dir.file_type, FileType::Dir);

    let meta_file = fs
        .lstat(Path::new("/capsule/home/file.txt"))
        .expect("file lstat ok");
    assert!(meta_file.is_file());
    assert_eq!(meta_file.file_type, FileType::File);
    assert_eq!(meta_file.len, 7);

    let meta_link = fs
        .lstat(Path::new("/capsule/home/link"))
        .expect("link lstat ok");
    assert!(meta_link.is_symlink());
    assert_eq!(meta_link.file_type, FileType::Symlink);
}

#[test]
fn fake_readlink_returns_target() {
    let mut fs = FakeFs::new();
    fs.add_symlink("/capsule/home/link", PathBuf::from("file.txt"));
    fs.add_file("/capsule/home/file.txt", b"content");

    let target = fs
        .readlink(Path::new("/capsule/home/link"))
        .expect("readlink ok");
    assert_eq!(target, PathBuf::from("file.txt"));

    let err = fs
        .readlink(Path::new("/capsule/home/file.txt"))
        .expect_err("readlink on file must fail");
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
}

#[test]
fn fake_missing_is_enoent() {
    let fs = FakeFs::new();

    let err_lstat = fs
        .lstat(Path::new("/nonexistent"))
        .expect_err("missing lstat must fail");
    assert_eq!(err_lstat.kind(), ErrorKind::NotFound);

    let err_readlink = fs
        .readlink(Path::new("/nonexistent"))
        .expect_err("missing readlink must fail");
    assert_eq!(err_readlink.kind(), ErrorKind::NotFound);
}
