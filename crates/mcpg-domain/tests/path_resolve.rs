use std::path::{Path, PathBuf};

use mcpg_domain::path::resolve::{resolve, EscapeKind};
use mcpg_domain::testing::FakeFs;

#[test]
fn p1_path_01_relative_join() {
    let mut fs = FakeFs::new();
    fs.add_file("/c/ws/a/b.txt", b"hello");

    let root = Path::new("/c/ws");
    let base = Path::new("/c/ws");
    let res = resolve(&fs, root, base, b"a/b.txt", true);

    assert_eq!(res.resolved, PathBuf::from("/c/ws/a/b.txt"));
    assert_eq!(res.escaped_via, None);
    assert!(res.exists);
}

#[test]
fn p1_path_02_dotdot_escape() {
    let mut fs = FakeFs::new();
    fs.add_file("/c/home/.ssh/id_ed25519", b"key");

    let root = Path::new("/c/ws");
    let base = Path::new("/c/ws");
    let res = resolve(&fs, root, base, b"../home/.ssh/id_ed25519", true);

    assert_eq!(res.resolved, PathBuf::from("/c/home/.ssh/id_ed25519"));
    assert_eq!(res.escaped_via, Some(EscapeKind::DotDot));
    assert!(res.exists);
}

#[test]
fn p1_path_03_absolute_escape() {
    let mut fs = FakeFs::new();
    fs.add_file("/etc/passwd", b"root:x:0:0:...");

    let root = Path::new("/c/ws");
    let base = Path::new("/c/ws");
    let res = resolve(&fs, root, base, b"/etc/passwd", true);

    assert_eq!(res.resolved, PathBuf::from("/etc/passwd"));
    assert_eq!(res.escaped_via, Some(EscapeKind::Absolute));
    assert!(res.exists);
}

#[test]
fn p1_path_04_dotdot_clamps_at_root() {
    let mut fs = FakeFs::new();
    fs.add_file("/x", b"target");

    let root = Path::new("/c/ws");
    let base = Path::new("/c/ws");
    let res = resolve(&fs, root, base, b"../../../../../../x", true);

    assert_eq!(res.resolved, PathBuf::from("/x"));
    assert_eq!(res.escaped_via, Some(EscapeKind::DotDot));
    assert!(res.exists);
}

#[test]
fn p1_path_09_redundant_separators() {
    let mut fs = FakeFs::new();
    fs.add_file("/c/ws/a/b", b"data");

    let root = Path::new("/c/ws");
    let base = Path::new("/c/ws");
    let res = resolve(&fs, root, base, b".//a/./b//", true);

    assert_eq!(res.resolved, PathBuf::from("/c/ws/a/b"));
    assert_eq!(res.escaped_via, None);
    assert!(res.exists);
}

#[test]
fn p1_path_11_dirfd_base_inside_root() {
    let mut fs = FakeFs::new();
    fs.add_file("/c/ws/f", b"data");

    let root = Path::new("/c/ws");
    let base = Path::new("/c/ws/sub");
    let res = resolve(&fs, root, base, b"../f", true);

    assert_eq!(res.resolved, PathBuf::from("/c/ws/f"));
    assert_eq!(res.escaped_via, None);
    assert!(res.exists);
}
