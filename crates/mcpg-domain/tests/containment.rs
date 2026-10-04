use std::path::Path;

use mcpg_domain::path::contain::is_within;

#[test]
fn p1_cont_01_sibling_prefix_is_outside() {
    assert!(!is_within(Path::new("/work/space"), Path::new("/work/spa")));
}

#[test]
fn p1_cont_02_child_is_inside() {
    assert!(is_within(
        Path::new("/work/space/child.txt"),
        Path::new("/work/space")
    ));
    assert!(is_within(
        Path::new("/work/space/sub/dir/leaf"),
        Path::new("/work/space")
    ));
}

#[test]
fn p1_cont_03_equal_is_inside() {
    assert!(is_within(
        Path::new("/work/space"),
        Path::new("/work/space")
    ));
}

#[test]
fn p1_cont_04_root_not_inside_subdir() {
    assert!(!is_within(Path::new("/work"), Path::new("/work/space")));
    assert!(!is_within(Path::new("/"), Path::new("/work/space")));
}

#[test]
fn p1_cont_05_everything_inside_root() {
    assert!(is_within(Path::new("/work/space"), Path::new("/")));
    assert!(is_within(Path::new("/etc/passwd"), Path::new("/")));
    assert!(is_within(Path::new("/"), Path::new("/")));
}
