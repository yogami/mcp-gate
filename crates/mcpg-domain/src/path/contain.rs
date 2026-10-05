//! Component-wise path containment checking.
//!
//! Under REQ-PATH-002, containment is checked component by component rather
//! than by string prefix matching, so `/work/space` is not inside `/work/spa`.

use std::path::{Component, Path};

/// Check whether `path` is within `root` component-wise.
///
/// Everything is inside `/`. For any other root, a path that still holds a `..` component is
/// never reported as inside: it has not been normalised, so a prefix match would say nothing
/// about where it ends up (`/c/ws/../etc` starts with `/c/ws` but lands in `/c/etc`).
pub fn is_within(path: &Path, root: &Path) -> bool {
    if root == Path::new("/") {
        return true;
    }
    if path.components().any(|c| c == Component::ParentDir) {
        return false;
    }
    path.starts_with(root)
}
