//! Component-wise path containment checking.
//!
//! Under REQ-PATH-002, containment is checked component by component rather
//! than by string prefix matching, so `/work/space` is not inside `/work/spa`.

use std::path::Path;

/// Check whether `path` is within `root` component-wise.
pub fn is_within(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}
