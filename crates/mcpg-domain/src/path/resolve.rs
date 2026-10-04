//! Kernel-like path resolution and containment tracking.

use std::path::{Component, Path, PathBuf};

use crate::fs_view::FsView;
use crate::path::contain::is_within;

/// How a path escaped the declared containment root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscapeKind {
    DotDot,
    Symlink,
    Absolute,
    ProcFd,
}

/// The result of resolving a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub resolved: PathBuf,
    pub lexical: PathBuf,
    pub symlinks_followed: u8,
    pub exists: bool,
    pub escaped_via: Option<EscapeKind>,
}

fn initial_state(root: &Path, base: &Path, raw: &[u8]) -> (PathBuf, Option<EscapeKind>) {
    if raw.starts_with(b"/") {
        let esc = if is_within(Path::new("/"), root) {
            None
        } else {
            Some(EscapeKind::Absolute)
        };
        (PathBuf::from("/"), esc)
    } else {
        (base.to_path_buf(), None)
    }
}

fn check_dotdot_escape(current: &Path, root: &Path, escaped_via: &mut Option<EscapeKind>) {
    if escaped_via.is_none() && !is_within(current, root) {
        *escaped_via = Some(EscapeKind::DotDot);
    }
}

fn handle_dotdot(current: &mut PathBuf, root: &Path, escaped_via: &mut Option<EscapeKind>) {
    if current != Path::new("/") {
        current.pop();
        check_dotdot_escape(current, root, escaped_via);
    }
}

fn handle_normal(current: &mut PathBuf, comp: &std::ffi::OsStr) {
    current.push(comp);
}

fn apply_component(
    comp: Component,
    current: &mut PathBuf,
    root: &Path,
    escaped_via: &mut Option<EscapeKind>,
) {
    match comp {
        Component::ParentDir => handle_dotdot(current, root, escaped_via),
        Component::Normal(c) => handle_normal(current, c),
        _ => {}
    }
}

fn raw_to_path(raw: &[u8]) -> &Path {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Path::new(std::ffi::OsStr::from_bytes(raw))
    }
    #[cfg(not(unix))]
    {
        Path::new(std::str::from_utf8(raw).unwrap_or(""))
    }
}

/// Resolve a path following kernel-like semantics.
pub fn resolve(
    fs: &dyn FsView,
    root: &Path,
    base: &Path,
    raw: &[u8],
    _follow_last: bool,
) -> Resolution {
    let (mut current, mut escaped_via) = initial_state(root, base, raw);
    let raw_path = raw_to_path(raw);

    for comp in raw_path.components() {
        apply_component(comp, &mut current, root, &mut escaped_via);
    }

    let exists = fs.lstat(&current).is_ok();
    let lexical = current.clone();

    Resolution {
        resolved: current,
        lexical,
        symlinks_followed: 0,
        exists,
        escaped_via,
    }
}
