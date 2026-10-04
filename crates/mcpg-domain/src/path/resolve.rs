use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};

use crate::fs_view::FsView;
use crate::path::contain::is_within;

/// Error occurring during path resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    Eloop,
}

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
    pub error: Option<ResolveError>,
}

impl Resolution {
    pub fn is_eloop(&self) -> bool {
        self.error == Some(ResolveError::Eloop)
    }
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

fn check_symlink_escape(target: &Path, root: &Path, escaped_via: &mut Option<EscapeKind>) {
    if escaped_via.is_none() && !is_within(target, root) {
        *escaped_via = Some(EscapeKind::Symlink);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StepComp {
    ParentDir,
    Normal(std::ffi::OsString),
}

fn to_step_comp(comp: Component) -> Option<StepComp> {
    match comp {
        Component::ParentDir => Some(StepComp::ParentDir),
        Component::Normal(c) => Some(StepComp::Normal(c.to_os_string())),
        _ => None,
    }
}

fn push_target_components(target: &Path, pending: &mut VecDeque<StepComp>) {
    for comp in target.components().rev() {
        if let Some(step) = to_step_comp(comp) {
            pending.push_front(step);
        }
    }
}

fn check_is_symlink(fs: &dyn FsView, path: &Path, follow: bool) -> bool {
    if !follow {
        return false;
    }
    fs.lstat(path).map(|m| m.is_symlink()).unwrap_or(false)
}

struct Walker<'a> {
    fs: &'a dyn FsView,
    root: &'a Path,
    follow_last: bool,
    current: PathBuf,
    pending: VecDeque<StepComp>,
    symlinks_followed: u8,
    escaped_via: Option<EscapeKind>,
}

impl<'a> Walker<'a> {
    fn apply_symlink_target(&mut self, target: PathBuf) {
        check_symlink_escape(&target, self.root, &mut self.escaped_via);
        self.current.pop();
        if target.starts_with("/") {
            self.current = PathBuf::from("/");
        }
        push_target_components(&target, &mut self.pending);
    }

    fn handle_symlink(&mut self) -> Option<ResolveError> {
        if self.symlinks_followed >= 40 {
            return Some(ResolveError::Eloop);
        }
        self.symlinks_followed += 1;
        let target = self.fs.readlink(&self.current).ok()?;
        self.apply_symlink_target(target);
        None
    }

    fn step_normal(&mut self, c: &std::ffi::OsStr) -> Option<ResolveError> {
        self.current.push(c);
        let follow = !self.pending.is_empty() || self.follow_last;
        if !check_is_symlink(self.fs, &self.current, follow) {
            return None;
        }
        self.handle_symlink()
    }

    fn step_component(&mut self, comp: StepComp) -> Option<ResolveError> {
        match comp {
            StepComp::ParentDir => {
                handle_dotdot(&mut self.current, self.root, &mut self.escaped_via);
                None
            }
            StepComp::Normal(c) => self.step_normal(&c),
        }
    }

    fn run(&mut self) -> Option<ResolveError> {
        while let Some(comp) = self.pending.pop_front() {
            if let Some(err) = self.step_component(comp) {
                return Some(err);
            }
        }
        None
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

fn apply_lexical_comp(comp: Component, current: &mut PathBuf) {
    match comp {
        Component::ParentDir => {
            if current != Path::new("/") {
                current.pop();
            }
        }
        Component::Normal(c) => current.push(c),
        _ => {}
    }
}

fn compute_lexical(base: &Path, raw: &[u8]) -> PathBuf {
    let mut current = if raw.starts_with(b"/") {
        PathBuf::from("/")
    } else {
        base.to_path_buf()
    };

    let raw_path = raw_to_path(raw);
    for comp in raw_path.components() {
        apply_lexical_comp(comp, &mut current);
    }
    current
}

/// Resolve a path following kernel-like semantics.
pub fn resolve(
    fs: &dyn FsView,
    root: &Path,
    base: &Path,
    raw: &[u8],
    follow_last: bool,
) -> Resolution {
    let (current, escaped_via) = initial_state(root, base, raw);
    let raw_path = raw_to_path(raw);
    let pending: VecDeque<StepComp> = raw_path.components().filter_map(to_step_comp).collect();

    let mut walker = Walker {
        fs,
        root,
        follow_last,
        current,
        pending,
        symlinks_followed: 0,
        escaped_via,
    };

    let error = walker.run();
    let exists = fs.lstat(&walker.current).is_ok();
    let lexical = compute_lexical(base, raw);

    Resolution {
        resolved: walker.current,
        lexical,
        symlinks_followed: walker.symlinks_followed,
        exists,
        escaped_via: walker.escaped_via,
        error,
    }
}
