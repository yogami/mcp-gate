use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};

use crate::fs_view::FsView;
use crate::path::contain::is_within;
use crate::path::proc_map::{
    build_proc_prefix, classify_proc_target, parse_fd, ProcCtx, ProcTarget,
};

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

    pub fn display(&self) -> String {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            escape_bytes(self.resolved.as_os_str().as_bytes())
        }
        #[cfg(not(unix))]
        {
            self.resolved.to_string_lossy().into_owned()
        }
    }
}

impl std::fmt::Display for Resolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

fn format_hex_byte(byte: u8, out: &mut String) {
    use std::fmt::Write;
    let _ = write!(out, "\\x{:02x}", byte);
}

fn append_error_bytes(bytes: &[u8], len: Option<usize>, out: &mut String) -> usize {
    let count = len.unwrap_or(bytes.len());
    for &b in &bytes[..count] {
        format_hex_byte(b, out);
    }
    count
}

fn step_escape_chunk(bytes: &[u8], out: &mut String) -> usize {
    match std::str::from_utf8(bytes) {
        Ok(valid) => {
            out.push_str(valid);
            valid.len()
        }
        Err(e) => {
            let valid_len = e.valid_up_to();
            if valid_len > 0 {
                let valid = &bytes[..valid_len];
                let s = std::str::from_utf8(valid).unwrap_or("");
                out.push_str(s);
                return valid_len;
            }
            append_error_bytes(bytes, e.error_len(), out)
        }
    }
}

/// Convert raw bytes into a UTF-8 string, escaping invalid UTF-8 bytes as `\xNN`.
pub fn escape_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        let consumed = step_escape_chunk(&bytes[offset..], &mut out);
        if consumed == 0 {
            break;
        }
        offset += consumed;
    }
    out
}

fn initial_state(base: &Path, raw: &[u8]) -> PathBuf {
    if raw.starts_with(b"/") {
        PathBuf::from("/")
    } else {
        base.to_path_buf()
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

fn apply_fd_target(
    target: Option<&Path>,
    fd: i32,
    current: &mut PathBuf,
    root: &Path,
    escaped_via: &mut Option<EscapeKind>,
) {
    if let Some(p) = target {
        *current = p.to_path_buf();
        if !is_within(current, root) {
            *escaped_via = Some(EscapeKind::ProcFd);
        }
    } else {
        current.push(fd.to_string());
    }
}

fn intercept_dev_fd(
    ctx: &ProcCtx,
    root: &Path,
    current: &mut PathBuf,
    pending: &mut VecDeque<StepComp>,
    escaped_via: &mut Option<EscapeKind>,
) -> bool {
    let next_str = match pending.front() {
        Some(StepComp::Normal(s)) => s.to_str(),
        _ => None,
    };
    let Some(fd) = next_str.and_then(parse_fd) else {
        return false;
    };
    pending.pop_front();
    let target = ctx.resolve_fd(None, fd);
    apply_fd_target(target, fd, current, root, escaped_via);
    true
}

fn check_is_fd_component(comp: Option<&StepComp>) -> bool {
    match comp {
        Some(StepComp::Normal(s)) => s == "fd",
        _ => false,
    }
}

fn try_pop_fd_num(pending: &mut VecDeque<StepComp>) -> Option<i32> {
    let s = match pending.front() {
        Some(StepComp::Normal(os)) => os.to_str(),
        _ => None,
    }?;
    let fd = parse_fd(s)?;
    pending.pop_front();
    Some(fd)
}

fn finish_proc_logical(
    target: ProcTarget,
    current: &mut PathBuf,
    pending: &mut VecDeque<StepComp>,
    escaped_via: &mut Option<EscapeKind>,
) {
    if matches!(target, ProcTarget::Foreign(_)) {
        *escaped_via = Some(EscapeKind::ProcFd);
    }
    *current = build_proc_prefix(&target);
    while let Some(comp) = pending.pop_front() {
        match comp {
            StepComp::Normal(s) => current.push(s),
            StepComp::ParentDir => {
                current.pop();
            }
        }
    }
}

fn handle_classified_proc(
    target: ProcTarget,
    name: &str,
    ctx: &ProcCtx,
    root: &Path,
    current: &mut PathBuf,
    pending: &mut VecDeque<StepComp>,
    escaped_via: &mut Option<EscapeKind>,
) {
    if check_is_fd_component(pending.front()) {
        pending.pop_front();
        if let Some(fd) = try_pop_fd_num(pending) {
            let pid = name.parse::<u32>().ok();
            let target_path = ctx.resolve_fd(pid, fd);
            apply_fd_target(target_path, fd, current, root, escaped_via);
            return;
        }
    }
    finish_proc_logical(target, current, pending, escaped_via);
}

fn peek_target_name(pending: &VecDeque<StepComp>) -> Option<String> {
    match pending.front() {
        Some(StepComp::Normal(s)) => s.to_str().map(|s| s.to_string()),
        _ => None,
    }
}

fn intercept_proc(
    ctx: &ProcCtx,
    root: &Path,
    current: &mut PathBuf,
    pending: &mut VecDeque<StepComp>,
    escaped_via: &mut Option<EscapeKind>,
) -> bool {
    let Some(target_name) = peek_target_name(pending) else {
        return false;
    };
    let Some(proc_target) = classify_proc_target(&target_name, ctx) else {
        return false;
    };
    pending.pop_front();
    handle_classified_proc(
        proc_target,
        &target_name,
        ctx,
        root,
        current,
        pending,
        escaped_via,
    );
    true
}

fn check_proc_intercept(
    ctx: &ProcCtx,
    root: &Path,
    current: &mut PathBuf,
    pending: &mut VecDeque<StepComp>,
    escaped_via: &mut Option<EscapeKind>,
) -> bool {
    if current == Path::new("/dev/fd") {
        return intercept_dev_fd(ctx, root, current, pending, escaped_via);
    }
    if current == Path::new("/proc") {
        return intercept_proc(ctx, root, current, pending, escaped_via);
    }
    false
}

struct Walker<'a> {
    fs: &'a dyn FsView,
    root: &'a Path,
    follow_last: bool,
    proc_ctx: Option<&'a ProcCtx>,
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

    fn step(&mut self) -> Option<ResolveError> {
        if let Some(ctx) = self.proc_ctx {
            if check_proc_intercept(
                ctx,
                self.root,
                &mut self.current,
                &mut self.pending,
                &mut self.escaped_via,
            ) {
                return None;
            }
        }
        let comp = self.pending.pop_front()?;
        self.step_component(comp)
    }

    fn run(&mut self) -> Option<ResolveError> {
        while !self.pending.is_empty() {
            if let Some(err) = self.step() {
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

fn is_proc_capsule(current: &Path) -> bool {
    current.to_string_lossy().starts_with("proc:capsule")
}

fn is_uncontained_absolute(raw: &[u8], root: &Path, current: &Path) -> bool {
    raw.starts_with(b"/") && !is_within(current, root)
}

fn finalize_escape(
    raw: &[u8],
    root: &Path,
    current: &Path,
    escaped_via: Option<EscapeKind>,
) -> Option<EscapeKind> {
    if escaped_via.is_some() {
        return escaped_via;
    }
    if is_proc_capsule(current) {
        return None;
    }
    if is_uncontained_absolute(raw, root, current) {
        return Some(EscapeKind::Absolute);
    }
    None
}

/// Resolve a path following kernel-like semantics.
pub fn resolve(
    fs: &dyn FsView,
    root: &Path,
    base: &Path,
    raw: &[u8],
    follow_last: bool,
    proc_ctx: Option<&ProcCtx>,
) -> Resolution {
    let current = initial_state(base, raw);
    let raw_path = raw_to_path(raw);
    let pending: VecDeque<StepComp> = raw_path.components().filter_map(to_step_comp).collect();

    let mut walker = Walker {
        fs,
        root,
        follow_last,
        proc_ctx,
        current,
        pending,
        symlinks_followed: 0,
        escaped_via: None,
    };

    let error = walker.run();
    let exists = if walker.current.to_string_lossy().starts_with("proc:") {
        false
    } else {
        fs.lstat(&walker.current).is_ok()
    };
    let lexical = compute_lexical(base, raw);
    let escaped_via = finalize_escape(raw, root, &walker.current, walker.escaped_via);

    Resolution {
        resolved: walker.current,
        lexical,
        symlinks_followed: walker.symlinks_followed,
        exists,
        escaped_via,
        error,
    }
}
