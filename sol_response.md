There are several security issues beyond those in the report:

| Issue | Impact |
|---|---|
| Successful seccomp responses have `flags = 0` | This **emulates a successful syscall returning zero**; it does not execute the syscall. For example, an intercepted `openat()` appears to return stdin. Allowed syscalls need `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. |
| `openat2` uses the wrong pathname argument | Its pathname is argument **1**, not argument 0. |
| Failed pathname reads default to allow | Unreadable, invalid, or unterminated exec arguments bypass validation. |
| Lossy UTF-8 conversion | Different filesystem byte strings can become the same inspected string. |
| Notification IDs are not validated | Inspection results may belong to an interrupted/stale notification. |
| `allow_access` is combined across all scenarios | A scenario allowance incorrectly exempts startup and other scenarios. |
| Allowed canary leaks are suppressed | This directly contradicts `REQ-POL-009`: **leaks always remain MCPG002 errors**. |
| Every finding is tested as a warning | Default `fail_on: error` can produce PASS for credential leaks and unauthorized execution. |
| Landlock construction errors are discarded | An enforcement-mode run can silently execute without filesystem enforcement. |
| Tripwire initialization/watch errors and queue overflow are ignored | Missing observation can produce a false PASS. |
| Inotify buffer is cast to an aligned reference | A byte buffer need not be aligned for `inotify_event`; this is undefined behavior. |
| Tripwire file descriptor is never closed | Repeated runs leak descriptors. |
| Leak scanning examines independent read chunks | A secret split across two reads can evade detection. |
| Report-writing errors are discarded | The command can return success without producing its required evidence. |
| Environment PATH validation uses `\|_\| true` | Configured PATH entries are never checked against the EnforcementSet. |

**Important limitation:** changing `/proc/<pid>/mem` to `process_vm_readv`, canonicalizing a pathname, or validating a notification ID does **not** eliminate the pointer-argument race. Landlock must enforce filesystem/execute policy on the kernel’s actual object. Observe mode retains the documented weaker protection.

Below are complete replacements for the two Linux modules, followed by the necessary changes to `run.rs`. The complete repository, particularly the domain/report types and launcher, was not supplied, so I cannot honestly claim a workspace build or passing integration tests.

## 1. Replace `crates/mcpg-linux/src/observer.rs`

This retains the existing tuple channel to avoid inventing interfaces for unavailable report code. It removes basename matching, fixes syscall continuation and argument indexing, rejects failed exec inspection, validates notification IDs, and adds a narrowly scoped root-exec allowance.

```rust
use std::io;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::thread;

pub struct ObserverConfig {
    pub allow_network: bool,

    /// Canonical absolute paths, resolved using the final capsule PATH.
    pub allowed_child_binaries: Vec<PathBuf>,

    /// Canonical absolute path of the initial server executable.
    pub root_command: PathBuf,

    /// PID of the directly launched capsule.
    pub root_pid: u32,
}

#[cfg(target_os = "linux")]
fn validate_config(cfg: &ObserverConfig) -> io::Result<()> {
    for path in std::iter::once(&cfg.root_command)
        .chain(cfg.allowed_child_binaries.iter())
    {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "observer executable entries must be absolute",
            ));
        }

        // Do not silently reinterpret unresolved configuration.
        if std::fs::canonicalize(path)? != *path {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "observer executable entries must be canonical",
            ));
        }

        if !std::fs::metadata(path)?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "observer executable entry is not a file",
            ));
        }
    }

    Ok(())
}

/// Exact path comparison only. Inputs must already be canonical.
pub fn executable_allowed(path: &Path, allowed: &[PathBuf]) -> bool {
    path.is_absolute() && allowed.iter().any(|entry| entry == path)
}

#[cfg(target_os = "linux")]
fn notification_valid(fd: RawFd, id: u64) -> io::Result<bool> {
    let mut id = id;

    // SAFETY: `id` is writable storage of the type expected by this ioctl.
    let result = unsafe {
        libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_ID_VALID, &mut id)
    };

    if result == 0 {
        return Ok(true);
    }

    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOENT) => Ok(false),
        _ => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn resolve_exec_path(
    pid: u32,
    dirfd: Option<i32>,
    bytes: &[u8],
) -> io::Result<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    if bytes.is_empty() {
        // AT_EMPTY_PATH execution requires a separate fd-object evaluator.
        // Do not permit it through an empty-string bypass.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fd-based exec is not supported by the provisional evaluator",
        ));
    }

    let raw = Path::new(OsStr::from_bytes(bytes));
    let candidate = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        let proc_base = match dirfd {
            Some(fd) if fd != libc::AT_FDCWD => {
                PathBuf::from(format!("/proc/{pid}/fd/{fd}"))
            }
            _ => PathBuf::from(format!("/proc/{pid}/cwd")),
        };

        std::fs::read_link(proc_base)?.join(raw)
    };

    // Evidence/early rejection only: this is not race-free enforcement.
    std::fs::canonicalize(candidate)
}

#[cfg(target_os = "linux")]
pub fn start_observer_thread(
    listener_fd: RawFd,
    cfg: ObserverConfig,
    violations_tx: std::sync::mpsc::Sender<(String, String)>,
) -> io::Result<thread::JoinHandle<io::Result<()>>> {
    use libc::{
        seccomp_notif, seccomp_notif_resp, SECCOMP_IOCTL_NOTIF_RECV,
        SECCOMP_IOCTL_NOTIF_SEND,
    };

    validate_config(&cfg)?;

    Ok(thread::spawn(move || {
        let mut root_exec_pending = true;

        loop {
            // SAFETY: these C structures consist of integer fields; zero is
            // a valid initialization and RECV requires a cleared buffer.
            let mut req: seccomp_notif = unsafe { std::mem::zeroed() };

            // SAFETY: req points to writable notification storage.
            let result = unsafe {
                libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut req)
            };

            if result < 0 {
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EINTR) | Some(libc::ENOENT) => continue,
                    _ => return Err(error),
                }
            }

            if !notification_valid(listener_fd, req.id)? {
                continue;
            }

            let nr = req.data.nr as libc::c_long;
            let mut denied = false;
            let mut consume_root_exec = false;
            let mut finding: Option<(String, String)> = None;

            // The socket domain is a scalar argument, not a mutable pointer.
            // Do not label every AF_UNIX operation as IP networking.
            if nr == libc::SYS_socket
                && !cfg.allow_network
                && matches!(
                    req.data.args[0] as i32,
                    libc::AF_INET | libc::AF_INET6
                )
            {
                denied = true;
                finding = Some((
                    "MCPG007".into(),
                    "IP socket creation while allow_network is false".into(),
                ));
            }

            if nr == libc::SYS_execve || nr == libc::SYS_execveat {
                let (path_index, dirfd) = if nr == libc::SYS_execveat {
                    (1, Some(req.data.args[0] as i32))
                } else {
                    (0, None)
                };

                let inspected = read_child_path(
                    req.pid,
                    req.data.args[path_index],
                    4096,
                )
                .and_then(|bytes| resolve_exec_path(req.pid, dirfd, &bytes));

                match inspected {
                    Ok(path) => {
                        let initial_root_exec = root_exec_pending
                            && req.pid == cfg.root_pid
                            && path == cfg.root_command;

                        let allowed = initial_root_exec
                            || executable_allowed(
                                &path,
                                &cfg.allowed_child_binaries,
                            );

                        if allowed {
                            consume_root_exec = initial_root_exec;
                        } else {
                            denied = true;
                            finding = Some((
                                "MCPG006".into(),
                                format!(
                                    "Unapproved executable: {}",
                                    path.display()
                                ),
                            ));
                        }
                    }
                    Err(_) => {
                        denied = true;
                        finding = Some((
                            "MCPG006".into(),
                            "Executable could not be inspected reliably"
                                .into(),
                        ));
                    }
                }
            }

            // open/openat/openat2 are intentionally continued here.
            //
            // Their pointer arguments are observation, not authorization.
            // Landlock enforces access on the kernel's actual resolved object.
            // A domain evaluator must decide traversal using the resolved
            // policy, not `path.contains("..")`.
            //
            // In particular, openat2's pathname is args[1], as is openat's.

            if !notification_valid(listener_fd, req.id)? {
                continue;
            }

            // SAFETY: integer-only C response structure.
            let mut resp: seccomp_notif_resp =
                unsafe { std::mem::zeroed() };
            resp.id = req.id;

            if denied {
                resp.error = -libc::EACCES;
            } else {
                // Without this flag the syscall is NOT executed.
                resp.flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            }

            // SAFETY: resp points to a valid response structure.
            let result = unsafe {
                libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &mut resp)
            };

            if result < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENOENT) {
                    continue;
                }
                return Err(error);
            }

            if consume_root_exec {
                root_exec_pending = false;
            }

            if let Some(finding) = finding {
                violations_tx.send(finding).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "observer finding receiver disconnected",
                    )
                })?;
            }
        }
    }))
}

#[cfg(not(target_os = "linux"))]
pub fn start_observer_thread(
    _listener_fd: RawFd,
    _cfg: ObserverConfig,
    _violations_tx: std::sync::mpsc::Sender<(String, String)>,
) -> io::Result<thread::JoinHandle<io::Result<()>>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "seccomp observation requires Linux",
    ))
}

/// Read a NUL-terminated pathname, preserving its filesystem bytes.
///
/// Reading up to a page boundary avoids rejecting a valid short pathname
/// merely because memory beyond its terminator is unmapped.
#[cfg(target_os = "linux")]
pub fn read_child_path(
    pid: u32,
    addr: u64,
    max_len: usize,
) -> io::Result<Vec<u8>> {
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    if addr == 0 || max_len == 0 || max_len > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid pathname address or limit",
        ));
    }

    // SAFETY: sysconf has no pointer arguments.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Err(io::Error::other("could not determine page size"));
    }
    let page_size = page_size as u64;

    let file = File::open(format!("/proc/{pid}/mem"))?;
    let mut output = Vec::with_capacity(max_len);

    while output.len() < max_len {
        let offset = addr.checked_add(output.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "address overflow")
        })?;

        if offset > i64::MAX as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pathname address exceeds pread offset range",
            ));
        }

        let remaining_page = (page_size - offset % page_size) as usize;
        let count = remaining_page
            .min(max_len - output.len())
            .min(256);
        let mut buffer = [0u8; 256];

        let n = loop {
            match file.read_at(&mut buffer[..count], offset) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };

        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "pathname memory ended before its terminator",
            ));
        }

        if let Some(end) = buffer[..n].iter().position(|byte| *byte == 0) {
            output.extend_from_slice(&buffer[..end]);
            return Ok(output);
        }

        output.extend_from_slice(&buffer[..n]);
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "pathname is not NUL-terminated within PATH_MAX",
    ))
}

/// Compatibility helper. Security decisions should use read_child_path().
#[cfg(target_os = "linux")]
pub fn read_child_string(
    pid: u32,
    addr: u64,
    max_len: usize,
) -> io::Result<String> {
    String::from_utf8(read_child_path(pid, addr, max_len)?).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "pathname is not UTF-8",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p1_pol_04_same_basename_does_not_allow_another_executable() {
        let allowed = vec![PathBuf::from("/usr/bin/python3")];
        assert!(!executable_allowed(
            Path::new("/tmp/malware/python3"),
            &allowed,
        ));
    }

    #[test]
    fn exact_absolute_executable_is_allowed() {
        let allowed = vec![PathBuf::from("/usr/bin/python3")];
        assert!(executable_allowed(
            Path::new("/usr/bin/python3"),
            &allowed,
        ));
        assert!(!executable_allowed(Path::new("python3"), &allowed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pathname_reader_requires_a_terminator() {
        let bytes = [b'x'; 32];
        assert!(read_child_path(
            std::process::id(),
            bytes.as_ptr() as u64,
            bytes.len(),
        )
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pathname_reader_preserves_non_utf8() {
        let bytes = [b'/', 0xff, 0];
        assert_eq!(
            read_child_path(
                std::process::id(),
                bytes.as_ptr() as u64,
                bytes.len(),
            )
            .unwrap(),
            vec![b'/', 0xff],
        );
    }
}
```

This deliberately removes the incorrect `contains("..")` evaluator. A path such as `report..txt` is not traversal, and `../file` can still be authorized. Traversal findings require the domain resolver and EvaluationSet.

The module above does **not** replace the full syscall evaluator described in SPEC: Unix socket policy, process-tree signal decisions, tamper denials, and post-exec confirmation still require their respective implementations.

## 2. Replace `crates/mcpg-linux/src/inotify.rs`

This version:

- freezes the watch map before polling;
- rejects additions after start;
- owns the descriptor safely;
- parses events without alignment assumptions;
- propagates queue overflow and lost-watch errors;
- drains already queued events after stop;
- retains phase information rather than returning a run-wide set of kinds.

```rust
use std::collections::{HashMap, HashSet};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TripwireHit {
    pub kind_id: String,
    pub phase: String,
}

struct WatchState {
    started: bool,
    watches: HashMap<i32, HashSet<String>>,
}

pub struct Tripwire {
    fd: Arc<OwnedFd>,
    stop_flag: Arc<AtomicBool>,
    state: Mutex<WatchState>,
}

impl Tripwire {
    pub fn new() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: no pointer arguments; result is a new descriptor.
            let fd = unsafe {
                libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK)
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // SAFETY: fd is newly created and has exactly one owner.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };

            Ok(Self {
                fd: Arc::new(fd),
                stop_flag: Arc::new(AtomicBool::new(false)),
                state: Mutex::new(WatchState {
                    started: false,
                    watches: HashMap::new(),
                }),
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "inotify requires Linux",
            ))
        }
    }

    pub fn add_watch(&self, path: &Path, kind_id: String) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStrExt;

            let mut state = self.state.lock().map_err(|_| {
                io::Error::other("tripwire state lock poisoned")
            })?;

            if state.started {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cannot add watches after tripwire start",
                ));
            }

            let path = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "watch pathname contains NUL",
                    )
                })?;

            let mask = libc::IN_OPEN
                | libc::IN_ACCESS
                | libc::IN_CLOSE_NOWRITE
                | libc::IN_DELETE_SELF
                | libc::IN_MOVE_SELF
                | libc::IN_DONT_FOLLOW
                | libc::IN_MASK_ADD;

            // SAFETY: path is a valid, NUL-terminated CString.
            let wd = unsafe {
                libc::inotify_add_watch(
                    self.fd.as_raw_fd(),
                    path.as_ptr(),
                    mask,
                )
            };

            if wd < 0 {
                return Err(io::Error::last_os_error());
            }

            // Multiple aliases of the same inode can share a descriptor.
            state.watches.entry(wd).or_default().insert(kind_id);
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, kind_id);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "inotify requires Linux",
            ))
        }
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
    }

    pub fn start(
        &self,
        phase: Arc<dyn Fn() -> String + Send + Sync>,
    ) -> io::Result<thread::JoinHandle<io::Result<Vec<TripwireHit>>>> {
        let watches = {
            let mut state = self.state.lock().map_err(|_| {
                io::Error::other("tripwire state lock poisoned")
            })?;

            if state.started {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "tripwire already started",
                ));
            }
            state.started = true;
            std::mem::take(&mut state.watches)
        };

        let fd = Arc::clone(&self.fd);
        let stop_flag = Arc::clone(&self.stop_flag);

        Ok(thread::spawn(move || {
            #[cfg(target_os = "linux")]
            {
                poll_events(fd, stop_flag, watches, phase)
            }

            #[cfg(not(target_os = "linux"))]
            {
                let _ = (fd, stop_flag, watches, phase);
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "inotify requires Linux",
                ))
            }
        }))
    }
}

#[cfg(target_os = "linux")]
fn poll_events(
    fd: Arc<OwnedFd>,
    stop_flag: Arc<AtomicBool>,
    watches: HashMap<i32, HashSet<String>>,
    phase: Arc<dyn Fn() -> String + Send + Sync>,
) -> io::Result<Vec<TripwireHit>> {
    let mut buffer = [0u8; 16 * 1024];
    let mut hits = Vec::new();
    let mut seen = HashSet::new();
    let mut events_seen = 0usize;

    loop {
        let stopping = stop_flag.load(Ordering::Acquire);
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };

        // SAFETY: pollfd is valid writable storage for one descriptor.
        let result = unsafe {
            libc::poll(&mut pollfd, 1, if stopping { 0 } else { 100 })
        };

        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }

        if result == 0 {
            if stopping {
                return Ok(hits);
            }
            continue;
        }

        if pollfd.revents
            & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
            != 0
        {
            return Err(io::Error::other("tripwire descriptor failed"));
        }

        if pollfd.revents & libc::POLLIN == 0 {
            continue;
        }

        // SAFETY: buffer is writable for its advertised size.
        let n = unsafe {
            libc::read(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };

        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted
                || error.kind() == io::ErrorKind::WouldBlock
            {
                continue;
            }
            return Err(error);
        }

        if n == 0 {
            return Err(io::Error::other("unexpected tripwire EOF"));
        }

        let n = n as usize;
        let mut offset = 0usize;
        let header_size = std::mem::size_of::<libc::inotify_event>();

        while offset < n {
            if n - offset < header_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated inotify header",
                ));
            }

            // SAFETY: the bounds check guarantees a complete header.
            // read_unaligned is required because buffer is a byte array.
            let event = unsafe {
                std::ptr::read_unaligned(
                    buffer
                        .as_ptr()
                        .add(offset)
                        .cast::<libc::inotify_event>(),
                )
            };

            let size = header_size
                .checked_add(event.len as usize)
                .ok_or_else(|| io::Error::other("inotify length overflow"))?;

            if size > n - offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated inotify event",
                ));
            }
            offset += size;

            events_seen += 1;
            if events_seen > 200_000 {
                return Err(io::Error::other(
                    "tripwire event limit exceeded; coverage incomplete",
                ));
            }

            if event.mask & libc::IN_Q_OVERFLOW != 0 {
                return Err(io::Error::other(
                    "inotify queue overflow; coverage incomplete",
                ));
            }

            if event.mask
                & (libc::IN_IGNORED | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF)
                != 0
            {
                return Err(io::Error::other(
                    "canary watch invalidated; coverage incomplete",
                ));
            }

            if event.mask
                & (libc::IN_OPEN | libc::IN_ACCESS | libc::IN_CLOSE_NOWRITE)
                == 0
            {
                continue;
            }

            let kinds = watches.get(&event.wd).ok_or_else(|| {
                io::Error::other("event for unknown canary watch")
            })?;

            let current_phase = phase();
            for kind in kinds {
                if seen.insert((kind.clone(), current_phase.clone())) {
                    hits.push(TripwireHit {
                        kind_id: kind.clone(),
                        phase: current_phase.clone(),
                    });
                }
            }
        }
    }
}
```

The phase callback must be the **same cursor used by the MCP driver**. As the specification states, this is arrival-time attribution; inotify does not provide the originating PID or the time at which access occurred. Parent-directory watches additionally need filename filtering and replacement-file handling; do not add unfiltered directory watches to this map.

## 3. Replace tuple-only aggregation with a typed finding model

Add `crates/mcpg-domain/src/security_finding.rs` and export it from `lib.rs`:

```rust
pub mod security_finding;
```

```rust
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingLevel {
    Note,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityFinding {
    pub rule_id: String,
    pub normalized_target: String,
    pub phase: String,
    pub level: FindingLevel,
    pub message: String,
    pub occurrences: usize,
}

pub fn group_findings(
    findings: impl IntoIterator<Item = SecurityFinding>,
) -> Vec<SecurityFinding> {
    let mut groups: BTreeMap<
        (String, String, String),
        SecurityFinding,
    > = BTreeMap::new();

    for finding in findings {
        let key = (
            finding.rule_id.clone(),
            finding.normalized_target.clone(),
            finding.phase.clone(),
        );

        match groups.get_mut(&key) {
            Some(existing) => {
                existing.occurrences = existing
                    .occurrences
                    .saturating_add(finding.occurrences);
                existing.level = existing.level.max(finding.level);
            }
            None => {
                groups.insert(key, finding);
            }
        }
    }

    groups.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(message: &str, phase: &str) -> SecurityFinding {
        SecurityFinding {
            rule_id: "MCPG002".into(),
            normalized_target: "canary:ssh".into(),
            phase: phase.into(),
            level: FindingLevel::Error,
            message: message.into(),
            occurrences: 1,
        }
    }

    #[test]
    fn different_messages_group_by_semantic_identity() {
        let grouped = group_findings([
            finding("seen on stdout", "scenario:sign"),
            finding("seen on stderr", "scenario:sign"),
        ]);

        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].occurrences, 2);
        assert_eq!(grouped[0].message, "seen on stdout");
    }

    #[test]
    fn allowances_cannot_merge_different_phases() {
        let grouped = group_findings([
            finding("startup", "startup"),
            finding("scenario", "scenario:sign"),
        ]);
        assert_eq!(grouped.len(), 2);
    }
}
```

Create this model **at each observation source**, using the canary ID, executable path, or resolved path as the target. Do not recover identity by parsing a human-readable message.

Keep converting findings to `(rule_id, message)` only at the existing `RunRecord` compatibility boundary. The actual report model should subsequently be upgraded to retain level, phase, occurrences, and fingerprints.

## 4. Required `run.rs` corrections

### A. Remove leak exemptions entirely

Delete this block:

```rust
// Also filter data leak violations
violations.retain(|(reason, msg)| {
    // ...
});
```

Do **not** replace it with another allowance filter. Neither `declared_use` nor `allow_access` can exempt MCPG002.

Also delete the run-wide union of `allow_access`. Evaluate an access finding using its own phase:

```rust
fn scenario_allows_access(
    cfg: &Config,
    phase: &str,
    kind: mcpg_domain::canary::catalogue::CanaryKind,
) -> bool {
    let Some(id) = phase.strip_prefix("scenario:") else {
        return false;
    };

    cfg.scenarios
        .iter()
        .find(|scenario| scenario.id == id)
        .and_then(|scenario| scenario.canaries.as_ref())
        .is_some_and(|canaries| {
            canaries
                .allow_access
                .iter()
                .any(|configured| {
                    let configured:
                        mcpg_domain::canary::catalogue::CanaryKind =
                        (*configured).into();
                    configured == kind
                })
        })
}
```

For a matching access, emit **MCPG001 at note**, not no finding. Determine the ordinary level from the registry’s tier: tier A error, tier B warning.

### B. Share the phase cursor with the tripwire

Create `PhaseCursor` before starting either observer:

```rust
let phase = Arc::new(PhaseCursor::new());
```

Pass `&phase` into `execute_capsule_run`; remove its local `PhaseCursor::new()`.

Start the tripwire with a callback that obtains the current phase from the existing cursor API:

```rust
let phase_for_tripwire = Arc::clone(&phase);
let phase_reader: Arc<dyn Fn() -> String + Send + Sync> =
    Arc::new(move || {
        // Use PhaseCursor's actual current-phase accessor here.
        // That accessor was not included in the supplied files.
        phase_for_tripwire.current_phase_string()
    });

let handle = tw.start(phase_reader).map_err(|e| {
    eprintln!("failed to start tripwire: {e}");
    ExitCode::Internal
})?;
```

`current_phase_string()` above is the required integration seam, **not an assertion that this method already exists**. Implement it using the cursor’s existing synchronized state.

Propagate failures from `Tripwire::new()`, every `add_watch()`, thread joining, and the worker’s `io::Result`. Observation loss must never become PASS.

### C. Supply resolved executable entries to the observer

The existing observer receives raw YAML paths. Change `prepare_plan` to return the resolved policy as well, and pass its canonical `allowed_child_binaries` to `execute_capsule_run`.

Build the observer configuration as follows:

```rust
let obs_cfg = mcpg_linux::observer::ObserverConfig {
    allow_network: resolved_policy.allow_network,
    allowed_child_binaries:
        resolved_policy.allowed_child_binaries.clone(),
    root_command: canonical_root_command,
    root_pid: cap.child.id(),
};
```

Resolve `canonical_root_command` using the **final capsule PATH**, not a hard-coded host search or `unwrap_or_else`.

Handle `start_observer_thread` failure by shutting down the already launched capsule and returning an internal error.

The launcher must also provide an explicit observer shutdown/ownership contract. Its implementation was not supplied; leaving `_observer_thread` detached is not adequate.

### D. Propagate Landlock errors

Change the signature:

```rust
fn build_landlock_ruleset(
    policy: &ResolvedPolicy,
    vars: &VarTable,
    cmd: &str,
    caps: &HostCaps,
) -> Result<std::os::fd::OwnedFd, ExitCode>
```

Replace the final expression:

```rust
mcpg_linux::landlock::build(&plan).map_err(|e| {
    eprintln!("failed to build Landlock ruleset: {e}");
    ExitCode::Internal
})
```

Then in `prepare_plan`:

```rust
let ruleset =
    if ctx.mode == Mode::Enforce && ctx.caps.landlock.available {
        Some(build_landlock_ruleset(
            &resolved,
            &ctx.vars,
            &ctx.cfg.server.command,
            &ctx.caps,
        )?)
    } else {
        None
    };
```

Missing Landlock follows the documented fallback. **Failing to construct an available, requested ruleset does not.**

Similarly, replace ignored directory-creation errors:

```rust
for path in &resolved.to_create {
    fs::create_dir_all(path).map_err(|e| {
        eprintln!("failed to create policy directory {}: {e}", path.display());
        ExitCode::Internal
    })?;
}
```

### E. Apply the threshold to each finding’s real level

Replace the blanket warning check with:

```rust
use mcpg_domain::security_finding::FindingLevel;

let threshold = match effective_fail_on {
    mcpg_domain::config::model::FailOnLevel::Note => FindingLevel::Note,
    mcpg_domain::config::model::FailOnLevel::Warning => FindingLevel::Warning,
    mcpg_domain::config::model::FailOnLevel::Error => FindingLevel::Error,
};

if findings.iter().any(|finding| finding.level >= threshold) {
    final_code = mcpg_domain::verdict::combine([
        final_code,
        ExitCode::FailSecurity,
    ]);

    if final_code == ExitCode::FailSecurity {
        final_verdict = Verdict::FailSecurity;
    }
}
```

Use the rule catalogue’s level when constructing findings. In particular, MCPG002, MCPG006, and MCPG007 are errors.

### F. Fix streaming leak scanning

The scanner implementation was not supplied, so a correct replacement cannot assume its pattern-length API. The necessary implementation is:

1. Expose the maximum encoded pattern length from `LeakScanner`.
2. Retain the previous `max_pattern_len - 1` bytes.
3. Scan that tail plus each new chunk.
4. Ignore matches ending entirely within the old tail.
5. Track absolute stream offsets.
6. Apply this to **both stdout and stderr**.
7. Scan decoded JSON strings as well as raw transport bytes.

Do not use an arbitrary fixed overlap: longer encoded patterns would still evade detection.

Also, the existing stdout `if/else` constructs different concrete reader types. Always wrap stdout in one `ScanningReader` type with an optional scanner, or erase the reader type using `Box<dyn Read + Send>`.

### G. Stop ignoring report failures

For each output, use this pattern:

```rust
if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
    fs::create_dir_all(parent).map_err(|e| {
        eprintln!("failed to create report directory: {e}");
        ExitCode::Internal
    })?;
}

let mut file = fs::File::create(&path).map_err(|e| {
    eprintln!("failed to create report {}: {e}", path.display());
    ExitCode::Internal
})?;

writer.write(record, &mut file).map_err(|e| {
    eprintln!("failed to write report {}: {e}", path.display());
    ExitCode::Internal
})?;
```

Likewise, propagate `harden_self()` failure. Replace the permissive environment reachability predicate with the resolved EnforcementSet predicate, building the environment after policy resolution.

## 5. Regression tests required before merging

At minimum:

- Same basename under `/tmp` is denied; the exact canonical allowed executable is accepted.
- Root executable is permitted only for the initial root execution.
- Allowed `openat` really executes, rather than returning an emulated zero.
- `openat2` inspection reads argument 1.
- Unreadable, nonterminated, and empty exec paths cannot bypass validation.
- AF_UNIX socket creation is not classified as IP networking.
- Stale notifications produce neither responses nor trusted evidence.
- Inotify overflow, watch invalidation, and setup failure cannot yield PASS.
- An allowed SSH access produces MCPG001 at note **only in its scenario**.
- The same access during startup or another scenario remains an error.
- An allowed SSH value printed on stdout or stderr still produces MCPG002 and exit 1.
- A canary split at every possible read boundary is detected.
- Landlock build failure prevents capsule execution.
- Default `fail_on: error` fails for MCPG002, MCPG006, and MCPG007.
- Report-write failure returns exit 70.

One further confirmed problem exists in the supplied `SPEC.md` action example: direct `${{ inputs.* }}` interpolation into shell source permits command injection through inputs containing quotes. Move **all** action inputs into environment variables, then quote their shell expansions when constructing the argument array.

These changes address the concrete flaws in the supplied modules, but the remaining evaluator, streaming scanner, phase accessor, and launcher lifecycle need their actual source files to produce a complete, compile-verified repository patch.
