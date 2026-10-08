use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::thread;

#[cfg(target_os = "linux")]
pub use libc::{
    seccomp_data, seccomp_notif, seccomp_notif_resp, SECCOMP_IOCTL_NOTIF_ID_VALID,
    SECCOMP_IOCTL_NOTIF_RECV, SECCOMP_IOCTL_NOTIF_SEND,
};

pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 0x00000001;

pub mod syscalls {
    pub const SYS_OPENAT: i64 = 257;
    pub const SYS_OPENAT2: i64 = 437;
    pub const SYS_EXECVE: i64 = 59;
    pub const SYS_EXECVEAT: i64 = 322;
    pub const SYS_CLONE: i64 = 56;
    pub const SYS_CLONE3: i64 = 435;
    pub const SYS_SOCKET: i64 = 41;
    pub const SYS_CONNECT: i64 = 42;
    pub const SYS_BIND: i64 = 49;
    pub const SYS_SENDTO: i64 = 44;
    pub const SYS_KILL: i64 = 62;
    pub const SYS_TKILL: i64 = 200;
    pub const SYS_TGKILL: i64 = 234;
    pub const SYS_IO_URING_SETUP: i64 = 425;
    pub const SYS_IO_URING_ENTER: i64 = 426;
    pub const SYS_IO_URING_REGISTER: i64 = 427;
}

pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const AT_FDCWD: i32 = -100;
pub const X32_SYSCALL_BIT: i64 = 0x4000_0000;
pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// Memory reader abstraction for inspecting child process memory and symlinks.
pub trait MemoryReader: Send + Sync {
    fn read_string(&self, pid: u32, addr: u64, max_len: usize) -> std::io::Result<String>;
    fn read_bytes(&self, pid: u32, addr: u64, len: usize) -> std::io::Result<Vec<u8>>;
    fn read_link(&self, path: &Path) -> std::io::Result<PathBuf>;
}

/// Real memory reader using Linux `/proc/<pid>/mem` and `readlink`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealMemoryReader;

impl MemoryReader for RealMemoryReader {
    fn read_string(&self, pid: u32, addr: u64, max_len: usize) -> std::io::Result<String> {
        read_child_string(pid, addr, max_len)
    }

    fn read_bytes(&self, pid: u32, addr: u64, len: usize) -> std::io::Result<Vec<u8>> {
        read_child_bytes(pid, addr, len)
    }

    fn read_link(&self, path: &Path) -> std::io::Result<PathBuf> {
        std::fs::read_link(path)
    }
}

/// In-memory mock reader for portable cross-platform testing.
#[derive(Debug, Default, Clone)]
pub struct MockMemoryReader {
    pub strings: HashMap<(u32, u64), String>,
    pub bytes: HashMap<(u32, u64), Vec<u8>>,
    pub links: HashMap<PathBuf, PathBuf>,
}

impl MemoryReader for MockMemoryReader {
    fn read_string(&self, pid: u32, addr: u64, _max_len: usize) -> std::io::Result<String> {
        self.strings.get(&(pid, addr)).cloned().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "mock string not found")
        })
    }

    fn read_bytes(&self, pid: u32, addr: u64, len: usize) -> std::io::Result<Vec<u8>> {
        if let Some(data) = self.bytes.get(&(pid, addr)) {
            let take_len = len.min(data.len());
            Ok(data[..take_len].to_vec())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "mock bytes not found",
            ))
        }
    }

    fn read_link(&self, path: &Path) -> std::io::Result<PathBuf> {
        self.links
            .get(path)
            .cloned()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "mock link not found"))
    }
}

/// Observer configuration parameters.
#[derive(Debug, Clone, Default)]
pub struct ObserverConfig {
    pub allow_network: bool,
    pub allowed_child_binaries: Vec<PathBuf>,
    pub root_command: Option<PathBuf>,
    pub allowed_unix_sockets: Vec<String>,
    pub capsule_pids: Vec<u32>,
    pub active_phase: Option<String>,
    pub events_tx: Option<Sender<mcpg_domain::event::Event>>,
}

/// Outcome of handling a single system call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallResult {
    pub flags: u32,
    pub error: i32,
    pub val: i64,
    pub violation: Option<(String, String)>,
    pub event: Option<mcpg_domain::event::Event>,
}

/// Pure observer engine that implements syscall mediation policies.
#[derive(Debug)]
pub struct ObserverEngine<M: MemoryReader> {
    pub cfg: ObserverConfig,
    pub reader: M,
    pub has_seen_root_exec: std::sync::atomic::AtomicBool,
}

pub fn clean_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

impl<M: MemoryReader> ObserverEngine<M> {
    pub fn new(cfg: ObserverConfig, reader: M) -> Self {
        Self { cfg, reader, has_seen_root_exec: std::sync::atomic::AtomicBool::new(false) }
    }

    pub fn handle_syscall(&self, pid: u32, nr: i64, args: [u64; 6]) -> SyscallResult {
        let phase = self
            .cfg
            .active_phase
            .clone()
            .unwrap_or_else(|| "startup".to_string());

        // 1. x32 ABI filter
        if (nr & X32_SYSCALL_BIT) != 0 {
            let event = mcpg_domain::event::Event::builder(
                mcpg_domain::event::EventKind::TamperDenied,
                phase,
            )
            .message("x32 ABI system call denied")
            .build();
            return SyscallResult {
                flags: 0,
                error: -libc::ENOSYS,
                val: 0,
                violation: Some((
                    "MCPG010".to_string(),
                    "x32 ABI system call denied".to_string(),
                )),
                event: Some(event),
            };
        }

        // 2. io_uring denial
        if nr == syscalls::SYS_IO_URING_SETUP
            || nr == syscalls::SYS_IO_URING_ENTER
            || nr == syscalls::SYS_IO_URING_REGISTER
        {
            let event = mcpg_domain::event::Event::builder(
                mcpg_domain::event::EventKind::TamperDenied,
                phase,
            )
            .message("io_uring system call denied")
            .build();
            return SyscallResult {
                flags: 0,
                error: -libc::ENOSYS,
                val: 0,
                violation: Some(("MCPG010".to_string(), "io_uring denial".to_string())),
                event: Some(event),
            };
        }

        // 3. clone user namespace denial
        if nr == syscalls::SYS_CLONE || nr == syscalls::SYS_CLONE3 {
            let flags = args[0];
            if (flags & CLONE_NEWUSER) != 0 {
                let event = mcpg_domain::event::Event::builder(
                    mcpg_domain::event::EventKind::TamperDenied,
                    phase,
                )
                .message("CLONE_NEWUSER denied")
                .build();
                return SyscallResult {
                    flags: 0,
                    error: -libc::EPERM,
                    val: 0,
                    violation: Some(("MCPG010".to_string(), "CLONE_NEWUSER denial".to_string())),
                    event: Some(event),
                };
            }
        }

        // 4. Signal target check
        if nr == syscalls::SYS_KILL || nr == syscalls::SYS_TKILL || nr == syscalls::SYS_TGKILL {
            let target_pid = args[0] as i64 as i32;
            let is_foreign = target_pid == -1
                || (!self.cfg.capsule_pids.is_empty()
                    && target_pid > 0
                    && !self.cfg.capsule_pids.contains(&(target_pid as u32)));
            if is_foreign {
                let event = mcpg_domain::event::Event::builder(
                    mcpg_domain::event::EventKind::SignalSend,
                    phase,
                )
                .message(format!("Signal to foreign PID {target_pid} denied"))
                .build();
                return SyscallResult {
                    flags: 0,
                    error: -libc::EPERM,
                    val: 0,
                    violation: Some((
                        "MCPG010".to_string(),
                        format!("Signal foreign targets denial: PID {target_pid}"),
                    )),
                    event: Some(event),
                };
            }
        }

        // 5. Network and sockets
        if nr == syscalls::SYS_SOCKET {
            let domain = args[0] as i32;
            if domain != libc::AF_UNIX && !self.cfg.allow_network {
                let event = mcpg_domain::event::Event::builder(
                    mcpg_domain::event::EventKind::NetSocket,
                    phase,
                )
                .message("Network activity while allow_network is false")
                .build();
                return SyscallResult {
                    flags: 0,
                    error: -libc::EACCES,
                    val: 0,
                    violation: Some((
                        "MCPG007".to_string(),
                        "Network activity while allow_network is false".to_string(),
                    )),
                    event: Some(event),
                };
            }
        } else if nr == syscalls::SYS_CONNECT
            || nr == syscalls::SYS_BIND
            || nr == syscalls::SYS_SENDTO
        {
            let sockaddr_addr = if nr == syscalls::SYS_SENDTO { args[4] } else { args[1] };
            if sockaddr_addr != 0 {
                if let Ok(family_bytes) = self.reader.read_bytes(pid, sockaddr_addr, 2) {
                    let family = u16::from_ne_bytes([family_bytes[0], family_bytes[1]]);
                    if (family == AF_INET || family == AF_INET6) && !self.cfg.allow_network {
                        let event = mcpg_domain::event::Event::builder(
                            mcpg_domain::event::EventKind::NetConnect,
                            phase,
                        )
                        .message("Network activity while allow_network is false")
                        .build();
                        return SyscallResult {
                            flags: 0,
                            error: -libc::EACCES,
                            val: 0,
                            violation: Some((
                                "MCPG007".to_string(),
                                "Network activity while allow_network is false".to_string(),
                            )),
                            event: Some(event),
                        };
                    } else if family == AF_UNIX {
                        let addrlen = if nr == syscalls::SYS_SENDTO { args[5] } else { args[2] } as usize;
                        let path_len = addrlen.saturating_sub(2).min(108);
                        if path_len > 0 {
                            if let Ok(bytes) = self.reader.read_bytes(pid, sockaddr_addr + 2, path_len) {
                                let sun_path = if bytes[0] == 0 {
                                    let mut s = String::new();
                                    s.push('@');
                                    let content = if let Some(nul) = bytes[1..].iter().position(|&b| b == 0) {
                                        &bytes[1..=nul]
                                    } else {
                                        &bytes[1..]
                                    };
                                    s.push_str(&String::from_utf8_lossy(content));
                                    s
                                } else {
                                    if let Some(nul) = bytes.iter().position(|&b| b == 0) {
                                        String::from_utf8_lossy(&bytes[..nul]).to_string()
                                    } else {
                                        String::from_utf8_lossy(&bytes).to_string()
                                    }
                                };
                                
                                if !sun_path.is_empty()
                                    && !self.cfg.allowed_unix_sockets.contains(&sun_path)
                            {
                                let event = mcpg_domain::event::Event::builder(
                                    mcpg_domain::event::EventKind::UnixConnect,
                                    phase,
                                )
                                .target(sun_path.clone())
                                .message(format!("Unapproved unix socket: {}", sun_path))
                                .build();
                                return SyscallResult {
                                    flags: 0,
                                    error: -libc::EACCES,
                                    val: 0,
                                    violation: Some((
                                        "MCPG009".to_string(),
                                        format!("Unapproved unix socket: {}", sun_path),
                                    )),
                                    event: Some(event),
                                };
                                }
                            }
                        }
                    }
                }
            }
        }

        // 6. Path operations: openat and openat2
        if nr == syscalls::SYS_OPENAT || nr == syscalls::SYS_OPENAT2 {
            let dirfd = args[0] as i64 as i32;
            let addr = args[1];
            let flags = if nr == syscalls::SYS_OPENAT2 {
                if let Ok(bytes) = self.reader.read_bytes(pid, args[2], 8) {
                    u64::from_ne_bytes(bytes.try_into().unwrap()) as i32
                } else {
                    0
                }
            } else {
                args[2] as i32
            };

            if let Ok(raw_path) = self.reader.read_string(pid, addr, 4096) {
                let resolved = if raw_path.starts_with('/') {
                    PathBuf::from(&raw_path)
                } else {
                    let base = if dirfd == AT_FDCWD {
                        self.reader
                            .read_link(&PathBuf::from(format!("/proc/{pid}/cwd")))
                            .unwrap_or_else(|_| PathBuf::from("/"))
                    } else {
                        self.reader
                            .read_link(&PathBuf::from(format!("/proc/{pid}/fd/{dirfd}")))
                            .unwrap_or_else(|_| PathBuf::from("/"))
                    };
                    base.join(&raw_path)
                };

                let cleaned = clean_path(&resolved);
                let is_write = (flags & (libc::O_WRONLY | libc::O_RDWR)) != 0;

                if raw_path.contains("..") || cleaned.to_string_lossy().contains("..") {
                    let event = mcpg_domain::event::Event::builder(
                        if is_write {
                            mcpg_domain::event::EventKind::FsMutate
                        } else {
                            mcpg_domain::event::EventKind::FsOpen
                        },
                        phase,
                    )
                    .resolved(cleaned.clone())
                    .escaped_via("..")
                    .access(if is_write {
                        mcpg_domain::event::AccessKind::Write
                    } else {
                        mcpg_domain::event::AccessKind::Read
                    })
                    .build();

                    return SyscallResult {
                        flags: 0,
                        error: -libc::EACCES,
                        val: 0,
                        violation: Some((
                            "MCPG005".to_string(),
                            format!("Path traversal detected: {}", cleaned.display()),
                        )),
                        event: Some(event),
                    };
                }

                let event = mcpg_domain::event::Event::builder(
                    if is_write {
                        mcpg_domain::event::EventKind::FsMutate
                    } else {
                        mcpg_domain::event::EventKind::FsOpen
                    },
                    phase,
                )
                .resolved(cleaned)
                .access(if is_write {
                    mcpg_domain::event::AccessKind::Write
                } else {
                    mcpg_domain::event::AccessKind::Read
                })
                .build();

                return SyscallResult {
                    flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
                    error: 0,
                    val: 0,
                    violation: None,
                    event: Some(event),
                };
            }
        }

        // 7. Process execution: execve and execveat
        if nr == syscalls::SYS_EXECVE || nr == syscalls::SYS_EXECVEAT {
            let path_arg_idx = if nr == syscalls::SYS_EXECVEAT { 1 } else { 0 };
            let addr = args[path_arg_idx];

            if let Ok(raw_path) = self.reader.read_string(pid, addr, 4096) {
                let path = PathBuf::from(&raw_path);
                let is_root = self
                    .cfg
                    .root_command
                    .as_ref()
                    .is_some_and(|r| r == &path);
                let is_allowed = if is_root && !self.has_seen_root_exec.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    true
                } else {
                    self
                        .cfg
                        .allowed_child_binaries
                        .iter()
                        .any(|b| b == &path)
                };

                if !is_allowed {
                    let event = mcpg_domain::event::Event::builder(
                        mcpg_domain::event::EventKind::ProcExec,
                        phase,
                    )
                    .exe(path.clone())
                    .decision(mcpg_domain::event::Decision::Denied)
                    .build();

                    return SyscallResult {
                        flags: 0,
                        error: -libc::EACCES,
                        val: 0,
                        violation: Some((
                            "MCPG006".to_string(),
                            format!("Unapproved child process: {}", path.display()),
                        )),
                        event: Some(event),
                    };
                }

                let event = mcpg_domain::event::Event::builder(
                    mcpg_domain::event::EventKind::ProcExec,
                    phase,
                )
                .exe(path)
                .decision(mcpg_domain::event::Decision::Allowed)
                .build();

                return SyscallResult {
                    flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
                    error: 0,
                    val: 0,
                    violation: None,
                    event: Some(event),
                };
            }
        }

        // Default: continue
        SyscallResult {
            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
            error: 0,
            val: 0,
            violation: None,
            event: None,
        }
    }
}

#[cfg(target_os = "linux")]
pub fn start_observer_thread(
    listener_fd: RawFd,
    cfg: ObserverConfig,
    violations_tx: Sender<(String, String)>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let engine = ObserverEngine::new(cfg, RealMemoryReader);
        loop {
            let mut req: seccomp_notif = unsafe { std::mem::zeroed() };
            let ret = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut req) };

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOENT) {
                    continue; // Process died or syscall interrupted
                }
                break;
            }

            let mut check_id = req.id;
            if unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &mut check_id) } < 0
            {
                continue; // Process ended or notification expired
            }

            let mut resp: seccomp_notif_resp = unsafe { std::mem::zeroed() };
            resp.id = req.id;

            let nr = req.data.nr as i64;
            let res = engine.handle_syscall(req.pid, nr, req.data.args);
            resp.flags = res.flags;
            resp.error = res.error;
            resp.val = res.val;

            if let Some(vio) = res.violation {
                let _ = violations_tx.send(vio);
            }
            if let Some(ev) = res.event {
                if let Some(tx) = &engine.cfg.events_tx {
                    let _ = tx.send(ev);
                }
            }

            unsafe {
                libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &mut resp);
            }
        }
    })
}

#[cfg(not(target_os = "linux"))]
pub fn start_observer_thread(
    _listener_fd: RawFd,
    _cfg: ObserverConfig,
    _violations_tx: Sender<(String, String)>,
) -> thread::JoinHandle<()> {
    thread::spawn(|| {})
}

pub fn read_child_string(pid: u32, addr: u64, max_len: usize) -> std::io::Result<String> {
    #[cfg(target_os = "linux")]
    {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};

        let mem_path = format!("/proc/{pid}/mem");
        let mut file = File::open(&mem_path)?;
        file.seek(SeekFrom::Start(addr))?;

        let mut buf = vec![0u8; max_len];
        let n = file.read(&mut buf)?;

        if let Some(pos) = buf[..n].iter().position(|&c| c == 0) {
            Ok(String::from_utf8_lossy(&buf[..pos]).into_owned())
        } else {
            Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, addr, max_len);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "proc mem not available on this OS",
        ))
    }
}

pub fn read_child_bytes(pid: u32, addr: u64, len: usize) -> std::io::Result<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};

        let mem_path = format!("/proc/{pid}/mem");
        let mut file = File::open(&mem_path)?;
        file.seek(SeekFrom::Start(addr))?;

        let mut buf = vec![0u8; len];
        file.read_exact(&mut buf)?;
        Ok(buf)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, addr, len);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "proc mem not available on this OS",
        ))
    }
}
