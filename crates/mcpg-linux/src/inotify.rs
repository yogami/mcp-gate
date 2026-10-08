use std::os::unix::io::RawFd;
use std::path::Path;
use std::thread;

pub struct Tripwire {
    fd: RawFd,
    stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    wd_map: std::sync::Mutex<std::collections::HashMap<i32, String>>,
}

impl Tripwire {
    pub fn new() -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        #[cfg(not(target_os = "linux"))]
        let fd = -1;

        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            stop_flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            wd_map: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    pub fn add_watch(&self, _path: &Path, _kind_id: String) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStrExt;
            let cstr = std::ffi::CString::new(_path.as_os_str().as_bytes()).unwrap();
            let wd = unsafe {
                libc::inotify_add_watch(self.fd, cstr.as_ptr(), libc::IN_ACCESS | libc::IN_OPEN)
            };
            if wd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Ok(mut map) = self.wd_map.lock() {
                map.insert(wd, _kind_id);
            }
        }
        Ok(())
    }

    pub fn stop(&self) {
        self.stop_flag
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn start(&self) -> thread::JoinHandle<Vec<String>> {
        let handle = self.start_with_phase(mcpg_app::phase::PhaseCursor::new());
        thread::spawn(move || {
            let entries = handle.join().unwrap_or_default();
            entries.into_iter().map(|(kind, _)| kind).collect()
        })
    }

    pub fn start_with_phase(
        &self,
        phase: mcpg_app::phase::PhaseCursor,
    ) -> thread::JoinHandle<Vec<(String, String)>> {
        let fd = self.fd;
        let stop_flag = self.stop_flag.clone();

        let readonly_map = if let Ok(map) = self.wd_map.lock() {
            std::sync::Arc::new(map.clone())
        } else {
            std::sync::Arc::new(std::collections::HashMap::new())
        };

        thread::spawn(move || {
            #[cfg(target_os = "linux")]
            {
                let mut buf = [0u8; 4096];
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let mut tripped = Vec::new();
                loop {
                    if stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    let ret = unsafe { libc::poll(&mut pfd, 1, 100) };
                    if ret > 0 {
                        let n = unsafe {
                            libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                        };
                        if n > 0 {
                            let mut offset = 0;
                            while offset + std::mem::size_of::<libc::inotify_event>() <= n as usize
                            {
                                let ev = unsafe {
                                    &*(buf.as_ptr().add(offset) as *const libc::inotify_event)
                                };
                                if let Some(kind) = readonly_map.get(&ev.wd) {
                                    let current_phase = phase.current().to_string();
                                    let entry = (kind.clone(), current_phase);
                                    if !tripped.contains(&entry) {
                                        tripped.push(entry);
                                    }
                                }
                                offset +=
                                    std::mem::size_of::<libc::inotify_event>() + ev.len as usize;
                            }
                        }
                    }
                }
                tripped
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (fd, stop_flag, readonly_map, phase);
                Vec::new()
            }
        })
    }
}
