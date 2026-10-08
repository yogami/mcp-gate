//! Panic and drop guard for running capsules.
//!
//! SPEC 3.1.6: Drop guard sends SIGKILL to the process group and every
//! known child pid before unwinding, preventing orphaned unobserved capsules.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};

static NEXT_GUARD_ID: AtomicUsize = AtomicUsize::new(1);
static ACTIVE_GUARDS: Mutex<Vec<Arc<GuardInner>>> = Mutex::new(Vec::new());
static HOOK_INIT: Once = Once::new();

struct GuardInner {
    id: usize,
    pgid: i32,
    pids: Mutex<Vec<u32>>,
    disarmed: AtomicBool,
}

fn kill_process_group(pgid: i32) {
    if pgid > 1 {
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
}

fn kill_single_pid(pid: u32) {
    let self_pid = std::process::id();
    if pid <= 1 || pid == self_pid {
        return;
    }
    unsafe {
        if libc::kill(pid as i32, 0) == 0 {
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }
}

fn kill_pid_list(pids: &[u32]) {
    for &pid in pids {
        kill_single_pid(pid);
    }
}

impl GuardInner {
    fn kill(&self) {
        if self.disarmed.swap(true, Ordering::SeqCst) {
            return;
        }
        kill_process_group(self.pgid);
        let pids = self.pids.lock().unwrap_or_else(|e| e.into_inner());
        kill_pid_list(&pids);
    }
}

fn fire_all_guards() {
    let guards = ACTIVE_GUARDS.lock().unwrap_or_else(|e| e.into_inner());
    for guard in guards.iter() {
        guard.kill();
    }
}

fn register_guard(guard: Arc<GuardInner>) {
    let mut guards = ACTIVE_GUARDS.lock().unwrap_or_else(|e| e.into_inner());
    guards.push(guard);
}

fn unregister_guard(id: usize) {
    let mut guards = ACTIVE_GUARDS.lock().unwrap_or_else(|e| e.into_inner());
    guards.retain(|g| g.id != id);
}

fn install_panic_hook() {
    HOOK_INIT.call_once(|| {
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            fire_all_guards();
            prev_hook(info);
        }));
    });
}

/// Guard terminating capsule processes if runner drops or panics.
pub struct CapsuleGuard {
    inner: Arc<GuardInner>,
}

impl CapsuleGuard {
    /// Create a new capsule guard tracking a process group and child pids.
    pub fn new(pgid: i32, known_pids: Vec<u32>) -> Self {
        install_panic_hook();
        let id = NEXT_GUARD_ID.fetch_add(1, Ordering::Relaxed);
        let inner = Arc::new(GuardInner {
            id,
            pgid,
            pids: Mutex::new(known_pids),
            disarmed: AtomicBool::new(false),
        });
        register_guard(Arc::clone(&inner));
        Self { inner }
    }

    /// Create a guard from a process group id without extra child pids.
    pub fn from_pgid(pgid: i32) -> Self {
        Self::new(pgid, Vec::new())
    }

    /// Add a child pid discovered during observation.
    pub fn add_pid(&self, pid: u32) {
        let mut pids = self.inner.pids.lock().unwrap_or_else(|e| e.into_inner());
        if !pids.contains(&pid) {
            pids.push(pid);
        }
    }

    /// Disarm the guard to allow normal graceful shutdown.
    pub fn disarm(&self) {
        self.inner.disarmed.store(true, Ordering::SeqCst);
    }

    /// Return true if the guard is disarmed.
    pub fn is_disarmed(&self) -> bool {
        self.inner.disarmed.load(Ordering::SeqCst)
    }

    /// Return the guarded process group id.
    pub fn pgid(&self) -> i32 {
        self.inner.pgid
    }
}

impl Drop for CapsuleGuard {
    fn drop(&mut self) {
        unregister_guard(self.inner.id);
        self.inner.kill();
    }
}
