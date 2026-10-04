#![cfg(unix)]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use mcpg_app::capsule_plan::{CapsulePlan, Mode};
use mcpg_app::ports::{CapsuleLauncher, RunningCapsule};
use mcpg_linux::launcher::LinuxLauncher;
use mcpg_linux::shutdown::{shutdown, ShutdownStage};

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

mod tempfile_helper {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        pub fn new(prefix: &str) -> Self {
            let count = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("{prefix}_{count}_{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create test dir");
            Self { path }
        }

        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn find_syscall_probe() -> PathBuf {
    let mut path = std::env::current_exe().expect("current exe");
    path.pop();
    path.pop();
    path.push("syscall-probe");
    if path.exists() {
        return path;
    }
    assert_cmd::cargo::cargo_bin("syscall-probe")
}

fn launch_probe(subcmd: &str, args: &[&str], workspace: &Path) -> RunningCapsule {
    let _ = mcpg_linux::self_harden::harden_self();

    let probe_bin = find_syscall_probe();
    let probe_cstr = CString::new(probe_bin.as_os_str().as_bytes()).unwrap();

    let mut argv = vec![probe_cstr.clone(), CString::new(subcmd).unwrap()];
    for a in args {
        argv.push(CString::new(*a).unwrap());
    }

    let plan = CapsulePlan {
        program: probe_cstr,
        argv,
        envp: vec![CString::new("PATH=/usr/bin:/bin").unwrap()],
        cwd: workspace.to_path_buf(),
        mode: Mode::Enforce,
    };

    LinuxLauncher::new().launch(&plan).expect("launch probe")
}

#[test]
fn stdin_close_ends_cooperative_capsule() {
    let _lock = TEST_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("mcpg_shut_coop");
    let cap = launch_probe("wait-stdin-eof", &[], tmp.path());

    let report = shutdown(cap, Duration::from_millis(500));
    assert_eq!(report.stage, ShutdownStage::StdinClosed);
    assert!(report.survivors.is_empty());
}

#[test]
fn stubborn_capsule_gets_sigkill() {
    let _lock = TEST_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("mcpg_shut_kill");
    let mut cap = launch_probe("ignore-sigterm", &[], tmp.path());

    // Wait until probe has started and installed signal handler
    let stdout = cap.child.stdout.as_mut().expect("stdout");
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut line).expect("read line");
    assert!(line.contains("ignoring_sigterm"));

    let report = shutdown(cap, Duration::from_millis(50));
    assert_eq!(report.stage, ShutdownStage::Killed);
}

#[test]
#[cfg(target_os = "linux")]
fn daemonized_grandchild_reaped_and_reported() {
    let _lock = TEST_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("mcpg_shut_daemon");
    let mut cap = launch_probe("daemon", &[], tmp.path());

    // Read grandchild PID from daemon stdout
    let stdout = cap.child.stdout.take().expect("take stdout");
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut line).expect("read daemon line");
    let val: serde_json::Value = serde_json::from_str(line.trim()).expect("valid json");
    let grandchild_pid = val["pid"].as_i64().expect("grandchild pid") as u32;
    assert!(grandchild_pid > 0);

    let report = shutdown(cap, Duration::from_millis(100));
    assert!(
        report.survivors.contains(&grandchild_pid),
        "survivors should contain grandchild {grandchild_pid}, got: {:?}",
        report.survivors
    );

    // Verify grandchild is dead and reaped
    assert_ne!(
        unsafe { libc::kill(grandchild_pid as i32, 0) },
        0,
        "grandchild should be terminated"
    );
}

#[test]
fn no_children_left() {
    let _lock = TEST_LOCK.lock().unwrap();
    let tmp = tempfile_helper::TempDir::new("mcpg_shut_nochld");
    let cap = launch_probe("wait-stdin-eof", &[], tmp.path());
    let _ = shutdown(cap, Duration::from_millis(500));

    let res = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(res, -1, "waitpid should return -1");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD),
        "waitpid error should be ECHILD"
    );
}
