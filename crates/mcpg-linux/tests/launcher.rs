#![cfg(unix)]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use mcpg_app::capsule_plan::{CapsulePlan, Mode};
use mcpg_app::ports::CapsuleLauncher;
use mcpg_linux::launcher::LinuxLauncher;

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

fn make_plan(subcmd: &str, args: &[&str], workspace: &Path) -> CapsulePlan {
    let probe_bin = find_syscall_probe();
    let probe_cstr = CString::new(probe_bin.as_os_str().as_bytes()).unwrap();

    let mut argv = vec![probe_cstr.clone(), CString::new(subcmd).unwrap()];
    for a in args {
        argv.push(CString::new(*a).unwrap());
    }

    CapsulePlan {
        program: probe_cstr,
        argv,
        envp: vec![CString::new("PATH=/usr/bin:/bin").unwrap()],
        cwd: workspace.to_path_buf(),
        mode: Mode::Enforce,
    }
}

fn run_probe_subcommand(subcmd: &str, args: &[&str], workspace: &Path) -> serde_json::Value {
    #[cfg(target_os = "linux")]
    let _ = mcpg_linux::self_harden::harden_self();

    let plan = make_plan(subcmd, args, workspace);
    let launcher = LinuxLauncher::new();
    let running = launcher.launch(&plan).expect("launch failed");

    let output = running.child.wait_with_output().expect("wait output");
    assert!(output.status.success(), "probe exited with error");
    let text = String::from_utf8(output.stdout).expect("utf8");
    serde_json::from_str(text.trim()).expect("valid json")
}

#[test]
#[ignore]
#[cfg(target_os = "linux")]
fn helper_hardened_parent() {
    if std::env::var("MCPG_HELPER").as_deref() != Ok("hardened_parent") {
        return;
    }

    mcpg_linux::self_harden::harden_self().expect("harden self");

    let tmp = tempfile_helper::TempDir::new("mcpg_helper_parent");
    let runner_pid = std::process::id();
    let target_path = format!("/proc/{runner_pid}/environ");

    let plan = make_plan("read", &[&target_path], tmp.path());
    let launcher = LinuxLauncher::new();
    let running = launcher.launch(&plan).expect("launch failed");

    let output = running.child.wait_with_output().expect("wait output");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("utf8");
    let val: serde_json::Value = serde_json::from_str(text.trim()).expect("valid json");

    assert_eq!(val["status"], "error");
    assert_eq!(val["error"], "EACCES");
}

#[test]
#[cfg(target_os = "linux")]
fn p2_launch_04_capsule_cannot_read_runner_environ() {
    let current_exe = std::env::current_exe().expect("current exe");
    let status = std::process::Command::new(current_exe)
        .env("MCPG_HELPER", "hardened_parent")
        .args([
            "--exact",
            "helper_hardened_parent",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .expect("run helper");

    assert!(status.success(), "helper_hardened_parent failed");
}

#[test]
#[ignore]
#[cfg(target_os = "linux")]
fn helper_runner() {
    use std::io::Write;

    if std::env::var("MCPG_HELPER").as_deref() != Ok("runner") {
        return;
    }

    mcpg_linux::self_harden::harden_self().expect("harden self");

    let tmp = tempfile_helper::TempDir::new("mcpg_helper_runner");
    let plan = make_plan("sleep", &["60"], tmp.path());
    let launcher = LinuxLauncher::new();
    let running = launcher.launch(&plan).expect("launch failed");

    println!("capsule_pid:{}", running.pid);
    let _ = std::io::stdout().flush();

    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

#[test]
#[cfg(target_os = "linux")]
fn p2_launch_05_capsule_dies_with_runner() {
    use std::io::BufRead;

    let current_exe = std::env::current_exe().expect("current exe");
    let mut child = std::process::Command::new(current_exe)
        .env("MCPG_HELPER", "runner")
        .args(["--exact", "helper_runner", "--ignored", "--nocapture"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn helper runner");

    let helper_pid = child.id() as i32;
    let stdout = child.stdout.take().expect("take stdout");
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();

    let mut capsule_pid = 0i32;
    while reader.read_line(&mut line).unwrap() > 0 {
        if let Some(rest) = line.trim().strip_prefix("capsule_pid:") {
            capsule_pid = rest.parse::<i32>().expect("parse capsule pid");
            break;
        }
        line.clear();
    }
    assert!(capsule_pid > 0, "failed to get capsule pid");

    assert_eq!(unsafe { libc::kill(capsule_pid, 0) }, 0);

    unsafe {
        libc::kill(helper_pid, libc::SIGKILL);
    }
    let _ = child.wait();

    let mut died = false;
    for _ in 0..40 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if unsafe { libc::kill(capsule_pid, 0) } != 0 {
            died = true;
            break;
        }
        #[cfg(target_os = "linux")]
        if std::fs::read_to_string(format!("/proc/{capsule_pid}/status"))
            .map(|s| s.contains("State:\tZ"))
            .unwrap_or(true)
        {
            died = true;
            break;
        }
    }
    assert!(died, "capsule should die within 2s after runner is killed");
}

#[test]
fn p2_launch_01_environ_only_expected_keys() {
    let tmp = tempfile_helper::TempDir::new("mcpg_launch_env");

    std::env::set_var("MCPG_HOST_SECRET", "supersecret");
    std::env::set_var("GITHUB_TOKEN", "ghp_supersecret");

    let mut plan = make_plan("env", &[], tmp.path());
    plan.envp = vec![
        CString::new("DECOY_AWS_KEY=fake_key").unwrap(),
        CString::new("HOME=/capsule/home").unwrap(),
        CString::new("LANG=C.UTF-8").unwrap(),
        CString::new("PATH=/usr/bin:/bin").unwrap(),
        CString::new("TMPDIR=/capsule/tmp").unwrap(),
    ];

    let launcher = LinuxLauncher::new();
    let running = launcher.launch(&plan).expect("launch failed");
    let output = running.child.wait_with_output().expect("wait output");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("utf8");
    let val: serde_json::Value = serde_json::from_str(text.trim()).expect("valid json");

    let actual_keys: std::collections::BTreeSet<String> = val["keys"]
        .as_array()
        .expect("keys array")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .filter(|k| !k.starts_with("__LLVM_") && !k.starts_with("LLVM_"))
        .collect();

    let expected_keys: std::collections::BTreeSet<String> =
        ["DECOY_AWS_KEY", "HOME", "LANG", "PATH", "TMPDIR"]
            .iter()
            .map(|s| s.to_string())
            .collect();

    assert_eq!(
        actual_keys, expected_keys,
        "capsule environment must contain only expected keys"
    );
    assert!(!actual_keys.contains("MCPG_HOST_SECRET"));
    assert!(!actual_keys.contains("GITHUB_TOKEN"));
}

#[test]
fn p2_launch_02_only_stdio_fds() {
    let tmp = tempfile_helper::TempDir::new("mcpg_launch_fds");
    let extra_fd1 = unsafe { libc::dup(1) };
    let extra_fd2 = unsafe { libc::dup(2) };
    assert!(extra_fd1 >= 3);
    assert!(extra_fd2 >= 3);

    let val = run_probe_subcommand("fds", &[], tmp.path());

    unsafe {
        libc::close(extra_fd1);
        libc::close(extra_fd2);
    }

    let fds: Vec<i64> = val["fds"]
        .as_array()
        .expect("fds array")
        .iter()
        .filter_map(|v| v.as_i64())
        .collect();

    assert_eq!(
        fds,
        vec![0, 1, 2],
        "expected only stdio fds [0, 1, 2], got: {fds:?}"
    );
}

#[test]
fn p2_launch_03_cwd_is_workspace() {
    let tmp = tempfile_helper::TempDir::new("mcpg_launch_cwd");
    let val = run_probe_subcommand("cwd", &[], tmp.path());
    let cwd = val["cwd"].as_str().expect("cwd string");
    let canonical_workspace = std::fs::canonicalize(tmp.path()).unwrap();
    let canonical_reported = std::fs::canonicalize(Path::new(cwd)).unwrap();
    assert_eq!(canonical_reported, canonical_workspace);
}

#[test]
fn capsule_is_session_and_group_leader() {
    let tmp = tempfile_helper::TempDir::new("mcpg_launch_ids");
    let val = run_probe_subcommand("ids", &[], tmp.path());
    let pid = val["pid"].as_i64().expect("pid");
    let pgid = val["pgid"].as_i64().expect("pgid");
    let sid = val["sid"].as_i64().expect("sid");
    assert_eq!(pid, pgid, "pid should equal pgid");
    assert_eq!(pgid, sid, "pgid should equal sid");
}

#[test]
#[cfg(target_os = "linux")]
fn no_new_privs_is_set() {
    let tmp = tempfile_helper::TempDir::new("mcpg_launch_nnp");
    let val = run_probe_subcommand("ids", &[], tmp.path());
    let nnp = val["NoNewPrivs"]
        .as_bool()
        .or_else(|| val["no_new_privs"].as_bool());
    assert_eq!(nnp, Some(true), "NoNewPrivs must be set");
}

#[test]
fn umask_is_077() {
    let tmp = tempfile_helper::TempDir::new("mcpg_launch_umask");
    let val = run_probe_subcommand("ids", &[], tmp.path());
    let umask = val["umask"].as_i64().expect("umask");
    assert_eq!(umask, 0o077, "umask must be 077 (octal 077 = 63)");
}

#[test]
fn launch_missing_program_is_err() {
    let plan = mcpg_app::capsule_plan::CapsulePlan {
        program: std::ffi::CString::new("/nonexistent/binary/does/not/exist").unwrap(),
        argv: vec![],
        envp: vec![],
        cwd: PathBuf::from("/tmp"),
        mode: mcpg_domain::mode::Mode::Enforce,
    };
    use mcpg_app::ports::CapsuleLauncher;
    let launcher = mcpg_linux::launcher::LinuxLauncher::new();
    let res = launcher.launch(&plan);
    assert!(res.is_err(), "Launch of missing program should fail before returning from spawn");
}

#[test]
fn launch_with_bad_landlock_fd_is_err() {
    // Fails on Linux because landlock_restrict_self expects a valid ruleset FD.
    #[cfg(target_os = "linux")]
    {
        let plan = mcpg_app::capsule_plan::CapsulePlan {
            program: std::ffi::CString::new("/bin/true").unwrap(),
            argv: vec![std::ffi::CString::new("true").unwrap()],
            envp: vec![],
            cwd: PathBuf::from("/tmp"),
            mode: mcpg_domain::mode::Mode::Enforce,
        };
        use mcpg_app::ports::CapsuleLauncher;
        // 9999 is highly likely an invalid FD
        let launcher = mcpg_linux::launcher::LinuxLauncher::new().with_landlock_fd(9999);
        let res = launcher.launch(&plan);
        assert!(res.is_err(), "Launch with invalid landlock FD should fail in pre_exec and bubble up");
    }
}
