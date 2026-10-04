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
    let plan = make_plan(subcmd, args, workspace);
    let launcher = LinuxLauncher::new();
    let running = launcher.launch(&plan).expect("launch failed");

    let output = running.child.wait_with_output().expect("wait output");
    assert!(output.status.success(), "probe exited with error");
    let text = String::from_utf8(output.stdout).expect("utf8");
    serde_json::from_str(text.trim()).expect("valid json")
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
