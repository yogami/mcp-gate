#![cfg(unix)]

use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use mcpg_app::capsule_plan::{CapsulePlan, Mode};
use mcpg_app::ports::CapsuleLauncher;
use mcpg_domain::policy::resolve::PathEntry;
use mcpg_domain::policy::sets::EnforcementSet;
use mcpg_linux::landlock::{build, get_landlock_abi};
use mcpg_linux::launcher::LinuxLauncher;
use serde_json::Value;

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

fn find_sort_binary() -> Option<PathBuf> {
    for candidate in ["/usr/bin/sort", "/bin/sort"] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

struct ProbeRun {
    ran: bool,
    val: Value,
    success: bool,
}

fn run_landlock_probe(
    subcmd: &str,
    args: &[&str],
    workspace: &Path,
    capsule_home: &Path,
    capsule_tmp: &Path,
    extra_exec: &[PathBuf],
) -> ProbeRun {
    let abi = get_landlock_abi();
    if abi == 0 {
        eprintln!("skipping test: Landlock is not supported on this host");
        return ProbeRun {
            ran: false,
            val: Value::Null,
            success: false,
        };
    }

    let _ = mcpg_linux::self_harden::harden_self();

    let probe_bin = find_syscall_probe();
    let mut exec_roots = vec![probe_bin.clone()];
    exec_roots.extend_from_slice(extra_exec);

    let fs = mcpg_domain::fs_view::StdFs;
    let read = |p: &Path| std::fs::read(p);
    let full_exec = mcpg_domain::exec_deps::exec_closure(&exec_roots, &fs, &read);
    println!("FULL_EXEC: {:?}", full_exec);

    let mut read_paths = Vec::new();
    for d in ["/usr", "/lib", "/lib64", "/bin", "/etc"] {
        let p = PathBuf::from(d);
        if p.exists() {
            read_paths.push(PathEntry::Dir(p));
        }
    }
    if let Some(parent) = probe_bin.parent() {
        if parent.exists() {
            read_paths.push(PathEntry::Dir(parent.to_path_buf()));
        }
    }

    let sets = EnforcementSet {
        read_paths,
        write_paths: vec![PathEntry::Dir(workspace.to_path_buf())],
        capsule_home: capsule_home.to_path_buf(),
        capsule_tmp: capsule_tmp.to_path_buf(),
    };

    let landlock_plan =
        mcpg_domain::landlock_plan::plan(&sets, &full_exec, abi, Mode::Enforce, true);
    let ruleset_fd = build(&landlock_plan).expect("build ruleset");

    let probe_cstr = CString::new(probe_bin.as_os_str().as_bytes()).unwrap();
    let mut argv = vec![probe_cstr.clone(), CString::new(subcmd).unwrap()];
    for a in args {
        argv.push(CString::new(*a).unwrap());
    }

    let cplan = CapsulePlan {
        program: probe_cstr,
        argv,
        envp: vec![
            CString::new("PATH=/usr/bin:/bin").unwrap(),
            CString::new(format!("HOME={}", capsule_home.display())).unwrap(),
            CString::new(format!("TMPDIR={}", capsule_tmp.display())).unwrap(),
        ],
        cwd: workspace.to_path_buf(),
        mode: Mode::Enforce,
    };

    let launcher = LinuxLauncher::new().with_landlock_fd(ruleset_fd.as_raw_fd());
    let running = launcher.launch(&cplan).expect("launch capsule");
    let output = running.child.wait_with_output().expect("wait output");

    let text = String::from_utf8_lossy(&output.stdout);
    let val = serde_json::from_str(text.trim()).unwrap_or_else(|_| {
        eprintln!(
            "LANDLOCK PROBE FAILED TO PARSE JSON: status={:?}, stdout={:?}, stderr={:?}",
            output.status,
            text,
            String::from_utf8_lossy(&output.stderr)
        );
        Value::Null
    });

    ProbeRun {
        ran: true,
        val,
        success: output.status.success(),
    }
}

#[test]
fn read_inside_workspace_ok() {
    let ws = tempfile_helper::TempDir::new("mcpg_ll_ws");
    let home = tempfile_helper::TempDir::new("mcpg_ll_home");
    let tmp = tempfile_helper::TempDir::new("mcpg_ll_tmp");

    let file_path = ws.path().join("inside.txt");
    std::fs::write(&file_path, "inside workspace content").unwrap();

    let res = run_landlock_probe(
        "read",
        &[file_path.to_str().unwrap()],
        ws.path(),
        home.path(),
        tmp.path(),
        &[],
    );
    if !res.ran {
        return;
    }
    assert_eq!(res.val["status"], "ok");
    assert_eq!(res.val["ok"], true);
}

#[test]
fn read_outside_policy_eacces() {
    let ws = tempfile_helper::TempDir::new("mcpg_ll_ws");
    let home = tempfile_helper::TempDir::new("mcpg_ll_home");
    let tmp = tempfile_helper::TempDir::new("mcpg_ll_tmp");
    let outside = tempfile_helper::TempDir::new("mcpg_ll_outside");

    let secret_file = outside.path().join("secret.txt");
    std::fs::write(&secret_file, "secret outside policy").unwrap();

    let res = run_landlock_probe(
        "read",
        &[secret_file.to_str().unwrap()],
        ws.path(),
        home.path(),
        tmp.path(),
        &[],
    );
    if !res.ran {
        return;
    }
    assert_eq!(res.val["status"], "error");
    assert_eq!(res.val["error"], "EACCES");
    assert_eq!(res.val["ok"], false);
}

#[test]
fn decoy_zone_readable() {
    let ws = tempfile_helper::TempDir::new("mcpg_ll_ws");
    let home = tempfile_helper::TempDir::new("mcpg_ll_home");
    let tmp = tempfile_helper::TempDir::new("mcpg_ll_tmp");

    let canary_file = home.path().join("canary.txt");
    std::fs::write(&canary_file, "canary credential").unwrap();

    let res = run_landlock_probe(
        "read",
        &[canary_file.to_str().unwrap()],
        ws.path(),
        home.path(),
        tmp.path(),
        &[],
    );
    if !res.ran {
        return;
    }
    assert_eq!(res.val["status"], "ok");
    assert_eq!(res.val["ok"], true);
}

#[test]
fn write_to_decoy_zone_eacces() {
    let ws = tempfile_helper::TempDir::new("mcpg_ll_ws");
    let home = tempfile_helper::TempDir::new("mcpg_ll_home");
    let tmp = tempfile_helper::TempDir::new("mcpg_ll_tmp");

    let target_file = home.path().join("tamper.txt");

    let res = run_landlock_probe(
        "write",
        &[target_file.to_str().unwrap(), "leak data"],
        ws.path(),
        home.path(),
        tmp.path(),
        &[],
    );
    if !res.ran {
        return;
    }
    assert_eq!(res.val["status"], "error");
    assert_eq!(res.val["error"], "EACCES");
    assert_eq!(res.val["ok"], false);
}

#[test]
fn exec_unlisted_binary_eacces() {
    let ws = tempfile_helper::TempDir::new("mcpg_ll_ws");
    let home = tempfile_helper::TempDir::new("mcpg_ll_home");
    let tmp = tempfile_helper::TempDir::new("mcpg_ll_tmp");

    let res = run_landlock_probe(
        "exec",
        &["/bin/sh", "-c", "true"],
        ws.path(),
        home.path(),
        tmp.path(),
        &[],
    );
    if !res.ran {
        return;
    }
    assert_eq!(res.val["status"], "error");
    assert_eq!(res.val["error"], "EACCES");
    assert_eq!(res.val["ok"], false);
}

#[test]
fn exec_listed_binary_ok() {
    let ws = tempfile_helper::TempDir::new("mcpg_ll_ws");
    let home = tempfile_helper::TempDir::new("mcpg_ll_home");
    let tmp = tempfile_helper::TempDir::new("mcpg_ll_tmp");

    let Some(sort_bin) = find_sort_binary() else {
        return;
    };

    let sort_str = sort_bin.to_str().unwrap();
    let res = run_landlock_probe(
        "exec",
        &[sort_str, "--version"],
        ws.path(),
        home.path(),
        tmp.path(),
        std::slice::from_ref(&sort_bin),
    );
    if !res.ran {
        return;
    }
    assert!(res.success, "executing listed binary should succeed");
}

#[test]
fn build_ruleset_with_python_baseline_succeeds() {
    let abi = mcpg_linux::landlock::get_landlock_abi();
    if abi == 0 {
        return;
    }

    use mcpg_domain::config::model::Baseline;
    use mcpg_domain::fs_view::StdFs;
    use mcpg_domain::landlock_plan::plan;
    use mcpg_domain::policy::baseline::expand_baseline;
    use mcpg_domain::policy::sets::EnforcementSet;

    let baseline_paths = expand_baseline(Baseline::Python, &StdFs);
    let sets = EnforcementSet {
        read_paths: baseline_paths,
        write_paths: Vec::new(),
        capsule_home: PathBuf::from("/tmp"),
        capsule_tmp: PathBuf::from("/tmp"),
    };

    let plan = plan(&sets, &[], abi, mcpg_domain::mode::Mode::Enforce, false);
    let ruleset = mcpg_linux::landlock::build(&plan);
    assert!(
        ruleset.is_ok(),
        "Failed to build Landlock ruleset with Python baseline: {:?}",
        ruleset.err()
    );
}

#[test]
fn non_existent_target_dir_allows_write_under_existing_ancestor() {
    let ws = tempfile_helper::TempDir::new("mcpg_ll_ws");
    let home = tempfile_helper::TempDir::new("mcpg_ll_home");
    let tmp = tempfile_helper::TempDir::new("mcpg_ll_tmp");

    // Configure a write target inside a nested directory that does not exist yet
    let missing_dir = ws.path().join("nested_missing_dir").join("sub");
    let missing_file = missing_dir.join("output.txt");

    // Landlock probe that attempts to write to a missing path
    let res = run_landlock_probe(
        "write",
        &[missing_file.to_str().unwrap(), "test data"],
        ws.path(),
        home.path(),
        tmp.path(),
        &[],
    );
    if !res.ran {
        return;
    }
    assert_eq!(
        res.val["status"], "error",
        "Writing to a path with a non-existent parent should be allowed via existing ancestor rule, resulting in ENOENT from the filesystem"
    );
    assert_eq!(res.val["error"], "ENOENT");
}
