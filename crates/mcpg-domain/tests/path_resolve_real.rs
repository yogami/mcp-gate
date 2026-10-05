use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use mcpg_domain::fs_view::StdFs;
use mcpg_domain::path::resolve::{resolve, EscapeKind};
use mcpg_domain::path::ProcCtx;

// These tests run the resolver against the real filesystem and compare it with what the
// kernel does (`std::fs::canonicalize`). No fake filesystem is involved.

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct RealTree {
    root: PathBuf,
}

impl RealTree {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("mcpg-pr-{}-{}-{}", tag, std::process::id(), n));
        std::fs::create_dir_all(&dir).expect("create tree dir");
        // Canonical, so a symlinked temp dir (macOS /tmp) does not skew the comparison.
        let root = std::fs::canonicalize(&dir).expect("canonicalize tree dir");
        Self { root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn file(&self, rel: &str, body: &str) {
        let p = self.path(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn dir(&self, rel: &str) {
        std::fs::create_dir_all(self.path(rel)).unwrap();
    }

    fn link(&self, rel: &str, target: &str) {
        let p = self.path(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, p).unwrap();
    }
}

impl Drop for RealTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn run(root: &Path, base: &Path, raw: &str) -> mcpg_domain::path::Resolution {
    resolve(&StdFs, root, base, raw.as_bytes(), true, None)
}

#[test]
fn p1_path_16_relative_symlink_inside_root_is_not_an_escape() {
    let t = RealTree::new("rel-in");
    let ws = t.path("ws");
    t.file("ws/file.txt", "x");
    t.link("ws/a", "file.txt");
    t.file("ws/node_modules/pkg/bin/x.js", "js");
    t.link("ws/node_modules/.bin/x", "../pkg/bin/x.js");

    let a = run(&ws, &ws, "a");
    assert_eq!(a.resolved, std::fs::canonicalize(t.path("ws/a")).unwrap());
    assert_eq!(
        a.escaped_via, None,
        "relative link to a sibling stays inside"
    );
    assert_eq!(a.symlinks_followed, 1);

    let bin = run(&ws, &ws, "node_modules/.bin/x");
    assert_eq!(
        bin.resolved,
        std::fs::canonicalize(t.path("ws/node_modules/.bin/x")).unwrap()
    );
    assert_eq!(
        bin.escaped_via, None,
        "node_modules/.bin style link is not an escape"
    );
}

#[test]
fn p1_path_17_relative_symlink_leaving_root_is_a_symlink_escape() {
    let t = RealTree::new("rel-out");
    let ws = t.path("ws");
    t.dir("ws");
    t.file("outside/secret", "s");
    t.link("ws/out", "../outside/secret");
    t.link("ws/dirlink", "../outside");

    let direct = run(&ws, &ws, "out");
    assert_eq!(
        direct.resolved,
        std::fs::canonicalize(t.path("ws/out")).unwrap()
    );
    assert_eq!(direct.escaped_via, Some(EscapeKind::Symlink));

    let via_dir = run(&ws, &ws, "dirlink/secret");
    assert_eq!(
        via_dir.resolved,
        std::fs::canonicalize(t.path("ws/dirlink/secret")).unwrap()
    );
    assert_eq!(via_dir.escaped_via, Some(EscapeKind::Symlink));
}

#[test]
fn p1_path_18_dotdot_that_returns_inside_root_is_not_an_escape() {
    let t = RealTree::new("dd-back");
    let ws = t.path("ws");
    t.file("ws/f", "x");

    let r = run(&ws, &ws, "../ws/f");
    assert_eq!(r.resolved, std::fs::canonicalize(t.path("ws/f")).unwrap());
    assert_eq!(r.escaped_via, None, "the walk ends inside the root");
}

#[test]
fn p1_path_19_resolver_matches_kernel_realpath() {
    let t = RealTree::new("oracle");
    let ws = t.path("ws");
    t.file("ws/a/b.txt", "b");
    t.file("outside/deep/leaf", "l");
    t.file("outside/sibling", "s");
    t.link("ws/to_a", "a");
    t.link("ws/to_outside", "../outside/deep");
    t.link("ws/chain1", "chain2");
    t.link("ws/chain2", "a/b.txt");
    t.link("ws/abs", &t.path("outside/sibling").display().to_string());
    t.link("ws/a/up", "..");

    let cases: &[&str] = &[
        "a/b.txt",
        "to_a/b.txt",
        "to_a/../a/b.txt",
        "to_outside/leaf",
        "to_outside/../sibling",
        "chain1",
        "abs",
        "a/up/a/b.txt",
        "a/./b.txt",
        ".//a///b.txt",
        "a/../a/b.txt",
        "../outside/sibling",
    ];
    for raw in cases {
        let ours = run(&ws, &ws, raw);
        let kernel = std::fs::canonicalize(ws.join(raw))
            .unwrap_or_else(|e| panic!("kernel could not resolve {raw}: {e}"));
        assert_eq!(
            ours.resolved, kernel,
            "resolver disagrees with realpath for {raw:?}"
        );
        assert!(ours.exists, "{raw:?} should exist");
    }
}

#[test]
fn p1_path_20_escape_follows_final_location_for_mixed_paths() {
    let t = RealTree::new("final");
    let ws = t.path("ws");
    t.file("ws/inside", "i");
    t.file("outside/o", "o");
    t.link("ws/to_out", "../outside");
    t.link("ws/back", "../ws/inside");

    // Leaves through a link, comes back through a link: the final location is inside.
    let back = run(&ws, &ws, "back");
    assert_eq!(back.escaped_via, None);

    // Leaves through a link and stays out.
    let out = run(&ws, &ws, "to_out/o");
    assert_eq!(out.escaped_via, Some(EscapeKind::Symlink));

    // Plain `..` out of the root.
    let dd = run(&ws, &ws, "../outside/o");
    assert_eq!(dd.escaped_via, Some(EscapeKind::DotDot));
}

#[test]
fn p1_path_21_proc_cwd_dotdot_resolves_through_the_real_target() {
    // B-16: `/proc/self/cwd/../x` must be relative to the cwd target, not to a logical prefix.
    let t = RealTree::new("proc-cwd");
    let ws = t.path("ws");
    t.dir("ws");
    t.file("secret-home/.ssh/id_ed25519", "k");

    let pid = 4242u32;
    let ctx =
        ProcCtx::new([pid].into_iter().collect(), Default::default()).with_link(pid, "cwd", &ws);

    let raw = "/proc/self/cwd/../secret-home/.ssh/id_ed25519";
    let r = resolve(&StdFs, &ws, &ws, raw.as_bytes(), true, Some(&ctx));
    assert_eq!(r.resolved, t.path("secret-home/.ssh/id_ed25519"));
    // The jump to cwd lands inside the root; the `..` after it is what leaves.
    assert_eq!(r.escaped_via, Some(EscapeKind::DotDot));
    assert!(r.exists);
}

#[test]
fn p1_path_22_proc_root_and_exe_follow_their_targets() {
    let t = RealTree::new("proc-root");
    let ws = t.path("ws");
    t.file("ws/bin/tool", "elf");
    let pid = 77u32;
    let ctx = ProcCtx::new([pid].into_iter().collect(), Default::default())
        .with_link(pid, "root", "/")
        .with_link(pid, "exe", t.path("ws/bin/tool"));

    let exe = resolve(&StdFs, &ws, &ws, b"/proc/self/exe", true, Some(&ctx));
    assert_eq!(exe.resolved, t.path("ws/bin/tool"));
    assert_eq!(exe.escaped_via, None, "exe points inside the root");

    let via_root = resolve(
        &StdFs,
        &ws,
        &ws,
        b"/proc/self/root/etc/hostname",
        true,
        Some(&ctx),
    );
    assert_eq!(via_root.resolved, PathBuf::from("/etc/hostname"));
    assert_eq!(via_root.escaped_via, Some(EscapeKind::ProcFd));
}

#[test]
fn p1_path_23_dotdot_above_proc_prefix_returns_to_real_proc() {
    // Kernel: /proc/self is /proc/<pid>, so /proc/self/../../etc/passwd is /etc/passwd.
    let ws = PathBuf::from("/c/ws");
    let ctx = ProcCtx::new([9u32].into_iter().collect(), Default::default());
    let r = resolve(
        &StdFs,
        &ws,
        &ws,
        b"/proc/self/../../etc/passwd",
        true,
        Some(&ctx),
    );
    assert_eq!(r.resolved, PathBuf::from("/etc/passwd"));
    assert!(
        r.resolved.is_absolute(),
        "must never produce a relative path"
    );
    assert_eq!(r.escaped_via, Some(EscapeKind::Absolute));
}

#[test]
fn p1_path_24_dotdot_after_unknown_magic_link_is_flagged_not_guessed() {
    let ws = PathBuf::from("/c/ws");
    // No cwd target recorded for the pid, so `..` after it cannot be placed.
    let ctx = ProcCtx::new([9u32].into_iter().collect(), Default::default());
    let r = resolve(&StdFs, &ws, &ws, b"/proc/self/cwd/../x", true, Some(&ctx));
    assert_eq!(r.escaped_via, Some(EscapeKind::ProcFd));
}

#[test]
fn p1_path_25_unknown_fd_keeps_its_fd_component() {
    let ws = PathBuf::from("/c/ws");
    let ctx = ProcCtx::new([9u32].into_iter().collect(), Default::default());
    let r = resolve(&StdFs, &ws, &ws, b"/proc/self/fd/9/x", true, Some(&ctx));
    assert_eq!(r.resolved, PathBuf::from("proc:capsule/fd/9/x"));
}

#[cfg(target_os = "linux")]
#[test]
fn p1_path_26_proc_self_cwd_matches_the_live_kernel() {
    // Oracle test against the real /proc of this test process.
    let cwd = std::fs::read_link("/proc/self/cwd").expect("read /proc/self/cwd");
    let pid = std::process::id();
    let ctx =
        ProcCtx::new([pid].into_iter().collect(), Default::default()).with_link(pid, "cwd", &cwd);

    for raw in [
        "/proc/self/cwd/Cargo.toml",
        "/proc/self/cwd/../mcpg-domain/Cargo.toml",
        "/proc/self/cwd/../../Cargo.toml",
        "/proc/self/../../etc/passwd",
    ] {
        let ours = resolve(&StdFs, &cwd, &cwd, raw.as_bytes(), true, Some(&ctx));
        let kernel = std::fs::canonicalize(raw).expect("kernel resolves");
        assert_eq!(ours.resolved, kernel, "disagreement for {raw}");
    }
}
