use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use mcpg_app::hygiene::{check_source_checkout_hint, checkout_hint};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(name: &str) -> Self {
        let count = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("{name}_{count}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create test temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn p2_launch_06_extraheader_warns() {
    let raw_config = r#"[core]
	repositoryformatversion = 0
[http "https://github.com/"]
	extraheader = AUTHORIZATION: basic eG-hY2Nlc3MtdG9rZW46ZXhhbXBsZQ==
"#;

    let warning = checkout_hint(Some(raw_config));
    assert!(warning.is_some(), "expected warning for extraheader");
    let msg = warning.unwrap().message;
    assert!(
        msg.contains("persist-credentials: false"),
        "warning should recommend persist-credentials: false, got: {msg}"
    );

    // Call site test reading <source>/.git/config
    let tmp = TempDirGuard::new("mcpg_cred_hint_extraheader");
    let git_dir = tmp.path().join(".git");
    fs::create_dir_all(&git_dir).expect("create .git");
    fs::write(git_dir.join("config"), raw_config).expect("write .git/config");

    let source_warning = check_source_checkout_hint(tmp.path());
    assert!(
        source_warning.is_some(),
        "expected warning when scanning source directory"
    );
    assert!(source_warning
        .unwrap()
        .message
        .contains("persist-credentials: false"));
}

#[test]
fn no_git_dir_no_warning() {
    let warning = checkout_hint(None);
    assert!(
        warning.is_none(),
        "none git config should produce no warning"
    );

    let tmp = TempDirGuard::new("mcpg_cred_hint_no_git");
    let source_warning = check_source_checkout_hint(tmp.path());
    assert!(
        source_warning.is_none(),
        "directory without .git should produce no warning"
    );
}

#[test]
fn git_without_extraheader_no_warning() {
    let raw_config = r#"[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
"#;

    let warning = checkout_hint(Some(raw_config));
    assert!(
        warning.is_none(),
        "clean git config should produce no warning"
    );

    let tmp = TempDirGuard::new("mcpg_cred_hint_clean");
    let git_dir = tmp.path().join(".git");
    fs::create_dir_all(&git_dir).expect("create .git");
    fs::write(git_dir.join("config"), raw_config).expect("write .git/config");

    let source_warning = check_source_checkout_hint(tmp.path());
    assert!(
        source_warning.is_none(),
        "directory with clean .git should produce no warning"
    );
}
