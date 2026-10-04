//! Minimal syscall probe fixture for launcher and boundary tests.
//!
//! SPEC 4.2.3:
//! Provides single-action subcommands outputting JSON lines.

use std::io::Write;

fn cmd_env() {
    let mut keys: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
    keys.sort();
    println!("{}", serde_json::json!({ "keys": keys }));
}

fn fd_dir_path() -> &'static str {
    if std::path::Path::new("/proc/self/fd").exists() {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    }
}

fn parse_fd(name: &std::ffi::CStr, dir_fd: i32) -> Option<i32> {
    let s = name.to_str().ok()?;
    let fd = s.parse::<i32>().ok()?;
    (fd != dir_fd).then_some(fd)
}

unsafe fn next_fd(dir: *mut libc::DIR, dir_fd: i32) -> Option<i32> {
    loop {
        let entry = libc::readdir(dir);
        if entry.is_null() {
            return None;
        }
        let name = std::ffi::CStr::from_ptr((*entry).d_name.as_ptr());
        if let Some(fd) = parse_fd(name, dir_fd) {
            return Some(fd);
        }
    }
}

fn collect_dir_fds(dir_path: &str) -> Vec<i32> {
    let mut fds = Vec::new();
    let c_path = std::ffi::CString::new(dir_path).unwrap_or_default();
    unsafe {
        let dir = libc::opendir(c_path.as_ptr());
        if dir.is_null() {
            return fds;
        }
        let dir_fd = libc::dirfd(dir);
        while let Some(fd) = next_fd(dir, dir_fd) {
            fds.push(fd);
        }
        libc::closedir(dir);
    }
    fds
}

fn cmd_fds() {
    let mut fds = collect_dir_fds(fd_dir_path());
    fds.sort();
    println!("{}", serde_json::json!({ "fds": fds }));
}

fn cmd_cwd() {
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    println!("{}", serde_json::json!({ "cwd": cwd }));
}

fn read_no_new_privs() -> bool {
    let content = match std::fs::read_to_string("/proc/self/status") {
        Ok(c) => c,
        Err(_) => return false,
    };
    content
        .lines()
        .find(|l| l.starts_with("NoNewPrivs:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .is_some_and(|val| val == "1")
}

fn current_umask() -> u32 {
    unsafe {
        let mask = libc::umask(0);
        libc::umask(mask);
        mask as u32
    }
}

fn cmd_ids() {
    let pid = unsafe { libc::getpid() };
    let pgid = unsafe { libc::getpgid(0) };
    let sid = unsafe { libc::getsid(0) };
    let no_new_privs = read_no_new_privs();
    let umask = current_umask();

    println!(
        "{}",
        serde_json::json!({
            "pid": pid,
            "pgid": pgid,
            "sid": sid,
            "no_new_privs": no_new_privs,
            "NoNewPrivs": no_new_privs,
            "umask": umask,
        })
    );
}

fn errno_name(code: i32) -> &'static str {
    match code {
        libc::EACCES => "EACCES",
        libc::ENOENT => "ENOENT",
        libc::ELOOP => "ELOOP",
        libc::EPERM => "EPERM",
        libc::EISDIR => "EISDIR",
        _ => "EIO",
    }
}

fn cmd_read(path: &str) {
    match std::fs::read(path) {
        Ok(_) => println!("{}", serde_json::json!({ "status": "ok", "ok": true })),
        Err(e) => {
            let name = e.raw_os_error().map_or("EIO", errno_name);
            println!(
                "{}",
                serde_json::json!({ "status": "error", "error": name, "ok": false })
            );
        }
    }
}

fn cmd_write(path: &str, content: &str) {
    match std::fs::write(path, content) {
        Ok(_) => println!("{}", serde_json::json!({ "status": "ok", "ok": true })),
        Err(e) => {
            let name = e.raw_os_error().map_or("EIO", errno_name);
            println!(
                "{}",
                serde_json::json!({ "status": "error", "error": name, "ok": false })
            );
        }
    }
}

fn cmd_exec(path: &str, args: &[String]) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(path).args(args).exec();
        let name = err.raw_os_error().map_or("EIO", errno_name);
        println!(
            "{}",
            serde_json::json!({ "status": "error", "error": name, "ok": false })
        );
    }
    #[cfg(not(unix))]
    {
        let _ = (path, args);
        println!(
            "{}",
            serde_json::json!({ "status": "error", "error": "ENOSYS", "ok": false })
        );
    }
}

fn cmd_sleep(s_str: &str) {
    let secs: f64 = s_str.parse().unwrap_or(0.0);
    std::thread::sleep(std::time::Duration::from_secs_f64(secs));
    println!(
        "{}",
        serde_json::json!({ "status": "slept", "seconds": secs })
    );
}

fn cmd_wait_stdin_eof() {
    let mut stdin = std::io::stdin();
    let _ = std::io::copy(&mut stdin, &mut std::io::sink());
    println!("{}", serde_json::json!({ "status": "eof" }));
}

fn cmd_ignore_sigterm() {
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
    }
    println!("{}", serde_json::json!({ "status": "ignoring_sigterm" }));
    std::io::stdout().flush().ok();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

fn detach_grandchild(write_pipe: i32) -> ! {
    let gpid = unsafe { libc::getpid() as i64 };
    let bytes = gpid.to_le_bytes();
    unsafe {
        libc::write(write_pipe, bytes.as_ptr() as *const libc::c_void, 8);
        libc::close(write_pipe);

        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            libc::close(devnull);
        }

        loop {
            libc::pause();
        }
    }
}

fn run_child_and_grandchild(write_pipe: i32) {
    unsafe {
        libc::setsid();
        let pid2 = libc::fork();
        if pid2 < 0 {
            libc::close(write_pipe);
            std::process::exit(1);
        }
        if pid2 > 0 {
            libc::close(write_pipe);
            std::process::exit(0);
        }
    }
    detach_grandchild(write_pipe);
}

fn cmd_daemon() {
    let mut pipe_fds = [0i32; 2];
    unsafe {
        if libc::pipe(pipe_fds.as_mut_ptr()) != 0 {
            return;
        }

        let pid1 = libc::fork();
        if pid1 < 0 {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
            return;
        }

        if pid1 == 0 {
            libc::close(pipe_fds[0]);
            run_child_and_grandchild(pipe_fds[1]);
        }

        libc::close(pipe_fds[1]);
        let mut buf = [0u8; 8];
        let n = libc::read(pipe_fds[0], buf.as_mut_ptr() as *mut libc::c_void, 8);
        libc::close(pipe_fds[0]);

        if n == 8 {
            let gpid = i64::from_le_bytes(buf);
            println!("{}", serde_json::json!({ "pid": gpid }));
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: syscall-probe <subcommand> [args...]");
        std::process::exit(64);
    }

    let subcmd = args[1].as_str();
    let target = args.get(2).map_or("", |s| s.as_str());
    let rest = if args.len() > 3 { &args[3..] } else { &[] };

    match subcmd {
        "env" => cmd_env(),
        "fds" => cmd_fds(),
        "cwd" => cmd_cwd(),
        "ids" => cmd_ids(),
        "read" => cmd_read(target),
        "write" => cmd_write(target, rest.first().map_or("", |s| s.as_str())),
        "exec" => cmd_exec(target, rest),
        "sleep" => cmd_sleep(target),
        "wait-stdin-eof" => cmd_wait_stdin_eof(),
        "ignore-sigterm" => cmd_ignore_sigterm(),
        "daemon" => cmd_daemon(),
        other => {
            eprintln!("unknown subcommand: {other}");
            std::process::exit(64);
        }
    }
}
