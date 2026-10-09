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
    let mut links = std::collections::BTreeMap::new();
    let dir_path = fd_dir_path();
    for &fd in &fds {
        #[cfg(target_os = "macos")]
        {
            let mut buf = [0u8; 1024];
            if unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) } != -1 {
                if let Ok(c_str) = std::ffi::CStr::from_bytes_until_nul(&buf) {
                    links.insert(fd.to_string(), c_str.to_string_lossy().into_owned());
                }
            }
        }
        #[cfg(target_os = "linux")]
        if let Ok(path) = std::fs::read_link(format!("{}/{}", dir_path, fd)) {
            links.insert(fd.to_string(), path.to_string_lossy().into_owned());
        }
    }
    println!("{}", serde_json::json!({ "fds": fds, "links": links }));
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
        libc::ENOSYS => "ENOSYS",
        libc::EINVAL => "EINVAL",
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

fn cmd_openat_dirfd(dir: &str, rel: &str) {
    let dfd = if dir.is_empty() || dir == "." {
        libc::AT_FDCWD
    } else {
        let c_dir = std::ffi::CString::new(dir).unwrap_or_default();
        let fd = unsafe { libc::open(c_dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        if fd < 0 {
            let err = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            println!(
                "{}",
                serde_json::json!({ "status": "error", "error": errno_name(err) })
            );
            return;
        }
        fd
    };

    let c_rel = std::ffi::CString::new(rel).unwrap_or_default();
    let fd = unsafe { libc::openat(dfd, c_rel.as_ptr(), libc::O_RDONLY) };
    if dfd != libc::AT_FDCWD {
        unsafe {
            libc::close(dfd);
        }
    }

    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
        println!("{}", serde_json::json!({ "status": "ok", "ok": true }));
    } else {
        let err = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        println!(
            "{}",
            serde_json::json!({ "status": "error", "error": errno_name(err) })
        );
    }
}

fn cmd_openat2(path: &str) {
    #[cfg(target_os = "linux")]
    {
        #[repr(C)]
        struct open_how {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        let how = open_how {
            flags: libc::O_RDONLY as u64,
            mode: 0,
            resolve: 0,
        };
        let c_path = std::ffi::CString::new(path).unwrap_or_default();
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                c_path.as_ptr(),
                &how,
                std::mem::size_of::<open_how>(),
            )
        };
        if fd >= 0 {
            unsafe {
                libc::close(fd as i32);
            }
            println!("{}", serde_json::json!({ "status": "ok", "ok": true }));
        } else {
            let err = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            println!(
                "{}",
                serde_json::json!({ "status": "error", "error": errno_name(err) })
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        println!(
            "{}",
            serde_json::json!({ "status": "error", "error": "ENOSYS" })
        );
    }
}

#[allow(deprecated)]
fn cmd_vfork_exec(bin: &str, args: &[String]) {
    #[cfg(target_os = "linux")]
    unsafe {
        let c_bin = std::ffi::CString::new(bin).unwrap_or_default();
        let mut c_args = vec![c_bin.clone()];
        for a in args {
            c_args.push(std::ffi::CString::new(a.as_str()).unwrap_or_default());
        }
        let mut argv: Vec<*const libc::c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());

        let pid = libc::vfork();
        if pid == 0 {
            libc::execve(c_bin.as_ptr(), argv.as_ptr(), [std::ptr::null()].as_ptr());
            libc::_exit(127);
        } else if pid > 0 {
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
            println!(
                "{}",
                serde_json::json!({ "status": "ok", "pid": pid, "exit_code": libc::WEXITSTATUS(status) })
            );
        } else {
            let err = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            println!(
                "{}",
                serde_json::json!({ "status": "error", "error": errno_name(err) })
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (bin, args);
        println!(
            "{}",
            serde_json::json!({ "status": "error", "error": "ENOSYS" })
        );
    }
}

fn cmd_clone_newuser() {
    #[cfg(target_os = "linux")]
    {
        let res = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
        if res == 0 {
            println!("{}", serde_json::json!({ "status": "ok" }));
        } else {
            let err = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            println!(
                "{}",
                serde_json::json!({ "status": "error", "error": errno_name(err) })
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!(
            "{}",
            serde_json::json!({ "status": "error", "error": "ENOSYS" })
        );
    }
}

fn cmd_io_uring() {
    #[cfg(target_os = "linux")]
    {
        #[repr(C)]
        struct io_uring_params {
            sq_entries: u32,
            cq_entries: u32,
            flags: u32,
            sq_thread_cpu: u32,
            sq_thread_idle: u32,
            features: u32,
            wq_fd: u32,
            resv: [u32; 3],
            sq_off: [u32; 10],
            cq_off: [u32; 10],
        }
        let mut p: io_uring_params = unsafe { std::mem::zeroed() };
        let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 8, &mut p) };
        if fd >= 0 {
            unsafe {
                libc::close(fd as i32);
            }
            println!("{}", serde_json::json!({ "status": "ok" }));
        } else {
            let err = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            println!(
                "{}",
                serde_json::json!({ "status": "error", "error": errno_name(err) })
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!(
            "{}",
            serde_json::json!({ "status": "error", "error": "ENOSYS" })
        );
    }
}

fn cmd_x32_syscall() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let res = unsafe { libc::syscall(0x40000000 | libc::SYS_getpid) };
        println!("{}", serde_json::json!({ "status": "ok", "res": res }));
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        println!("{}", serde_json::json!({ "status": "unsupported" }));
    }
}

fn cmd_kill_minus_one() {
    let rc = unsafe { libc::kill(-1, libc::SIGTERM) };
    if rc == 0 {
        println!("{}", serde_json::json!({ "status": "ok" }));
    } else {
        let err = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        println!(
            "{}",
            serde_json::json!({ "status": "error", "error": errno_name(err) })
        );
    }
}

fn cmd_threads_open(path: &str, thread_count: usize, count_per_thread: usize) {
    let path = path.to_string();
    let mut handles = Vec::new();
    for _ in 0..thread_count {
        let p = path.clone();
        handles.push(std::thread::spawn(move || {
            let mut ok_count = 0;
            let c_path = std::ffi::CString::new(p).unwrap_or_default();
            for _ in 0..count_per_thread {
                let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
                if fd >= 0 {
                    ok_count += 1;
                    unsafe {
                        libc::close(fd);
                    }
                }
            }
            ok_count
        }));
    }

    let mut total = 0;
    for h in handles {
        total += h.join().unwrap_or(0);
    }
    println!("{}", serde_json::json!({ "status": "ok", "count": total }));
}

fn cmd_deep_symlink(dir: &str) {
    let base = std::path::Path::new(dir);
    let target = base.join("target.txt");
    let _ = std::fs::write(&target, "secret");

    let mut prev = target;
    for i in 0..41 {
        let link = base.join(format!("link_{i}"));
        let _ = std::fs::remove_file(&link);
        #[cfg(unix)]
        if let Err(e) = std::os::unix::fs::symlink(&prev, &link) {
            println!(
                "{}",
                serde_json::json!({ "status": "error", "error": e.to_string() })
            );
            return;
        }
        prev = link;
    }

    let last_link = base.join("link_40");
    match std::fs::read(&last_link) {
        Ok(_) => println!("{}", serde_json::json!({ "status": "ok" })),
        Err(e) => {
            let name = e.raw_os_error().map_or("EIO", errno_name);
            println!(
                "{}",
                serde_json::json!({ "status": "error", "error": name })
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn open_dir_fd(dir: &str) -> Result<i32, i32> {
    let c_dir = std::ffi::CString::new(dir).map_err(|_| libc::EINVAL)?;
    let fd = unsafe { libc::open(c_dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd < 0 {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    } else {
        Ok(fd)
    }
}

#[cfg(target_os = "linux")]
fn call_execveat(dirfd: i32, rel: &str, args: &[String]) -> i32 {
    let c_rel = std::ffi::CString::new(rel).unwrap_or_default();
    let mut c_args = vec![c_rel.clone()];
    for a in args {
        c_args.push(std::ffi::CString::new(a.as_str()).unwrap_or_default());
    }
    let mut argv: Vec<*const libc::c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());
    let res = unsafe {
        libc::syscall(
            libc::SYS_execveat,
            dirfd,
            c_rel.as_ptr(),
            argv.as_ptr(),
            [std::ptr::null::<libc::c_char>()].as_ptr(),
            0,
        )
    };
    if res < 0 {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    } else {
        0
    }
}

fn cmd_execveat(dir: &str, rel: &str, args: &[String]) {
    #[cfg(target_os = "linux")]
    {
        let dirfd = match open_dir_fd(dir) {
            Ok(fd) => fd,
            Err(e) => {
                println!(
                    "{}",
                    serde_json::json!({ "status": "error", "error": errno_name(e) })
                );
                return;
            }
        };
        let err = call_execveat(dirfd, rel, args);
        unsafe {
            libc::close(dirfd);
        }
        if err != 0 {
            println!(
                "{}",
                serde_json::json!({ "status": "error", "error": errno_name(err) })
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dir, rel, args);
        println!(
            "{}",
            serde_json::json!({ "status": "error", "error": "ENOSYS" })
        );
    }
}

fn cmd_sendto_addr(ip: &str, port_str: &str, msg: &str) {
    let port = port_str.parse::<u16>().unwrap_or(0);
    let sock = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            let name = e.raw_os_error().map_or("EIO", errno_name);
            println!(
                "{}",
                serde_json::json!({ "status": "error", "error": name })
            );
            return;
        }
    };
    let dest = format!("{ip}:{port}");
    match sock.send_to(msg.as_bytes(), &dest) {
        Ok(n) => println!("{}", serde_json::json!({ "status": "ok", "bytes": n })),
        Err(e) => {
            let name = e.raw_os_error().map_or("EIO", errno_name);
            println!(
                "{}",
                serde_json::json!({ "status": "error", "error": name })
            );
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
        "path-traversal" => cmd_path_traversal(),
        "env-echo" => cmd_env_echo(target),
        "ignore-sigterm" => cmd_ignore_sigterm(),
        "daemon" => cmd_daemon(),
        "openat-dirfd" => cmd_openat_dirfd(target, rest.first().map_or("", |s| s.as_str())),
        "openat2" => cmd_openat2(target),
        "execveat" => cmd_execveat(
            target,
            rest.first().map_or("", |s| s.as_str()),
            if rest.len() > 1 { &rest[1..] } else { &[] },
        ),
        "vfork-exec" => cmd_vfork_exec(target, rest),
        "clone-newuser" => cmd_clone_newuser(),
        "io-uring" => cmd_io_uring(),
        "x32-syscall" => cmd_x32_syscall(),
        "sendto-addr" => cmd_sendto_addr(
            target,
            rest.first().map_or("", |s| s.as_str()),
            rest.get(1).map_or("ping", |s| s.as_str()),
        ),
        "kill-minus-one" => cmd_kill_minus_one(),
        "threads-open" => cmd_threads_open(target, 8, 1000),
        "deep-symlink" => cmd_deep_symlink(target),
        "unshare" => cmd_unshare(),
        "process-vm-readv" => cmd_process_vm_readv(target),
        "open-by-handle-at" => cmd_open_by_handle_at(),
        other => {
            eprintln!("unknown subcommand: {other}");
            std::process::exit(64);
        }
    }
}

fn cmd_path_traversal() {
    let target = "../../../../../../../../../../../etc/passwd";
    if let Ok(content) = std::fs::read_to_string(target) {
        println!("{}", serde_json::json!({ "content_len": content.len() }));
    } else {
        let err = std::io::Error::last_os_error();
        println!("{}", serde_json::json!({ "error": err.raw_os_error() }));
    }
}

fn cmd_env_echo(target: &str) {
    if let Ok(val) = std::env::var(target) {
        println!("{}", serde_json::json!({ target: val }));
    } else {
        println!("{}", serde_json::json!({ "error": "not_found" }));
    }
}

#[cfg(target_os = "linux")]
fn cmd_unshare() {
    // CLONE_NEWUSER is 0x10000000
    let res = unsafe { libc::unshare(0x10000000) };
    if res == 0 {
        println!("{}", serde_json::json!({ "status": "ok" }));
    } else {
        println!("{}", serde_json::json!({ "status": "error", "error": errno_name(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)) }));
    }
}

#[cfg(not(target_os = "linux"))]
fn cmd_unshare() {
    println!("{}", serde_json::json!({ "status": "error", "error": "ENOSYS" }));
}

#[cfg(target_os = "linux")]
fn cmd_process_vm_readv(target: &str) {
    let pid: libc::pid_t = target.parse().unwrap_or(1); // default to init
    let mut local_buf = [0u8; 8];
    let local_iov = libc::iovec {
        iov_base: local_buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: local_buf.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: 0x400000 as *mut libc::c_void,
        iov_len: 8,
    };
    let res = unsafe {
        libc::syscall(
            libc::SYS_process_vm_readv,
            pid,
            &local_iov as *const libc::iovec,
            1,
            &remote_iov as *const libc::iovec,
            1,
            0,
        )
    };
    if res >= 0 {
        println!("{}", serde_json::json!({ "status": "ok" }));
    } else {
        println!("{}", serde_json::json!({ "status": "error", "error": errno_name(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)) }));
    }
}

#[cfg(not(target_os = "linux"))]
fn cmd_process_vm_readv(_target: &str) {
    println!("{}", serde_json::json!({ "status": "error", "error": "ENOSYS" }));
}

#[cfg(target_os = "linux")]
fn cmd_open_by_handle_at() {
    let res = unsafe {
        libc::syscall(
            libc::SYS_open_by_handle_at,
            libc::AT_FDCWD, // mount_fd
            std::ptr::null::<libc::c_void>(), // handle
            libc::O_RDONLY,
        )
    };
    if res >= 0 {
        println!("{}", serde_json::json!({ "status": "ok" }));
    } else {
        println!("{}", serde_json::json!({ "status": "error", "error": errno_name(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)) }));
    }
}

#[cfg(not(target_os = "linux"))]
fn cmd_open_by_handle_at() {
    println!("{}", serde_json::json!({ "status": "error", "error": "ENOSYS" }));
}

