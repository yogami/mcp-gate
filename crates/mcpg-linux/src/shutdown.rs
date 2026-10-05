//! Capsule shutdown sequence and orphan process management.
//!
//! SPEC 3.1.6: Closes stdin, waits grace period, sends SIGTERM to process group,
//! escalates to SIGKILL, and reaps all descendants via PR_SET_CHILD_SUBREAPER.

use std::path::Path;
use std::time::{Duration, Instant};

use mcpg_app::ports::RunningCapsule;

/// Stage at which the capsule exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownStage {
    StdinClosed,
    Terminated,
    Killed,
}

/// Report summarizing shutdown exit status and reaped orphan processes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    pub stage: ShutdownStage,
    pub survivors: Vec<u32>,
}

fn wait_for_exit(child: &mut std::process::Child, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(Some(_)) = child.try_wait() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.try_wait().ok().flatten().is_some()
}

fn parse_children_file(path: &Path) -> Vec<u32> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|s| s.parse::<u32>().ok())
        .collect()
}

fn collect_thread_children(entry: std::fs::DirEntry) -> Vec<u32> {
    let path = entry.path().join("children");
    parse_children_file(&path)
}

fn collect_tree_pids(root_pid: u32) -> Vec<u32> {
    let mut pids = vec![root_pid];
    let task_dir = format!("/proc/{root_pid}/task");
    if let Ok(entries) = std::fs::read_dir(task_dir) {
        for cpid in entries.flatten().flat_map(collect_thread_children) {
            pids.extend(collect_tree_pids(cpid));
        }
    }
    pids
}

fn kill_survivor_pid(pid: u32, survivors: &mut Vec<u32>) {
    unsafe {
        if libc::kill(pid as i32, 0) == 0 {
            libc::kill(pid as i32, libc::SIGKILL);
            if !survivors.contains(&pid) {
                survivors.push(pid);
            }
        }
    }
}

fn kill_known_pids(pids: &[u32], survivors: &mut Vec<u32>) {
    for &pid in pids {
        kill_survivor_pid(pid, survivors);
    }
}

enum ReapResult {
    Reaped,
    Pending,
    Done,
}

fn record_reaped(reaped: i32, main_pid: u32, survivors: &mut Vec<u32>) {
    let rpid = reaped as u32;
    if rpid != main_pid && !survivors.contains(&rpid) {
        survivors.push(rpid);
    }
}

fn reap_one(main_pid: u32, survivors: &mut Vec<u32>) -> ReapResult {
    let mut status = 0;
    let res = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
    if res > 0 {
        record_reaped(res, main_pid, survivors);
        ReapResult::Reaped
    } else if res == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
        ReapResult::Pending
    } else {
        ReapResult::Done
    }
}

fn reap_all_children(survivors: &mut Vec<u32>, main_pid: u32) {
    let start = Instant::now();
    let timeout = Duration::from_millis(500);
    while start.elapsed() < timeout {
        match reap_one(main_pid, survivors) {
            ReapResult::Reaped => continue,
            ReapResult::Pending => std::thread::sleep(Duration::from_millis(10)),
            ReapResult::Done => break,
        }
    }
}

fn collect_subreaper_adopted_children(runner_pid: u32, main_pid: u32) -> Vec<u32> {
    let mut orphans = Vec::new();
    let task_dir = format!("/proc/{runner_pid}/task");
    if let Ok(entries) = std::fs::read_dir(task_dir) {
        for cpid in entries.flatten().flat_map(collect_thread_children) {
            if cpid != main_pid {
                orphans.extend(collect_tree_pids(cpid));
            }
        }
    }
    orphans
}

fn execute_shutdown_escalation(
    child: &mut std::process::Child,
    pgid: i32,
    grace: Duration,
) -> ShutdownStage {
    if wait_for_exit(child, grace) {
        return ShutdownStage::StdinClosed;
    }
    unsafe {
        libc::kill(-pgid, libc::SIGTERM);
    }
    if wait_for_exit(child, Duration::from_secs(1)) {
        return ShutdownStage::Terminated;
    }
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    ShutdownStage::Killed
}

/// Execute graceful capsule shutdown with signal escalation and orphan reaping.
pub fn shutdown(mut cap: RunningCapsule, grace: Duration) -> ShutdownReport {
    let mut survivors = Vec::new();
    let runner_pid = unsafe { libc::getpid() } as u32;
    let known_pids = collect_tree_pids(cap.pid);
    let pgid = cap.pid as i32;

    drop(cap.child.stdin.take());

    let stage = execute_shutdown_escalation(&mut cap.child, pgid, grace);
    let _ = cap.child.wait();

    kill_known_pids(&known_pids, &mut survivors);
    let orphans = collect_subreaper_adopted_children(runner_pid, cap.pid);
    kill_known_pids(&orphans, &mut survivors);
    reap_all_children(&mut survivors, cap.pid);

    ShutdownReport { stage, survivors }
}
