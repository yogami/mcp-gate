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

fn reap_specific(pid: u32) {
    let mut status = 0;
    unsafe { libc::waitpid(pid as i32, &mut status, 0) };
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
    let pgid = cap.pid as i32;

    drop(cap.child.stdin.take());

    let stage = execute_shutdown_escalation(&mut cap.child, pgid, grace);
    let _ = cap.child.wait();

    let orphans = collect_subreaper_adopted_children(runner_pid, cap.pid);
    let mut all_known = collect_tree_pids(cap.pid);
    all_known.extend(orphans);
    
    // We only reap processes that actually belong to this capsule's process group.
    // Since concurrent tests run, we don't want to kill siblings. We filter by PGID.
    let mut capsule_pids = Vec::new();
    for pid in all_known {
        let p_pgid = unsafe { libc::getpgid(pid as i32) };
        if p_pgid == pgid {
            capsule_pids.push(pid);
        }
    }
    
    capsule_pids.sort_unstable();
    capsule_pids.dedup();

    kill_known_pids(&capsule_pids, &mut survivors);
    for pid in &capsule_pids {
        if *pid != cap.pid {
            reap_specific(*pid);
        }
    }

    ShutdownReport { stage, survivors }
}
