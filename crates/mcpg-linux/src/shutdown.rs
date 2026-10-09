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

fn is_process_alive(pid: u32) -> bool {
    let status_path = format!("/proc/{pid}/status");
    if let Ok(content) = std::fs::read_to_string(status_path) {
        if let Some(state_line) = content.lines().find(|l| l.starts_with("State:")) {
            // State: Z (zombie) or X (dead)
            if state_line.contains('Z') || state_line.contains('X') {
                return false;
            }
        }
        true
    } else {
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
}

fn kill_survivor_pid(pid: u32, survivors: &mut Vec<u32>) {
    if is_process_alive(pid) {
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
        if !survivors.contains(&pid) {
            survivors.push(pid);
        }
    }
}

fn kill_known_pids(pids: &[u32], survivors: &mut Vec<u32>) {
    for &pid in pids {
        kill_survivor_pid(pid, survivors);
    }
}

fn collect_subreaper_adopted_children(runner_pid: u32, main_pid: u32) -> Vec<u32> {
    let mut orphans = Vec::new();
    
    // In Linux, adopted children reparent to the subreaper process, but they do NOT
    // appear in /proc/PID/task/TID/children. The only reliable way to find them is to
    // scan all processes and check if their PPID matches our runner_pid.
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<u32>() {
                if pid == runner_pid || pid == main_pid {
                    continue;
                }
                
                let stat_path = entry.path().join("stat");
                if let Ok(stat) = std::fs::read_to_string(stat_path) {
                    if let Some(rparen) = stat.rfind(')') {
                        let after = &stat[rparen + 1..];
                        let parts: Vec<&str> = after.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(ppid) = parts[1].parse::<u32>() {
                                if ppid == runner_pid {
                                    orphans.push(pid);
                                    orphans.extend(collect_tree_pids(pid));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    orphans.sort_unstable();
    orphans.dedup();
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
    if pgid > 1 {
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
    ShutdownStage::Killed
}

/// Execute graceful capsule shutdown with signal escalation and orphan reaping.
pub fn shutdown(mut cap: RunningCapsule, grace: Duration) -> ShutdownReport { eprintln!("DEBUG: shutdown start");
    let mut survivors = Vec::new();
    let runner_pid = unsafe { libc::getpid() } as u32;
    let pgid = cap.pid as i32;

    drop(cap.child.stdin.take());

    eprintln!("DEBUG: shutdown escalation start"); let stage = execute_shutdown_escalation(&mut cap.child, pgid, grace); eprintln!("DEBUG: shutdown escalation done");
    let _ = cap.child.wait();

    let orphans = collect_subreaper_adopted_children(runner_pid, cap.pid);
    let mut all_known = collect_tree_pids(cap.pid);
    all_known.extend(orphans);
    all_known.sort_unstable();
    all_known.dedup();

    // SPEC 3.1.6 step 4: SIGKILL every pid in the observed process tree that is still alive
    kill_known_pids(&all_known, &mut survivors);

    // SPEC 3.1.6 step 5: Reap with waitpid(-1, WNOHANG) until no children remain
    let start = Instant::now();
    let timeout = Duration::from_millis(500);
    while start.elapsed() < timeout {
        let mut status = 0;
        let res = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if res > 0 {
            continue;
        }
        if res < 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    ShutdownReport { stage, survivors }
}
