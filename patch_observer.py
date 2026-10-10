import sys

with open("crates/mcpg-linux/src/observer.rs", "r") as f:
    content = f.read()

old_obs = """pub fn start_observer_thread(
    listener_fd: RawFd,
    cfg: ObserverConfig,
    violations_tx: Sender<(String, String)>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let engine = ObserverEngine::new(cfg, RealMemoryReader);"""

new_obs = """pub fn start_observer_thread(
    handover_fd: RawFd,
    cfg: ObserverConfig,
    violations_tx: Sender<(String, String)>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let listener_fd = match crate::seccomp::recv_fd(handover_fd) {
            Ok(fd) => fd,
            Err(_) => return, // Failed to receive, maybe process died or execve failed
        };
        unsafe { libc::close(handover_fd); }
        let engine = ObserverEngine::new(cfg, RealMemoryReader);"""

content = content.replace(old_obs, new_obs)

with open("crates/mcpg-linux/src/observer.rs", "w") as f:
    f.write(content)
