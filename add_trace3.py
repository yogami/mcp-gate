import sys

def patch_file(filepath, replacements):
    with open(filepath, "r") as f:
        content = f.read()
    for old, new in replacements:
        content = content.replace(old, new)
    with open(filepath, "w") as f:
        f.write(content)

patch_file("crates/mcpg-linux/src/shutdown.rs", [
    ("pub fn shutdown(mut cap: RunningCapsule, grace: Duration) -> ShutdownReport {", "pub fn shutdown(mut cap: RunningCapsule, grace: Duration) -> ShutdownReport {\n    eprintln!(\"shutdown - start\");"),
    ("let stage = execute_shutdown_escalation(&mut cap.child, pgid, grace);", "eprintln!(\"shutdown - execute_shutdown_escalation\"); let stage = execute_shutdown_escalation(&mut cap.child, pgid, grace);"),
    ("let _ = cap.child.wait();", "eprintln!(\"shutdown - cap.child.wait()\"); let _ = cap.child.wait(); eprintln!(\"shutdown - cap.child.wait() finished\");"),
    ("kill_known_pids(&all_known, &mut survivors);", "eprintln!(\"shutdown - kill_known_pids\"); kill_known_pids(&all_known, &mut survivors);"),
    ("let start = Instant::now();", "eprintln!(\"shutdown - waitpid loop\"); let start = Instant::now();"),
])
