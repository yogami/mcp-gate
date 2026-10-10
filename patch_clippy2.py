import sys

with open("crates/mcpg-linux/src/launcher.rs", "r") as f:
    content = f.read()

old_if = """                if fd >= start_fd {
                    if next_keep == -1 || fd < next_keep {
                        next_keep = fd;
                    }
                }"""
new_if = """                if fd >= start_fd && (next_keep == -1 || fd < next_keep) {
                    next_keep = fd;
                }"""
content = content.replace(old_if, new_if)

old_clamp = "libc::sysconf(libc::_SC_OPEN_MAX).max(1024).min(65536)"
new_clamp = "libc::sysconf(libc::_SC_OPEN_MAX).clamp(1024, 65536)"
content = content.replace(old_clamp, new_clamp)

with open("crates/mcpg-linux/src/launcher.rs", "w") as f:
    f.write(content)
