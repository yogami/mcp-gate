import sys

with open("crates/mcpg-linux/src/launcher.rs", "r") as f:
    content = f.read()

old_vec = """        let mut keep = vec![];
        if _landlock_fd >= 0 {
            keep.push(_landlock_fd);
        }
        if _child_sock >= 0 {
            keep.push(_child_sock);
        }
        close_extra_fds_except(&keep);"""

new_vec = """        let mut keep = [-1; 2];
        let mut keep_len = 0;
        if _landlock_fd >= 0 {
            keep[keep_len] = _landlock_fd;
            keep_len += 1;
        }
        if _child_sock >= 0 {
            keep[keep_len] = _child_sock;
            keep_len += 1;
        }
        close_extra_fds_except(&keep[..keep_len]);"""

if old_vec in content:
    content = content.replace(old_vec, new_vec)
    with open("crates/mcpg-linux/src/launcher.rs", "w") as f:
        f.write(content)
    print("Patched!")
else:
    print("Could not find the target code to patch!")

