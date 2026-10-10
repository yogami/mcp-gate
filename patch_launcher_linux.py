import sys

with open("crates/mcpg-linux/src/launcher.rs", "r") as f:
    lines = f.readlines()

in_func = False
out_lines = []
for line in lines:
    if line.startswith("fn close_extra_fds_except("):
        in_func = True
        out_lines.append("fn close_extra_fds_except(keep_fds: &[std::os::fd::RawFd]) {\n")
        out_lines.append("    #[cfg(target_os = \"linux\")]\n")
        out_lines.append("    unsafe {\n")
        out_lines.append("        let max_fd = libc::sysconf(libc::_SC_OPEN_MAX).max(1024) as i32;\n")
        out_lines.append("        for fd in 3..max_fd {\n")
        out_lines.append("            if !keep_fds.contains(&fd) {\n")
        out_lines.append("                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);\n")
        out_lines.append("            }\n")
        out_lines.append("        }\n")
        out_lines.append("    }\n")
        out_lines.append("}\n")
        continue

    if in_func:
        if line.startswith("}"):
            in_func = False
        continue
    
    out_lines.append(line)

content = "".join(out_lines)

# Now remove the unused `parent_sock` variables in `launch()`
content = content.replace("        #[cfg(target_os = \"linux\")]\n        let mut parent_sock = None;\n", "")
content = content.replace("                    parent_sock = Some(sv[0]);\n", "")

with open("crates/mcpg-linux/src/launcher.rs", "w") as f:
    f.write(content)
