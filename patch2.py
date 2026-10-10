with open("crates/mcpg-linux/tests/launch_handshake.rs", "r") as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if "let mut launcher = LinuxLauncher::new().with_seccomp(true);" in line:
        new_lines.append("    eprintln!(\"DEBUG: Before launch\");\n")
        new_lines.append(line)
    elif "let mut capsule = launcher" in line:
        new_lines.append("    eprintln!(\"DEBUG: Calling launch\");\n")
        new_lines.append(line)
    elif "assert!(start.elapsed() < Duration::from_secs(6));" in line:
        new_lines.append(line)
        new_lines.append("    eprintln!(\"DEBUG: launch returned\");\n")
    elif "let ps = parent_sock.expect(\"parent sock\");" in line:
        new_lines.append("    eprintln!(\"DEBUG: Before recv_fd\");\n")
        new_lines.append(line)
    elif "let listener = unsafe {" in line:
        new_lines.append(line)
    elif "OwnedFd::from_raw_fd(mcpg_linux::seccomp::recv_fd(ps).expect(\"listener handover\"))" in line:
        new_lines.append(line)
    elif "    };" in line and "OwnedFd" in new_lines[-2]:
        new_lines.append(line)
        new_lines.append("    eprintln!(\"DEBUG: recv_fd returned\");\n")
    elif "let rc = unsafe { libc::poll(&mut pfd, 1, 50) };" in line:
        new_lines.append("        eprintln!(\"DEBUG: Polling...\");\n")
        new_lines.append(line)
    else:
        new_lines.append(line)

with open("crates/mcpg-linux/tests/launch_handshake.rs", "w") as f:
    f.writelines(new_lines)
