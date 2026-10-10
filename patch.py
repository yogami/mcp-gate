with open("crates/mcpg-linux/tests/launch_handshake.rs", "r") as f:
    lines = f.readlines()

new_lines = []
in_loop = False
loop_start = -1
for i, line in enumerate(lines):
    if "let deadline = Instant::now() + Duration::from_secs(30);" in line:
        new_lines.append("    let deadline = Instant::now() + Duration::from_secs(5);\n")
        new_lines.append("    let mut target_events = 0;\n")
        new_lines.append("    let mut loop_count = 0;\n")
        new_lines.append("    loop {\n")
        new_lines.append("        loop_count += 1;\n")
        new_lines.append("        if loop_count % 1000 == 0 {\n")
        new_lines.append("            eprintln!(\"DEBUG: Loop iteration {}, target_events={}\", loop_count, target_events);\n")
        new_lines.append("        }\n")
        new_lines.append("        if capsule.child.try_wait().unwrap().is_some() {\n")
        new_lines.append("            eprintln!(\"DEBUG: Child exited!\");\n")
        new_lines.append("            break;\n")
        new_lines.append("        }\n")
        new_lines.append("        assert!(Instant::now() < deadline, \"notification loop deadlocked after 5s\");\n")
        in_loop = True
    elif in_loop:
        if "assert!(Instant::now() < deadline, \"notification loop deadlocked\");" in line:
            pass
        elif "if capsule.child.try_wait().unwrap().is_some() {" in line:
            pass
        elif "break;" in line and "if capsule" not in lines[i-1]:
            pass
        elif "}" in line and "break;" in lines[i-1] and "if capsule" not in lines[i-2]:
            pass
        elif "let mut target_events = 0;" in line:
            pass
        elif "loop {" in line:
            pass
        else:
            new_lines.append(line)
        if "    let mut output = String::new();" in line:
            in_loop = False
    else:
        new_lines.append(line)

with open("crates/mcpg-linux/tests/launch_handshake.rs", "w") as f:
    f.writelines(new_lines)
