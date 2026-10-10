def replace_in_file(path):
    with open(path, "r") as f:
        lines = f.readlines()
        
    out_lines = []
    in_fn = False
    for line in lines:
        if line.startswith("fn to_base64(data: &[u8]) -> String {"):
            in_fn = True
            continue
        if in_fn:
            if line.startswith("}"):
                in_fn = False
            continue
        
        out_lines.append(line.replace("to_base64(", "crate::util::to_base64("))
        
    with open(path, "w") as f:
        f.writelines(out_lines)

replace_in_file("crates/mcpg-domain/src/canary/render.rs")
replace_in_file("crates/mcpg-domain/src/canary/ssh.rs")
