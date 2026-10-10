import os

with open("crates/mcpg-domain/src/lib.rs", "a") as f:
    f.write("\npub mod util;\n")

os.makedirs("crates/mcpg-domain/src", exist_ok=True)
with open("crates/mcpg-domain/src/util.rs", "w") as f:
    f.write("""pub fn to_base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < data.len() {
            out.push(ALPHABET[(((b1 & 15) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(ALPHABET[(b2 & 63) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}
""")

def replace_in_file(path):
    with open(path, "r") as f:
        content = f.read()
    
    # Remove the existing fn to_base64
    import re
    content = re.sub(r'fn to_base64\(data: &\[u8\]\) -> String \{.*?\}\n', '', content, flags=re.DOTALL)
    
    # Replace to_base64 calls with crate::util::to_base64
    content = content.replace("to_base64(", "crate::util::to_base64(")
    
    with open(path, "w") as f:
        f.write(content)

replace_in_file("crates/mcpg-domain/src/canary/render.rs")
replace_in_file("crates/mcpg-domain/src/canary/ssh.rs")
