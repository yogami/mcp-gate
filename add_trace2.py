import sys

def patch_file(filepath, replacements):
    with open(filepath, "r") as f:
        content = f.read()
    for old, new in replacements:
        content = content.replace(old, new)
    with open(filepath, "w") as f:
        f.write(content)

patch_file("crates/mcpg-mcp/src/client.rs", [
    ("let result = self.wait_for_response_with_deadline(id, \"initialize\", startup_deadline)?;", "eprintln!(\"client - waiting for initialize response\"); let result = self.wait_for_response_with_deadline(id, \"initialize\", startup_deadline)?; eprintln!(\"client - got initialize response\");"),
])
