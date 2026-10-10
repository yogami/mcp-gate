import os
import glob

def patch_file(path):
    with open(path, "r") as f:
        content = f.read()

    # Find all Command::cargo_bin("mcp-gate").expect("mcp-gate exists");
    content = content.replace('.expect("mcp-gate exists");\n', '.expect("mcp-gate exists").env_remove("GITHUB_ACTIONS");\n')
    content = content.replace('.unwrap();\n', '.unwrap().env_remove("GITHUB_ACTIONS");\n')
    # wait, this might match too many things.
    # Let's just write a regex.
    pass

import re
def patch_file_regex(path):
    with open(path, "r") as f:
        content = f.read()
    content = re.sub(r'Command::cargo_bin\("mcp-gate"\)(.*?;)', r'Command::cargo_bin("mcp-gate")\1\n    cmd.env_remove("GITHUB_ACTIONS");', content)
    # wait, sometimes it's assigned to `let mut cmd1`, etc.
    # A safer way: Just patch `Command::cargo_bin`? No, because it returns a `Command` object which has `.env_remove` method.
    pass

