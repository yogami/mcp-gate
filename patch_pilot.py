import sys

with open(".github/workflows/pilot.yml", "r") as f:
    content = f.read()

new_steps = """      - uses: actions/checkout@v4
      - name: Check Formatting
        run: cargo fmt --check

      - name: Run Clippy
        run: cargo clippy --workspace -- -D warnings

      - name: Run Unit Tests
        run: cargo test --workspace

      - name: Build mcp-gate
        run: cargo build --release"""

content = content.replace("      - uses: actions/checkout@v4\n      - name: Build mcp-gate\n        run: cargo build --release", new_steps)

with open(".github/workflows/pilot.yml", "w") as f:
    f.write(content)
