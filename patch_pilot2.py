import sys

with open(".github/workflows/pilot.yml", "r") as f:
    content = f.read()

content = content.replace(
    "timeout 30s strace -f -o mcp-gate.strace target/release/mcp-gate run --config fs-gate.yaml --sarif fs.sarif || true\n          cat mcp-gate.strace || true",
    "RUST_LOG=trace target/release/mcp-gate run --config fs-gate.yaml --sarif fs.sarif || true"
)

# And I want to change timeout-minutes from 2 to 5 for all of them just in case.
content = content.replace("timeout-minutes: 2", "timeout-minutes: 5")

with open(".github/workflows/pilot.yml", "w") as f:
    f.write(content)
