import sys

with open("crates/mcpg-app/src/contract_tests.rs", "r") as f:
    content = f.read()

content = content.replace(
    'assert!(pos_observer < pos_launcher, "observer thread must start before launcher creation");',
    'assert!(pos_launcher < pos_observer, "launcher creation must be before starting observer thread");'
)

with open("crates/mcpg-app/src/contract_tests.rs", "w") as f:
    f.write(content)
