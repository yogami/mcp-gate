import sys

with open("crates/mcpg-app/src/ports.rs", "r") as f:
    content = f.read()

content = content.replace("pub trait Sandbox {", "#[allow(clippy::too_many_arguments)]\n#[allow(clippy::result_unit_err)]\npub trait Sandbox {")
content = content.replace("pub trait TripwireHandle {", "#[allow(clippy::result_unit_err)]\npub trait TripwireHandle {")

with open("crates/mcpg-app/src/ports.rs", "w") as f:
    f.write(content)

with open("crates/mcpg-linux/src/canary_plant.rs", "r") as f:
    content = f.read()

content = content.replace("fn set_dirs_mode_0700", "#[allow(dead_code)]\nfn set_dirs_mode_0700")

with open("crates/mcpg-linux/src/canary_plant.rs", "w") as f:
    f.write(content)
