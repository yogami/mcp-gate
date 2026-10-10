import sys

def patch_file(filepath, replacements):
    with open(filepath, "r") as f:
        content = f.read()
    for old, new in replacements:
        content = content.replace(old, new)
    with open(filepath, "w") as f:
        f.write(content)

patch_file("crates/mcpg-linux/src/sandbox.rs", [
    ("fn setup(&self, plan: &CapsulePlan) -> Result<RunningCapsule, SetupError> {", "fn setup(&self, plan: &CapsulePlan) -> Result<RunningCapsule, SetupError> {\n    eprintln!(\"LinuxSandbox::setup - start\");"),
    ("let running = self.launcher.launch(plan)?;", "eprintln!(\"LinuxSandbox::setup - launch\"); let running = self.launcher.launch(plan)?;"),
    ("Ok(running)", "eprintln!(\"LinuxSandbox::setup - finish\"); Ok(running)"),
])

patch_file("crates/mcpg-linux/src/launcher.rs", [
    ("fn launch(&self, plan: &CapsulePlan) -> Result<RunningCapsule, LaunchError> {", "fn launch(&self, plan: &CapsulePlan) -> Result<RunningCapsule, LaunchError> {\n    eprintln!(\"LinuxLauncher::launch - start\");"),
    ("let child = cmd.spawn()?;", "eprintln!(\"LinuxLauncher::launch - cmd.spawn\"); let child = cmd.spawn()?; eprintln!(\"LinuxLauncher::launch - cmd.spawn finished\");"),
])
