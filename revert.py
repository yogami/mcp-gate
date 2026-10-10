import sys

def patch_file(filepath, replacements):
    with open(filepath, "r") as f:
        content = f.read()
    for old, new in replacements:
        content = content.replace(old, new)
    with open(filepath, "w") as f:
        f.write(content)

patch_file("crates/mcpg-app/src/orchestrator.rs", [
    ("eprintln!(\"AppOrchestrator::execute - create_run_plan\"); let plan = run_planner::create_run_plan(opts)?;", "let plan = run_planner::create_run_plan(opts)?;"),
    ("eprintln!(\"AppOrchestrator::execute - setup sandbox\"); let mut cap = match self.sandbox.setup(&plan) {", "let mut cap = match self.sandbox.setup(&plan) {"),
    ("eprintln!(\"AppOrchestrator::execute - StdioTransport\"); let mut transport = StdioTransport::new(", "let mut transport = StdioTransport::new("),
    ("eprintln!(\"AppOrchestrator::execute - drive_session\"); let (verdict, mut exit_code, violations) = match crate::session::drive_session(", "let (verdict, mut exit_code, violations) = match crate::session::drive_session("),
    ("eprintln!(\"AppOrchestrator::execute - teardown\"); let teardown_events = self", "let teardown_events = self"),
])

patch_file("crates/mcpg-app/src/session.rs", [
    ("pub fn drive_session<W: Write>(\n    eprintln!(\"drive_session - start\");", "pub fn drive_session<W: Write>("),
    ("eprintln!(\"drive_session - client.initialize\"); let client_handshake = match client.initialize(&plan.config.server.protocol_versions, roots) {", "let client_handshake = match client.initialize(&plan.config.server.protocol_versions, roots) {"),
    ("eprintln!(\"drive_session - execute_single_scenario\"); let scenario_res = execute_single_scenario(", "let scenario_res = execute_single_scenario("),
])

patch_file("crates/mcpg-mcp/src/client.rs", [
    ("eprintln!(\"client - waiting for initialize response\"); let result = self.wait_for_response_with_deadline(id, \"initialize\", startup_deadline)?; eprintln!(\"client - got initialize response\");", "let result = self.wait_for_response_with_deadline(id, \"initialize\", startup_deadline)?;"),
])

patch_file("crates/mcpg-linux/src/shutdown.rs", [
    ("pub fn shutdown(mut cap: RunningCapsule, grace: Duration) -> ShutdownReport {\n    eprintln!(\"shutdown - start\");", "pub fn shutdown(mut cap: RunningCapsule, grace: Duration) -> ShutdownReport {"),
    ("eprintln!(\"shutdown - execute_shutdown_escalation\"); let stage = execute_shutdown_escalation(&mut cap.child, pgid, grace);", "let stage = execute_shutdown_escalation(&mut cap.child, pgid, grace);"),
    ("eprintln!(\"shutdown - cap.child.wait()\"); let _ = cap.child.wait(); eprintln!(\"shutdown - cap.child.wait() finished\");", "let _ = cap.child.wait();"),
    ("eprintln!(\"shutdown - kill_known_pids\"); kill_known_pids(&all_known, &mut survivors);", "kill_known_pids(&all_known, &mut survivors);"),
    ("eprintln!(\"shutdown - waitpid loop\"); let start = Instant::now();", "let start = Instant::now();"),
])

patch_file("crates/mcpg-linux/src/sandbox.rs", [
    ("fn setup(&self, plan: &CapsulePlan) -> Result<RunningCapsule, SetupError> {\n    eprintln!(\"LinuxSandbox::setup - start\");", "fn setup(&self, plan: &CapsulePlan) -> Result<RunningCapsule, SetupError> {"),
    ("eprintln!(\"LinuxSandbox::setup - launch\"); let running = self.launcher.launch(plan)?;", "let running = self.launcher.launch(plan)?;"),
    ("eprintln!(\"LinuxSandbox::setup - finish\"); Ok(running)", "Ok(running)"),
])

patch_file("crates/mcpg-linux/src/launcher.rs", [
    ("fn launch(&self, plan: &CapsulePlan) -> Result<RunningCapsule, LaunchError> {\n    eprintln!(\"LinuxLauncher::launch - start\");", "fn launch(&self, plan: &CapsulePlan) -> Result<RunningCapsule, LaunchError> {"),
    ("eprintln!(\"LinuxLauncher::launch - cmd.spawn\"); let child = cmd.spawn()?; eprintln!(\"LinuxLauncher::launch - cmd.spawn finished\");", "let child = cmd.spawn()?;"),
])
