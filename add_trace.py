import sys

def patch_file(filepath, replacements):
    with open(filepath, "r") as f:
        content = f.read()
    for old, new in replacements:
        content = content.replace(old, new)
    with open(filepath, "w") as f:
        f.write(content)

patch_file("crates/mcpg-app/src/orchestrator.rs", [
    ("let plan = run_planner::create_run_plan(opts)?;", "eprintln!(\"AppOrchestrator::execute - create_run_plan\"); let plan = run_planner::create_run_plan(opts)?;"),
    ("let mut cap = match self.sandbox.setup(&plan) {", "eprintln!(\"AppOrchestrator::execute - setup sandbox\"); let mut cap = match self.sandbox.setup(&plan) {"),
    ("let mut transport = StdioTransport::new(", "eprintln!(\"AppOrchestrator::execute - StdioTransport\"); let mut transport = StdioTransport::new("),
    ("let (verdict, mut exit_code, violations) = match crate::session::drive_session(", "eprintln!(\"AppOrchestrator::execute - drive_session\"); let (verdict, mut exit_code, violations) = match crate::session::drive_session("),
    ("let teardown_events = self", "eprintln!(\"AppOrchestrator::execute - teardown\"); let teardown_events = self"),
])

patch_file("crates/mcpg-app/src/session.rs", [
    ("pub fn drive_session<W: Write>(", "pub fn drive_session<W: Write>(\n    eprintln!(\"drive_session - start\");"),
    ("let client_handshake = match client.initialize(&plan.config.server.protocol_versions, roots) {", "eprintln!(\"drive_session - client.initialize\"); let client_handshake = match client.initialize(&plan.config.server.protocol_versions, roots) {"),
    ("eprintln!(\"drive_session - checking scenarios\"); let scenario_res = execute_single_scenario(", "eprintln!(\"drive_session - execute_single_scenario\"); let scenario_res = execute_single_scenario("),
])
