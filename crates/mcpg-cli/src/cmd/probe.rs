use mcpg_domain::verdict::ExitCode;
use mcpg_linux::probe::probe;

pub fn execute() -> ExitCode {
    let caps = probe();
    if let Ok(json) = serde_json::to_string_pretty(&caps) {
        println!("{json}");
    }
    if caps.supported {
        ExitCode::Pass
    } else {
        ExitCode::UnsupportedHost
    }
}
