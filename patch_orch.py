import sys

with open("crates/mcpg-app/src/orchestrator.rs", "r") as f:
    content = f.read()

old_orch = """            let launcher = self.sandbox.create_launcher(ruleset);
            let mut cap = match launcher.launch(&plan) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("launch error: {:?}", e);
                    return Err(ExitCode::Internal);
                }
            };
            let (obs_tx, obs_rx) = std::sync::mpsc::channel();
            let mut _obs_handle = None;
            if let Some(fd) = cap.seccomp_listener_fd {
                _obs_handle = Some(self.sandbox.start_observer_thread(
                    fd,
                    cfg.policy.allow_network,
                    cfg.policy.allowed_child_binaries.iter().map(std::path::PathBuf::from).collect(),
                    Some(cfg.server.command.clone().into()),
                    cfg.policy.allowed_unix_sockets.clone(),
                    vec![cap.pid],
                    None,
                    None,
                    obs_tx
                ));
            }"""

new_orch = """            let (launcher, handover) = self.sandbox.create_launcher(ruleset);
            let (obs_tx, obs_rx) = std::sync::mpsc::channel();
            
            let mut _obs_handle = None;
            if let Some(fd) = handover {
                _obs_handle = Some(self.sandbox.start_observer_thread(
                    fd,
                    cfg.policy.allow_network,
                    cfg.policy.allowed_child_binaries.iter().map(std::path::PathBuf::from).collect(),
                    Some(cfg.server.command.clone().into()),
                    cfg.policy.allowed_unix_sockets.clone(),
                    vec![],
                    None,
                    None,
                    obs_tx
                ));
            }

            let mut cap = match launcher.launch(&plan) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("launch error: {:?}", e);
                    return Err(ExitCode::Internal);
                }
            };
"""

content = content.replace(old_orch, new_orch)

with open("crates/mcpg-app/src/orchestrator.rs", "w") as f:
    f.write(content)
