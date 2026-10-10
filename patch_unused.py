import sys

with open("crates/mcpg-linux/src/launcher.rs", "r") as f:
    content = f.read()

content = content.replace(
    "fn close_extra_fds_except(keep_fds: &[std::os::fd::RawFd]) {",
    "#[allow(unused_variables)]\nfn close_extra_fds_except(keep_fds: &[std::os::fd::RawFd]) {"
)

with open("crates/mcpg-linux/src/launcher.rs", "w") as f:
    f.write(content)
