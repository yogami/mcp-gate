#!/bin/bash
sed -i '' -e 's/if fd != keep_fd {/if \!keep_fds.contains(\&fd) {/g' crates/mcpg-linux/src/launcher.rs
sed -i '' -e 's/libc::SOCK_CLOEXEC/0x80000/g' crates/mcpg-linux/src/sandbox.rs
