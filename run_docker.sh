#!/bin/bash
docker run --rm -v $(pwd):/app -w /app rust:1.80-slim bash -c "apt-get update && apt-get install -y python3 && cargo test -p mcpg-cli contract_ipc_deadlock -- --nocapture"
