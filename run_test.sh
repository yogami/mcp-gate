#!/bin/bash
cargo test -p mcpg-cli stderr_flood_test_the_blocking_pipe_bug -- --nocapture
