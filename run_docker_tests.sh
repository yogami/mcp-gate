#!/bin/bash
docker run --rm -v $(pwd):/app -w /app rust:1.80 bash -c "cargo test --workspace -- --test-threads=1 --nocapture"
