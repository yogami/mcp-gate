#!/usr/bin/env bash
# Red test for `#![forbid(unsafe_code)]` compliance across crates.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."

failed=0
checked=0

for crate_dir in "$root"/crates/*; do
  crate_name="$(basename "$crate_dir")"
  if [[ "$crate_name" == "mcpg-linux" ]]; then
    continue
  fi

  for entry in "$crate_dir"/src/lib.rs "$crate_dir"/src/main.rs; do
    if [[ -f "$entry" ]]; then
      checked=$((checked + 1))
      if ! grep -q '#!\[forbid(unsafe_code)\]' "$entry"; then
        echo "FAIL $entry: missing #![forbid(unsafe_code)]" >&2
        failed=$((failed + 1))
      fi
    fi
  done
done

if [[ "$checked" -eq 0 ]]; then
  echo "FAIL: no crates checked" >&2
  exit 1
fi

if [[ "$failed" -eq 0 ]]; then
  echo "ok $checked files forbid unsafe code"
  exit 0
else
  echo "not ok $failed files failed" >&2
  exit 1
fi
