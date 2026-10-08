#!/usr/bin/env bash
# Red test for scripts/check-test-ids.sh (TASK-1.2).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/../check-test-ids.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/crates/dummy/src"
echo "fn p1_env_01_x() {}" > "$tmp/crates/dummy/src/lib.rs"

passed=0
failed=0

assert_eq() {
  local name="$1" want_rc="$2" want_str="$3"
  shift 3
  local out rc
  set +e
  out="$((cd "$tmp" && "$script" "$@") 2>&1)"
  rc=$?
  set -e

  if [[ "$rc" -eq "$want_rc" ]] && [[ -z "$want_str" || "$out" == *"$want_str"* ]]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL $name: want rc=$want_rc str='$want_str', got rc=$rc out='$out'" >&2
  fi
}

# 1. Existing ID exits 0
assert_eq "existing_id" 0 "" P1-ENV-01

# 2. Missing ID exits 1 and prints missing: P1-ENV-02
assert_eq "missing_id" 1 "missing: P1-ENV-02" P1-ENV-02

# 3. Range with missing member exits 1 and prints missing: P1-ENV-02
assert_eq "range_missing" 1 "missing: P1-ENV-02" P1-ENV-01..02

if [[ "$failed" -eq 0 ]]; then
  echo "ok $passed/3"
else
  echo "not ok $passed/3" >&2
  exit 1
fi
