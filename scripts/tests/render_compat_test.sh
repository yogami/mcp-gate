#!/usr/bin/env bash
# Red test for scripts/render-compat.sh (TASK-0.13). Prints "ok 4/4" on success.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/../render-compat.sh"
fix="$here/fixtures"
passed=0
failed=0

expect() {
  local name="$1" want_decision="$2"
  shift 2
  local out
  out="$("$script" "$@" 2>/dev/null)"
  local decision
  decision="$(echo "$out" | grep '^Decision:' || true)"
  if [[ "$decision" == "$want_decision" ]]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL $name: want '$want_decision', got '$decision'" >&2
  fi
}

# 1. All gating pass -> Decision: GO
expect "all_pass" "Decision: GO" \
  "$fix/compat-go/probe-ubuntu-latest/probe.json" \
  "$fix/compat-go/probe-ubuntu-22.04/probe.json" \
  "$fix/compat-go/probe-ubuntu-24.04-arm/probe.json"

# 2. P0-SPIKE-05 fails on ubuntu-22.04 -> Decision: GO (observe mode on ubuntu-22.04)
expect "landlock_fail" "Decision: GO (observe mode on ubuntu-22.04)" \
  "$fix/compat-observe/probe-ubuntu-latest/probe.json" \
  "$fix/compat-observe/probe-ubuntu-22.04/probe.json" \
  "$fix/compat-observe/probe-ubuntu-24.04-arm/probe.json"

# 3. P0-SPIKE-09 fails -> Decision: GO (REQ-PROC-001 dropped)
expect "dumpable_fail" "Decision: GO (REQ-PROC-001 dropped)" \
  "$fix/compat-proc/probe-ubuntu-latest/probe.json" \
  "$fix/compat-proc/probe-ubuntu-22.04/probe.json" \
  "$fix/compat-proc/probe-ubuntu-24.04-arm/probe.json"

# 4. P0-SPIKE-03 fails on ubuntu-latest -> Decision: NO-GO
expect "gating_fail" "Decision: NO-GO" \
  "$fix/compat-nogo/probe-ubuntu-latest/probe.json" \
  "$fix/compat-nogo/probe-ubuntu-22.04/probe.json" \
  "$fix/compat-nogo/probe-ubuntu-24.04-arm/probe.json"

if [[ "$failed" -eq 0 ]]; then
  echo "ok $passed/4"
else
  echo "not ok $passed/4" >&2
  exit 1
fi
