#!/usr/bin/env bash
# Red test for scripts/spike-result.sh (TASK-0.2). Prints "ok 4/4" on success.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/../spike-result.sh"
fix="$here/fixtures"
passed=0
failed=0

# expect <name> <expected stdout prefix> <expected exit> <args...>
expect() {
  local name="$1" want_out="$2" want_rc="$3"
  shift 3
  local out rc
  out="$("$script" "$@" 2>/dev/null)"
  rc=$?
  if [[ "$out" == "$want_out"* && "$rc" -eq "$want_rc" ]]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL $name: want '${want_out}*' rc=$want_rc, got '$out' rc=$rc" >&2
  fi
}

expect pass         "pass"            0 --file "$fix/probe-pass.json"    P0-SPIKE-01
expect fail         "fail"            1 --file "$fix/probe-fail.json"    P0-SPIKE-01
expect info         "info: "          0 --file "$fix/probe-info.json"    P0-SPIKE-01
expect not_impl     "not_implemented" 1 --file "$fix/probe-notimpl.json" P0-SPIKE-01

if [[ "$failed" -eq 0 ]]; then
  echo "ok $passed/4"
else
  echo "not ok $passed/4" >&2
  exit 1
fi
