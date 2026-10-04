#!/usr/bin/env bash
# Print the status of one runner-probe check.
#
#   spike-result.sh <CHECK> <runner>          read artifacts/spike/probe-<runner>/probe.json
#   spike-result.sh --file <json> <CHECK>     read an explicit file
#
# stdout: "pass" | "fail" | "info: <detail json>" | "not_implemented" | "missing"
# exit:   0 for pass and info, 1 for everything else.
set -euo pipefail

if [[ "${1:-}" == "--file" ]]; then
  file="${2:?usage: spike-result.sh --file <json> <CHECK>}"
  check="${3:?usage: spike-result.sh --file <json> <CHECK>}"
else
  check="${1:?usage: spike-result.sh <CHECK> <runner>}"
  runner="${2:?usage: spike-result.sh <CHECK> <runner>}"
  file="artifacts/spike/probe-${runner}/probe.json"
fi

if [[ ! -f "$file" ]]; then
  echo "missing"
  echo "spike-result: no such file: $file" >&2
  exit 1
fi

status="$(jq -r --arg c "$check" '.checks[$c].status // "missing"' "$file")"
case "$status" in
  pass)
    echo "pass"
    ;;
  info)
    echo "info: $(jq -c --arg c "$check" '.checks[$c].detail' "$file")"
    ;;
  fail | not_implemented | missing)
    echo "$status"
    exit 1
    ;;
  *)
    echo "unknown: $status"
    exit 1
    ;;
esac
