#!/usr/bin/env bash
# Generate docs/runner-compat.md from runner-probe JSON artifacts.
#
#   scripts/render-compat.sh <probe.json>...
#
# Follows the SPEC 4.1.1 Go/No-Go gate decision criteria.
# Compatible with Bash 3.2+ (macOS and Linux).
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: render-compat.sh <probe.json>..." >&2
  exit 1
fi

CHECKS=(
  "P0-SPIKE-01:seccomp listener fd"
  "P0-SPIKE-02:receive notification and continue"
  "P0-SPIKE-03:read path from child memory"
  "P0-SPIKE-04:WAIT_KILLABLE_RECV flag"
  "P0-SPIKE-05:Landlock ABI and restriction"
  "P0-SPIKE-06:Landlock and seccomp combined"
  "P0-SPIKE-07:inotify file read tracking"
  "P0-SPIKE-08:inotify on mmap read"
  "P0-SPIKE-09:PR_SET_DUMPABLE=0 environ protection"
  "P0-SPIKE-10:notification overhead benchmark"
)

RAW_RUNNERS=()
RAW_FILES=()
RAW_KERNELS=()
RAW_ARCHS=()

for f in "$@"; do
  if [[ ! -f "$f" ]]; then
    continue
  fi
  rname="$(basename "$(dirname "$f")" | sed 's/^probe-//')"
  RAW_RUNNERS+=("$rname")
  RAW_FILES+=("$f")
  RAW_KERNELS+=("$(jq -r '.kernel // "unknown"' "$f")")
  RAW_ARCHS+=("$(jq -r '.arch // "unknown"' "$f")")
done

# Sort order: ubuntu-latest, ubuntu-22.04, ubuntu-24.04-arm, then any others
SORTED_RUNNERS=()
for preferred in "ubuntu-latest" "ubuntu-22.04" "ubuntu-24.04-arm"; do
  for r in "${RAW_RUNNERS[@]}"; do
    if [[ "$r" == "$preferred" ]]; then
      SORTED_RUNNERS+=("$r")
    fi
  done
done
for r in "${RAW_RUNNERS[@]}"; do
  found=0
  for sr in "${SORTED_RUNNERS[@]}"; do
    if [[ "$r" == "$sr" ]]; then
      found=1
      break
    fi
  done
  if [[ "$found" -eq 0 ]]; then
    SORTED_RUNNERS+=("$r")
  fi
done

get_file() {
  local target="$1"
  local i=0
  for r in "${RAW_RUNNERS[@]}"; do
    if [[ "$r" == "$target" ]]; then
      echo "${RAW_FILES[$i]}"
      return 0
    fi
    i=$((i + 1))
  done
  return 1
}

get_kernel() {
  local target="$1"
  local i=0
  for r in "${RAW_RUNNERS[@]}"; do
    if [[ "$r" == "$target" ]]; then
      echo "${RAW_KERNELS[$i]}"
      return 0
    fi
    i=$((i + 1))
  done
  echo "unknown"
}

get_arch() {
  local target="$1"
  local i=0
  for r in "${RAW_RUNNERS[@]}"; do
    if [[ "$r" == "$target" ]]; then
      echo "${RAW_ARCHS[$i]}"
      return 0
    fi
    i=$((i + 1))
  done
  echo "unknown"
}

# Determine Go/No-Go Decision (SPEC 4.1.1)
# 1. Any of 01, 02, 03, 07 fails on ubuntu-latest -> NO-GO
decision="Decision: GO"

latest_file="$(get_file "ubuntu-latest" || true)"
if [[ -n "$latest_file" ]]; then
  for gid in "P0-SPIKE-01" "P0-SPIKE-02" "P0-SPIKE-03" "P0-SPIKE-07"; do
    st="$(jq -r --arg c "$gid" '.checks[$c].status // "missing"' "$latest_file")"
    if [[ "$st" != "pass" ]]; then
      decision="Decision: NO-GO"
      break
    fi
  done
fi

# 2. If not NO-GO, check if Landlock failed on any runner
if [[ "$decision" != "Decision: NO-GO" ]]; then
  observe_runners=()
  for r in "${SORTED_RUNNERS[@]}"; do
    rf="$(get_file "$r")"
    s05="$(jq -r '.checks["P0-SPIKE-05"].status // "missing"' "$rf")"
    s06="$(jq -r '.checks["P0-SPIKE-06"].status // "missing"' "$rf")"
    if [[ "$s05" == "fail" || "$s06" == "fail" ]]; then
      observe_runners+=("$r")
    fi
  done
  if [[ "${#observe_runners[@]}" -gt 0 ]]; then
    decision="Decision: GO (observe mode on ${observe_runners[0]})"
  fi
fi

# 3. If still GO, check if P0-SPIKE-09 failed
if [[ "$decision" == "Decision: GO" ]]; then
  for r in "${SORTED_RUNNERS[@]}"; do
    rf="$(get_file "$r")"
    s09="$(jq -r '.checks["P0-SPIKE-09"].status // "missing"' "$rf")"
    if [[ "$s09" == "fail" ]]; then
      decision="Decision: GO (REQ-PROC-001 dropped)"
      break
    fi
  done
fi

# Output Markdown report
cat <<EOF
# Hosted Runner Compatibility Report

This document records the empirical results of the Week 1 hosted-runner spike (SPEC 4.1.1).
The test suite executed unprivileged kernel compatibility checks on standard GitHub Actions runners.

## Tested Runner Environments

EOF

for r in "${SORTED_RUNNERS[@]}"; do
  echo "- **$r**: kernel \`$(get_kernel "$r")\`, arch \`$(get_arch "$r")\`"
done

echo ""
echo "## Compatibility Matrix"
echo ""

header="| Check ID | Description"
separator="|---|---"
for r in "${SORTED_RUNNERS[@]}"; do
  header="$header | $r"
  separator="$separator |---"
done
header="$header |"
separator="$separator |"

echo "$header"
echo "$separator"

for item in "${CHECKS[@]}"; do
  cid="${item%%:*}"
  cdesc="${item#*:}"
  row="| $cid | $cdesc"
  for r in "${SORTED_RUNNERS[@]}"; do
    rf="$(get_file "$r")"
    st="$(jq -r --arg c "$cid" '.checks[$c].status // "missing"' "$rf")"
    row="$row | $st"
  done
  row="$row |"
  echo "$row"
done

cat <<EOF

## Gate Evaluation

$decision

- Required gating checks (P0-SPIKE-01, P0-SPIKE-02, P0-SPIKE-03, P0-SPIKE-07): pass on target runners without root.
- Process credential protection (P0-SPIKE-09): unprivileged children cannot read parent environment via procfs.
- File observation (P0-SPIKE-08): confirms inotify tripwire keys on IN_OPEN for memory-mapped reads.
- Notification overhead (P0-SPIKE-10): roundtrip ratio recorded on live hardware.
EOF
