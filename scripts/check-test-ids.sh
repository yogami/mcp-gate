#!/usr/bin/env bash
# Traceability checker: verify tests matching SPEC IDs exist in the codebase.
#
#   scripts/check-test-ids.sh [--dir <path>] <ID|RANGE>...
#
# Examples:
#   scripts/check-test-ids.sh P1-ENV-01
#   scripts/check-test-ids.sh P1-ENV-01..13
set -euo pipefail

search_dir="."
if [[ "${1:-}" == "--dir" ]]; then
  search_dir="$2"
  shift 2
fi

if [[ $# -eq 0 ]]; then
  echo "usage: check-test-ids.sh [--dir <path>] <ID|RANGE>..." >&2
  exit 1
fi

expand_arg() {
  local item="$1"
  if [[ "$item" =~ ^([A-Za-z0-9]+-[A-Za-z0-9]+-)([0-9]+)\.\.([0-9]+)$ ]]; then
    local prefix="${BASH_REMATCH[1]}"
    local start="${BASH_REMATCH[2]}"
    local end="${BASH_REMATCH[3]}"
    local width="${#start}"
    local s=$((10#$start))
    local e=$((10#$end))
    for ((i = s; i <= e; i++)); do
      printf "%s%0*d\n" "$prefix" "$width" "$i"
    done
  else
    echo "$item"
  fi
}

ALL_IDS=()
for arg in "$@"; do
  while IFS= read -r id; do
    if [[ -n "$id" ]]; then
      ALL_IDS+=("$id")
    fi
  done < <(expand_arg "$arg")
done

# Search targets
search_paths=()
for sub in "crates" "fixtures" "spikes"; do
  if [[ -d "$search_dir/$sub" ]]; then
    search_paths+=("$search_dir/$sub")
  fi
done
if [[ ${#search_paths[@]} -eq 0 ]]; then
  search_paths=("$search_dir")
fi

missing=()
for id in "${ALL_IDS[@]}"; do
  snake_id="$(echo "$id" | tr '[:upper:]-' '[:lower:]_')"
  # Look for `fn <snake_id>` in rust files
  if ! grep -rqE "fn [a-z0-9_]*${snake_id}" "${search_paths[@]}" 2>/dev/null; then
    echo "missing: $id"
    missing+=("$id")
  fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
  exit 1
fi

exit 0
