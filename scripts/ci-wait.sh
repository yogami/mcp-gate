#!/usr/bin/env bash
# Wait for the GitHub Actions run of <workflow.yml> at the current HEAD SHA,
# download its artifacts into artifacts/<workflow-name>/, and exit 0 only if
# the run succeeded.
#
#   scripts/ci-wait.sh spike.yml
set -euo pipefail

wf="${1:?usage: ci-wait.sh <workflow.yml>}"
name="${wf%.yml}"
sha="$(git rev-parse HEAD)"
out="artifacts/${name}"

# The run can take a few seconds to appear after a push.
run_id=""
for _ in $(seq 1 30); do
  run_id="$(gh run list --workflow "$wf" --commit "$sha" --limit 1 \
    --json databaseId --jq '.[0].databaseId // empty')"
  [[ -n "$run_id" ]] && break
  sleep 5
done
if [[ -z "$run_id" ]]; then
  echo "ci-wait: no run of $wf found for $sha (was it pushed?)" >&2
  exit 2
fi

echo "ci-wait: watching run $run_id"
rc=0
gh run watch "$run_id" --exit-status || rc=$?

rm -rf "$out"
mkdir -p "$out"
gh run download "$run_id" --dir "$out" || echo "ci-wait: no artifacts to download" >&2

# Layout the helper expects: artifacts/spike/probe-<runner>/probe.json
exit "$rc"
