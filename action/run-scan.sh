#!/usr/bin/env bash
set -uo pipefail

target="${INPUT_PATH:-.}"
findings="$GITHUB_WORKSPACE/.reporook/findings.json"
sarif="$GITHUB_WORKSPACE/.reporook/results.sarif"
priorities="$GITHUB_WORKSPACE/.reporook/priorities.json"
args=(scan "$target" --fail-on "${INPUT_FAIL_ON:-high}" --output "$findings" --sarif-output "$sarif")

if [ -n "${INPUT_CONFIG:-}" ]; then
  args+=(--config "$INPUT_CONFIG")
fi
if [ "${INPUT_REQUIRE_SCANNERS:-true}" = "true" ]; then
  args+=(--require-scanners)
fi
if [ "${INPUT_MODE:-diff}" = "diff" ]; then
  base="${INPUT_BASE:-${PR_BASE_SHA:-}}"
  if [ -n "$base" ]; then
    args+=(--changed "$base" --head "${HEAD_SHA:-HEAD}")
  fi
fi

set +e
node "$GITHUB_ACTION_PATH/cli/dist/index.js" "${args[@]}"
exit_code=$?
set -e

case "$exit_code" in
  0|1|2) ;;
  *)
    echo "RepoRook terminated unexpectedly with exit code $exit_code; treating the scan as a tool error." >&2
    exit_code=2
    ;;
esac

{
  echo "exit_code=$exit_code"
  echo "findings_file=$findings"
  echo "sarif_file=$sarif"
  echo "priorities_file=$priorities"
} >> "$GITHUB_OUTPUT"

REPORT_PATH="$findings" node <<'NODE'
const { appendFileSync, readFileSync } = require("node:fs");
let policy = { summary: { actionable: 0, new: 0, suppressed: 0 } };
try { policy = JSON.parse(readFileSync(process.env.REPORT_PATH, "utf8")).policy ?? policy; }
catch { /* The scan exit code already records invalid or missing evidence. */ }
appendFileSync(process.env.GITHUB_OUTPUT, [
  `policy_actionable=${policy.summary?.actionable ?? 0}`,
  `policy_new=${policy.summary?.new ?? 0}`,
  `policy_suppressed=${policy.summary?.suppressed ?? 0}`,
  "",
].join("\n"));
NODE

exit 0
