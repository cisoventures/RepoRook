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

{
  echo "exit_code=$exit_code"
  echo "findings_file=$findings"
  echo "sarif_file=$sarif"
  echo "priorities_file=$priorities"
} >> "$GITHUB_OUTPUT"

exit 0
