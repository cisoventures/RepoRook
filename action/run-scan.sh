#!/usr/bin/env bash
set -uo pipefail

target="${INPUT_PATH:-.}"
findings="$GITHUB_WORKSPACE/.reporook/findings.json"
sarif="$GITHUB_WORKSPACE/.reporook/results.sarif"
priorities="$GITHUB_WORKSPACE/.reporook/priorities.json"
args=(scan "$target" --fail-on "${INPUT_FAIL_ON:-high}" --output "$findings" --sarif-output "$sarif")

# Never let a failed invocation reuse evidence left by an earlier scan in the
# workspace. These are the only files this Action owns.
rm -f -- "$findings" "$sarif" "$priorities"

if [ -n "${INPUT_CONFIG:-}" ]; then
  args+=(--config "$INPUT_CONFIG")
fi
if [ -n "${INPUT_SEMGREP_CONFIG:-}" ]; then
  args+=(--semgrep-config "$INPUT_SEMGREP_CONFIG")
fi
if [ "${INPUT_REQUIRE_SCANNERS:-true}" = "true" ]; then
  args+=(--require-scanners)
fi
if [ "${INPUT_ALLOW_EXTERNAL_TARGETS:-false}" = "true" ]; then
  args+=(--allow-external-targets)
fi
if [ "${INPUT_ALLOW_REPOSITORY_SUPPRESSIONS:-false}" = "true" ]; then
  args+=(--allow-repository-suppressions)
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

REPORT_PATH="$findings" OUTPUT_EXIT_CODE="$exit_code" OUTPUT_FINDINGS="$findings" OUTPUT_SARIF="$sarif" OUTPUT_PRIORITIES="$priorities" node <<'NODE'
const { randomBytes } = require("node:crypto");
const { appendFileSync, readFileSync } = require("node:fs");
let policy = { summary: { actionable: 0, new: 0, suppressed: 0 } };
try { policy = JSON.parse(readFileSync(process.env.REPORT_PATH, "utf8")).policy ?? policy; }
catch { /* The scan exit code already records invalid or missing evidence. */ }
const count = (value) => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const output = (name, value) => {
  const delimiter = `reporook_${randomBytes(16).toString("hex")}`;
  return `${name}<<${delimiter}\n${String(value)}\n${delimiter}\n`;
};
appendFileSync(process.env.GITHUB_OUTPUT,
  output("exit_code", process.env.OUTPUT_EXIT_CODE)
  + output("findings_file", process.env.OUTPUT_FINDINGS)
  + output("sarif_file", process.env.OUTPUT_SARIF)
  + output("priorities_file", process.env.OUTPUT_PRIORITIES)
  + output("policy_actionable", count(policy.summary?.actionable))
  + output("policy_new", count(policy.summary?.new))
  + output("policy_suppressed", count(policy.summary?.suppressed)));
NODE

exit 0
