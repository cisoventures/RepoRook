import { spawnSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const target = resolve(root, "test-fixtures/vulnerable-app");
const cli = resolve(root, "cli/dist/index.js");
const policyDirectory = resolve(target, ".reporook");
const baselinePath = resolve(policyDirectory, "fixture-baseline.json");
const configPath = resolve(policyDirectory, "fixture-policy.json");
const policyReportPath = resolve(policyDirectory, "policy-findings.json");
const prioritiesPath = resolve(policyDirectory, "priorities.json");

const baseline = spawnSync(process.execPath, [
  cli, "baseline", target,
  "--input", ".reporook/findings.json",
  "--output", ".reporook/fixture-baseline.json",
  "--quiet",
], { encoding: "utf8" });
if (baseline.status !== 0) throw new Error(`Could not create fixture baseline: ${baseline.stderr}`);

await writeFile(configPath, `${JSON.stringify({
  failOn: "high",
  baseline: ".reporook/fixture-baseline.json",
  suppressions: ".reporook/fixture-suppressions.json",
  pathPolicies: { "src/**": "medium" },
}, null, 2)}\n`);

const scan = spawnSync(process.execPath, [
  cli, "scan", target,
  "--config", ".reporook/fixture-policy.json",
  "--require-scanners",
  "--output", ".reporook/policy-findings.json",
  "--no-sarif",
  "--quiet",
], { encoding: "utf8" });
if (scan.status !== 0) throw new Error(`A complete scan matching the reviewed baseline must pass, received ${scan.status}: ${scan.stderr}`);

const baselineArtifact = JSON.parse(await readFile(baselinePath, "utf8"));
const report = JSON.parse(await readFile(policyReportPath, "utf8"));
const priorities = JSON.parse(await readFile(prioritiesPath, "utf8"));
if (!baselineArtifact.findings?.length || report.policy?.baseline?.configured !== true) {
  throw new Error("The fixture baseline was not loaded into policy evaluation");
}
if (report.policy.summary.actionable !== 0 || report.policy.summary.existing !== report.summary.total) {
  throw new Error("Reviewed fixture findings were not preserved as non-actionable baseline evidence");
}
if (priorities.priorities?.length) throw new Error("Baselined findings unexpectedly entered the guided-fix queue");
process.stdout.write(`Verified new-findings baseline policy for ${report.summary.total} fixture findings.\n`);
