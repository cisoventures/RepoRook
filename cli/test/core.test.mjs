import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseSimpleYaml, defaultConfig, normalizeConfig } from "../dist/config.js";
import { artifactPath, writeArtifacts } from "../dist/artifacts.js";
import { scanExitCode, scanRepository } from "../dist/engine.js";
import { renderAgentPrompt, renderTerminal } from "../dist/render.js";
import { toSarif } from "../dist/sarif.js";
import { gitChangedFiles } from "../dist/git.js";
import { plainSummary } from "../dist/knowledge.js";
import { matchesAny } from "../dist/path-utils.js";

test("simple YAML parser supports lists and scanner flags", () => {
  const parsed = parseSimpleYaml("failOn: medium\nignore:\n  - vendor/**\nscanners:\n  semgrep: false\n");
  assert.equal(parsed.failOn, "medium");
  assert.deepEqual(parsed.ignore, ["vendor/**"]);
  assert.deepEqual(parsed.scanners, { semgrep: false });
  assert.equal(normalizeConfig(parsed).scanners.semgrep, false);
});

test("configuration rejects values that can silently weaken coverage", () => {
  assert.throws(() => normalizeConfig({ requiredScanners: "semgrep" }), /list of non-empty strings/);
  assert.throws(() => normalizeConfig({ requiredScanners: ["semgrpe"] }), /Unknown required scanner/);
  assert.throws(() => normalizeConfig({ requiredScanners: ["semgrep"], scanners: { semgrep: false } }), /required and disabled/);
  assert.throws(() => normalizeConfig({ scanners: { gitleaks: "no" } }), /must be true or false/);
  assert.equal(normalizeConfig({ scanners: { "osv-scanner": true } }).scanners["osv-scanner"], true);
  assert.throws(() => normalizeConfig({ requireScanners: ["gitleaks"] }), /Unknown RepoRook configuration key/);
  assert.throws(() => normalizeConfig(parseSimpleYaml("paths: [false]\n")), /list of non-empty strings/);
  assert.throws(() => parseSimpleYaml("failOn: high\nfailOn: low\n"), /Duplicate configuration key/);
});

test("default configuration disables Semgrep telemetry while selecting explicit rules", () => {
  assert.equal(defaultConfig.semgrepConfig, "p/default");
});

test("artifact paths stay in the worktree while supporting monorepo scan targets", async () => {
  const root = await mkdtemp(join(tmpdir(), "reporook-artifact-root-"));
  const target = join(root, "packages", "app");
  try {
    await mkdir(join(root, ".git"));
    await mkdir(target, { recursive: true });
    assert.equal(artifactPath(target, "../../.reporook/findings.json"), join(root, ".reporook", "findings.json"));
    assert.throws(() => artifactPath(target, "../../../outside.json"), /outside the repository/);
  } finally {
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("engine deduplicates findings and produces SARIF", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-test-"));
  assert.throws(() => artifactPath(target, "../outside.json"), /outside the repository/);
  const finding = {
    id: "rr-aaaaaaaaaaaa", scanner: "fake", rule: "fake.rule", severity: "high", file: "src/app.js", line: 1, end_line: 2,
    plain_summary: "An unsafe operation can be reached.", description: "Unsafe operation", remediation_hint: "Use a safe operation", fingerprint: `sha256:${"a".repeat(64)}`,
    references: [], metadata: { cwe: ["CWE-1"], cve: [], package: null, raw_severity: "HIGH" },
  };
  const scanner = {
    name: "fake",
    async isApplicable() { return { applicable: true }; },
    async run() { return { status: { name: "fake", applicable: true, available: true, version: "1", status: "ok", finding_count: 2, duration_ms: 1 }, findings: [finding, finding] }; },
  };
  try {
    const report = await scanRepository({ target, config: structuredClone(defaultConfig) }, [scanner]);
    assert.equal(report.coverage_status, "complete");
    assert.equal(report.findings.length, 1);
    const sarif = toSarif(report);
    assert.equal(sarif.runs[0].results.length, 1);
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.endLine, 2);
    assert.equal("end_line" in sarif.runs[0].results[0].locations[0].physicalLocation.region, false);
    const artifacts = await writeArtifacts(target, report, { writeSarif: false });
    const prompt = await readFile(artifacts.promptPath, "utf8");
    assert.match(prompt, /Do not edit files until I approve that exact change/);
    if (process.platform !== "win32") assert.equal((await stat(artifacts.promptPath)).mode & 0o777, 0o600);
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("plain explanations do not confuse hardcoded regex advice with a leaked secret", () => {
  const summary = plainSummary({ scanner: "semgrep", rule: "javascript.lang.security.audit.detect-non-literal-regexp", description: "Prefer hardcoded regexes." });
  assert.match(summary, /regular expression|CPU time/);
  assert.doesNotMatch(summary, /API key|token|password/);
});

test("glob matching is bounded and preserves recursive wildcard behavior", () => {
  assert.equal(matchesAny("src/nested/app.ts", ["src/**"]), true);
  assert.equal(matchesAny("src/nested/app.ts", ["**/*.ts"]), true);
  assert.equal(matchesAny("src/nested/app.js", ["**/*.ts"]), false);
  assert.equal(matchesAny("src/[id].ts", ["src/[id].ts"]), true);
  assert.equal(matchesAny("src/xid.ts", ["src/[id].ts"]), false);
  assert.equal(matchesAny("a".repeat(2_048), [`${"*".repeat(2_048)}b`]), false);
});

test("failed coverage exits 2 unless the user explicitly allows no coverage", () => {
  const report = {
    schema_version: "1.0", tool: { name: "reporook", version: "0.1.0" }, target: { path: ".", commit: null }, generated_at: new Date().toISOString(),
    coverage_status: "failed", summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 }, scanners: [], findings: [],
    scan_receipt: { target: ".", commit: null, config_hash: "sha256:x", scanner_versions: {}, started_at: new Date().toISOString(), completed_at: new Date().toISOString() },
  };
  assert.equal(scanExitCode(report, "high", [], false, false), 2);
  assert.equal(scanExitCode(report, "high", [], false, true), 0);
});

test("terminal output groups dependency advisories and uses plain English", () => {
  const base = {
    id: "rr-bbbbbbbbbbbb", fingerprint: `sha256:${"b".repeat(64)}`, scanner: "pip-audit", rule: "pip-audit:CVE-1", severity: "high", file: "requirements.txt", line: 1,
    plain_summary: "The urllib3 package has a known flaw.", description: "Long advisory one", remediation_hint: "Upgrade urllib3.", references: [],
    metadata: { cwe: [], cve: ["CVE-1"], package: "urllib3", raw_severity: null },
  };
  const report = {
    schema_version: "1.0", tool: { name: "reporook", version: "0.1.0" }, target: { path: ".", commit: null }, generated_at: new Date().toISOString(), coverage_status: "complete",
    summary: { critical: 0, high: 2, medium: 0, low: 0, total: 2 }, scanners: [],
    findings: [base, { ...base, id: "rr-cccccccccccc", fingerprint: `sha256:${"c".repeat(64)}`, rule: "pip-audit:CVE-2", description: "Long advisory two" }],
    scan_receipt: { target: ".", commit: null, config_hash: "sha256:x", scanner_versions: {}, started_at: new Date().toISOString(), completed_at: new Date().toISOString() },
  };
  const output = renderTerminal(report);
  assert.match(output, /urllib3 — 2 known advisories/);
  assert.match(output, /What this means: The urllib3 package has a known flaw/);
  assert.equal((output.match(/Next step:/g) ?? []).length, 1);
  const prompt = renderAgentPrompt(report);
  assert.match(prompt, /Do not edit files until I approve that exact change/);
  assert.match(prompt, /reporook verify rr-bbbbbbbbbbbb \./);
  assert.match(prompt, /incomplete coverage as inconclusive/);
});

test("changed-file scans treat revisions as revisions, not Git options", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-git-ref-test-"));
  try {
    execFileSync("git", ["init", "--quiet"], { cwd: target });
    execFileSync("git", ["config", "user.email", "reporook@example.test"], { cwd: target });
    execFileSync("git", ["config", "user.name", "RepoRook Test"], { cwd: target });
    await writeFile(join(target, "README.md"), "test\n");
    execFileSync("git", ["add", "README.md"], { cwd: target });
    execFileSync("git", ["commit", "--quiet", "-m", "fixture"], { cwd: target });
    await assert.rejects(() => gitChangedFiles(target, "--help", "HEAD"), /Invalid Git revision/);
    await assert.rejects(() => gitChangedFiles(target, "HEAD\n--output=oops", "HEAD"), /single non-empty value/);
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});
