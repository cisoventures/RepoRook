import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { prioritizeViaCli, remediationPlanViaCli, scanViaCli } from "../dist/cli.js";

test("verification can inspect a valid failed-coverage report without calling it a successful scan", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-mcp-incomplete-"));
  await writeFile(join(target, ".reporook.json"), JSON.stringify({
    scanners: { semgrep: false, gitleaks: false, "npm-audit": false, "pip-audit": false },
  }));
  try {
    await assert.rejects(() => scanViaCli(target), /could not complete/);
    const report = await scanViaCli(target, [], { acceptIncompleteReport: true });
    assert.equal(report.coverage_status, "failed");
  } finally {
    await rm(target, { recursive: true, force: true });
  }
});

test("guided-fix MCP helpers return CLI priority and remediation artifacts", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-mcp-guided-"));
  const finding = {
    id: "rr-abcdefabcdef", scanner: "semgrep", rule: "rule.test", severity: "high", file: "app.js", line: 1,
    plain_summary: "A risky operation may be reachable.", description: "Risky operation", remediation_hint: "Use a safe operation.",
    fingerprint: `sha256:${"a".repeat(64)}`, references: [], metadata: { cwe: [], cve: [], package: null, raw_severity: "HIGH" },
  };
  const now = new Date().toISOString();
  const report = {
    schema_version: "1.0", tool: { name: "reporook", version: "0.3.0" }, target: { path: target, commit: null }, generated_at: now,
    coverage_status: "complete", summary: { critical: 0, high: 1, medium: 0, low: 0, total: 1 }, scanners: [], findings: [finding],
    scan_receipt: { target, commit: null, config_hash: "sha256:config", scanner_versions: {}, started_at: now, completed_at: now },
  };
  const reportPath = join(target, ".reporook", "findings.json");
  try {
    await mkdir(join(target, ".reporook"));
    await writeFile(reportPath, JSON.stringify(report));
    const priorities = await prioritizeViaCli(target, reportPath);
    assert.equal(priorities.priorities[0].priority, "fix-now");
    const plan = await remediationPlanViaCli(target, finding.id, reportPath);
    assert.equal(plan.finding.id, finding.id);
    assert.equal(plan.approval.status, "pending");
  } finally {
    await rm(target, { recursive: true, force: true });
  }
});
