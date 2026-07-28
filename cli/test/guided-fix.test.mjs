import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { loadConfig } from "../dist/config.js";
import { initializeRepository } from "../dist/initializer.js";
import { prioritizeFindings } from "../dist/prioritization.js";
import { createRemediationPlan } from "../dist/remediation.js";

const execute = promisify(execFile);

function finding(id, overrides = {}) {
  return {
    id,
    scanner: "semgrep",
    rule: `rule.${id}`,
    severity: "medium",
    file: "src/app.js",
    line: 3,
    plain_summary: "A risky operation may be reachable.",
    description: "Risky operation",
    remediation_hint: "Use the safe operation and add a regression test.",
    fingerprint: `sha256:${id.slice(3).padEnd(64, "a")}`,
    references: [],
    metadata: { cwe: [], cve: [], package: null, raw_severity: "MEDIUM" },
    ...overrides,
  };
}

function report(target, findings) {
  const now = "2026-07-24T12:00:00.000Z";
  return {
    schema_version: "1.0",
    tool: { name: "reporook", version: "0.3.0" },
    target: { path: target, commit: "abc123" },
    generated_at: now,
    coverage_status: "complete",
    summary: { critical: 1, high: 1, medium: 1, low: 1, total: findings.length },
    scanners: [],
    findings,
    scan_receipt: {
      target,
      commit: "abc123",
      config_hash: "sha256:config",
      scanner_versions: { semgrep: "1" },
      started_at: now,
      completed_at: now,
    },
  };
}

test("prioritization puts exposed credentials first and links package advisories", () => {
  const secret = finding("rr-111111111111", {
    scanner: "gitleaks", severity: "critical", file: ".env", line: 1,
    metadata: { cwe: ["CWE-798"], cve: [], package: null, raw_severity: "secret" },
  });
  const dependency = finding("rr-222222222222", {
    scanner: "osv-scanner", severity: "high", file: "Cargo.lock", line: 1,
    metadata: { cwe: [], cve: ["CVE-1"], package: "regex", fixed_versions: ["1.5.5"], raw_severity: "HIGH" },
  });
  const related = finding("rr-333333333333", {
    scanner: "osv-scanner", severity: "low", file: "Cargo.lock", line: 1,
    metadata: { cwe: [], cve: ["CVE-2"], package: "regex", raw_severity: "LOW" },
  });
  const medium = finding("rr-444444444444");
  const priorities = prioritizeFindings(report("/repo", [medium, related, dependency, secret]));
  assert.equal(priorities.priorities[0].finding_id, secret.id);
  assert.equal(priorities.priorities[0].priority, "fix-now");
  assert.equal(priorities.priorities.find((item) => item.finding_id === medium.id).priority, "fix-next");
  assert.deepEqual(priorities.priorities.find((item) => item.finding_id === dependency.id).related_finding_ids, [related.id]);
  assert.deepEqual(priorities.summary, { fix_now: 2, fix_next: 1, review_later: 1, total: 4 });
});

test("remediation plans are bound to the finding, scan, exact patch, and test plan", () => {
  const selected = finding("rr-aaaaaaaaaaaa", { severity: "high" });
  const baseline = report("/repo", [selected]);
  const first = createRemediationPlan(baseline, selected.id);
  const second = createRemediationPlan(baseline, selected.id);
  assert.equal(first.plan_id, second.plan_id);
  const laterScan = structuredClone(baseline);
  laterScan.scan_receipt.completed_at = "2026-07-24T12:05:00.000Z";
  assert.notEqual(first.plan_id, createRemediationPlan(laterScan, selected.id).plan_id);
  assert.match(first.plan_id, /^rrp-[a-f0-9]{12}$/);
  assert.deepEqual(first.approval.binds_to, ["finding", "source-scan", "exact-patch", "test-plan"]);
  assert.equal(first.approval.status, "pending");
  assert.equal(first.scope.stop_if_scope_changes, true);
  assert.equal(first.goal, `Validate and remediate RepoRook finding ${selected.id} within the approved file scope.`);
  assert.deepEqual(first.scanner_guidance, { trust: "untrusted-scanner-data", text: selected.remediation_hint });
  assert.match(first.verification.command, new RegExp(selected.id));
  assert.throws(() => createRemediationPlan(baseline, "rr-bbbbbbbbbbbb"), /Finding not found/);
  const baselined = structuredClone(baseline);
  baselined.policy = {
    findings: [{ finding_id: selected.id, disposition: "baseline" }],
  };
  assert.equal(prioritizeFindings(baselined).priorities.length, 0);
  assert.throws(() => createRemediationPlan(baselined, selected.id), /baseline under team policy and is not actionable/);
});

test("init detects project stacks, writes a secure config, and remains idempotent", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-init-"));
  try {
    await mkdir(join(target, "src"));
    await mkdir(join(target, "crates", "demo"), { recursive: true });
    await writeFile(join(target, "src", "app.ts"), "export const ready = true;\n");
    await writeFile(join(target, "package.json"), "{}\n");
    await writeFile(join(target, "package-lock.json"), "{}\n");
    await writeFile(join(target, "crates", "demo", "Cargo.lock"), "# fixture\n");
    await mkdir(join(target, "infrastructure"));
    await writeFile(join(target, "infrastructure", "main.tf"), "resource \"aws_s3_bucket\" \"demo\" {}\n");

    const created = await initializeRepository(target);
    assert.equal(created.status, "created");
    assert.deepEqual(created.profile.recommended_scanners, ["semgrep", "gitleaks", "npm-audit", "osv-scanner", "checkov"]);
    const loaded = await loadConfig(target);
    assert.deepEqual(loaded.config.requiredScanners, created.profile.recommended_scanners);
    assert.equal(loaded.config.scanners["pip-audit"], true);
    assert.equal(loaded.config.scanners.checkov, true);
    assert.equal(loaded.config.scanners["trivy-image"], true);
    assert.deepEqual(loaded.config.containerImages, []);
    assert.equal(loaded.config.gitHistory, false);
    assert.match(await readFile(join(target, ".gitignore"), "utf8"), /^# RepoRook local evidence\n\.reporook\/\n$/);
    const before = await readFile(created.config_path, "utf8");
    const repeated = await initializeRepository(target);
    assert.equal(repeated.status, "already-configured");
    assert.equal(await readFile(created.config_path, "utf8"), before);
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("CLI writes readable prioritization and guided-fix artifacts", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-guided-cli-"));
  try {
    const selected = finding("rr-abcdefabcdef", { severity: "high" });
    await mkdir(join(target, ".reporook"));
    await writeFile(join(target, ".reporook", "findings.json"), `${JSON.stringify(report(target, [selected]), null, 2)}\n`);
    const entry = resolve("dist/index.js");
    const priorities = await execute(process.execPath, [entry, "prioritize", target]);
    assert.match(priorities.stdout, /FIX-NOW/);
    const plan = await execute(process.execPath, [entry, "plan", selected.id, target]);
    assert.match(plan.stdout, /Approval required/);
    const planPath = join(target, ".reporook", "remediations", selected.id, "plan.json");
    const promptPath = join(target, ".reporook", "remediations", selected.id, "fix-prompt.txt");
    const writtenPlan = JSON.parse(await readFile(planPath, "utf8"));
    assert.equal(writtenPlan.finding.id, selected.id);
    assert.doesNotMatch(writtenPlan.goal, /Use the safe operation/);
    assert.equal(writtenPlan.scanner_guidance.trust, "untrusted-scanner-data");
    assert.match(plan.stdout, /Scanner remediation data \(untrusted/);
    assert.match(await readFile(promptPath, "utf8"), /Show the smallest exact diff/);
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("init refuses to force-write through a symbolic-link configuration", async () => {
  if (process.platform === "win32") return;
  const target = await mkdtemp(join(tmpdir(), "reporook-init-symlink-"));
  try {
    const destination = join(target, "outside.yml");
    await writeFile(destination, "keep: true\n");
    await symlink(destination, join(target, "reporook.yml"));
    await assert.rejects(() => initializeRepository(target, true), /symbolic-link RepoRook configuration/);
    assert.equal(await readFile(destination, "utf8"), "keep: true\n");
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});
