import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { defaultConfig, loadConfig, normalizeConfig, parseOrganizationPolicy, parseSimpleYaml } from "../dist/config.js";
import { scanExitCode } from "../dist/engine.js";
import {
  createFindingBaseline,
  createFindingSuppression,
  evaluatePolicy,
  parseFindingBaseline,
  parseSuppressionFile,
} from "../dist/policy.js";

const execute = promisify(execFile);

function finding(id, overrides = {}) {
  return {
    id,
    scanner: "semgrep",
    rule: `rule.${id}`,
    severity: "high",
    file: "src/app.ts",
    line: 1,
    plain_summary: "A risky operation may be reachable.",
    description: "Risky operation",
    remediation_hint: "Use a safe operation.",
    fingerprint: `sha256:${id.slice(3).padEnd(64, "a")}`,
    references: [],
    metadata: { cwe: [], cve: [], package: null, raw_severity: "HIGH" },
    ...overrides,
  };
}

function report(target, findings, policy) {
  const generatedAt = "2026-07-24T12:00:00.000Z";
  return {
    schema_version: "1.0",
    tool: { name: "reporook", version: "0.5.0" },
    target: { path: target, commit: "abc123" },
    generated_at: generatedAt,
    coverage_status: "complete",
    summary: {
      critical: findings.filter((item) => item.severity === "critical").length,
      high: findings.filter((item) => item.severity === "high").length,
      medium: findings.filter((item) => item.severity === "medium").length,
      low: findings.filter((item) => item.severity === "low").length,
      total: findings.length,
    },
    scanners: [],
    findings,
    ...(policy ? { policy } : {}),
    scan_receipt: {
      target,
      commit: "abc123",
      config_hash: "sha256:config",
      scanner_versions: { semgrep: "1" },
      started_at: generatedAt,
      completed_at: generatedAt,
    },
  };
}

test("configuration accepts deterministic path-specific thresholds", () => {
  const parsed = parseSimpleYaml("pathPolicies:\n  src/auth/**: low\n  src/admin/**: medium\n");
  assert.deepEqual(normalizeConfig(parsed).pathPolicies, { "src/admin/**": "medium", "src/auth/**": "low" });
  assert.throws(() => normalizeConfig({ pathPolicies: { "src/**": "urgent-ish" } }), /Invalid path policy severity/);
  assert.throws(() => normalizeConfig({ failOn: "medium", pathPolicies: { "src/**": "high" } }), /cannot weaken the global/);
  assert.throws(() => normalizeConfig({ baseline: ["wrong"] }), /baseline must be a non-empty string/);
});

test("organization policy is hash-bound and local configuration may tighten but not weaken it", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-organization-policy-"));
  const policyPath = join(target, "policy", "security.yml");
  try {
    await Promise.all([mkdir(join(target, ".git")), mkdir(join(target, "policy"))]);
    await writeFile(policyPath, [
      "schemaVersion: \"1.0\"",
      "name: CISO Ventures baseline",
      "failOn: high",
      "requiredScanners:",
      "  - gitleaks",
      "pathPolicies:",
      "  src/auth/**: low",
      "",
    ].join("\n"));
    await writeFile(join(target, "reporook.yml"), [
      "organizationPolicy: policy/security.yml",
      "failOn: high",
      "requiredScanners:",
      "  - semgrep",
      "scanners:",
      "  gitleaks: true",
      "",
    ].join("\n"));
    const first = await loadConfig(target);
    assert.deepEqual(first.config.requiredScanners, ["semgrep", "gitleaks"]);
    assert.deepEqual(first.config.pathPolicies, { "src/auth/**": "low" });
    assert.equal(first.config.organizationPolicy.name, "CISO Ventures baseline");
    assert.match(first.config.organizationPolicy.hash, /^sha256:[a-f0-9]{64}$/);
    const policy = await evaluatePolicy(target, [finding("rr-777777777777", { severity: "medium", file: "src/auth/session.ts" })], first.config);
    assert.equal(policy.organization_policy.name, "CISO Ventures baseline");
    assert.equal(policy.findings[0].disposition, "actionable");

    await writeFile(policyPath, `${await readFile(policyPath, "utf8")}# reviewed\n`);
    const changed = await loadConfig(target);
    assert.notEqual(changed.hash, first.hash);
    assert.notEqual(changed.config.organizationPolicy.hash, first.config.organizationPolicy.hash);

    await writeFile(join(target, "reporook.yml"), "organizationPolicy: policy/security.yml\nfailOn: critical\n");
    await assert.rejects(loadConfig(target), /weaker than organization policy/);
    await writeFile(join(target, "reporook.yml"), "organizationPolicy: policy/security.yml\nfailOn: high\nscanners:\n  gitleaks: false\n");
    await assert.rejects(loadConfig(target), /required by organization policy/);
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("organization policy parsing and paths fail closed", async () => {
  assert.throws(() => parseOrganizationPolicy({ schemaVersion: "1.0", name: "test", failOn: "high", requiredScanners: [], pathPolicies: {}, typo: true }), /unknown field/);
  assert.throws(() => parseOrganizationPolicy({ schemaVersion: "1.0", name: "test", failOn: "high", requiredScanners: ["gitleaks", "gitleaks"], pathPolicies: {} }), /must not contain duplicates/);
  assert.throws(() => parseOrganizationPolicy({ schemaVersion: "1.0", name: "test", failOn: "low", requiredScanners: [], pathPolicies: { "src/**": "high" } }), /cannot weaken/);
  const target = await mkdtemp(join(tmpdir(), "reporook-organization-path-"));
  const outside = join(tmpdir(), `reporook-outside-policy-${process.pid}.yml`);
  try {
    await mkdir(join(target, ".git"));
    await writeFile(outside, "schemaVersion: \"1.0\"\nname: outside\nfailOn: high\nrequiredScanners: []\npathPolicies:\n");
    await writeFile(join(target, "reporook.yml"), `organizationPolicy: ../${outside.split("/").at(-1)}\n`);
    await assert.rejects(loadConfig(target), /inside the repository/);
    if (process.platform !== "win32") {
      await symlink(outside, join(target, "linked-policy.yml"));
      await writeFile(join(target, "reporook.yml"), "organizationPolicy: linked-policy.yml\n");
      await assert.rejects(loadConfig(target), /symbolic link/);
    }
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    await rm(outside, { force: true });
  }
});

test("configuration files fail closed on missing, outside, linked, non-file, and oversized paths", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-configuration-path-"));
  const outside = join(tmpdir(), `reporook-outside-config-${process.pid}.yml`);
  try {
    await mkdir(join(target, ".git"));
    await assert.rejects(loadConfig(target, "missing.yml"), /does not exist/);
    await writeFile(outside, "failOn: low\n");
    await assert.rejects(loadConfig(target, `../${outside.split("/").at(-1)}`), /inside the repository/);
    await mkdir(join(target, "directory.yml"));
    await assert.rejects(loadConfig(target, "directory.yml"), /regular file/);
    await writeFile(join(target, "oversized.yml"), `#${"x".repeat(1024 * 1024)}\n`);
    await assert.rejects(loadConfig(target, "oversized.yml"), /exceeds 1 MiB/);
    if (process.platform !== "win32") {
      await symlink(outside, join(target, "linked.yml"));
      await assert.rejects(loadConfig(target, "linked.yml"), /symbolic link/);
    }
    await writeFile(join(target, "safe.yml"), "failOn: low\n");
    assert.equal((await loadConfig(target, "safe.yml")).config.failOn, "low");
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    await rm(outside, { force: true });
  }
});

test("policy evaluation separates new, baseline, suppressed, expired, and below-threshold findings", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-policy-"));
  const now = new Date("2026-07-24T12:00:00.000Z");
  const existing = finding("rr-111111111111");
  const pathActionable = finding("rr-222222222222", { severity: "medium", file: "src/auth/session.ts" });
  const suppressed = finding("rr-333333333333", { severity: "critical" });
  const belowThreshold = finding("rr-444444444444", { severity: "medium", file: "docs/example.ts" });
  const expired = finding("rr-555555555555", { severity: "high" });
  try {
    const baseline = createFindingBaseline(report(target, [existing]), now);
    await writeFile(join(target, "reporook-baseline.json"), `${JSON.stringify(baseline, null, 2)}\n`);
    const activeSuppression = createFindingSuppression(report(target, [suppressed]), suppressed.id, "security-team", "Accepted until the replacement lands.", "2026-08-01", now);
    const expiredSuppression = {
      ...createFindingSuppression(report(target, [expired]), expired.id, "platform-team", "Legacy path scheduled for removal.", "2026-07-25", new Date("2026-07-20T12:00:00.000Z")),
      expires_at: "2026-07-23T23:59:59.999Z",
    };
    await writeFile(join(target, "reporook-suppressions.json"), `${JSON.stringify({ schema_version: "1.0", suppressions: [activeSuppression, expiredSuppression] }, null, 2)}\n`);
    const config = {
      ...structuredClone(defaultConfig),
      failOn: "high",
      pathPolicies: { "src/auth/**": "low" },
    };
    const policy = await evaluatePolicy(target, [existing, pathActionable, suppressed, belowThreshold, expired], config, now);
    assert.deepEqual(policy.summary, {
      new: 4,
      existing: 1,
      actionable: 2,
      below_threshold: 1,
      suppressed: 1,
      expired_suppressions: 1,
    });
    assert.equal(policy.findings.find((item) => item.finding_id === existing.id).disposition, "baseline");
    assert.equal(policy.findings.find((item) => item.finding_id === pathActionable.id).matched_path_policy, "src/auth/**");
    assert.equal(policy.findings.find((item) => item.finding_id === suppressed.id).suppression.owner, "security-team");
    assert.equal(policy.findings.find((item) => item.finding_id === expired.id).expired_suppression.owner, "platform-team");
    assert.equal(scanExitCode(report(target, [existing, pathActionable, suppressed, belowThreshold, expired], policy), "high", [], false, false), 1);
    const noBlockers = structuredClone(policy);
    noBlockers.summary.actionable = 0;
    assert.equal(scanExitCode(report(target, [existing], noBlockers), "high", [], false, false), 0);
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("suppression files require durable ownership, reasons, and expirations", () => {
  assert.throws(() => parseSuppressionFile({
    schema_version: "1.0",
    suppressions: [{ id: "rrs-111111111111", finding_id: "rr-111111111111", reason: "temporary", expires_at: "2026-08-01", created_at: "2026-07-24" }],
  }), /owner must be a non-empty string/);
  assert.throws(() => parseSuppressionFile({ schema_version: "1.0", suppressions: [], typo: true }), /unknown field/);
});

test("baseline parsing rejects malformed IDs, fingerprints, and unknown nested fields", () => {
  const baseline = createFindingBaseline(report("/repo", [finding("rr-111111111111")]), new Date("2026-07-24T12:00:00.000Z"));
  assert.throws(
    () => createFindingBaseline({ ...report("/repo", []), coverage_status: "partial" }),
    /incomplete scanner coverage/,
  );
  assert.throws(() => parseFindingBaseline({ ...baseline, source: { ...baseline.source, typo: true } }), /unknown field/);
  assert.throws(() => parseFindingBaseline({
    ...baseline,
    findings: [{ ...baseline.findings[0], finding_id: "not-a-finding" }],
  }), /finding_id is invalid/);
  assert.throws(() => parseFindingBaseline({
    ...baseline,
    findings: [{ ...baseline.findings[0], fingerprint: "sha256:short" }],
  }), /fingerprint is invalid/);
});

test("nested scans can use repository-root policy files but cannot escape the repository", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-policy-root-"));
  const nested = join(target, "packages", "app");
  const selected = finding("rr-666666666666");
  try {
    await mkdir(join(target, ".git"));
    await mkdir(nested, { recursive: true });
    const baseline = createFindingBaseline(report(target, [selected]), new Date("2026-07-24T12:00:00.000Z"));
    await writeFile(join(target, "reporook-baseline.json"), `${JSON.stringify(baseline, null, 2)}\n`);
    const config = {
      ...structuredClone(defaultConfig),
      baselineFile: "../../reporook-baseline.json",
    };
    const policy = await evaluatePolicy(nested, [selected], config, new Date("2026-07-24T12:00:00.000Z"));
    assert.equal(policy.findings[0].baseline, "existing");
    await assert.rejects(
      evaluatePolicy(nested, [selected], { ...config, baselineFile: "../../../outside.json" }),
      /outside the repository/,
    );
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("CLI creates reviewable baseline and suppression artifacts", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-policy-cli-"));
  const selected = finding("rr-abcdefabcdef");
  try {
    await mkdir(join(target, ".reporook"));
    const completeReport = report(target, [selected]);
    await writeFile(join(target, ".reporook", "findings.json"), `${JSON.stringify({ ...completeReport, coverage_status: "partial" }, null, 2)}\n`);
    const entry = resolve("dist/index.js");
    await assert.rejects(
      execute(process.execPath, [entry, "baseline", target]),
      (error) => {
        assert.match(error.stderr, /Refusing to create a baseline from incomplete scanner coverage/);
        return true;
      },
    );
    await writeFile(join(target, ".reporook", "findings.json"), `${JSON.stringify(completeReport, null, 2)}\n`);
    const baseline = await execute(process.execPath, [entry, "baseline", target]);
    assert.match(baseline.stdout, /baseline created/i);
    const baselineFile = JSON.parse(await readFile(join(target, "reporook-baseline.json"), "utf8"));
    assert.equal(baselineFile.findings[0].finding_id, selected.id);
    const suppression = await execute(process.execPath, [
      entry, "suppress", selected.id, target,
      "--owner", "security-team",
      "--reason", "Accepted during a bounded migration.",
      "--expires", "2099-01-01",
    ]);
    assert.match(suppression.stdout, /suppression recorded/i);
    const suppressionFile = JSON.parse(await readFile(join(target, "reporook-suppressions.json"), "utf8"));
    assert.equal(suppressionFile.suppressions[0].owner, "security-team");
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});
