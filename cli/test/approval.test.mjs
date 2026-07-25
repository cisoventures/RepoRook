import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { approvalMatches, createApprovalReceipt, parseRemediationProposal } from "../dist/approval.js";
import { createRemediationPlan } from "../dist/remediation.js";

const execute = promisify(execFile);

function finding() {
  return {
    id: "rr-aaaaaaaaaaaa",
    scanner: "semgrep",
    rule: "rule.test",
    severity: "high",
    file: "src/app.ts",
    line: 1,
    plain_summary: "Unsafe input reaches an operation.",
    description: "Unsafe operation",
    remediation_hint: "Validate the input.",
    fingerprint: `sha256:${"a".repeat(64)}`,
    references: [],
    metadata: { cwe: ["CWE-20"], cve: [], package: null, raw_severity: "HIGH" },
  };
}

function report(target) {
  const selected = finding();
  const now = "2026-07-24T12:00:00.000Z";
  return {
    schema_version: "1.0",
    tool: { name: "reporook", version: "0.5.0" },
    target: { path: target, commit: "abc123" },
    generated_at: now,
    coverage_status: "complete",
    summary: { critical: 0, high: 1, medium: 0, low: 0, total: 1 },
    scanners: [],
    findings: [selected],
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

function proposal(plan) {
  return {
    schema_version: "1.0",
    plan_id: plan.plan_id,
    finding_id: plan.finding.id,
    created_at: "2026-07-24T12:05:00.000Z",
    risk_explanation: "Untrusted input may reach a sensitive operation.",
    behavior_impact: "Reject malformed input before the operation runs.",
    files: ["src/app.ts"],
    patch: [
      "diff --git a/src/app.ts b/src/app.ts",
      "--- a/src/app.ts",
      "+++ b/src/app.ts",
      "@@ -1 +1 @@",
      "-unsafe(value)",
      "+safe(value)",
    ].join("\n"),
    test_plan: ["npm test -- --test-name-pattern input"],
  };
}

test("approval receipts bind the exact plan, diff, files, and tests", () => {
  const plan = createRemediationPlan(report("/repo"), finding().id);
  const proposed = proposal(plan);
  const receipt = createApprovalReceipt(plan, proposed, "security-reviewer", "Reviewed the exact patch and regression test.", new Date("2026-07-24T12:10:00.000Z"));
  assert.match(receipt.approval_id, /^rra-[a-f0-9]{12}$/);
  assert.equal(receipt.bindings.files[0], "src/app.ts");
  assert.equal(approvalMatches(receipt, plan, proposed), true);
  assert.equal(approvalMatches(receipt, plan, { ...proposed, test_plan: ["npm test"] }), false);
  assert.equal(approvalMatches(receipt, plan, { ...proposed, patch: `${proposed.patch}\n` }), false);
  assert.throws(() => parseRemediationProposal({ ...proposed, files: ["../outside.ts"] }), /repository-relative/);
  assert.throws(() => parseRemediationProposal({ ...proposed, files: ["src/other.ts"] }), /exactly match/);
});

test("CLI writes a durable approval receipt from the generated proposal template", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-approval-cli-"));
  try {
    const baseline = report(target);
    await mkdir(join(target, ".reporook"));
    await writeFile(join(target, ".reporook", "findings.json"), `${JSON.stringify(baseline, null, 2)}\n`);
    const entry = resolve("dist/index.js");
    await execute(process.execPath, [entry, "plan", finding().id, target, "--quiet"]);
    const directory = join(target, ".reporook", "remediations", finding().id);
    const plan = JSON.parse(await readFile(join(directory, "plan.json"), "utf8"));
    const exactProposal = proposal(plan);
    await writeFile(join(directory, "proposal.json"), `${JSON.stringify(exactProposal, null, 2)}\n`);
    const result = await execute(process.execPath, [
      entry, "approve", finding().id, target,
      "--approved-by", "security-reviewer",
      "--reason", "Reviewed the exact patch and regression test.",
    ]);
    assert.match(result.stdout, /approval recorded/i);
    const receipt = JSON.parse(await readFile(join(directory, "approval.json"), "utf8"));
    assert.equal(receipt.approved_by, "security-reviewer");
    assert.equal(receipt.bindings.files[0], "src/app.ts");
    await rm(join(directory, "proposal.json"));
    await assert.rejects(
      execute(process.execPath, [entry, "verify", finding().id, target]),
      (error) => {
        assert.match(error.stderr, /ENOENT|no such file/i);
        return true;
      },
    );
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});
