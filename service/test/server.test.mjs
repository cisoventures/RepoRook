import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startDashboardServer } from "../dist/server.js";
import { RepositoryStore } from "../dist/repository.js";

const findingId = "rr-0123456789ab";

async function fixture() {
  const repository = await mkdtemp(join(tmpdir(), "reporook-service-test-"));
  await mkdir(join(repository, ".git"));
  await mkdir(join(repository, ".reporook", "remediations", findingId), { recursive: true });
  await writeFile(join(repository, "app.js"), "export const ready = true;\n");
  await writeFile(join(repository, "reporook.yml"), "failOn: high\n");
  const report = {
    schema_version: "1.0",
    tool: { name: "reporook", version: "0.7.0" },
    target: { path: repository, commit: "a".repeat(40) },
    generated_at: "2026-07-25T00:00:00.000Z",
    coverage_status: "complete",
    summary: { critical: 0, high: 1, medium: 0, low: 0, total: 1 },
    scanners: [{ name: "semgrep", applicable: true, available: true, version: "1", status: "ok", finding_count: 1, duration_ms: 1 }],
    findings: [{
      id: findingId, fingerprint: "sha256:" + "b".repeat(64), scanner: "semgrep", rule: "test-rule", severity: "high",
      file: "app.js", line: 1, end_line: 1, plain_summary: "Untrusted input reaches a command.", description: "LEAK_ME",
      remediation_hint: "Validate the input and avoid shell execution.", references: [], metadata: { raw_secret: "LEAK_ME" },
    }],
    policy: { findings: [{ finding_id: findingId, disposition: "actionable" }] },
    scan_receipt: { schema_version: "1.0", scan_id: "scan-test", target: repository, commit: "a".repeat(40), config_hash: "sha256:" + "c".repeat(64), scanners: [] },
  };
  const priorities = {
    schema_version: "1.0", tool: { name: "reporook", version: "0.7.0" }, generated_at: report.generated_at,
    coverage_status: "complete", source_scan: report.scan_receipt,
    summary: { fix_now: 1, fix_next: 0, review_later: 0, total: 1 },
    priorities: [{ rank: 1, priority: "fix-now", finding_id: findingId, severity: "high", scanner: "semgrep", package: null, file: "app.js", line: 1, title: "Command injection", reason: "High severity", next_step: "Avoid shell execution", related_finding_ids: [] }],
  };
  const proposal = {
    schema_version: "1.0", plan_id: "plan-test", finding_id: findingId, created_at: report.generated_at,
    risk_explanation: "An attacker could execute a command.", behavior_impact: "Invalid commands will be rejected.",
    files: ["app.js"], patch: "--- a/app.js\n+++ b/app.js\n@@ -1 +1 @@\n-dangerous(input)\n+safe(input)\n", test_plan: ["npm test"],
  };
  await writeFile(join(repository, ".reporook", "findings.json"), `${JSON.stringify(report)}\n`);
  await writeFile(join(repository, ".reporook", "priorities.json"), `${JSON.stringify(priorities)}\n`);
  await writeFile(join(repository, ".reporook", "remediations", findingId, "proposal.json"), `${JSON.stringify(proposal, null, 2)}\n`);
  return { repository, proposal };
}

async function session(dashboard) {
  const response = await fetch(`${dashboard.origin}/api/session`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: dashboard.origin },
    body: JSON.stringify({ token: "bootstrap-test-token" }),
  });
  assert.equal(response.status, 200);
  return response.headers.get("set-cookie").split(";", 1)[0];
}

async function startOrSkip(context, options) {
  try { return await startDashboardServer(options); }
  catch (error) {
    if (error?.code === "EPERM" && error?.syscall === "listen") {
      context.skip("This sandbox blocks loopback listeners; GitHub Actions runs the live HTTP test");
      return null;
    }
    throw error;
  }
}

test("repository snapshots expose plain evidence without raw scanner metadata", async () => {
  const { repository } = await fixture();
  try {
    const snapshot = await (await RepositoryStore.open(repository)).snapshot();
    const raw = JSON.stringify(snapshot);
    assert.doesNotMatch(raw, /LEAK_ME/);
    assert.equal(snapshot.findings[0].plain_summary, "Untrusted input reaches a command.");
    assert.equal(snapshot.findings[0].policy_status, "actionable");
    assert.match(snapshot.approvals[0].proposal_digest, /^[a-f0-9]{64}$/);
  } finally {
    await rm(repository, { recursive: true, force: true });
  }
});

test("dashboard requires its fragment token and exposes only redacted finding fields", async (context) => {
  const { repository } = await fixture();
  const dashboard = await startOrSkip(context, { repository, port: 0, bootstrapToken: "bootstrap-test-token", sessionToken: "session-test-token", cliRunner: async () => ({ code: 0, stdout: "{}", stderr: "" }) });
  if (!dashboard) { await rm(repository, { recursive: true, force: true }); return; }
  try {
    const unauthenticated = await fetch(`${dashboard.origin}/api/status`);
    assert.equal(unauthenticated.status, 401);
    const cookie = await session(dashboard);
    const response = await fetch(`${dashboard.origin}/api/status`, { headers: { cookie } });
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-security-policy"), /default-src 'none'/);
    const raw = await response.text();
    assert.doesNotMatch(raw, /LEAK_ME/);
    const snapshot = JSON.parse(raw);
    assert.equal(snapshot.repository.configured, true);
    assert.equal(snapshot.scan.coverage_status, "complete");
    assert.equal(snapshot.findings[0].policy_status, "actionable");
    assert.equal(snapshot.approvals[0].finding_id, findingId);
  } finally {
    await dashboard.close();
    await rm(repository, { recursive: true, force: true });
  }
});

test("approval rejects stale proposal content and records only an exact reviewed proposal", async (context) => {
  const { repository } = await fixture();
  const calls = [];
  const runner = async (args) => {
    calls.push(args);
    if (args[0] === "approve") {
      await writeFile(join(repository, ".reporook", "remediations", findingId, "approval.json"), "{\"approved\":true}\n");
      return { code: 0, stdout: "{\"approved\":true}\n", stderr: "" };
    }
    return { code: 0, stdout: "{}\n", stderr: "" };
  };
  const dashboard = await startOrSkip(context, { repository, port: 0, bootstrapToken: "bootstrap-test-token", sessionToken: "session-test-token", cliRunner: runner });
  if (!dashboard) { await rm(repository, { recursive: true, force: true }); return; }
  try {
    const cookie = await session(dashboard);
    const request = async (digest) => await fetch(`${dashboard.origin}/api/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: dashboard.origin, cookie },
      body: JSON.stringify({ finding_id: findingId, proposal_digest: digest, approved_by: "Security owner", reason: "Reviewed the exact patch and focused test plan" }),
    });
    assert.equal((await request("0".repeat(64))).status, 409);
    assert.equal(calls.length, 0);
    const proposalRaw = await readFile(join(repository, ".reporook", "remediations", findingId, "proposal.json"), "utf8");
    const digest = createHash("sha256").update(proposalRaw).digest("hex");
    assert.equal((await request(digest)).status, 200);
    assert.deepEqual(calls[0].slice(0, 2), ["approve", findingId]);
  } finally {
    await dashboard.close();
    await rm(repository, { recursive: true, force: true });
  }
});

test("scan execution is single-flight and preserves RepoRook exit semantics", async (context) => {
  const { repository } = await fixture();
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const runner = async (args) => {
    if (args[0] === "scan") { await pending; return { code: 1, stdout: "", stderr: "" }; }
    return { code: 0, stdout: "{}\n", stderr: "" };
  };
  const dashboard = await startOrSkip(context, { repository, port: 0, bootstrapToken: "bootstrap-test-token", sessionToken: "session-test-token", cliRunner: runner });
  if (!dashboard) { await rm(repository, { recursive: true, force: true }); return; }
  try {
    const cookie = await session(dashboard);
    const options = { method: "POST", headers: { "content-type": "application/json", origin: dashboard.origin, cookie }, body: "{}" };
    assert.equal((await fetch(`${dashboard.origin}/api/scan`, options)).status, 202);
    assert.equal((await fetch(`${dashboard.origin}/api/scan`, options)).status, 409);
    release();
    await new Promise((resolve) => setTimeout(resolve, 10));
    const job = await (await fetch(`${dashboard.origin}/api/job`, { headers: { cookie } })).json();
    assert.equal(job.status, "completed");
    assert.equal(job.exit_code, 1);
    assert.match(job.message, /actionable findings/);
  } finally {
    await dashboard.close();
    await rm(repository, { recursive: true, force: true });
  }
});
