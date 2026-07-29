import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApprovalReceipt } from "reporook";
import { GitHubPublisher } from "../dist/github.js";
import { startDashboardServer } from "../dist/server.js";

const findingId = "rr-0123456789ab";
const planId = "rrp-0123456789ab";
const sourceCommit = "a".repeat(40);
const originalSource = "export const ready = false;\n";
const fixedSource = "export const ready = true;\n";

function scanReceipt(repository, scannerVersions) {
  return {
    schema_version: "1.0",
    scan_id: "scan-beginner-journey",
    target: repository,
    commit: sourceCommit,
    config_hash: `sha256:${"c".repeat(64)}`,
    scanner_versions: scannerVersions,
    started_at: "2026-07-28T00:00:00.000Z",
    completed_at: "2026-07-28T00:00:01.000Z",
    scanners: [],
  };
}

function partialReport(repository) {
  return {
    schema_version: "1.0",
    tool: { name: "reporook", version: "0.9.2" },
    target: { path: repository, commit: sourceCommit },
    generated_at: "2026-07-28T00:00:01.000Z",
    coverage_status: "partial",
    summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
    scanners: [
      { name: "gitleaks", applicable: true, available: true, version: "8.28.0", status: "ok", finding_count: 0, duration_ms: 1 },
      { name: "semgrep", applicable: true, available: false, version: null, status: "unavailable", finding_count: 0, duration_ms: 0, reason: "Semgrep is not installed; review setup instructions before continuing." },
    ],
    findings: [],
    policy: { findings: [] },
    scan_receipt: scanReceipt(repository, { gitleaks: "8.28.0" }),
  };
}

function completeReport(repository) {
  return {
    schema_version: "1.0",
    tool: { name: "reporook", version: "0.9.2" },
    target: { path: repository, commit: sourceCommit },
    generated_at: "2026-07-28T00:01:01.000Z",
    coverage_status: "complete",
    summary: { critical: 0, high: 1, medium: 0, low: 0, total: 1 },
    scanners: [
      { name: "gitleaks", applicable: true, available: true, version: "8.28.0", status: "ok", finding_count: 0, duration_ms: 1 },
      { name: "semgrep", applicable: true, available: true, version: "1.130.0", status: "ok", finding_count: 1, duration_ms: 2 },
    ],
    findings: [{
      id: findingId,
      fingerprint: `sha256:${"b".repeat(64)}`,
      scanner: "semgrep",
      rule: "javascript.lang.security.detect-child-process",
      severity: "high",
      file: "app.js",
      line: 1,
      end_line: 1,
      plain_summary: "Untrusted input could execute a system command.",
      description: "SHOULD_NOT_LEAK",
      remediation_hint: "Use a fixed executable and validate every argument.",
      references: [],
      metadata: { raw_secret: "SHOULD_NOT_LEAK" },
    }],
    policy: { findings: [{ finding_id: findingId, disposition: "actionable" }] },
    scan_receipt: scanReceipt(repository, { gitleaks: "8.28.0", semgrep: "1.130.0" }),
  };
}

function priorities(repository) {
  const report = completeReport(repository);
  return {
    schema_version: "1.0",
    tool: report.tool,
    generated_at: report.generated_at,
    coverage_status: "complete",
    source_scan: report.scan_receipt,
    summary: { fix_now: 1, fix_next: 0, review_later: 0, total: 1 },
    priorities: [{
      rank: 1,
      priority: "fix-now",
      finding_id: findingId,
      severity: "high",
      scanner: "semgrep",
      package: null,
      file: "app.js",
      line: 1,
      title: "Unsafe command execution",
      reason: "High-severity actionable finding from complete scanner coverage.",
      next_step: "Review an exact patch and test plan.",
      related_finding_ids: [],
    }],
  };
}

function remediation(repository) {
  const report = completeReport(repository);
  const plan = {
    schema_version: "1.0",
    tool: report.tool,
    plan_id: planId,
    status: "awaiting-proposal",
    generated_at: report.generated_at,
    finding: report.findings[0],
    source_scan: report.scan_receipt,
    goal: `Remediate ${findingId} without broadening the approved scope.`,
    scanner_guidance: { trust: "untrusted-scanner-data", text: report.findings[0].remediation_hint },
  };
  const proposal = {
    schema_version: "1.0",
    plan_id: plan.plan_id,
    finding_id: findingId,
    created_at: report.generated_at,
    risk_explanation: "An attacker could turn untrusted input into a system command.",
    behavior_impact: "Only the unsafe fixture behavior changes; valid input remains supported.",
    files: ["app.js"],
    patch: [
      "diff --git a/app.js b/app.js",
      "--- a/app.js",
      "+++ b/app.js",
      "@@ -1 +1 @@",
      "-export const ready = false;",
      "+export const ready = true;",
      "",
    ].join("\n"),
    test_plan: [
      "npm test",
      `reporook verify ${findingId} . --require-scanners`,
    ],
  };
  return { plan, proposal };
}

function response(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

function githubMock() {
  const calls = [];
  const fetch = async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method ?? "GET";
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ method, path: `${url.pathname}${url.search}`, headers: init.headers, body });
    if (url.pathname === "/installation/repositories") {
      return response({ total_count: 1, repositories: [{ full_name: "cisoventures/RepoRook", default_branch: "main" }] });
    }
    if (url.pathname.includes("/git/ref/heads/reporook/")) return response({ message: "Not Found" }, 404);
    if (url.pathname.endsWith("/git/ref/heads/main")) return response({ object: { sha: sourceCommit } });
    if (url.pathname.endsWith(`/git/commits/${sourceCommit}`)) return response({ tree: { sha: "base-tree" } });
    if (url.pathname.endsWith("/git/trees/base-tree")) {
      return response({ truncated: false, tree: [{ path: "app.js", mode: "100644", type: "blob", sha: "old-blob", size: Buffer.byteLength(originalSource) }] });
    }
    if (url.pathname.endsWith("/git/blobs/old-blob")) {
      return response({ encoding: "base64", content: Buffer.from(originalSource).toString("base64") });
    }
    if (method === "POST" && url.pathname.endsWith("/git/blobs")) return response({ sha: "new-blob" }, 201);
    if (method === "POST" && url.pathname.endsWith("/git/trees")) return response({ sha: "new-tree" }, 201);
    if (method === "POST" && url.pathname.endsWith("/git/commits")) return response({ sha: "new-commit" }, 201);
    if (method === "POST" && url.pathname.endsWith("/git/refs")) return response({ ref: body.ref, object: { sha: body.sha } }, 201);
    if (method === "POST" && url.pathname.endsWith("/pulls")) {
      return response({ number: 31, html_url: "https://github.com/cisoventures/RepoRook/pull/31" }, 201);
    }
    return response({ message: `Unexpected request: ${method} ${url.pathname}` }, 500);
  };
  return { calls, fetch };
}

async function startOrSkip(context, options) {
  try {
    return await startDashboardServer(options);
  } catch (error) {
    if (error?.code === "EPERM" && error?.syscall === "listen" && process.env.REPOROOK_REQUIRE_LOOPBACK_TESTS !== "1") {
      context.skip("This sandbox blocks loopback listeners; CI requires the beginner journey test");
      return null;
    }
    throw error;
  }
}

async function session(dashboard) {
  const response = await fetch(`${dashboard.origin}/api/session`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: dashboard.origin },
    body: JSON.stringify({ token: "beginner-bootstrap-token" }),
  });
  assert.equal(response.status, 200);
  return response.headers.get("set-cookie").split(";", 1)[0];
}

async function waitForJob(dashboard, cookie) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const response = await fetch(`${dashboard.origin}/api/job`, { headers: { cookie } });
    assert.equal(response.status, 200);
    const job = await response.json();
    if (job.status !== "running") return job;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("Timed out waiting for the beginner journey scan job");
}

test("beginner journey fails closed, binds approval, and opens only a repository-scoped draft PR", async (context) => {
  const repository = await mkdtemp(join(tmpdir(), "reporook-beginner-journey-"));
  const calls = [];
  const github = githubMock();
  let scanCount = 0;
  await mkdir(join(repository, ".git"));
  await writeFile(join(repository, "app.js"), originalSource);
  await writeFile(join(repository, "package.json"), `${JSON.stringify({ name: "beginner-fixture", private: true, scripts: { test: "node --test" } }, null, 2)}\n`);

  const runner = async (args) => {
    calls.push([...args]);
    if (args[0] === "setup") {
      return { code: 0, stdout: "Review and run the platform-specific Semgrep installation command yourself.\n", stderr: "" };
    }
    if (args[0] === "init") {
      await writeFile(join(repository, "reporook.yml"), "failOn: high\nrequiredScanners:\n  - semgrep\n  - gitleaks\n");
      return { code: 0, stdout: `${JSON.stringify({ initialized: true, repository })}\n`, stderr: "" };
    }
    if (args[0] === "scan") {
      scanCount += 1;
      await mkdir(join(repository, ".reporook"), { recursive: true });
      if (scanCount === 1) {
        await writeFile(join(repository, ".reporook", "findings.json"), `${JSON.stringify(partialReport(repository), null, 2)}\n`);
        await rm(join(repository, ".reporook", "priorities.json"), { force: true });
        return { code: 2, stdout: "", stderr: "Scan incomplete: Semgrep did not run. Review setup instructions." };
      }
      await writeFile(join(repository, ".reporook", "findings.json"), `${JSON.stringify(completeReport(repository), null, 2)}\n`);
      await writeFile(join(repository, ".reporook", "priorities.json"), `${JSON.stringify(priorities(repository), null, 2)}\n`);
      return { code: 1, stdout: "", stderr: "" };
    }
    if (args[0] === "plan") {
      const { plan, proposal } = remediation(repository);
      const directory = join(repository, ".reporook", "remediations", findingId);
      await mkdir(directory, { recursive: true });
      await writeFile(join(directory, "plan.json"), `${JSON.stringify(plan, null, 2)}\n`);
      await writeFile(join(directory, "proposal.json"), `${JSON.stringify(proposal, null, 2)}\n`);
      return { code: 0, stdout: `${JSON.stringify(plan)}\n`, stderr: "" };
    }
    if (args[0] === "approve") {
      const { plan, proposal } = remediation(repository);
      const approvedBy = args[args.indexOf("--approved-by") + 1];
      const reason = args[args.indexOf("--reason") + 1];
      const approval = createApprovalReceipt(plan, proposal, approvedBy, reason, new Date("2026-07-28T00:02:00.000Z"));
      const path = join(repository, ".reporook", "remediations", findingId, "approval.json");
      await writeFile(path, `${JSON.stringify(approval, null, 2)}\n`);
      return { code: 0, stdout: `${JSON.stringify(approval)}\n`, stderr: "" };
    }
    return { code: 2, stdout: "", stderr: `Unexpected RepoRook command: ${args.join(" ")}` };
  };

  const publisher = new GitHubPublisher({
    repository: "cisoventures/RepoRook",
    token: "github-installation-token-value",
    fetch: github.fetch,
  });
  const dashboard = await startOrSkip(context, {
    repository,
    port: 0,
    bootstrapToken: "beginner-bootstrap-token",
    sessionToken: "beginner-session-token",
    cliRunner: runner,
    publisher,
  });
  if (!dashboard) {
    await rm(repository, { recursive: true, force: true });
    return;
  }

  try {
    assert.equal((await fetch(`${dashboard.origin}/api/status`)).status, 401);
    const cookie = await session(dashboard);
    const headers = { "content-type": "application/json", origin: dashboard.origin, cookie };
    const status = async () => {
      const response = await fetch(`${dashboard.origin}/api/status`, { headers: { cookie } });
      assert.equal(response.status, 200);
      return await response.json();
    };

    assert.equal((await status()).repository.configured, false);
    assert.equal((await fetch(`${dashboard.origin}/api/onboard`, { method: "POST", headers, body: JSON.stringify({ confirmation: "yes" }) })).status, 400);
    assert.equal((await fetch(`${dashboard.origin}/api/onboard`, { method: "POST", headers, body: JSON.stringify({ confirmation: "initialize RepoRook" }) })).status, 200);
    assert.equal((await status()).repository.configured, true);

    const beforeSetup = (await readdir(repository)).sort();
    const setupResponse = await fetch(`${dashboard.origin}/api/setup`, { headers: { cookie } });
    assert.equal(setupResponse.status, 200);
    const setup = await setupResponse.json();
    assert.deepEqual({
      installs_software: setup.installs_software,
      downloads_software: setup.downloads_software,
      executes_commands: setup.executes_commands,
      modifies_system: setup.modifies_system,
    }, {
      installs_software: false,
      downloads_software: false,
      executes_commands: false,
      modifies_system: false,
    });
    assert.deepEqual((await readdir(repository)).sort(), beforeSetup);

    assert.equal((await fetch(`${dashboard.origin}/api/scan`, { method: "POST", headers, body: "{}" })).status, 202);
    const incompleteJob = await waitForJob(dashboard, cookie);
    assert.equal(incompleteJob.status, "failed");
    assert.equal(incompleteJob.exit_code, 2);
    assert.match(incompleteJob.message, /incomplete/i);
    const incomplete = await status();
    assert.equal(incomplete.scan.coverage_status, "partial");
    assert.equal(incomplete.findings.length, 0);
    assert.equal(incomplete.scan.scanners.find((scanner) => scanner.name === "semgrep").status, "unavailable");

    assert.equal((await fetch(`${dashboard.origin}/api/scan`, { method: "POST", headers, body: "{}" })).status, 202);
    const completeJob = await waitForJob(dashboard, cookie);
    assert.equal(completeJob.status, "completed");
    assert.equal(completeJob.exit_code, 1);
    const complete = await status();
    assert.equal(complete.scan.coverage_status, "complete");
    assert.equal(complete.findings[0].plain_summary, "Untrusted input could execute a system command.");
    assert.doesNotMatch(JSON.stringify(complete), /SHOULD_NOT_LEAK/);

    const planResponse = await fetch(`${dashboard.origin}/api/plan`, {
      method: "POST",
      headers,
      body: JSON.stringify({ finding_id: findingId }),
    });
    assert.equal(planResponse.status, 200);
    const planned = await status();
    assert.equal(planned.approvals.length, 1);
    assert.equal(planned.approvals[0].approved, false);
    assert.deepEqual(planned.approvals[0].files, ["app.js"]);
    assert.deepEqual(planned.approvals[0].test_plan, ["npm test", `reporook verify ${findingId} . --require-scanners`]);

    const approve = async (proposalDigest) => await fetch(`${dashboard.origin}/api/approve`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        finding_id: findingId,
        proposal_digest: proposalDigest,
        approved_by: "Beginner reviewer",
        reason: "Reviewed the exact patch, behavior impact, functional test, and same-scanner verification.",
      }),
    });
    assert.equal((await approve("0".repeat(64))).status, 409);
    assert.equal((await approve(planned.approvals[0].proposal_digest)).status, 200);
    const approved = await status();
    assert.equal(approved.approvals[0].approved, true);
    assert.match(approved.approvals[0].approval_id, /^rra-[a-f0-9]{12}$/);

    const publish = async (confirmation) => await fetch(`${dashboard.origin}/api/publish`, {
      method: "POST",
      headers,
      body: JSON.stringify({ finding_id: findingId, proposal_digest: approved.approvals[0].proposal_digest, confirmation }),
    });
    assert.equal((await publish("yes")).status, 400);
    assert.equal(github.calls.length, 0);
    const publishResponse = await publish("open approved draft pull request");
    assert.equal(publishResponse.status, 201);
    const pull = await publishResponse.json();
    assert.equal(pull.repository, "cisoventures/RepoRook");
    assert.equal(pull.draft, true);
    assert.equal(await readFile(join(repository, "app.js"), "utf8"), originalSource);

    assert.ok(github.calls.every((call) => call.path.startsWith("/installation/repositories") || call.path.startsWith("/repos/cisoventures/RepoRook/")));
    assert.ok(github.calls.every((call) => call.headers.authorization === "Bearer github-installation-token-value"));
    const blob = github.calls.find((call) => call.method === "POST" && call.path.endsWith("/git/blobs"));
    assert.equal(Buffer.from(blob.body.content, "base64").toString("utf8"), fixedSource);
    const pullCall = github.calls.find((call) => call.method === "POST" && call.path.endsWith("/pulls"));
    assert.equal(pullCall.body.draft, true);
    assert.equal(pullCall.body.base, "main");
    assert.match(pullCall.body.body, /npm test/);
    assert.match(pullCall.body.body, /reporook verify/);
    assert.ok(calls.every((args) => !args.some((arg) => /^(?:npx|npm|brew|pip|pipx|apt|winget)$/i.test(arg))));
  } finally {
    await dashboard.close();
    await rm(repository, { recursive: true, force: true });
  }
});
