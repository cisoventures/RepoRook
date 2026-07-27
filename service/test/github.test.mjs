import test from "node:test";
import assert from "node:assert/strict";
import { createApprovalReceipt } from "reporook";
import { GitHubPublisher } from "../dist/github.js";

const sourceCommit = "a".repeat(40);
const findingId = "rr-0123456789ab";
const planId = "rrp-0123456789ab";
const original = "export const ready = false;\n";

function publication() {
  const source_scan = {
    target: "/repository",
    commit: sourceCommit,
    config_hash: `sha256:${"b".repeat(64)}`,
    scanner_versions: { semgrep: "1.0.0" },
    started_at: "2026-07-25T00:00:00.000Z",
    completed_at: "2026-07-25T00:00:01.000Z",
  };
  const plan = {
    schema_version: "1.0",
    tool: { name: "reporook", version: "0.9.0" },
    plan_id: planId,
    status: "awaiting-proposal",
    generated_at: source_scan.completed_at,
    finding: { id: findingId, plain_summary: "Unsafe command execution" },
    source_scan,
  };
  const proposal = {
    schema_version: "1.0",
    plan_id: planId,
    finding_id: findingId,
    created_at: source_scan.completed_at,
    risk_explanation: "Untrusted input could execute a command.",
    behavior_impact: "The unsafe path is disabled.",
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
    test_plan: ["npm test"],
  };
  const approval = createApprovalReceipt(plan, proposal, "Security owner", "Reviewed exact patch and tests", new Date("2026-07-25T00:01:00.000Z"));
  return { plan, proposal, approval, proposal_digest: "c".repeat(64) };
}

function response(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

function githubMock(options = {}) {
  const calls = [];
  const fetch = async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method ?? "GET";
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ method, path: `${url.pathname}${url.search}`, headers: init.headers, body });
    if (url.pathname === "/installation/repositories") {
      if (options.installationError) return response({ message: "Bad credentials" }, 403);
      const repositories = options.authorized === false ? [{ full_name: "example/other", default_branch: "main" }] : [{ full_name: "cisoventures/RepoRook", default_branch: "main" }];
      return response({ total_count: repositories.length, repositories });
    }
    if (url.pathname.includes("/git/ref/heads/reporook/")) return response({ message: "Not Found" }, 404);
    if (url.pathname.endsWith("/git/ref/heads/main")) return response({ object: { sha: options.baseSha ?? sourceCommit } });
    if (url.pathname.endsWith(`/git/commits/${sourceCommit}`)) return response({ tree: { sha: "base-tree" } });
    if (url.pathname.endsWith("/git/trees/base-tree")) return response({ truncated: false, tree: [{ path: "app.js", mode: "100644", type: "blob", sha: "old-blob", size: Buffer.byteLength(original) }] });
    if (url.pathname.endsWith("/git/blobs/old-blob")) return response({ encoding: "base64", content: Buffer.from(original).toString("base64") });
    if (method === "POST" && url.pathname.endsWith("/git/blobs")) return response({ sha: "new-blob" }, 201);
    if (method === "POST" && url.pathname.endsWith("/git/trees")) return response({ sha: "new-tree" }, 201);
    if (method === "POST" && url.pathname.endsWith("/git/commits")) return response({ sha: "new-commit" }, 201);
    if (method === "POST" && url.pathname.endsWith("/git/refs")) return response({ ref: body.ref, object: { sha: body.sha } }, 201);
    if (method === "POST" && url.pathname.endsWith("/pulls")) return response({ number: 21, html_url: "https://github.com/cisoventures/RepoRook/pull/21" }, 201);
    return response({ message: `Unexpected request: ${method} ${url.pathname}` }, 500);
  };
  return { calls, fetch };
}

test("GitHub publisher creates one repository-scoped draft PR from the exact approved patch", async () => {
  const mock = githubMock();
  const publisher = new GitHubPublisher({ repository: "cisoventures/RepoRook", token: "github-installation-token-value", fetch: mock.fetch });
  const result = await publisher.publish(publication());
  assert.equal(result.number, 21);
  assert.equal(result.draft, true);
  assert.equal(result.repository, "cisoventures/RepoRook");
  assert.match(result.branch, /^reporook\/0123456789ab-/);
  assert.ok(mock.calls.every((call) => call.path.startsWith("/installation/repositories") || call.path.startsWith("/repos/cisoventures/RepoRook/")));
  assert.ok(mock.calls.every((call) => call.headers.authorization === "Bearer github-installation-token-value"));
  const blob = mock.calls.find((call) => call.method === "POST" && call.path.endsWith("/git/blobs"));
  assert.equal(Buffer.from(blob.body.content, "base64").toString("utf8"), "export const ready = true;\n");
  const pull = mock.calls.find((call) => call.method === "POST" && call.path.endsWith("/pulls"));
  assert.equal(pull.body.draft, true);
  assert.equal(pull.body.base, "main");
});

test("GitHub publisher rejects a token that cannot see the selected repository before writes", async () => {
  const mock = githubMock({ authorized: false });
  const publisher = new GitHubPublisher({ repository: "cisoventures/RepoRook", token: "github-installation-token-value", fetch: mock.fetch });
  await assert.rejects(publisher.publish(publication()), /not authorized for cisoventures\/RepoRook/);
  assert.equal(mock.calls.length, 1);
  assert.equal(mock.calls.some((call) => call.method !== "GET"), false);
});

test("GitHub publisher requires an installation token and never falls back to a broad personal token", async () => {
  const mock = githubMock({ installationError: true });
  const publisher = new GitHubPublisher({ repository: "cisoventures/RepoRook", token: "personal-access-token-value", fetch: mock.fetch });
  await assert.rejects(publisher.publish(publication()), /must be a GitHub App installation token/);
  assert.equal(mock.calls.length, 1);
});

test("GitHub publisher rejects a stale default branch before creating remote objects", async () => {
  const mock = githubMock({ baseSha: "d".repeat(40) });
  const publisher = new GitHubPublisher({ repository: "cisoventures/RepoRook", token: "github-installation-token-value", fetch: mock.fetch });
  await assert.rejects(publisher.publish(publication()), /changed after the approved scan/);
  assert.equal(mock.calls.some((call) => call.method === "POST"), false);
});

test("GitHub publisher rejects a receipt whose source scan was altered", async () => {
  const mock = githubMock();
  const input = publication();
  input.approval.source_scan.commit = "d".repeat(40);
  const publisher = new GitHubPublisher({ repository: "cisoventures/RepoRook", token: "github-installation-token-value", fetch: mock.fetch });
  await assert.rejects(publisher.publish(input), /approval receipt no longer matches/);
  assert.equal(mock.calls.length, 0);
});
