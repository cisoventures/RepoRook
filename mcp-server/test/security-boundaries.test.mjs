import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";

async function serverWithStub(body) {
  const root = await mkdtemp(join(tmpdir(), "reporook-mcp-boundary-"));
  const stub = join(root, "reporook-stub.mjs");
  await writeFile(stub, `#!/usr/bin/env node\n${body}\n`);
  await chmod(stub, 0o755);
  const child = spawn(process.execPath, ["dist/index.js"], {
    cwd: new URL("..", import.meta.url),
    env: { ...process.env, REPOROOK_CLI: stub, REPOROOK_TEST_ROOT: root },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const responses = [];
  createInterface({ input: child.stdout }).on("line", (line) => responses.push(JSON.parse(line)));
  return { root, child, responses };
}

async function waitFor(responses, count) {
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`Timed out waiting for ${count} MCP responses; received ${responses.length}`)), 5_000);
    const interval = setInterval(() => {
      if (responses.length >= count) {
        clearTimeout(timeout);
        clearInterval(interval);
        resolve();
      }
    }, 10);
  });
}

function validReport(target) {
  const now = "2026-07-28T12:00:00.000Z";
  return {
    schema_version: "1.0",
    tool: { name: "reporook", version: "0.9.1" },
    target: { path: target, commit: null },
    generated_at: now,
    coverage_status: "complete",
    summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
    scanners: [{ name: "semgrep", applicable: true, available: true, version: "1", status: "ok", finding_count: 0, duration_ms: 1 }],
    findings: [],
    scan_receipt: {
      target,
      commit: null,
      config_hash: `sha256:${"a".repeat(64)}`,
      scanner_versions: { semgrep: "1" },
      started_at: now,
      completed_at: now,
    },
  };
}

test("option-like revisions are rejected before the CLI boundary", async () => {
  const { root, child, responses } = await serverWithStub(`
import { appendFileSync } from "node:fs";
appendFileSync(process.env.REPOROOK_TEST_ROOT + "/calls.txt", process.argv.slice(2).join(" ") + "\\n");
process.stdout.write("{}\\n");
`);
  try {
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "scan_changes", arguments: { path: root, base: "--output", head: "README.md" } } })}\n`);
    await waitFor(responses, 1);
    assert.equal(responses[0].result.isError, true);
    assert.match(responses[0].result.content[0].text, /must not begin with '-'/);
    await assert.rejects(readFile(join(root, "calls.txt"), "utf8"), /ENOENT/);
  } finally {
    child.kill("SIGTERM");
    await rm(root, { recursive: true, force: true });
  }
});

test("stdio tool calls have a hard in-flight concurrency bound", async () => {
  const { root, child, responses } = await serverWithStub(`
await new Promise((resolve) => setTimeout(resolve, 150));
process.stdout.write("{}\\n");
`);
  try {
    for (let id = 1; id <= 6; id += 1) {
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "scan_repository", arguments: { path: root } } })}\n`);
    }
    await waitFor(responses, 6);
    const busy = responses.filter((item) => item.result?.isError && /at most 2 tool calls/.test(item.result.content?.[0]?.text ?? ""));
    assert.equal(busy.length, 4);
    assert.equal(responses.filter((item) => !item.result?.isError).length, 2);
  } finally {
    child.kill("SIGTERM");
    await rm(root, { recursive: true, force: true });
  }
});

test("SARIF export is regenerated from the validated findings report", async () => {
  const { root, child, responses } = await serverWithStub('process.stdout.write("{}\\n");');
  try {
    await mkdir(join(root, ".reporook"));
    await writeFile(join(root, ".reporook", "findings.json"), `${JSON.stringify(validReport(root))}\n`);
    await writeFile(join(root, ".reporook", "results.sarif"), '{"forged":true}\n');
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "export_findings", arguments: { repository_path: root, format: "sarif" } } })}\n`);
    await waitFor(responses, 1);
    assert.equal(responses[0].result.isError, undefined);
    assert.equal(responses[0].result.structuredContent.version, "2.1.0");
    assert.equal(responses[0].result.structuredContent.runs[0].tool.driver.name, "RepoRook");
    assert.equal(responses[0].result.structuredContent.forged, undefined);
  } finally {
    child.kill("SIGTERM");
    await rm(root, { recursive: true, force: true });
  }
});
