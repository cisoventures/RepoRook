import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

test("stdio server negotiates MCP and exposes all tools", async () => {
  const child = spawn(process.execPath, ["dist/index.js"], { cwd: new URL("..", import.meta.url), stdio: ["pipe", "pipe", "pipe"] });
  const lines = createInterface({ input: child.stdout });
  const responses = [];
  lines.on("line", (line) => responses.push(JSON.parse(line)));
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "test", version: "1" } } })}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 3, method: "ping", params: {} })}\n`);

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("MCP response timed out")), 3_000);
    const poll = setInterval(() => {
      if (responses.length >= 3) { clearTimeout(timeout); clearInterval(poll); resolve(); }
    }, 10);
  });
  child.kill("SIGTERM");

  assert.equal(responses[0].result.protocolVersion, "2025-03-26");
  assert.equal(responses[0].result.serverInfo.name, "reporook");
  assert.deepEqual(responses[1].result.tools.map((tool) => tool.name), [
    "scan_repository", "scan_changes", "list_findings", "get_finding", "get_remediation_context", "verify_fix", "export_findings",
  ]);
  assert.equal(responses[1].result.tools.find((tool) => tool.name === "verify_fix").inputSchema.properties.require_scanners.default, true);
  assert.deepEqual(responses[2].result, {});
});
