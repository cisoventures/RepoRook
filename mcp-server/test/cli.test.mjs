import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanViaCli } from "../dist/cli.js";

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
