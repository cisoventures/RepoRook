import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultConfig } from "../dist/config.js";
import { CheckovScanner } from "../dist/scanners/checkov.js";
import { PipAuditScanner } from "../dist/scanners/pip-audit.js";
import { SemgrepScanner } from "../dist/scanners/semgrep.js";

test("the Action can block unverified Python scanner executables", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-python-scanner-trust-"));
  process.env.REPOROOK_PYTHON_SCANNERS_VERIFIED = "false";
  const context = { target, config: structuredClone(defaultConfig) };
  try {
    for (const scanner of [new SemgrepScanner(), new PipAuditScanner(), new CheckovScanner()]) {
      assert.equal(await scanner.version(), null);
      const result = await scanner.run(context);
      assert.equal(result.status.available, false);
      assert.equal(result.status.status, "skipped");
      assert.match(result.status.reason, /did not install it from a repository-owned hash lock/);
    }
  } finally {
    delete process.env.REPOROOK_PYTHON_SCANNERS_VERIFIED;
    await rm(target, { recursive: true, force: true });
  }
});
