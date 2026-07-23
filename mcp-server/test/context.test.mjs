import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { codeContext } from "../dist/context.js";

test("code context remains inside repository", async () => {
  const root = await mkdtemp(join(tmpdir(), "reporook-mcp-"));
  await mkdir(join(root, "src"));
  await writeFile(join(root, "src", "app.js"), "one\ntwo\nthree\n");
  try {
    const result = await codeContext(root, { id: "rr-test", file: "src/app.js", line: 2, description: "x", remediation_hint: "y" }, 1);
    assert.match(result.code, /2 \| two/);
    await assert.rejects(() => codeContext(root, { id: "rr-test", file: "../secret", line: 1, description: "x", remediation_hint: "y" }, 1));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
