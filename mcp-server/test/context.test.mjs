import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { codeContext, findingContext, readReport } from "../dist/context.js";

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

test("external and historical findings do not pretend current source context exists", async () => {
  const finding = { id: "rr-test", file: "container-image:example/app:1", line: 1, description: "x", remediation_hint: "y", metadata: { target_kind: "container-image" } };
  assert.equal(await findingContext("/tmp/repository", finding), null);
});

test("MCP evidence reads stay inside the repository and reject symbolic links", async () => {
  const root = await mkdtemp(join(tmpdir(), "reporook-mcp-report-"));
  const outside = join(tmpdir(), `reporook-mcp-outside-${process.pid}.json`);
  try {
    await mkdir(join(root, ".reporook"));
    await writeFile(join(root, ".reporook", "findings.json"), "{\"findings\":[]}\n");
    assert.deepEqual(await readReport(root, ".reporook/findings.json"), { findings: [] });
    await writeFile(outside, "{\"secret\":true}\n");
    await assert.rejects(readReport(root, outside), /outside the repository/);
    if (process.platform !== "win32") {
      await symlink(outside, join(root, ".reporook", "linked.json"));
      await assert.rejects(readReport(root, ".reporook/linked.json"), /symbolic link/);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { force: true });
  }
});

test("MCP source context rejects linked and oversized repository files", async () => {
  const root = await mkdtemp(join(tmpdir(), "reporook-mcp-source-"));
  const outside = join(tmpdir(), `reporook-mcp-source-outside-${process.pid}.txt`);
  try {
    await mkdir(join(root, "src"));
    await writeFile(join(root, "src", "large.js"), "x".repeat(1024 * 1024 + 1));
    await assert.rejects(
      codeContext(root, { id: "rr-test", file: "src/large.js", line: 1, description: "x", remediation_hint: "y" }, 1),
      /1 MiB limit/,
    );
    if (process.platform !== "win32") {
      await writeFile(outside, "do not expose\n");
      await symlink(outside, join(root, "src", "linked.js"));
      await assert.rejects(
        codeContext(root, { id: "rr-test", file: "src/linked.js", line: 1, description: "x", remediation_hint: "y" }, 1),
        /symbolic link/,
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { force: true });
  }
});
