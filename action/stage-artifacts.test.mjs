import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);
const script = resolve("action/stage-artifacts.mjs");

test("artifact staging copies only generated regular evidence files", async () => {
  const root = await mkdtemp(join(tmpdir(), "reporook-stage-artifacts-"));
  const source = join(root, "source");
  const destination = join(root, "destination");
  try {
    await import("node:fs/promises").then(({ mkdir }) => mkdir(source));
    await writeFile(join(source, "findings.json"), "{}\n");
    await writeFile(join(source, "unrecognized.txt"), "do not upload\n");
    await execute(process.execPath, [script, source, destination]);
    assert.equal(await readFile(join(destination, "findings.json"), "utf8"), "{}\n");
    await assert.rejects(readFile(join(destination, "unrecognized.txt"), "utf8"), /ENOENT/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("artifact staging rejects symlinks instead of following them", { skip: process.platform === "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "reporook-stage-artifacts-link-"));
  const source = join(root, "source");
  const destination = join(root, "destination");
  try {
    await import("node:fs/promises").then(({ mkdir }) => mkdir(source));
    await writeFile(join(root, "outside.json"), "{\"outside\":true}\n");
    await symlink(join(root, "outside.json"), join(source, "findings.json"));
    await assert.rejects(execute(process.execPath, [script, source, destination]), /regular non-link file/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
