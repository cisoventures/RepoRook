import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);

test("npm-style symlinked CLI executes its entry point", async () => {
  const directory = await mkdtemp(join(tmpdir(), "reporook-bin-test-"));
  const binary = join(directory, "reporook");
  try {
    await symlink(resolve("dist/index.js"), binary);
    const { stdout } = await execute(binary, ["--version"]);
    assert.equal(stdout.trim(), "0.1.0");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
