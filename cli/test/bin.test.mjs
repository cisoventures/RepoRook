import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);

test("CLI executes its entry point through the platform's package launch form", async () => {
  const directory = await mkdtemp(join(tmpdir(), "reporook-bin-test-"));
  const binary = join(directory, "reporook");
  try {
    const entry = resolve("dist/index.js");
    if (process.platform !== "win32") await symlink(entry, binary);
    const { stdout } = process.platform === "win32"
      ? await execute(process.execPath, [entry, "--version"])
      : await execute(binary, ["--version"]);
    assert.equal(stdout.trim(), "0.1.0");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
