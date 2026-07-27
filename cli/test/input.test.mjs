import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readBoundedJsonFile, readBoundedTextFile } from "../dist/input.js";

test("bounded evidence reads reject links, non-files, oversized content, and invalid UTF-8", async () => {
  const root = await mkdtemp(join(tmpdir(), "reporook-input-"));
  const outside = join(tmpdir(), `reporook-input-outside-${process.pid}.json`);
  try {
    const valid = join(root, "valid.json");
    await writeFile(valid, "{\"safe\":true}\n");
    assert.deepEqual(await readBoundedJsonFile(valid, "Test evidence", 32), { safe: true });

    const oversized = join(root, "oversized.json");
    await writeFile(oversized, `\"${"x".repeat(32)}\"`);
    await assert.rejects(readBoundedJsonFile(oversized, "Test evidence", 32), /exceeds the 32 bytes limit/);

    const invalid = join(root, "invalid.txt");
    await writeFile(invalid, Buffer.from([0xff, 0xfe]));
    await assert.rejects(readBoundedTextFile(invalid, "Test evidence", 32), /valid UTF-8/);

    const directory = join(root, "directory.json");
    await mkdir(directory);
    await assert.rejects(readBoundedJsonFile(directory, "Test evidence", 32), /regular file/);

    if (process.platform !== "win32") {
      await writeFile(outside, "{\"outside\":true}\n");
      const linked = join(root, "linked.json");
      await symlink(outside, linked);
      await assert.rejects(readBoundedJsonFile(linked, "Test evidence", 32), /symbolic link/);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { force: true });
  }
});
