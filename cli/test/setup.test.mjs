import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { setupInstructions } from "../dist/setup.js";

const execute = promisify(execFile);

test("scanner setup is explicit display-only guidance", () => {
  const instructions = setupInstructions();
  assert.match(instructions, /DISPLAY ONLY — NO COMMANDS WERE RUN/);
  assert.match(instructions, /never downloads, installs, or updates executable software/);
  assert.match(instructions, /does not run any command shown above/);
});

test("the setup command never invokes an installer from PATH", { skip: process.platform === "win32" }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "reporook-inert-setup-"));
  const marker = join(directory, "installer-was-run");
  try {
    for (const command of ["brew", "npm", "pip", "pip3", "python", "python3", "winget"]) {
      const path = join(directory, command);
      await writeFile(path, "#!/bin/sh\n: > \"$REPOROOK_SETUP_MARKER\"\nexit 99\n");
      await chmod(path, 0o755);
    }
    const result = await execute(process.execPath, [fileURLToPath(new URL("../dist/index.js", import.meta.url)), "setup"], {
      env: { ...process.env, PATH: directory, REPOROOK_SETUP_MARKER: marker },
    });
    assert.match(result.stdout, /DISPLAY ONLY — NO COMMANDS WERE RUN/);
    await assert.rejects(stat(marker), /ENOENT/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
