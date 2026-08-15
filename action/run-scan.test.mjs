import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);

test("unexpected CLI termination is normalized to a fail-closed tool error", { skip: process.platform === "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "reporook-action-exit-"));
  const actionRoot = join(root, "action-root");
  const workspace = join(root, "workspace");
  const output = join(root, "output.txt");
  try {
    await mkdir(join(actionRoot, "cli", "dist"), { recursive: true });
    await mkdir(workspace);
    const stub = join(actionRoot, "cli", "dist", "index.js");
    await writeFile(stub, "#!/usr/bin/env node\nprocess.exit(137);\n");
    await chmod(stub, 0o755);
    const result = await execute("bash", [resolve("action/run-scan.sh")], { env: { ...process.env, GITHUB_ACTION_PATH: actionRoot, GITHUB_WORKSPACE: workspace, GITHUB_OUTPUT: output, INPUT_MODE: "full" } });
    assert.equal(result.stderr.includes("treating the scan as a tool error"), true);
    assert.match(await readFile(output, "utf8"), /^exit_code=2$/m);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("external target approval is forwarded only by the explicit Action input", { skip: process.platform === "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "reporook-action-external-targets-"));
  const actionRoot = join(root, "action-root");
  const workspace = join(root, "workspace");
  const output = join(root, "output.txt");
  const argsPath = join(root, "args.json");
  try {
    await mkdir(join(actionRoot, "cli", "dist"), { recursive: true });
    await mkdir(workspace);
    const stub = join(actionRoot, "cli", "dist", "index.js");
    await writeFile(stub, "#!/usr/bin/env node\nrequire('node:fs').writeFileSync(process.env.REPOROOK_TEST_ARGS, JSON.stringify(process.argv.slice(2)));\n");
    await chmod(stub, 0o755);
    await execute("bash", [resolve("action/run-scan.sh")], { env: { ...process.env, GITHUB_ACTION_PATH: actionRoot, GITHUB_WORKSPACE: workspace, GITHUB_OUTPUT: output, INPUT_MODE: "full", INPUT_ALLOW_EXTERNAL_TARGETS: "true", REPOROOK_TEST_ARGS: argsPath } });
    assert.ok(JSON.parse(await readFile(argsPath, "utf8")).includes("--allow-external-targets"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
