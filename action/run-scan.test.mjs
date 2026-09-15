import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);

function actionOutputs(raw) {
  const result = new Map();
  const lines = raw.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    if (index === lines.length - 1 && lines[index] === "") break;
    const start = lines[index].match(/^([a-z0-9_-]+)<<(.+)$/);
    if (!start) throw new Error(`Unexpected Action output line: ${lines[index]}`);
    const value = [];
    index += 1;
    while (index < lines.length && lines[index] !== start[2]) value.push(lines[index++]);
    if (index >= lines.length) throw new Error(`Unterminated Action output: ${start[1]}`);
    result.set(start[1], value.join("\n"));
  }
  return result;
}

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
    const outputs = actionOutputs(await readFile(output, "utf8"));
    assert.equal(outputs.get("exit_code"), "2");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("stale or hostile findings cannot inject Action outputs", { skip: process.platform === "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "reporook-action-output-injection-"));
  const actionRoot = join(root, "action-root");
  const workspace = join(root, "workspace");
  const output = join(root, "output.txt");
  try {
    await mkdir(join(actionRoot, "cli", "dist"), { recursive: true });
    await mkdir(join(workspace, ".reporook"), { recursive: true });
    await writeFile(join(workspace, ".reporook", "findings.json"), JSON.stringify({
      policy: { summary: { actionable: "0\nforged=true", new: -1, suppressed: 1.5 } },
    }));
    const stub = join(actionRoot, "cli", "dist", "index.js");
    await writeFile(stub, "#!/usr/bin/env node\nprocess.exit(137);\n");
    await chmod(stub, 0o755);
    await execute("bash", [resolve("action/run-scan.sh")], {
      env: { ...process.env, GITHUB_ACTION_PATH: actionRoot, GITHUB_WORKSPACE: workspace, GITHUB_OUTPUT: output, INPUT_MODE: "full" },
    });
    const raw = await readFile(output, "utf8");
    const outputs = actionOutputs(raw);
    assert.equal(outputs.size, 7);
    assert.equal(outputs.get("exit_code"), "2");
    assert.equal(outputs.get("policy_actionable"), "0");
    assert.equal(outputs.get("policy_new"), "0");
    assert.equal(outputs.get("policy_suppressed"), "0");
    assert.equal(outputs.has("forged"), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("operator scan authority is forwarded only by explicit Action inputs", { skip: process.platform === "win32" }, async () => {
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
    await execute("bash", [resolve("action/run-scan.sh")], { env: { ...process.env, GITHUB_ACTION_PATH: actionRoot, GITHUB_WORKSPACE: workspace, GITHUB_OUTPUT: output, INPUT_MODE: "full", INPUT_ALLOW_EXTERNAL_TARGETS: "true", INPUT_ALLOW_REPOSITORY_SUPPRESSIONS: "true", INPUT_SEMGREP_CONFIG: "security/semgrep.yml", REPOROOK_TEST_ARGS: argsPath } });
    const approved = JSON.parse(await readFile(argsPath, "utf8"));
    assert.ok(approved.includes("--allow-external-targets"));
    assert.ok(approved.includes("--allow-repository-suppressions"));
    assert.equal(approved[approved.indexOf("--semgrep-config") + 1], "security/semgrep.yml");

    await execute("bash", [resolve("action/run-scan.sh")], { env: { ...process.env, GITHUB_ACTION_PATH: actionRoot, GITHUB_WORKSPACE: workspace, GITHUB_OUTPUT: output, INPUT_MODE: "full", INPUT_ALLOW_EXTERNAL_TARGETS: "yes", INPUT_ALLOW_REPOSITORY_SUPPRESSIONS: "yes", REPOROOK_TEST_ARGS: argsPath } });
    const denied = JSON.parse(await readFile(argsPath, "utf8"));
    assert.equal(denied.includes("--allow-external-targets"), false);
    assert.equal(denied.includes("--allow-repository-suppressions"), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
