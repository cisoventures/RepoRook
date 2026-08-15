import test from "node:test";
import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";

test("privileged release workflows do not self-install npm from the registry", async () => {
  const release = await readFile(".github/workflows/release.yml", "utf8");
  assert.doesNotMatch(release, /npm\s+(?:install|i)\s+--global/);
  assert.match(release, /staged trusted publishing requires npm 11\.15\.0 or later/);
  await assert.rejects(access(".github/workflows/bootstrap-service-v0.9.0.yml"), /ENOENT/);
});

test("CodeQL action components stay on one immutable release", async () => {
  const codeqlWorkflow = await readFile(".github/workflows/codeql.yml", "utf8");
  const action = await readFile("action.yml", "utf8");
  const dependabot = await readFile(".github/dependabot.yml", "utf8");
  const references = [...`${codeqlWorkflow}\n${action}`.matchAll(
    /github\/codeql-action\/(init|analyze|upload-sarif)@([0-9a-f]{40}) # v(\d+\.\d+\.\d+)/g,
  )];

  assert.deepEqual(
    references.map((match) => match[1]).sort(),
    ["analyze", "init", "upload-sarif"],
  );
  assert.equal(new Set(references.map((match) => match[2])).size, 1);
  assert.equal(new Set(references.map((match) => match[3])).size, 1);
  assert.match(
    dependabot,
    /groups:\s+codeql-actions:\s+patterns:\s+- "github\/codeql-action\/\*"/,
  );
});

test("Python scanner installation is hash-locked, wheel-only, and disabled without the lock", async () => {
  const installer = await readFile("action/install-python-scanners.sh", "utf8");
  const aggregate = await readFile("action/install-scanners.sh", "utf8");
  assert.doesNotMatch(aggregate, /python3\s+-m\s+pip\s+install/);
  assert.match(installer, /--require-hashes/);
  assert.match(installer, /--only-binary=:all:/);
  assert.match(installer, /--force-reinstall/);
  assert.match(installer, /semgrep==1\.171\.0/);
  assert.match(installer, /pip-audit==2\.10\.1/);
  assert.match(installer, /checkov==3\.3\.8/);
  assert.match(installer, /REPOROOK_PYTHON_SCANNERS_VERIFIED=false/);
  await assert.rejects(access("action/python-scanners.requirements.txt"), /ENOENT/);
});

test("shipped automatic agent hooks preserve repository policy and require every applicable scanner", async () => {
  const expected = "reporook scan . --quiet --require-scanners";
  const copilot = JSON.parse(await readFile("adapters/copilot/reporook/hooks.json", "utf8"));
  const cursor = JSON.parse(await readFile("adapters/cursor/reporook/hooks/hooks.json", "utf8"));
  assert.equal(copilot.hooks?.agentStop?.[0]?.bash, expected);
  assert.equal(copilot.hooks?.agentStop?.[0]?.powershell, expected);
  assert.equal(cursor.hooks?.stop?.[0]?.command, expected);
});
