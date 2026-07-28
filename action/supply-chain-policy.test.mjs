import test from "node:test";
import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";

test("privileged release workflows do not self-install npm from the registry", async () => {
  const release = await readFile(".github/workflows/release.yml", "utf8");
  assert.doesNotMatch(release, /npm\s+(?:install|i)\s+--global/);
  assert.match(release, /staged trusted publishing requires npm 11\.15\.0 or later/);
  await assert.rejects(access(".github/workflows/bootstrap-service-v0.9.0.yml"), /ENOENT/);
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

test("shipped quiet Copilot hooks require every applicable scanner", async () => {
  const hooks = JSON.parse(await readFile("adapters/copilot/reporook/hooks.json", "utf8"));
  const commands = hooks.hooks?.agentStop?.[0];
  assert.equal(commands?.bash, "reporook scan . --quiet --fail-on critical --require-scanners");
  assert.equal(commands?.powershell, "reporook scan . --quiet --fail-on critical --require-scanners");
});
