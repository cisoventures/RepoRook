import test from "node:test";
import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";

async function source(path) {
  return (await readFile(path, "utf8")).replace(/\r\n/g, "\n");
}

test("privileged release workflows do not self-install npm from the registry", async () => {
  const release = await source(".github/workflows/release.yml");
  assert.doesNotMatch(release, /npm\s+(?:install|i)\s+--global/);
  assert.match(release, /does not support trusted staged publishing/);
  assert.match(release, /validate-and-pack:/);
  assert.match(release, /release:\n    needs: validate-and-pack/);
  assert.match(release, /test "\$GITHUB_SHA" = "\$main_commit"/);
  assert.match(release, /npm stage publish[^\n]+--ignore-scripts/g);
  assert.equal((release.match(/persist-credentials: false/g) ?? []).length, 1);
  const privileged = release.slice(release.indexOf("\n  release:"));
  assert.doesNotMatch(privileged, /npm ci|npm run check|npm pack|node scripts\//);
  assert.doesNotMatch(privileged, /uses: \.\//);
  assert.doesNotMatch(privileged, /actions\/checkout|git fetch|require\('\.\//);
  await assert.rejects(access(".github/workflows/bootstrap-service-v0.9.0.yml"), /ENOENT/);
});

test("published Action examples use immutable source revisions", async () => {
  const paths = ["README.md", "action/README.md", "docs/QUICKSTART.md"];
  for (const path of paths) {
    const document = await source(path);
    assert.doesNotMatch(document, /uses:\s+[^\s]+@(?:v|main|master|latest)/);
    assert.match(document, /actions\/checkout@[0-9a-f]{40} # v7/);
    assert.match(document, /cisoventures\/RepoRook@755ff83b9d341b2b9a1cb528dd068545c1e136fc # v1\.0\.0 source pin/);
    assert.match(document, /persist-credentials: false/);
  }
});

test("the repository self-scan executes pull-request code without write permissions", async () => {
  const workflow = await source(".github/workflows/reporook-example.yml");
  assert.match(workflow, /permissions:\n  contents: read/);
  assert.doesNotMatch(workflow, /pull-requests: write|security-events: write/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /upload-sarif: "false"/);
  assert.match(workflow, /comment-pr: "false"/);
});

test("fixture security journeys cannot be skipped by a missing optional scanner lock", async () => {
  const workflow = await source(".github/workflows/ci.yml");
  for (const command of ["fixture:verify", "fixture:guided", "fixture:policy"]) {
    const line = workflow.indexOf(`run: npm run ${command}`);
    assert.ok(line >= 0);
    assert.doesNotMatch(workflow.slice(Math.max(0, line - 120), line), /hashFiles/);
  }
});

test("CodeQL action components stay on one immutable release", async () => {
  const codeqlWorkflow = await source(".github/workflows/codeql.yml");
  const action = await source("action.yml");
  const dependabot = await source(".github/dependabot.yml");
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
  const installer = await source("action/install-python-scanners.sh");
  const aggregate = await source("action/install-scanners.sh");
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
  const copilot = JSON.parse(await source("adapters/copilot/reporook/hooks.json"));
  const cursor = JSON.parse(await source("adapters/cursor/reporook/hooks/hooks.json"));
  assert.equal(copilot.hooks?.agentStop?.[0]?.bash, expected);
  assert.equal(copilot.hooks?.agentStop?.[0]?.powershell, expected);
  assert.equal(cursor.hooks?.stop?.[0]?.command, expected);
});
