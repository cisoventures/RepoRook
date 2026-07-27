import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultConfig } from "../dist/config.js";
import { scanRepository } from "../dist/engine.js";
import { gitChangedFiles } from "../dist/git.js";
import { inConfiguredScope } from "../dist/incremental.js";
import { CheckovScanner } from "../dist/scanners/checkov.js";
import { NpmAuditScanner } from "../dist/scanners/npm-audit.js";
import { OsvScanner } from "../dist/scanners/osv-scanner.js";
import { PipAuditScanner } from "../dist/scanners/pip-audit.js";
import { SemgrepScanner } from "../dist/scanners/semgrep.js";

function git(target, args) {
  return execFileSync("git", args, { cwd: target, encoding: "utf8" }).trim();
}

async function repository(prefix) {
  const target = await mkdtemp(join(tmpdir(), prefix));
  git(target, ["init", "--quiet"]);
  git(target, ["config", "user.email", "reporook@example.test"]);
  git(target, ["config", "user.name", "RepoRook Test"]);
  await writeFile(join(target, ".gitignore"), ".reporook/\n");
  await writeFile(join(target, "README.md"), "base\n");
  git(target, ["add", "."]);
  git(target, ["commit", "--quiet", "-m", "base"]);
  return target;
}

function successful(name) {
  return { status: { name, applicable: true, available: true, version: "1", status: "ok", finding_count: 0, duration_ms: 1 }, findings: [] };
}

test("changed scans record scanner scope and skip irrelevant adapters before execution", async () => {
  const target = await repository("reporook-incremental-engine-");
  const config = structuredClone(defaultConfig);
  config.cacheEnabled = false;
  const base = git(target, ["rev-parse", "HEAD"]);
  let changedRuns = 0;
  let repositoryRuns = 0;
  const scanners = [
    {
      name: "changed-test",
      async incremental(context) {
        assert.deepEqual(context.changedFiles, ["src/app.ts"]);
        return { applicable: true, scope: "changed-files", scanFiles: ["src/app.ts"] };
      },
      async isApplicable() { throw new Error("incremental scan files already establish applicability"); },
      async run(context) { changedRuns += 1; assert.deepEqual(context.scanFiles, ["src/app.ts"]); return successful("changed-test"); },
    },
    {
      name: "irrelevant-test",
      async incremental() { return { applicable: false, scope: "changed-files", reason: "no relevant files" }; },
      async isApplicable() { throw new Error("must not inspect the full repository"); },
      async run() { throw new Error("must not run"); },
    },
    {
      name: "repository-test",
      async incremental() { return { applicable: true, scope: "repository" }; },
      async isApplicable() { return { applicable: true }; },
      async run() { repositoryRuns += 1; return successful("repository-test"); },
    },
  ];
  try {
    await mkdir(join(target, "src"));
    await writeFile(join(target, "src", "app.ts"), "export {};\n");
    git(target, ["add", "."]);
    git(target, ["commit", "--quiet", "-m", "change"]);
    const report = await scanRepository({ target, config, changedBase: base }, scanners);
    assert.equal(report.coverage_status, "complete");
    assert.equal(changedRuns, 1);
    assert.equal(repositoryRuns, 1);
    assert.deepEqual(report.scan_receipt.changed_files, ["src/app.ts"]);
    assert.deepEqual(report.scan_receipt.scanner_scopes, {
      "changed-test": "changed-files",
      "irrelevant-test": "not-applicable",
      "repository-test": "repository",
    });
    assert.equal(report.scanners.find((item) => item.name === "irrelevant-test").status, "skipped");
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("built-in adapters select only changed files they own in a nested monorepo", async () => {
  const target = await mkdtemp(join(tmpdir(), "reporook-incremental-adapters-"));
  const config = structuredClone(defaultConfig);
  try {
    await Promise.all([
      mkdir(join(target, "src"), { recursive: true }),
      mkdir(join(target, "packages", "api"), { recursive: true }),
      mkdir(join(target, "infrastructure"), { recursive: true }),
    ]);
    await Promise.all([
      writeFile(join(target, "src", "app.ts"), "export {};\n"),
      writeFile(join(target, "docs.md"), "docs\n"),
      writeFile(join(target, "package.json"), "{}\n"),
      writeFile(join(target, "package-lock.json"), "{}\n"),
      writeFile(join(target, "packages", "api", "Cargo.lock"), "# lock\n"),
      writeFile(join(target, "infrastructure", "main.tf"), "resource \"x\" \"y\" {}\n"),
    ]);
    const changedFiles = ["docs.md", "infrastructure/main.tf", "package-lock.json", "package.json", "packages/api/Cargo.lock", "src/app.ts"];
    const context = { target, config, changedFiles };
    assert.deepEqual((await new SemgrepScanner().incremental(context)).scanFiles, ["src/app.ts"]);
    assert.deepEqual((await new NpmAuditScanner().incremental(context)).scanFiles, ["package-lock.json"]);
    assert.deepEqual((await new OsvScanner().incremental(context)).scanFiles, ["packages/api/Cargo.lock"]);
    assert.deepEqual((await new CheckovScanner().incremental(context)).scanFiles, ["infrastructure/main.tf"]);
    assert.equal((await new PipAuditScanner().incremental(context)).applicable, false);
    assert.equal((await new NpmAuditScanner().incremental({ ...context, changedFiles: ["package.json"] })).applicable, false);
    assert.equal(inConfiguredScope("src/app.ts", { ...config, paths: ["src/app.ts"] }), true);
  } finally {
    await rm(target, { recursive: true, force: true });
  }
});

test("Git changed-file discovery preserves unusual filenames without line splitting", async () => {
  if (process.platform === "win32") return;
  const target = await repository("reporook-incremental-paths-");
  const base = git(target, ["rev-parse", "HEAD"]);
  const unusual = "src/line\nbreak.ts";
  try {
    await mkdir(join(target, "src"));
    await writeFile(join(target, unusual), "export {};\n");
    git(target, ["add", "."]);
    git(target, ["commit", "--quiet", "-m", "unusual path"]);
    assert.deepEqual(await gitChangedFiles(target, base), [unusual]);
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});
