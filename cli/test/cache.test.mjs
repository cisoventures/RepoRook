import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readScannerCache, scannerCacheKey, writeScannerCache } from "../dist/cache.js";
import { defaultConfig } from "../dist/config.js";
import { scanRepository } from "../dist/engine.js";

const testCacheHome = await mkdtemp(join(tmpdir(), "reporook-cache-auth-"));
process.env.XDG_CACHE_HOME = testCacheHome;
test.after(async () => {
  delete process.env.XDG_CACHE_HOME;
  await rm(testCacheHome, { recursive: true, force: true });
});

const finding = {
  id: "rr-eeeeeeeeeeee",
  scanner: "fake",
  rule: "fake.rule",
  severity: "high",
  file: "src/app.js",
  line: 1,
  plain_summary: "An unsafe operation can be reached.",
  description: "Unsafe operation",
  remediation_hint: "Use the safe operation.",
  fingerprint: `sha256:${"e".repeat(64)}`,
  references: [],
  metadata: { cwe: ["CWE-1"], cve: [], package: null, raw_severity: "HIGH" },
};

async function cleanRepository(prefix) {
  const target = await mkdtemp(join(tmpdir(), prefix));
  execFileSync("git", ["init", "--quiet"], { cwd: target });
  execFileSync("git", ["config", "user.email", "reporook@example.test"], { cwd: target });
  execFileSync("git", ["config", "user.name", "RepoRook Test"], { cwd: target });
  await writeFile(join(target, ".gitignore"), ".reporook/\n");
  await writeFile(join(target, "README.md"), "initial\n");
  execFileSync("git", ["add", ".gitignore", "README.md"], { cwd: target });
  execFileSync("git", ["commit", "--quiet", "-m", "fixture"], { cwd: target });
  return target;
}

function successfulResult(scanner, version, findings = []) {
  return {
    status: {
      name: scanner,
      applicable: true,
      available: true,
      version,
      status: "ok",
      finding_count: findings.length,
      duration_ms: 7,
    },
    findings,
  };
}

test("scanner cache resumes clean commits and invalidates on refresh, config, version, or local changes", async () => {
  const target = await cleanRepository("reporook-cache-engine-");
  const config = structuredClone(defaultConfig);
  let runs = 0;
  let version = "fake 1.0";
  const scanner = {
    name: "fake",
    async isApplicable() { return { applicable: true }; },
    async version() { return version; },
    async run(context) {
      runs += 1;
      if (context.scannerVersion !== undefined) assert.equal(context.scannerVersion, version);
      return successfulResult("fake", version, [finding]);
    },
  };
  try {
    const first = await scanRepository({ target, config }, [scanner]);
    assert.equal(runs, 1);
    assert.equal(first.scanners[0].reason, undefined);

    const cached = await scanRepository({ target, config }, [scanner]);
    assert.equal(runs, 1);
    assert.match(cached.scanners[0].reason, /cached successful evidence/);
    assert.equal(cached.scanners[0].duration_ms, 0);

    await scanRepository({ target, config, refreshCache: true }, [scanner]);
    assert.equal(runs, 2);

    config.failOn = "low";
    await scanRepository({ target, config }, [scanner]);
    assert.equal(runs, 3);

    version = "fake 2.0";
    await scanRepository({ target, config }, [scanner]);
    assert.equal(runs, 4);

    await writeFile(join(target, "README.md"), "dirty\n");
    await scanRepository({ target, config }, [scanner]);
    await scanRepository({ target, config }, [scanner]);
    assert.equal(runs, 6, "tracked working-tree changes must disable both cache reads and writes");

    await writeFile(join(target, "README.md"), "initial\n");
    const cleanAgain = await scanRepository({ target, config }, [scanner]);
    assert.equal(runs, 6);
    assert.match(cleanAgain.scanners[0].reason, /cached successful evidence/);

    await writeFile(join(target, "new-source.js"), "export {};\n");
    await scanRepository({ target, config }, [scanner]);
    assert.equal(runs, 7, "relevant untracked files must disable cache reuse");

    const files = await readdir(join(target, ".reporook", "cache", "v1", "fake"));
    assert.ok(files.length >= 2);
    if (process.platform !== "win32") {
      for (const file of files) assert.equal((await stat(join(target, ".reporook", "cache", "v1", "fake", file))).mode & 0o777, 0o600);
    }
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("failed scans retry but never become resumable checkpoints", async () => {
  const target = await cleanRepository("reporook-cache-retry-");
  const config = structuredClone(defaultConfig);
  config.scannerRetries = 1;
  let calls = 0;
  let failuresRemaining = Number.POSITIVE_INFINITY;
  const scanner = {
    name: "fake-retry",
    async isApplicable() { return { applicable: true }; },
    async version() { return "fake-retry 1.0"; },
    async run() {
      calls += 1;
      if (failuresRemaining > 0) {
        failuresRemaining -= 1;
        return {
          status: { name: "fake-retry", applicable: true, available: true, version: "fake-retry 1.0", status: "error", finding_count: 0, duration_ms: 3, reason: "temporary failure" },
          findings: [],
        };
      }
      return successfulResult("fake-retry", "fake-retry 1.0");
    },
  };
  try {
    const first = await scanRepository({ target, config }, [scanner]);
    const second = await scanRepository({ target, config }, [scanner]);
    assert.equal(calls, 4);
    assert.equal(first.scanners[0].status, "error");
    assert.match(second.scanners[0].reason, /failed after 2 attempts/);
    await assert.rejects(() => readdir(join(target, ".reporook", "cache", "v1", "fake-retry")), /ENOENT/);

    calls = 0;
    failuresRemaining = 1;
    const recovered = await scanRepository({ target, config }, [scanner]);
    assert.equal(calls, 2);
    assert.equal(recovered.scanners[0].status, "ok");
    assert.match(recovered.scanners[0].reason, /completed after 1 retry/);

    const resumed = await scanRepository({ target, config }, [scanner]);
    assert.equal(calls, 2);
    assert.match(resumed.scanners[0].reason, /cached successful evidence/);
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("cache records are content-addressed, freshness-bounded, and strictly reconstructed", async () => {
  const target = await cleanRepository("reporook-cache-record-");
  const config = structuredClone(defaultConfig);
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: target, encoding: "utf8" }).trim();
  const key = scannerCacheKey({ commit, scanner: "fake", scannerVersion: "fake 1.0", config });
  const created = new Date("2026-07-26T12:00:00.000Z");
  try {
    await writeScannerCache({ target, scanner: "fake", version: "fake 1.0", key, result: successfulResult("fake", "fake 1.0", [finding]), now: created });
    const current = await readScannerCache({ target, scanner: "fake", version: "fake 1.0", key, ttlMs: 60_000, now: new Date(created.getTime() + 30_000) });
    assert.equal(current?.findings[0].id, finding.id);
    assert.match(current?.status.reason ?? "", /30s old/);

    const stale = await readScannerCache({ target, scanner: "fake", version: "fake 1.0", key, ttlMs: 60_000, now: new Date(created.getTime() + 60_001) });
    assert.equal(stale, null);
    assert.notEqual(key, scannerCacheKey({ commit, scanner: "fake", scannerVersion: "fake 2.0", config }));
    assert.notEqual(key, scannerCacheKey({ commit, scanner: "fake", scannerVersion: "fake 1.0", config: { ...config, failOn: "low" } }));

    const path = join(target, ".reporook", "cache", "v1", "fake", `${key}.json`);
    const record = JSON.parse(await readFile(path, "utf8"));
    record.result.status.finding_count = 99;
    await writeFile(path, `${JSON.stringify(record)}\n`);
    const poisoned = await readScannerCache({ target, scanner: "fake", version: "fake 1.0", key, ttlMs: 60_000, now: new Date(created.getTime() + 30_000) });
    assert.equal(poisoned, null);
  } finally {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});
