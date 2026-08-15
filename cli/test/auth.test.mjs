import test from "node:test";
import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { authenticateArtifact, verifyArtifactAuthentication } from "../dist/auth.js";

test("artifact authentication uses a protected host-local key and binds the repository", async () => {
  const cache = await mkdtemp(join(tmpdir(), "reporook-artifact-auth-"));
  const priorKey = process.env.REPOROOK_AUTH_KEY;
  const priorCache = process.env.XDG_CACHE_HOME;
  delete process.env.REPOROOK_AUTH_KEY;
  process.env.XDG_CACHE_HOME = cache;
  try {
    const artifact = authenticateArtifact("/repo/one", { schema_version: "1.0", value: "evidence" });
    assert.doesNotThrow(() => verifyArtifactAuthentication("/repo/one", artifact, "Fixture"));
    assert.throws(() => verifyArtifactAuthentication("/repo/two", artifact, "Fixture"), /different repository|modified/);
    const keyPath = join(cache, "reporook", "artifact-auth-key");
    const metadata = await lstat(keyPath);
    assert.equal(metadata.isFile(), true);
    assert.equal(metadata.size, 32);
    if (process.platform !== "win32") assert.equal(metadata.mode & 0o777, 0o600);
    await chmod(keyPath, 0o644);
    assert.throws(() => authenticateArtifact("/repo/one", { value: "other" }), /unsafe permissions/);
  } finally {
    if (priorKey === undefined) delete process.env.REPOROOK_AUTH_KEY;
    else process.env.REPOROOK_AUTH_KEY = priorKey;
    if (priorCache === undefined) delete process.env.XDG_CACHE_HOME;
    else process.env.XDG_CACHE_HOME = priorCache;
    await rm(cache, { recursive: true, force: true });
  }
});
