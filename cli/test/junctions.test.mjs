import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { artifactPath } from "../dist/artifacts.js";
import { loadConfig } from "../dist/config.js";
import { manageIntegrations } from "../dist/integrations.js";
import { createDirectoryLink, removeDirectoryLink } from "../../test-support/path-links.mjs";

test("CLI path boundaries reject linked directories including Windows junctions", async () => {
  const repository = await mkdtemp(join(tmpdir(), "reporook-cli-junction-repository-"));
  const outside = await mkdtemp(join(tmpdir(), "reporook-cli-junction-outside-"));
  const linked = join(repository, "linked");
  const cursor = join(repository, ".cursor");
  try {
    await mkdir(join(repository, ".git"));
    await writeFile(join(outside, "config.yml"), "failOn: low\n");
    await writeFile(join(outside, "policy.yml"), "schemaVersion: \"1.0\"\nname: outside\nfailOn: high\nrequiredScanners: []\npathPolicies:\n");
    await createDirectoryLink(outside, linked);

    assert.throws(() => artifactPath(repository, "linked/findings.json"), /symbolic link/);
    await assert.rejects(loadConfig(repository, "linked/config.yml"), /symbolic link/);
    await writeFile(join(repository, "reporook.yml"), "organizationPolicy: linked/policy.yml\n");
    await assert.rejects(loadConfig(repository), /symbolic link/);

    await createDirectoryLink(outside, cursor);
    await assert.rejects(
      manageIntegrations({ target: repository, operation: "install", hosts: ["cursor"] }),
      /symbolic link/,
    );
    await assert.rejects(readFile(join(outside, "mcp.json")), /ENOENT/);
  } finally {
    await removeDirectoryLink(cursor);
    await removeDirectoryLink(linked);
    await rm(repository, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});
