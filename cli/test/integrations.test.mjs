import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { integrationExitCode, manageIntegrations, parseIntegrationHosts } from "../dist/integrations.js";

async function repository() {
  const target = await mkdtemp(join(tmpdir(), "reporook-integration-test-"));
  await mkdir(join(target, ".git"));
  return target;
}

test("agent integrations preview, install, merge, diagnose, and uninstall safely", async () => {
  const target = await repository();
  try {
    await writeFile(join(target, ".mcp.json"), `${JSON.stringify({ mcpServers: { existing: { command: "existing" } }, keep: true }, null, 2)}\n`, { mode: 0o600 });
    const preview = await manageIntegrations({ target, operation: "install", hosts: parseIntegrationHosts("all") });
    assert.equal(preview.applied, false);
    assert.equal(preview.actions.length, 25);
    assert.equal(preview.actions.every((item) => item.status === "create"), true);
    await assert.rejects(() => stat(join(target, ".reporook", "integrations.json")));

    const installed = await manageIntegrations({ target, operation: "install", hosts: parseIntegrationHosts("all"), apply: true });
    assert.equal(installed.applied, true);
    assert.equal(integrationExitCode(installed), 0);
    const rootMcp = JSON.parse(await readFile(join(target, ".mcp.json"), "utf8"));
    assert.deepEqual(rootMcp.mcpServers.existing, { command: "existing" });
    assert.deepEqual(rootMcp.mcpServers.reporook.args, ["--yes", "@reporook/mcp-server"]);
    assert.equal(rootMcp.keep, true);
    if (process.platform !== "win32") assert.equal((await stat(join(target, ".mcp.json"))).mode & 0o777, 0o600);

    const doctor = await manageIntegrations({ target, operation: "doctor", hosts: parseIntegrationHosts("all") });
    assert.equal(doctor.actions.every((item) => item.status === "ready"), true);
    assert.equal(integrationExitCode(doctor), 0);

    const removed = await manageIntegrations({ target, operation: "uninstall", hosts: parseIntegrationHosts("all"), apply: true });
    assert.equal(removed.applied, true);
    assert.equal(removed.actions.every((item) => item.status === "remove"), true);
    const preservedMcp = JSON.parse(await readFile(join(target, ".mcp.json"), "utf8"));
    assert.deepEqual(preservedMcp, { mcpServers: { existing: { command: "existing" } }, keep: true });
    await assert.rejects(() => stat(join(target, ".cursor", "rules", "reporook.mdc")));
    await assert.rejects(() => stat(join(target, ".reporook", "integrations.json")));
  } finally {
    await rm(target, { recursive: true, force: true });
  }
});

test("integration conflicts block the entire write pass", async () => {
  const target = await repository();
  try {
    await mkdir(join(target, ".cursor", "rules"), { recursive: true });
    await writeFile(join(target, ".cursor", "rules", "reporook.mdc"), "user-owned rule\n");
    const result = await manageIntegrations({ target, operation: "install", hosts: parseIntegrationHosts("cursor"), apply: true });
    assert.equal(result.applied, false);
    assert.equal(integrationExitCode(result), 2);
    assert.equal(result.actions.some((item) => item.status === "modified"), true);
    await assert.rejects(() => stat(join(target, ".cursor", "mcp.json")));
    await assert.rejects(() => stat(join(target, ".reporook", "integrations.json")));
    assert.equal(await readFile(join(target, ".cursor", "rules", "reporook.mdc"), "utf8"), "user-owned rule\n");
  } finally {
    await rm(target, { recursive: true, force: true });
  }
});

test("updates replace receipt-owned old content but uninstall refuses user edits", async () => {
  const target = await repository();
  try {
    await manageIntegrations({ target, operation: "install", hosts: parseIntegrationHosts("windsurf"), apply: true });
    const skillPath = join(target, ".windsurf", "skills", "reporook-security", "SKILL.md");
    const receiptPath = join(target, ".reporook", "integrations.json");
    const oldContents = "---\nname: reporook-security\ndescription: old managed copy\n---\n";
    await writeFile(skillPath, oldContents);
    const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
    const entry = receipt.hosts.windsurf.entries.find((item) => item.path.endsWith("SKILL.md"));
    entry.hash = `sha256:${createHash("sha256").update(oldContents).digest("hex")}`;
    receipt.hosts.windsurf.version = "0.0.1";
    await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);

    const updated = await manageIntegrations({ target, operation: "update", hosts: parseIntegrationHosts("windsurf"), apply: true });
    assert.equal(updated.applied, true);
    assert.equal(updated.actions.find((item) => item.path.endsWith("SKILL.md"))?.status, "update");
    assert.match(await readFile(skillPath, "utf8"), /deterministic evidence layer/i);

    await writeFile(skillPath, `${await readFile(skillPath, "utf8")}user edit\n`);
    const refused = await manageIntegrations({ target, operation: "uninstall", hosts: parseIntegrationHosts("windsurf"), apply: true });
    assert.equal(refused.applied, false);
    assert.equal(integrationExitCode(refused), 2);
    assert.equal(refused.actions.find((item) => item.path.endsWith("SKILL.md"))?.status, "modified");
    assert.match(await readFile(skillPath, "utf8"), /user edit/);
    assert.equal((await stat(join(target, ".windsurf", "rules", "reporook.md"))).isFile(), true);
  } finally {
    await rm(target, { recursive: true, force: true });
  }
});

test("malformed host JSON is rejected without rewriting it", async () => {
  const target = await repository();
  try {
    await writeFile(join(target, ".mcp.json"), '{"mcpServers":"not-an-object"}\n');
    await assert.rejects(
      () => manageIntegrations({ target, operation: "install", hosts: parseIntegrationHosts("claude"), apply: true }),
      /JSON path is not an object/,
    );
    assert.equal(await readFile(join(target, ".mcp.json"), "utf8"), '{"mcpServers":"not-an-object"}\n');
    await assert.rejects(() => stat(join(target, ".claude", "skills", "reporook-security", "SKILL.md")));
  } finally {
    await rm(target, { recursive: true, force: true });
  }
});

test("a tampered receipt cannot make uninstall target arbitrary repository files", async () => {
  const target = await repository();
  try {
    await manageIntegrations({ target, operation: "install", hosts: parseIntegrationHosts("windsurf"), apply: true });
    const protectedPath = join(target, "README.md");
    const protectedContents = "do not delete\n";
    await writeFile(protectedPath, protectedContents);
    const receiptPath = join(target, ".reporook", "integrations.json");
    const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
    receipt.hosts.windsurf.entries[0].id = "README.md";
    receipt.hosts.windsurf.entries[0].path = "README.md";
    receipt.hosts.windsurf.entries[0].hash = `sha256:${createHash("sha256").update(protectedContents).digest("hex")}`;
    await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);

    await assert.rejects(
      () => manageIntegrations({ target, operation: "uninstall", hosts: parseIntegrationHosts("windsurf"), apply: true }),
      /outside the windsurf allowlist/,
    );
    assert.equal(await readFile(protectedPath, "utf8"), protectedContents);
  } finally {
    await rm(target, { recursive: true, force: true });
  }
});
