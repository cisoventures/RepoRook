import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageVersion = JSON.parse(await readFile(resolve(root, "cli/package.json"), "utf8")).version;
const canonical = await readFile(resolve(root, "adapters/shared/skills/reporook-security/SKILL.md"), "utf8");
const copies = [
  "adapters/claude/reporook/skills/reporook-security/SKILL.md",
  "adapters/codex/reporook/skills/reporook-security/SKILL.md",
  "adapters/cursor/reporook/skills/reporook-security/SKILL.md",
  "adapters/copilot/reporook/skills/reporook-security/SKILL.md",
  "adapters/gemini/reporook/skills/reporook-security/SKILL.md",
  "adapters/windsurf/reporook/.windsurf/skills/reporook-security/SKILL.md"
];
for (const copy of copies) {
  const contents = await readFile(resolve(root, copy), "utf8");
  if (contents !== canonical) throw new Error(`Adapter skill drift: ${copy}`);
}
const manifests = [
  "adapters/claude/reporook/.claude-plugin/plugin.json",
  "adapters/codex/reporook/.codex-plugin/plugin.json",
  "adapters/cursor/reporook/.cursor-plugin/plugin.json",
  "adapters/copilot/reporook/plugin.json",
  "adapters/gemini/reporook/gemini-extension.json"
];
for (const manifest of manifests) {
  const parsed = JSON.parse(await readFile(resolve(root, manifest), "utf8"));
  if (parsed.version !== packageVersion) throw new Error(`Adapter version drift: ${manifest} is ${parsed.version}, expected ${packageVersion}`);
}
const mcpConfigurations = [
  ["adapters/claude/reporook/.mcp.json", "wrapped"],
  ["adapters/codex/reporook/.mcp.json", "direct"],
  ["adapters/cursor/reporook/.mcp.json", "wrapped"],
  ["adapters/copilot/reporook/.mcp.json", "wrapped"],
  ["adapters/gemini/reporook/gemini-extension.json", "wrapped"],
  ["adapters/windsurf/reporook/.mcp.json", "wrapped"],
];
for (const [path, format] of mcpConfigurations) {
  const parsed = JSON.parse(await readFile(resolve(root, path), "utf8"));
  const server = format === "direct" ? parsed.reporook : parsed.mcpServers?.reporook;
  if (server?.command !== "reporook-mcp" || !Array.isArray(server.args) || server.args.length !== 0) {
    throw new Error(`Invalid RepoRook MCP adapter: ${path}`);
  }
}
const executableIntegrationFiles = [
  "adapters/cursor/reporook/hooks/hooks.json",
  "adapters/copilot/reporook/hooks.json",
  ...mcpConfigurations.map(([path]) => path),
];
for (const path of executableIntegrationFiles) {
  const contents = await readFile(resolve(root, path), "utf8");
  if (/\b(?:npx|npm\s+exec|pnpm\s+dlx|bunx)\b/i.test(contents)) {
    throw new Error(`Adapter may bootstrap executable software: ${path}`);
  }
}
const schemas = [
  "schemas/findings.schema.json",
  "schemas/agent-review.schema.json",
  "schemas/verification.schema.json",
  "schemas/priorities.schema.json",
  "schemas/remediation-plan.schema.json",
  "schemas/baseline.schema.json",
  "schemas/suppressions.schema.json",
  "schemas/policy-evaluation.schema.json",
  "schemas/organization-policy.schema.json",
  "schemas/remediation-proposal.schema.json",
  "schemas/approval-receipt.schema.json",
];
for (const schema of schemas) JSON.parse(await readFile(resolve(root, schema), "utf8"));
process.stdout.write(`Validated ${copies.length} skill copies, ${manifests.length} manifests, ${mcpConfigurations.length} MCP configs, ${executableIntegrationFiles.length} executable integration files, and ${schemas.length} schemas.\n`);
