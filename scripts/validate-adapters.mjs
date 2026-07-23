import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
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
for (const manifest of manifests) JSON.parse(await readFile(resolve(root, manifest), "utf8"));
process.stdout.write(`Validated ${copies.length} skill copies and ${manifests.length} manifests.\n`);
