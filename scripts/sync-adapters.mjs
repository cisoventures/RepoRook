import { cp, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const canonical = resolve(root, "adapters/shared/skills/reporook-security");
const destinations = [
  "adapters/claude/reporook/skills/reporook-security",
  "adapters/codex/reporook/skills/reporook-security",
  "adapters/cursor/reporook/skills/reporook-security",
  "adapters/copilot/reporook/skills/reporook-security",
  "adapters/gemini/reporook/skills/reporook-security",
  "adapters/windsurf/reporook/.windsurf/skills/reporook-security",
];

for (const destination of destinations) {
  const absolute = resolve(root, destination);
  await mkdir(dirname(absolute), { recursive: true });
  await cp(canonical, absolute, { recursive: true, force: true });
}
process.stdout.write(`Synced RepoRook skill to ${destinations.length} adapters.\n`);
