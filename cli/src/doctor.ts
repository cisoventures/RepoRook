import { access, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { commandVersion } from "./process.js";

async function exists(path: string): Promise<boolean> { try { await access(path); return true; } catch { return false; } }

export interface DoctorCheck { name: string; needed: boolean; available: boolean; version: string | null; reason: string; }

export async function diagnose(targetInput: string): Promise<DoctorCheck[]> {
  const target = resolve(targetInput);
  const names = await readdir(target).catch(() => [] as string[]);
  const codeNeeded = names.some((name) => /\.(js|jsx|ts|tsx|py|go|java|rb|php|cs|rs|kt|swift)$/i.test(name)) || names.some((name) => ["src", "app", "lib"].includes(name));
  const npmNeeded = await exists(join(target, "package-lock.json"));
  const pipNeeded = names.some((name) => /^requirements.*\.txt$/i.test(name)) || await exists(join(target, "poetry.lock")) || await exists(join(target, "uv.lock"));
  const specs = [
    { name: "semgrep", needed: codeNeeded, reason: "source-code vulnerability checks" },
    { name: "gitleaks", needed: true, reason: "secret and credential checks" },
    { name: "npm", needed: npmNeeded, reason: "Node dependency checks" },
    { name: "pip-audit", needed: pipNeeded, reason: "Python dependency checks" },
  ];
  return await Promise.all(specs.map(async (spec) => {
    const version = await commandVersion(spec.name);
    return { ...spec, available: version !== null, version };
  }));
}

export function renderDoctor(checks: DoctorCheck[]): string {
  const lines = ["RepoRook environment check", ""];
  for (const check of checks) {
    if (!check.needed) lines.push(`- ${check.name}: not needed for this repository`);
    else if (check.available) lines.push(`✓ ${check.name}: ready (${check.version})`);
    else lines.push(`! ${check.name}: missing — needed for ${check.reason}`);
  }
  const missing = checks.filter((check) => check.needed && !check.available);
  if (missing.length) lines.push("", "Coverage will be incomplete. Run `reporook setup` for installation commands.");
  else lines.push("", "All applicable deterministic scanners are ready.");
  return lines.join("\n");
}
