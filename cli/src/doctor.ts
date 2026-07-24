import { resolve } from "node:path";
import { detectProject } from "./initializer.js";
import { commandVersion } from "./process.js";

export interface DoctorCheck { name: string; needed: boolean; available: boolean; version: string | null; reason: string; }

export async function diagnose(targetInput: string): Promise<DoctorCheck[]> {
  const target = resolve(targetInput);
  const profile = await detectProject(target);
  const recommended = new Set(profile.recommended_scanners);
  const specs = [
    { name: "semgrep", needed: recommended.has("semgrep"), reason: "source-code vulnerability checks" },
    { name: "gitleaks", needed: recommended.has("gitleaks"), reason: "secret and credential checks" },
    { name: "npm", needed: recommended.has("npm-audit"), reason: "Node dependency checks" },
    { name: "pip-audit", needed: recommended.has("pip-audit"), reason: "Python dependency checks" },
    { name: "osv-scanner", needed: recommended.has("osv-scanner"), reason: "additional ecosystem dependency checks" },
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
