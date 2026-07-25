import { resolve } from "node:path";
import { loadConfig } from "./config.js";
import { detectProject } from "./initializer.js";
import { commandVersion } from "./process.js";

export interface DoctorCheck { name: string; needed: boolean; available: boolean; version: string | null; reason: string; }

export async function diagnose(targetInput: string, requestedConfig?: string): Promise<DoctorCheck[]> {
  const target = resolve(targetInput);
  const profile = await detectProject(target);
  const { config } = await loadConfig(target, requestedConfig);
  const recommended = new Set(profile.recommended_scanners);
  const specs = [
    { name: "semgrep", command: "semgrep", scanner: "semgrep", reason: "source-code vulnerability checks" },
    { name: "gitleaks", command: "gitleaks", scanner: "gitleaks", reason: config.gitHistory ? "working-tree and opt-in Git-history secret checks" : "working-tree secret and credential checks" },
    { name: "npm", command: "npm", scanner: "npm-audit", reason: "Node dependency checks" },
    { name: "pip-audit", command: "pip-audit", scanner: "pip-audit", reason: "Python dependency checks" },
    { name: "osv-scanner", command: "osv-scanner", scanner: "osv-scanner", reason: "additional ecosystem dependency checks" },
    { name: "checkov", command: "checkov", scanner: "checkov", reason: "Terraform, Kubernetes, Dockerfile, and GitHub Actions checks" },
    { name: "trivy-image", command: "trivy", scanner: "trivy-image", reason: "explicitly configured container image checks" },
  ];
  return await Promise.all(specs.map(async (spec) => {
    const neededByTarget = recommended.has(spec.scanner) || (spec.scanner === "trivy-image" && config.containerImages.length > 0);
    const needed = config.scanners[spec.scanner] !== false && (neededByTarget || config.requiredScanners.includes(spec.scanner));
    const version = needed ? await commandVersion(spec.command) : null;
    return { name: spec.name, needed, reason: spec.reason, available: version !== null, version };
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
