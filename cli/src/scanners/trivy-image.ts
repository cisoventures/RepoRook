import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { findingFingerprint } from "../fingerprint.js";
import { runCommand } from "../process.js";
import { normalizeSeverity } from "../severity.js";
import type { Finding, RepoRookConfig, ScannerAdapter, ScannerContext, ScannerResult } from "../types.js";
import { array, errored, jsonFromOutput, record, scannerParseError, scannerVersion, strings, successful, text, unavailable } from "./shared.js";

function unique(values: string[]): string[] { return values.filter((value, index) => value && values.indexOf(value) === index); }

function fixedVersions(value: unknown): string[] {
  return unique(text(value).split(/[\s,]+/).map((item) => item.trim()).filter(Boolean));
}

export function parseTrivyImage(raw: unknown, image: string): Finding[] {
  const root = record(raw);
  const findings: Finding[] = [];
  for (const resultValue of array(root.Results)) {
    const result = record(resultValue);
    const component = text(result.Target, image);
    const resultType = text(result.Type, "unknown");
    for (const vulnerabilityValue of array(result.Vulnerabilities)) {
      const vulnerability = record(vulnerabilityValue);
      const advisory = text(vulnerability.VulnerabilityID, "UNKNOWN-VULNERABILITY");
      const packageName = text(vulnerability.PkgName, "unknown-package");
      const installedVersion = text(vulnerability.InstalledVersion) || null;
      const fixed_versions = fixedVersions(vulnerability.FixedVersion);
      const rawSeverity = text(vulnerability.Severity) || null;
      const primary = text(vulnerability.PrimaryURL);
      const references = unique([primary, ...strings(vulnerability.References)]).filter((value) => /^https?:\/\//i.test(value)).slice(0, 10);
      const ids = findingFingerprint(["trivy-image", image, component, packageName, advisory]);
      findings.push({
        ...ids,
        scanner: "trivy-image",
        rule: `trivy-image:${advisory}`,
        severity: normalizeSeverity(rawSeverity, "medium"),
        file: `container-image:${image}`,
        line: 1,
        plain_summary: `The ${packageName} package inside container image ${image} has a known security flaw.`,
        description: text(vulnerability.Title, text(vulnerability.Description, `${packageName} is affected by ${advisory}.`)),
        remediation_hint: fixed_versions.length
          ? `Rebuild ${image} with ${packageName} ${fixed_versions.join(" or ")} or later, run the image tests, and scan the rebuilt immutable image reference.`
          : `Review ${advisory}, update or replace the affected image package, then test and rescan the rebuilt immutable image reference.`,
        references,
        metadata: {
          cwe: strings(vulnerability.CweIDs),
          cve: /^CVE-/i.test(advisory) ? [advisory.toUpperCase()] : [],
          package: packageName,
          installed_version: installedVersion,
          fixed_versions,
          raw_severity: rawSeverity,
          tags: [`component:${component}`, `type:${resultType}`],
          target_kind: "container-image",
          target: image,
        },
      });
    }
  }
  return findings;
}

export class TrivyImageScanner implements ScannerAdapter {
  name = "trivy-image";

  async isApplicable(_target: string, config?: RepoRookConfig) {
    return config?.containerImages.length
      ? { applicable: true }
      : { applicable: false, reason: "no explicit containerImages targets configured; RepoRook never guesses or builds images" };
  }
  async incremental(_context: ScannerContext) { return { applicable: true, scope: "external-targets" as const }; }
  async version() { return scannerVersion("trivy"); }

  async run(context: ScannerContext): Promise<ScannerResult> {
    const started = Date.now();
    const version = context.scannerVersion !== undefined ? context.scannerVersion : await scannerVersion("trivy");
    if (!version) return unavailable(this.name, Date.now() - started, "trivy is not installed; run `reporook setup`");
    const temporary = await mkdtemp(join(tmpdir(), "reporook-trivy-"));
    const configPath = join(temporary, "trivy.yaml");
    await writeFile(configPath, "---\n", { encoding: "utf8", mode: 0o600 });
    const findings: Finding[] = [];
    let duration_ms = 0;
    try {
      for (const image of context.config.containerImages) {
        const result = await runCommand("trivy", [
          "--config", configPath,
          "--cache-dir", join(temporary, "cache"),
          "image",
          "--format", "json",
          "--quiet",
          "--scanners", "vuln",
          "--skip-version-check",
          image,
        ], { cwd: temporary });
        duration_ms += result.duration_ms;
        if (result.missing) return unavailable(this.name, duration_ms, "trivy is not installed");
        try {
          const parsed = parseTrivyImage(jsonFromOutput(result.stdout, result.stderr), image);
          findings.push(...parsed);
        } catch (error) {
          return errored(this.name, version, duration_ms, `${image}: ${scannerParseError(error, result.stderr)}`);
        }
        if (result.code !== 0) {
          const failed = errored(this.name, version, duration_ms, `${image}: ${result.stderr.trim() || `trivy exited ${result.code}`}`);
          failed.findings = findings;
          failed.status.finding_count = findings.length;
          return failed;
        }
      }
      return successful(this.name, version, duration_ms, findings);
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  }
}
