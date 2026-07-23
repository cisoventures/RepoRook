import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { findingFingerprint } from "../fingerprint.js";
import { plainSummary } from "../knowledge.js";
import { repoRelative } from "../path-utils.js";
import { runCommand } from "../process.js";
import type { Finding, ScannerAdapter, ScannerContext, ScannerResult } from "../types.js";
import { array, errored, record, scannerVersion, strings, successful, text, unavailable } from "./shared.js";

export function parseGitleaks(raw: unknown, target: string): Finding[] {
  return array(raw).map((item) => {
    const result = record(item);
    const rule = text(result.RuleID, "gitleaks.unknown");
    const file = repoRelative(target, text(result.File));
    const sourceFingerprint = text(result.Fingerprint).replace(/:\d+$/g, "") || text(result.Description);
    const ids = findingFingerprint(["gitleaks", rule, file, sourceFingerprint]);
    return {
      ...ids,
      scanner: "gitleaks",
      rule,
      severity: "critical",
      file,
      line: Number(result.StartLine ?? 1),
      end_line: Number(result.EndLine ?? result.StartLine ?? 1),
      column: Number(result.StartColumn ?? 1),
      plain_summary: plainSummary({ scanner: "gitleaks", rule, cwes: ["CWE-798"] }),
      description: text(result.Description, "A credential or secret may be committed in this file."),
      remediation_hint: "Remove the secret from code and history, rotate it with the provider, and load its replacement from a secret store or environment variable.",
      references: ["https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning"],
      metadata: { cwe: ["CWE-798"], cve: [], package: null, raw_severity: "secret", tags: strings(result.Tags) },
    } satisfies Finding;
  });
}

export class GitleaksScanner implements ScannerAdapter {
  name = "gitleaks";
  async isApplicable() { return { applicable: true }; }

  async run(context: ScannerContext): Promise<ScannerResult> {
    const started = Date.now();
    const version = await scannerVersion("gitleaks");
    if (!version) return unavailable(this.name, Date.now() - started, "gitleaks is not installed; run `reporook setup`");
    const temporary = await mkdtemp(join(tmpdir(), "reporook-gitleaks-"));
    const reportPath = join(temporary, "report.json");
    try {
      let result = await runCommand("gitleaks", ["dir", context.target, "--report-format", "json", "--report-path", reportPath, "--redact"], { cwd: context.target });
      if (![0, 1].includes(result.code) && /unknown command|accepts|usage/i.test(result.stderr)) {
        result = await runCommand("gitleaks", ["detect", "--source", context.target, "--report-format", "json", "--report-path", reportPath, "--redact", "--no-git"], { cwd: context.target });
      }
      if (result.missing) return unavailable(this.name, result.duration_ms, "gitleaks is not installed");
      if (![0, 1].includes(result.code)) return errored(this.name, version, result.duration_ms, result.stderr.trim() || `gitleaks exited ${result.code}`);
      let raw: unknown = [];
      try { raw = JSON.parse(await readFile(reportPath, "utf8")); } catch { raw = []; }
      return successful(this.name, version, result.duration_ms, parseGitleaks(raw, context.target));
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  }
}
