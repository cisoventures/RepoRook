import type { Finding, ScanReport, ScannerStatus } from "./types.js";

export interface VerificationResult {
  scanner_resolution: "passed" | "failed" | "inconclusive";
  reason: string;
  remaining_finding: Finding | null;
  original_scanner_status: ScannerStatus | null;
  config_unchanged: boolean | null;
}

function scannerStatus(report: ScanReport, scanner: string): ScannerStatus | undefined {
  return report.scanners.find((value) => value.name === scanner);
}

export function verifyFindingResolution(previous: ScanReport, current: ScanReport, findingId: string, requiredCoverageFailed = false): VerificationResult {
  const original = previous.findings.find((finding) => finding.id === findingId);
  if (!original) throw new Error(`Finding not found: ${findingId}`);

  const status = scannerStatus(current, original.scanner);
  const previousHash = previous.scan_receipt.config_hash || null;
  const currentHash = current.scan_receipt.config_hash || null;
  const configUnchanged = previousHash && currentHash ? previousHash === currentHash : null;

  if (!status || status.status !== "ok") {
    return {
      scanner_resolution: "inconclusive",
      reason: `The original ${original.scanner} scanner did not complete successfully, so disappearance is not evidence of a fix.`,
      remaining_finding: null,
      original_scanner_status: status ?? null,
      config_unchanged: configUnchanged,
    };
  }
  if (configUnchanged !== true) {
    return {
      scanner_resolution: "inconclusive",
      reason: previousHash && currentHash
        ? "The RepoRook configuration changed; a finding may have been hidden or excluded rather than fixed."
        : "The scan receipts do not contain comparable configuration hashes.",
      remaining_finding: null,
      original_scanner_status: status,
      config_unchanged: configUnchanged,
    };
  }

  const remaining = current.findings.find((finding) =>
    finding.id === original.id
    || finding.fingerprint === original.fingerprint
    || (finding.scanner === original.scanner && finding.rule === original.rule && finding.file === original.file),
  );
  if (!remaining && requiredCoverageFailed) {
    return {
      scanner_resolution: "inconclusive",
      reason: "The original finding disappeared, but at least one required scanner did not complete. Treat the remediation as inconclusive.",
      remaining_finding: null,
      original_scanner_status: status,
      config_unchanged: true,
    };
  }
  return {
    scanner_resolution: remaining ? "failed" : "passed",
    reason: remaining
      ? "The original finding or an equivalent finding from the same scanner, rule, and file remains."
      : "The original scanner completed under the same configuration and no equivalent finding remains.",
    remaining_finding: remaining ?? null,
    original_scanner_status: status,
    config_unchanged: true,
  };
}
