type JsonRecord = Record<string, unknown>;

function record(value: unknown): JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : {};
}

function reportFindings(report: JsonRecord): JsonRecord[] {
  return Array.isArray(report.findings) ? report.findings.filter((value): value is JsonRecord => Boolean(value) && typeof value === "object" && !Array.isArray(value)) : [];
}

function scannerStatus(report: JsonRecord, scanner: string): JsonRecord | undefined {
  if (!Array.isArray(report.scanners)) return undefined;
  return report.scanners.find((value): value is JsonRecord => Boolean(value) && typeof value === "object" && !Array.isArray(value) && value.name === scanner);
}

function configHash(report: JsonRecord): string | null {
  const value = record(report.scan_receipt).config_hash;
  return typeof value === "string" && value ? value : null;
}

export interface VerificationResult {
  scanner_resolution: "passed" | "failed" | "inconclusive";
  reason: string;
  remaining_finding: JsonRecord | null;
  original_scanner_status: JsonRecord | null;
  config_unchanged: boolean | null;
}

export function verifyFindingResolution(previous: JsonRecord, current: JsonRecord, findingId: string): VerificationResult {
  const original = reportFindings(previous).find((finding) => finding.id === findingId);
  if (!original) throw new Error(`Finding not found: ${findingId}`);
  const scanner = typeof original.scanner === "string" ? original.scanner : "";
  if (!scanner) throw new Error(`Finding ${findingId} does not identify its scanner`);

  const status = scannerStatus(current, scanner);
  const previousHash = configHash(previous);
  const currentHash = configHash(current);
  const configUnchanged = previousHash && currentHash ? previousHash === currentHash : null;

  if (!status || status.status !== "ok") {
    return {
      scanner_resolution: "inconclusive",
      reason: `The original ${scanner} scanner did not complete successfully, so disappearance is not evidence of a fix.`,
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

  const remaining = reportFindings(current).find((finding) =>
    finding.id === original.id
    || finding.fingerprint === original.fingerprint
    || (finding.scanner === original.scanner && finding.rule === original.rule && finding.file === original.file),
  );
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
