import { commandVersion } from "../process.js";
import type { Finding, ScannerResult, ScannerRunStatus, ScannerStatus } from "../types.js";

export function text(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

export function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

export function strings(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap((item) => typeof item === "string" ? [item] : []);
  return typeof value === "string" ? [value] : [];
}

export async function scannerVersion(command: string): Promise<string | null> {
  return await commandVersion(command);
}

export function status(
  name: string,
  options: Partial<ScannerStatus> & Pick<ScannerStatus, "applicable" | "available" | "status">,
): ScannerStatus {
  return {
    name,
    applicable: options.applicable,
    available: options.available,
    version: options.version ?? null,
    status: options.status as ScannerRunStatus,
    finding_count: options.finding_count ?? 0,
    duration_ms: options.duration_ms ?? 0,
    ...(options.reason ? { reason: options.reason } : {}),
  };
}

export function unavailable(name: string, duration_ms: number, reason: string): ScannerResult {
  return { status: status(name, { applicable: true, available: false, status: "skipped", duration_ms, reason }), findings: [] };
}

export function errored(name: string, version: string | null, duration_ms: number, reason: string): ScannerResult {
  return { status: status(name, { applicable: true, available: true, version, status: "error", duration_ms, reason }), findings: [] };
}

export function successful(name: string, version: string | null, duration_ms: number, findings: Finding[]): ScannerResult {
  return { status: status(name, { applicable: true, available: true, version, status: "ok", duration_ms, finding_count: findings.length }), findings };
}

export function jsonFromOutput(stdout: string, stderr: string): unknown {
  const candidates = [stdout.trim(), stderr.trim()].filter(Boolean);
  for (const candidate of candidates) {
    try {
      return JSON.parse(candidate);
    } catch {
      const start = Math.min(...[candidate.indexOf("{"), candidate.indexOf("[")].filter((value) => value >= 0));
      if (Number.isFinite(start)) {
        try {
          return JSON.parse(candidate.slice(start));
        } catch {
          // Continue to the next candidate.
        }
      }
    }
  }
  throw new Error("Scanner did not return valid JSON");
}
