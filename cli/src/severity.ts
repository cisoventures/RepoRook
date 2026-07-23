import type { Severity } from "./types.js";

const rank: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function normalizeSeverity(value: unknown, fallback: Severity = "medium"): Severity {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (["critical", "blocker", "urgent"].includes(normalized)) return "critical";
  if (["high", "error", "important"].includes(normalized)) return "high";
  if (["medium", "moderate", "warning", "warn"].includes(normalized)) return "medium";
  if (["low", "info", "informational", "note"].includes(normalized)) return "low";
  return fallback;
}

export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return rank[severity] >= rank[threshold];
}

export function sortBySeverity<T extends { severity: Severity }>(items: T[]): T[] {
  return [...items].sort((a, b) => rank[b.severity] - rank[a.severity]);
}
