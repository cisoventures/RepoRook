export const severities = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof severities)[number];
export type CoverageStatus = "complete" | "partial" | "failed";
export type ScannerRunStatus = "ok" | "skipped" | "error";

export interface FindingMetadata {
  cwe: string[];
  cve: string[];
  package: string | null;
  installed_version?: string | null;
  fixed_versions?: string[];
  raw_severity: string | null;
  confidence?: string | null;
  tags?: string[];
}

export interface Finding {
  id: string;
  scanner: string;
  rule: string;
  severity: Severity;
  file: string;
  line: number;
  end_line?: number;
  column?: number;
  description: string;
  remediation_hint: string;
  fingerprint: string;
  references: string[];
  metadata: FindingMetadata;
}

export interface ScannerStatus {
  name: string;
  applicable: boolean;
  available: boolean;
  version: string | null;
  status: ScannerRunStatus;
  finding_count: number;
  duration_ms: number;
  reason?: string;
}

export interface ScanReceipt {
  target: string;
  commit: string | null;
  config_hash: string;
  scanner_versions: Record<string, string | null>;
  started_at: string;
  completed_at: string;
  changed_files?: string[];
}

export interface ScanReport {
  schema_version: "1.0";
  tool: { name: "reporook"; version: string };
  target: { path: string; commit: string | null };
  generated_at: string;
  coverage_status: CoverageStatus;
  summary: Record<Severity | "total", number>;
  scanners: ScannerStatus[];
  findings: Finding[];
  scan_receipt: ScanReceipt;
}

export interface RepoRookConfig {
  failOn: Severity;
  outputDir: string;
  semgrepConfig: string;
  paths: string[];
  ignore: string[];
  requiredScanners: string[];
  scanners: Record<string, boolean>;
}

export interface ScanOptions {
  target: string;
  config: RepoRookConfig;
  changedBase?: string;
  changedHead?: string;
  requireScanners?: boolean;
}

export interface ScannerContext {
  target: string;
  config: RepoRookConfig;
}

export interface ScannerResult {
  status: ScannerStatus;
  findings: Finding[];
}

export interface ScannerAdapter {
  name: string;
  isApplicable(target: string): Promise<{ applicable: boolean; reason?: string }>;
  run(context: ScannerContext): Promise<ScannerResult>;
}
