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
  target_kind?: "container-image" | "git-history";
  target?: string;
  source_commit?: string;
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
  plain_summary: string;
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

export interface FindingBaselineEntry {
  finding_id: string;
  fingerprint: string;
  scanner: string;
  rule: string;
  severity: Severity;
  file: string;
}

export interface FindingBaseline {
  schema_version: "1.0";
  tool: { name: "reporook"; version: string };
  created_at: string;
  source: {
    commit: string | null;
    config_hash: string;
    generated_at: string;
  };
  findings: FindingBaselineEntry[];
}

export interface FindingSuppression {
  id: string;
  finding_id: string;
  owner: string;
  reason: string;
  expires_at: string;
  created_at: string;
}

export interface SuppressionFile {
  schema_version: "1.0";
  suppressions: FindingSuppression[];
}

export type BaselineDisposition = "new" | "existing" | "not-configured";
export type PolicyDisposition = "actionable" | "baseline" | "suppressed" | "below-threshold";

export interface FindingPolicyResult {
  finding_id: string;
  baseline: BaselineDisposition;
  disposition: PolicyDisposition;
  effective_fail_on: Severity;
  matched_path_policy: string | null;
  suppression: FindingSuppression | null;
  expired_suppression: FindingSuppression | null;
}

export interface PolicyEvaluation {
  evaluated_at: string;
  policy_hash: string;
  baseline: {
    configured: boolean;
    path: string;
    source_commit: string | null;
    finding_count: number;
  };
  suppressions: {
    configured: boolean;
    path: string;
    active: number;
    expired: number;
  };
  path_policies: Record<string, Severity>;
  summary: {
    new: number;
    existing: number;
    actionable: number;
    below_threshold: number;
    suppressed: number;
    expired_suppressions: number;
  };
  findings: FindingPolicyResult[];
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
  policy?: PolicyEvaluation;
  scan_receipt: ScanReceipt;
}

export interface VerificationReport {
  schema_version: "1.0";
  tool: { name: "reporook"; version: string };
  finding_id: string;
  generated_at: string;
  scanner_resolution: "passed" | "failed" | "inconclusive";
  reason: string;
  config_unchanged: boolean | null;
  original_finding: Finding;
  remaining_finding: Finding | null;
  original_scanner_status: ScannerStatus | null;
  source_scan: ScanReceipt;
  verification_scan: ScanReceipt;
  functional_tests: {
    status: "not-recorded";
    reminder: string;
  };
  approval?: {
    status: "approved" | "not-recorded";
    receipt: ApprovalReceipt | null;
  };
}

export const priorityBands = ["fix-now", "fix-next", "review-later"] as const;
export type PriorityBand = (typeof priorityBands)[number];

export interface PrioritizedFinding {
  rank: number;
  priority: PriorityBand;
  finding_id: string;
  severity: Severity;
  scanner: string;
  package: string | null;
  file: string;
  line: number;
  title: string;
  reason: string;
  next_step: string;
  related_finding_ids: string[];
}

export interface PrioritizationReport {
  schema_version: "1.0";
  tool: { name: "reporook"; version: string };
  generated_at: string;
  coverage_status: CoverageStatus;
  policy_summary?: PolicyEvaluation["summary"];
  source_scan: ScanReceipt;
  summary: {
    fix_now: number;
    fix_next: number;
    review_later: number;
    total: number;
  };
  priorities: PrioritizedFinding[];
}

export interface RemediationPlan {
  schema_version: "1.0";
  tool: { name: "reporook"; version: string };
  plan_id: string;
  status: "awaiting-proposal";
  generated_at: string;
  finding: Finding;
  priority: PrioritizedFinding;
  source_scan: ScanReceipt;
  goal: string;
  validation_questions: string[];
  scope: {
    allowed_files: string[];
    related_finding_ids: string[];
    stop_if_scope_changes: true;
  };
  proposal_requirements: {
    explain_risk_in_plain_english: true;
    exact_patch_preview: true;
    behavior_impact: true;
    focused_test_plan: true;
  };
  approval: {
    required: true;
    status: "pending";
    binds_to: ["finding", "source-scan", "exact-patch", "test-plan"];
    instruction: string;
  };
  safety_rules: string[];
  verification: {
    command: string;
    scanner_pass_condition: string;
    functional_tests_required: true;
  };
}

export interface RemediationProposal {
  schema_version: "1.0";
  plan_id: string;
  finding_id: string;
  created_at: string;
  risk_explanation: string;
  behavior_impact: string;
  files: string[];
  patch: string;
  test_plan: string[];
}

export interface ApprovalReceipt {
  schema_version: "1.0";
  tool: { name: "reporook"; version: string };
  approval_id: string;
  status: "approved";
  approved_at: string;
  approved_by: string;
  reason: string;
  finding_id: string;
  plan_id: string;
  source_scan: ScanReceipt;
  bindings: {
    plan_hash: string;
    proposal_hash: string;
    patch_hash: string;
    test_plan_hash: string;
    files: string[];
  };
  invalidation_rule: string;
}

export interface ProjectStack {
  name: string;
  evidence: string[];
}

export interface ProjectProfile {
  target: string;
  stacks: ProjectStack[];
  recommended_scanners: string[];
  evidence_truncated: boolean;
}

export interface InitializationResult {
  target: string;
  config_path: string;
  status: "created" | "overwritten" | "already-configured";
  gitignore_updated: boolean;
  profile: ProjectProfile;
  next_commands: string[];
}

export interface RepoRookConfig {
  failOn: Severity;
  outputDir: string;
  semgrepConfig: string;
  paths: string[];
  ignore: string[];
  requiredScanners: string[];
  scanners: Record<string, boolean>;
  baselineFile: string;
  suppressionsFile: string;
  pathPolicies: Record<string, Severity>;
  containerImages: string[];
  gitHistory: boolean;
  cacheEnabled: boolean;
  cacheTtlMinutes: number;
  scannerRetries: number;
}

export interface ScanOptions {
  target: string;
  config: RepoRookConfig;
  changedBase?: string;
  changedHead?: string;
  requireScanners?: boolean;
  cacheEnabled?: boolean;
  refreshCache?: boolean;
  cacheTtlMs?: number;
}

export interface ScannerContext {
  target: string;
  config: RepoRookConfig;
  scannerVersion?: string | null;
}

export interface ScannerResult {
  status: ScannerStatus;
  findings: Finding[];
}

export interface ScannerAdapter {
  name: string;
  isApplicable(target: string, config?: RepoRookConfig): Promise<{ applicable: boolean; reason?: string }>;
  version?(context: ScannerContext): Promise<string | null>;
  run(context: ScannerContext): Promise<ScannerResult>;
}
