import { isAbsolute, posix } from "node:path";
import { sha256 } from "./fingerprint.js";
import type { ApprovalReceipt, RemediationPlan, RemediationProposal, ScanReceipt } from "./types.js";
import { VERSION } from "./version.js";

const proposalKeys = new Set([
  "schema_version", "plan_id", "finding_id", "created_at", "risk_explanation", "behavior_impact", "files", "patch", "test_plan",
]);
const receiptKeys = new Set([
  "schema_version", "tool", "approval_id", "status", "approved_at", "approved_by", "reason", "finding_id", "plan_id", "source_scan", "bindings", "invalidation_rule",
]);
const toolKeys = new Set(["name", "version"]);
const receiptBindingKeys = new Set(["plan_hash", "proposal_hash", "patch_hash", "test_plan_hash", "files"]);
const scanReceiptKeys = new Set(["target", "commit", "config_hash", "scanner_versions", "started_at", "completed_at", "changed_files"]);

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function nonEmpty(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} must be a non-empty string`);
  return value.trim();
}

function exactKeys(value: Record<string, unknown>, allowed: Set<string>, label: string): void {
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length) throw new Error(`${label} contains unknown field${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`);
}

function timestamp(value: unknown, label: string): string {
  const text = nonEmpty(value, label);
  const parsed = Date.parse(text);
  if (!Number.isFinite(parsed)) throw new Error(`${label} must be an ISO-8601 timestamp`);
  return new Date(parsed).toISOString();
}

function digest(value: unknown): string {
  return `sha256:${sha256(typeof value === "string" ? value : JSON.stringify(value))}`;
}

function safeFile(value: unknown, label: string): string {
  const file = nonEmpty(value, label).replaceAll("\\", "/").replace(/^\.\//, "");
  if (isAbsolute(file) || /^[A-Za-z]:\//.test(file) || file === ".." || file.startsWith("../") || file.includes("\0")) {
    throw new Error(`${label} must be a repository-relative path`);
  }
  const normalized = posix.normalize(file);
  if (normalized === "." || normalized.startsWith("../")) throw new Error(`${label} must name a repository file`);
  return normalized;
}

function stringList(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || !value.length) throw new Error(`${label} must be a non-empty list`);
  return value.map((item, index) => nonEmpty(item, `${label}[${index}]`));
}

function filesInPatch(patch: string): string[] {
  const files = new Set<string>();
  for (const line of patch.split(/\r?\n/)) {
    const match = line.match(/^(?:\+\+\+ b\/|--- a\/)(.+)$/);
    if (match?.[1] && match[1] !== "/dev/null") files.add(safeFile(match[1], "Patch file"));
  }
  return [...files].sort();
}

function parseScanReceipt(value: unknown, label: string): ScanReceipt {
  const input = record(value, label);
  exactKeys(input, scanReceiptKeys, label);
  const commit = input.commit === null ? null : nonEmpty(input.commit, `${label}.commit`);
  const scannerVersionsInput = record(input.scanner_versions, `${label}.scanner_versions`);
  const scannerVersions: Record<string, string | null> = {};
  for (const [scanner, version] of Object.entries(scannerVersionsInput).sort(([left], [right]) => left.localeCompare(right))) {
    const name = nonEmpty(scanner, `${label}.scanner_versions key`);
    scannerVersions[name] = version === null ? null : nonEmpty(version, `${label}.scanner_versions.${name}`);
  }
  let changedFiles: string[] | undefined;
  if (input.changed_files !== undefined) {
    if (!Array.isArray(input.changed_files)) throw new Error(`${label}.changed_files must be a list`);
    changedFiles = input.changed_files.map((file, index) => safeFile(file, `${label}.changed_files[${index}]`));
    if (new Set(changedFiles).size !== changedFiles.length) throw new Error(`${label}.changed_files must be unique`);
  }
  return {
    target: nonEmpty(input.target, `${label}.target`),
    commit,
    config_hash: nonEmpty(input.config_hash, `${label}.config_hash`),
    scanner_versions: scannerVersions,
    started_at: timestamp(input.started_at, `${label}.started_at`),
    completed_at: timestamp(input.completed_at, `${label}.completed_at`),
    ...(changedFiles ? { changed_files: changedFiles } : {}),
  };
}

export function parseRemediationProposal(value: unknown): RemediationProposal {
  const input = record(value, "Remediation proposal");
  const unknown = Object.keys(input).filter((key) => !proposalKeys.has(key));
  if (unknown.length) throw new Error(`Remediation proposal contains unknown field${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`);
  if (input.schema_version !== "1.0") throw new Error("Remediation proposal schema_version must be 1.0");
  const planId = nonEmpty(input.plan_id, "Remediation proposal plan_id");
  const findingId = nonEmpty(input.finding_id, "Remediation proposal finding_id");
  if (!/^rrp-[a-f0-9]{12}$/.test(planId)) throw new Error("Remediation proposal plan_id is invalid");
  if (!/^rr-[a-f0-9]{12}$/.test(findingId)) throw new Error("Remediation proposal finding_id is invalid");
  const files = stringList(input.files, "Remediation proposal files").map((item, index) => safeFile(item, `Remediation proposal files[${index}]`)).sort();
  if (new Set(files).size !== files.length) throw new Error("Remediation proposal files must be unique");
  if (typeof input.patch !== "string" || !input.patch.trim()) throw new Error("Remediation proposal patch must be a non-empty string");
  const patch = input.patch;
  const patchFiles = filesInPatch(patch);
  if (!patchFiles.length) throw new Error("Remediation proposal patch must be a unified diff with file headers");
  if (JSON.stringify(patchFiles) !== JSON.stringify(files)) {
    throw new Error("Remediation proposal files must exactly match the unified diff file headers");
  }
  return {
    schema_version: "1.0",
    plan_id: planId,
    finding_id: findingId,
    created_at: timestamp(input.created_at, "Remediation proposal created_at"),
    risk_explanation: nonEmpty(input.risk_explanation, "Remediation proposal risk_explanation"),
    behavior_impact: nonEmpty(input.behavior_impact, "Remediation proposal behavior_impact"),
    files,
    patch,
    test_plan: stringList(input.test_plan, "Remediation proposal test_plan"),
  };
}

export function validateRemediationPlan(value: unknown): RemediationPlan {
  const plan = record(value, "Remediation plan");
  const planId = nonEmpty(plan.plan_id, "Remediation plan plan_id");
  if (!/^rrp-[a-f0-9]{12}$/.test(planId)) throw new Error("Remediation plan plan_id is invalid");
  const finding = record(plan.finding, "Remediation plan finding");
  const findingId = nonEmpty(finding.id, "Remediation plan finding.id");
  if (!/^rr-[a-f0-9]{12}$/.test(findingId)) throw new Error("Remediation plan finding.id is invalid");
  const sourceScan = record(plan.source_scan, "Remediation plan source_scan");
  parseScanReceipt(sourceScan, "Remediation plan source_scan");
  if (plan.status !== "awaiting-proposal") throw new Error("Remediation plan status must be awaiting-proposal");
  return value as RemediationPlan;
}

export function createApprovalReceipt(
  planValue: unknown,
  proposalValue: unknown,
  approvedBy: string,
  reason: string,
  now = new Date(),
): ApprovalReceipt {
  const plan = validateRemediationPlan(planValue);
  const proposal = parseRemediationProposal(proposalValue);
  if (proposal.plan_id !== plan.plan_id) throw new Error("Proposal plan_id does not match the remediation plan");
  if (proposal.finding_id !== plan.finding.id) throw new Error("Proposal finding_id does not match the remediation plan");
  const actor = nonEmpty(approvedBy, "approved-by");
  const approvalReason = nonEmpty(reason, "reason");
  const approvedAt = now.toISOString();
  const sourceScan = parseScanReceipt(plan.source_scan, "Remediation plan source_scan");
  const bindings = {
    plan_hash: digest(plan),
    proposal_hash: digest(proposal),
    patch_hash: digest(proposal.patch),
    test_plan_hash: digest(proposal.test_plan),
    files: proposal.files,
  };
  const approvalIdentity = [plan.plan_id, bindings.proposal_hash, actor, approvalReason, approvedAt].join("\0");
  return {
    schema_version: "1.0",
    tool: { name: "reporook", version: VERSION },
    approval_id: `rra-${sha256(approvalIdentity).slice(0, 12)}`,
    status: "approved",
    approved_at: approvedAt,
    approved_by: actor,
    reason: approvalReason,
    finding_id: plan.finding.id,
    plan_id: plan.plan_id,
    source_scan: sourceScan,
    bindings,
    invalidation_rule: "This approval is invalid if the plan, exact patch, file list, or test plan changes.",
  };
}

export function parseApprovalReceipt(value: unknown): ApprovalReceipt {
  const input = record(value, "Approval receipt");
  const unknown = Object.keys(input).filter((key) => !receiptKeys.has(key));
  if (unknown.length) throw new Error(`Approval receipt contains unknown field${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`);
  if (input.schema_version !== "1.0" || input.status !== "approved") throw new Error("Approval receipt schema or status is invalid");
  const approvalId = nonEmpty(input.approval_id, "Approval receipt approval_id");
  if (!/^rra-[a-f0-9]{12}$/.test(approvalId)) throw new Error("Approval receipt approval_id is invalid");
  const findingId = nonEmpty(input.finding_id, "Approval receipt finding_id");
  const planId = nonEmpty(input.plan_id, "Approval receipt plan_id");
  if (!/^rr-[a-f0-9]{12}$/.test(findingId) || !/^rrp-[a-f0-9]{12}$/.test(planId)) throw new Error("Approval receipt finding or plan ID is invalid");
  const tool = record(input.tool, "Approval receipt tool");
  exactKeys(tool, toolKeys, "Approval receipt tool");
  if (tool.name !== "reporook") throw new Error("Approval receipt tool.name must be reporook");
  const bindings = record(input.bindings, "Approval receipt bindings");
  exactKeys(bindings, receiptBindingKeys, "Approval receipt bindings");
  const files = stringList(bindings.files, "Approval receipt bindings.files").map((item, index) => safeFile(item, `Approval receipt bindings.files[${index}]`)).sort();
  for (const name of ["plan_hash", "proposal_hash", "patch_hash", "test_plan_hash"] as const) {
    if (!/^sha256:[a-f0-9]{64}$/.test(nonEmpty(bindings[name], `Approval receipt bindings.${name}`))) {
      throw new Error(`Approval receipt bindings.${name} is invalid`);
    }
  }
  const sourceScan = parseScanReceipt(input.source_scan, "Approval receipt source_scan");
  return {
    schema_version: "1.0",
    tool: { name: "reporook", version: nonEmpty(tool.version, "Approval receipt tool.version") },
    approval_id: approvalId,
    status: "approved",
    approved_at: timestamp(input.approved_at, "Approval receipt approved_at"),
    approved_by: nonEmpty(input.approved_by, "Approval receipt approved_by"),
    reason: nonEmpty(input.reason, "Approval receipt reason"),
    finding_id: findingId,
    plan_id: planId,
    source_scan: sourceScan,
    bindings: {
      plan_hash: String(bindings.plan_hash),
      proposal_hash: String(bindings.proposal_hash),
      patch_hash: String(bindings.patch_hash),
      test_plan_hash: String(bindings.test_plan_hash),
      files,
    },
    invalidation_rule: nonEmpty(input.invalidation_rule, "Approval receipt invalidation_rule"),
  };
}

export function approvalMatches(receipt: ApprovalReceipt, planValue: unknown, proposalValue: unknown): boolean {
  const plan = validateRemediationPlan(planValue);
  const proposal = parseRemediationProposal(proposalValue);
  const sourceScan = parseScanReceipt(plan.source_scan, "Remediation plan source_scan");
  return receipt.status === "approved"
    && receipt.plan_id === plan.plan_id
    && receipt.finding_id === plan.finding.id
    && receipt.bindings.plan_hash === digest(plan)
    && receipt.bindings.proposal_hash === digest(proposal)
    && receipt.bindings.patch_hash === digest(proposal.patch)
    && receipt.bindings.test_plan_hash === digest(proposal.test_plan)
    && JSON.stringify(receipt.bindings.files) === JSON.stringify(proposal.files)
    && JSON.stringify(receipt.source_scan) === JSON.stringify(sourceScan);
}
