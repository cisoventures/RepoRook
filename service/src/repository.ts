import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath, stat } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import {
  approvalMatches,
  detectProject,
  parseApprovalReceipt,
  parseRemediationProposal,
  type Finding,
  type PrioritizationReport,
  type ProjectProfile,
  type RemediationPlan,
  type ScanReport,
} from "reporook";
import type { RemediationPublication } from "./github.js";

const configCandidates = ["reporook.yml", "reporook.yaml", ".reporook.yml", ".reporook.json"];
const maxArtifactBytes = 10 * 1024 * 1024;

export interface DashboardFinding {
  id: string;
  scanner: string;
  rule: string;
  severity: string;
  file: string;
  line: number;
  plain_summary: string;
  remediation_hint: string;
  policy_status: string | null;
  priority: string | null;
}

export interface ApprovalItem {
  finding_id: string;
  proposal_digest: string;
  risk_explanation: string;
  behavior_impact: string;
  files: string[];
  patch: string;
  test_plan: string[];
  approved: boolean;
  approval_id: string | null;
}

export interface DashboardSnapshot {
  repository: { name: string; path: string; configured: boolean; stacks: string[]; recommended_scanners: string[] };
  scan: null | {
    generated_at: string;
    coverage_status: string;
    source_commit: string | null;
    summary: Record<string, number>;
    scanners: Array<{ name: string; status: string; finding_count: number; reason?: string }>;
  };
  findings: DashboardFinding[];
  approvals: ApprovalItem[];
}

function cleanText(value: unknown, limit = 10_000): string {
  return typeof value === "string" ? value.slice(0, limit) : "";
}

function stringList(value: unknown, maximum = 100): string[] {
  return Array.isArray(value) ? value.slice(0, maximum).flatMap((item) => typeof item === "string" ? [item.slice(0, 2_000)] : []) : [];
}

async function rejectSymbolicLinks(root: string, path: string): Promise<void> {
  const traversal = relative(root, path);
  if (traversal === ".." || traversal.startsWith(`..${sep}`) || isAbsolute(traversal)) throw new Error("Artifact path resolves outside the repository");
  let current = root;
  for (const segment of traversal.split(sep).filter(Boolean)) {
    current = join(current, segment);
    const entry = await lstat(current).catch(() => null);
    if (entry?.isSymbolicLink()) throw new Error(`Artifact path contains a symbolic link: ${relative(root, current)}`);
  }
}

export class RepositoryStore {
  readonly target: string;
  private readonly profile: ProjectProfile;

  private constructor(target: string, profile: ProjectProfile) {
    this.target = target;
    this.profile = profile;
  }

  static async open(targetInput: string): Promise<RepositoryStore> {
    const target = await realpath(resolve(targetInput));
    if (!(await stat(target)).isDirectory()) throw new Error("Repository target must be a directory");
    return new RepositoryStore(target, await detectProject(target));
  }

  private async artifact(relativePath: string): Promise<string> {
    if (!relativePath.startsWith(".reporook/") || relativePath.includes("\0")) throw new Error("Service artifacts must stay inside .reporook");
    const path = resolve(this.target, relativePath);
    await rejectSymbolicLinks(this.target, path);
    return path;
  }

  private async readArtifact(relativePath: string): Promise<{ raw: string; value: unknown } | null> {
    const path = await this.artifact(relativePath);
    const metadata = await stat(path).catch(() => null);
    if (!metadata) return null;
    if (!metadata.isFile()) throw new Error(`Artifact is not a regular file: ${relativePath}`);
    if (metadata.size > maxArtifactBytes) throw new Error(`Artifact exceeds the 10 MiB dashboard limit: ${relativePath}`);
    const raw = await readFile(path, "utf8");
    return { raw, value: JSON.parse(raw) as unknown };
  }

  async proposalDigest(findingId: string): Promise<string> {
    if (!/^rr-[a-f0-9]{12}$/.test(findingId)) throw new Error("Invalid finding ID");
    const proposal = await this.readArtifact(`.reporook/remediations/${findingId}/proposal.json`);
    if (!proposal) throw new Error("Prepare a remediation plan before approving it");
    return createHash("sha256").update(proposal.raw).digest("hex");
  }

  async publication(findingId: string, expectedProposalDigest: string): Promise<RemediationPublication> {
    if (!/^rr-[a-f0-9]{12}$/.test(findingId)) throw new Error("Invalid finding ID");
    const planArtifact = await this.readArtifact(`.reporook/remediations/${findingId}/plan.json`);
    const proposalArtifact = await this.readArtifact(`.reporook/remediations/${findingId}/proposal.json`);
    const approvalArtifact = await this.readArtifact(`.reporook/remediations/${findingId}/approval.json`);
    if (!planArtifact || !proposalArtifact || !approvalArtifact) {
      throw new Error("An exact plan, proposal, and approval receipt are required before opening a pull request");
    }
    const proposalDigest = createHash("sha256").update(proposalArtifact.raw).digest("hex");
    if (proposalDigest !== expectedProposalDigest) throw new Error("The proposal changed after it was displayed; review and approve the new exact patch");
    const plan = planArtifact.value as RemediationPlan;
    const proposal = parseRemediationProposal(proposalArtifact.value);
    const approval = parseApprovalReceipt(approvalArtifact.value);
    if (!approvalMatches(approval, plan, proposal)) {
      throw new Error("The approval receipt no longer matches the exact plan, patch, files, and tests");
    }
    if (proposal.finding_id !== findingId) throw new Error("The proposal does not match the requested finding");
    return { plan, proposal, approval, proposal_digest: proposalDigest };
  }

  private async approvalItems(priorities: PrioritizationReport | null): Promise<ApprovalItem[]> {
    if (!priorities) return [];
    const output: ApprovalItem[] = [];
    for (const priority of priorities.priorities.slice(0, 250)) {
      const findingId = priority.finding_id;
      if (!/^rr-[a-f0-9]{12}$/.test(findingId)) continue;
      const proposal = await this.readArtifact(`.reporook/remediations/${findingId}/proposal.json`);
      if (!proposal || proposal.value === null || typeof proposal.value !== "object" || Array.isArray(proposal.value)) continue;
      const value = proposal.value as Record<string, unknown>;
      const approval = await this.readArtifact(`.reporook/remediations/${findingId}/approval.json`);
      const plan = await this.readArtifact(`.reporook/remediations/${findingId}/plan.json`);
      let approvalId: string | null = null;
      if (approval && plan) {
        try {
          const parsedProposal = parseRemediationProposal(proposal.value);
          const parsedApproval = parseApprovalReceipt(approval.value);
          if (approvalMatches(parsedApproval, plan.value, parsedProposal)) approvalId = parsedApproval.approval_id;
        } catch {
          approvalId = null;
        }
      }
      output.push({
        finding_id: findingId,
        proposal_digest: createHash("sha256").update(proposal.raw).digest("hex"),
        risk_explanation: cleanText(value.risk_explanation, 4_000),
        behavior_impact: cleanText(value.behavior_impact, 4_000),
        files: stringList(value.files, 100),
        patch: cleanText(value.patch, 200_000),
        test_plan: stringList(value.test_plan, 100),
        approved: approvalId !== null,
        approval_id: approvalId,
      });
    }
    return output;
  }

  async snapshot(): Promise<DashboardSnapshot> {
    const configured = (await Promise.all(configCandidates.map(async (candidate) => {
      const entry = await lstat(join(this.target, candidate)).catch(() => null);
      return Boolean(entry?.isFile() && !entry.isSymbolicLink());
    }))).some(Boolean);
    const reportArtifact = await this.readArtifact(".reporook/findings.json");
    const priorityArtifact = await this.readArtifact(".reporook/priorities.json");
    const report = reportArtifact?.value as ScanReport | undefined;
    const priorities = priorityArtifact?.value as PrioritizationReport | undefined;
    const priorityByFinding = new Map((priorities?.priorities ?? []).map((item) => [item.finding_id, item.priority]));
    const policyByFinding = new Map((report?.policy?.findings ?? []).map((item) => [item.finding_id, item.disposition]));
    const findings: DashboardFinding[] = Array.isArray(report?.findings) ? report.findings.slice(0, 1_000).map((finding: Finding) => ({
      id: finding.id,
      scanner: finding.scanner,
      rule: finding.rule,
      severity: finding.severity,
      file: finding.file,
      line: finding.line,
      plain_summary: finding.plain_summary,
      remediation_hint: finding.remediation_hint,
      policy_status: policyByFinding.get(finding.id) ?? null,
      priority: priorityByFinding.get(finding.id) ?? null,
    })) : [];
    return {
      repository: {
        name: basename(this.target),
        path: this.target,
        configured,
        stacks: this.profile.stacks.map((stack) => stack.name),
        recommended_scanners: this.profile.recommended_scanners,
      },
      scan: report ? {
        generated_at: report.generated_at,
        coverage_status: report.coverage_status,
        source_commit: report.target.commit,
        summary: { ...report.summary },
        scanners: report.scanners.map((scanner) => ({
          name: scanner.name,
          status: scanner.status,
          finding_count: scanner.finding_count,
          ...(scanner.reason ? { reason: scanner.reason } : {}),
        })),
      } : null,
      findings,
      approvals: await this.approvalItems(priorities ?? null),
    };
  }
}
