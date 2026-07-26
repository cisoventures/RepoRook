import { execFile } from "node:child_process";
import { lstat, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, posix } from "node:path";
import { approvalMatches, type ApprovalReceipt, type RemediationPlan, type RemediationProposal } from "reporook";

const maxPatchBytes = 512 * 1024;
const maxFileBytes = 2 * 1024 * 1024;
const githubVersion = "2022-11-28";

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface RemediationPublication {
  plan: RemediationPlan;
  proposal: RemediationProposal;
  approval: ApprovalReceipt;
  proposal_digest: string;
}

export interface PublishedPullRequest {
  repository: string;
  number: number;
  url: string;
  branch: string;
  commit: string;
  draft: true;
}

export interface RemediationPublisher {
  readonly repository: string;
  publish(publication: RemediationPublication): Promise<PublishedPullRequest>;
}

interface GitHubPublisherOptions {
  repository: string;
  token: string;
  fetch?: FetchLike;
  apiBase?: string;
}

interface TreeEntry {
  path: string;
  mode: "100644" | "100755";
  type: "blob";
  sha: string | null;
}

interface SourceFile {
  path: string;
  mode: "100644" | "100755";
  content: Buffer;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} returned an invalid response`);
  return value as Record<string, unknown>;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || !value) throw new Error(`${label} is missing`);
  return value;
}

function safeRepository(value: string): string {
  const repository = value.trim();
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,38})\/[A-Za-z0-9_.-]{1,100}$/.test(repository)) {
    throw new Error("GitHub repository must use the OWNER/REPOSITORY form");
  }
  return repository;
}

function safePath(value: string): string {
  const path = value.replaceAll("\\", "/").replace(/^\.\//, "");
  const normalized = posix.normalize(path);
  if (!path || path.includes("\0") || path.startsWith("/") || normalized === "." || normalized === ".." || normalized.startsWith("../")) {
    throw new Error("Approved patch contains an unsafe repository path");
  }
  return normalized;
}

function encodedRepository(repository: string): string {
  return repository.split("/").map(encodeURIComponent).join("/");
}

function encodedRef(branch: string): string {
  return branch.split("/").map(encodeURIComponent).join("/");
}

function validatePatch(proposal: RemediationProposal): string[] {
  const patchBytes = Buffer.byteLength(proposal.patch, "utf8");
  if (patchBytes > maxPatchBytes) throw new Error("Approved patch exceeds the 512 KiB publishing limit");
  if (/^(?:GIT binary patch|Binary files |rename (?:from|to) |copy (?:from|to) |similarity index )/m.test(proposal.patch)) {
    throw new Error("Draft pull requests accept text patches only; binary, rename, and copy patches require manual review");
  }
  for (const match of proposal.patch.matchAll(/^(?:old mode|new mode|new file mode|deleted file mode) (\d+)$/gm)) {
    if (match[1] !== "100644" && match[1] !== "100755") throw new Error("Approved patch cannot create symbolic links, submodules, or special files");
  }
  if (!/^@@ /m.test(proposal.patch)) throw new Error("Approved patch must contain at least one unified-diff hunk");
  const files = proposal.files.map(safePath).sort();
  if (new Set(files).size !== files.length) throw new Error("Approved patch file list must be unique");
  return files;
}

async function runGit(args: string[], cwd: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    execFile("git", ["-c", "core.autocrlf=false", "-c", "core.eol=lf", ...args], { cwd, encoding: "utf8", maxBuffer: 2 * 1024 * 1024 }, (error, _stdout, stderr) => {
      if (!error) return resolve();
      reject(new Error((stderr || error.message).trim().slice(0, 2_000)));
    });
  });
}

async function materializePatch(proposal: RemediationProposal, sources: Map<string, SourceFile>): Promise<TreeEntry[]> {
  const files = validatePatch(proposal);
  const temporary = await mkdtemp(join(tmpdir(), "reporook-approved-patch-"));
  const working = join(temporary, "working");
  const patchPath = join(temporary, "proposal.patch");
  try {
    await mkdir(working);
    for (const file of files) {
      const source = sources.get(file);
      if (!source) continue;
      const target = join(working, ...file.split("/"));
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, source.content, { mode: source.mode === "100755" ? 0o755 : 0o644 });
    }
    await writeFile(patchPath, proposal.patch, { mode: 0o600 });
    await runGit(["apply", "--check", "--whitespace=nowarn", patchPath], working);
    await runGit(["apply", "--whitespace=nowarn", patchPath], working);
    const entries: TreeEntry[] = [];
    for (const file of files) {
      const target = join(working, ...file.split("/"));
      const metadata = await lstat(target).catch(() => null);
      if (!metadata) {
        if (!sources.has(file)) throw new Error(`Approved patch did not create ${file}`);
        entries.push({ path: file, mode: sources.get(file)?.mode ?? "100644", type: "blob", sha: null });
        continue;
      }
      if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error(`Approved patch produced a non-regular file: ${file}`);
      if (metadata.size > maxFileBytes) throw new Error(`Approved patch produced a file larger than 2 MiB: ${file}`);
      const originalMode = sources.get(file)?.mode;
      const mode = originalMode === "100755" || (metadata.mode & 0o111) !== 0 ? "100755" : "100644";
      entries.push({ path: file, mode, type: "blob", sha: (await readFile(target)).toString("base64") });
    }
    return entries;
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

export class GitHubPublisher implements RemediationPublisher {
  readonly repository: string;
  private readonly token: string;
  private readonly fetcher: FetchLike;
  private readonly apiBase: string;

  constructor(options: GitHubPublisherOptions) {
    this.repository = safeRepository(options.repository);
    this.token = options.token.trim();
    if (this.token.length < 20 || /\s/.test(this.token)) throw new Error("REPOROOK_GITHUB_TOKEN is missing or invalid");
    this.fetcher = options.fetch ?? fetch;
    this.apiBase = (options.apiBase ?? "https://api.github.com").replace(/\/$/, "");
    const api = new URL(this.apiBase);
    if (api.protocol !== "https:" && api.hostname !== "127.0.0.1" && api.hostname !== "localhost") {
      throw new Error("GitHub API base must use HTTPS");
    }
  }

  private async request(path: string, init: RequestInit = {}, allowNotFound = false): Promise<Record<string, unknown> | null> {
    const response = await this.fetcher(`${this.apiBase}${path}`, {
      ...init,
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${this.token}`,
        "x-github-api-version": githubVersion,
        "user-agent": "RepoRook-Service",
        ...(init.body ? { "content-type": "application/json" } : {}),
        ...(init.headers ?? {}),
      },
    });
    if (allowNotFound && response.status === 404) return null;
    const value = await response.json().catch(() => null) as unknown;
    if (!response.ok) {
      const message = value && typeof value === "object" && !Array.isArray(value) && typeof (value as Record<string, unknown>).message === "string"
        ? String((value as Record<string, unknown>).message)
        : `GitHub API returned ${response.status}`;
      throw new Error(message.slice(0, 1_000));
    }
    return record(value, "GitHub API");
  }

  private async installationRepository(): Promise<{ defaultBranch: string }> {
    const wanted = this.repository.toLowerCase();
    for (let page = 1; page <= 10; page += 1) {
      let response: Record<string, unknown> | null;
      try {
        response = await this.request(`/installation/repositories?per_page=100&page=${page}`);
      } catch (error) {
        throw new Error(`REPOROOK_GITHUB_TOKEN must be a GitHub App installation token: ${(error as Error).message}`);
      }
      const repositories = response?.repositories;
      if (!Array.isArray(repositories)) throw new Error("GitHub installation response did not include repositories");
      for (const value of repositories) {
        const repository = record(value, "GitHub installation repository");
        if (String(repository.full_name).toLowerCase() === wanted) {
          return { defaultBranch: text(repository.default_branch, "GitHub default branch") };
        }
      }
      const total = Number(response?.total_count);
      if (!Number.isFinite(total) || page * 100 >= total) break;
    }
    throw new Error(`The GitHub App installation is not authorized for ${this.repository}`);
  }

  async publish(publication: RemediationPublication): Promise<PublishedPullRequest> {
    if (!approvalMatches(publication.approval, publication.plan, publication.proposal)) {
      throw new Error("The approval receipt no longer matches the exact plan, patch, files, and tests");
    }
    validatePatch(publication.proposal);
    if (!publication.approval.source_scan.commit || !/^[a-f0-9]{40}$/.test(publication.approval.source_scan.commit)) {
      throw new Error("The approved scan must be bound to a Git commit before publishing");
    }
    const installation = await this.installationRepository();
    const repository = encodedRepository(this.repository);
    const branch = `reporook/${publication.proposal.finding_id.slice(3)}-${publication.approval.approval_id.slice(4)}`;
    const existing = await this.request(`/repos/${repository}/git/ref/heads/${encodedRef(branch)}`, {}, true);
    if (existing) throw new Error(`The approval branch already exists: ${branch}`);
    const reference = await this.request(`/repos/${repository}/git/ref/heads/${encodedRef(installation.defaultBranch)}`);
    const baseSha = text(record(reference?.object, "GitHub base reference").sha, "GitHub base SHA");
    if (baseSha !== publication.approval.source_scan.commit) {
      throw new Error("The GitHub default branch changed after the approved scan; rescan and approve a new exact proposal");
    }
    const commit = await this.request(`/repos/${repository}/git/commits/${baseSha}`);
    const baseTreeSha = text(record(commit?.tree, "GitHub base commit tree").sha, "GitHub base tree SHA");
    const tree = await this.request(`/repos/${repository}/git/trees/${baseTreeSha}?recursive=1`);
    if (tree?.truncated === true || !Array.isArray(tree?.tree)) throw new Error("GitHub could not return a complete repository tree");
    const approvedFiles = validatePatch(publication.proposal);
    const sourceEntries = new Map<string, Record<string, unknown>>();
    for (const value of tree.tree) {
      const entry = record(value, "GitHub tree entry");
      if (typeof entry.path === "string" && approvedFiles.includes(entry.path)) sourceEntries.set(entry.path, entry);
    }
    const sources = new Map<string, SourceFile>();
    for (const file of approvedFiles) {
      const entry = sourceEntries.get(file);
      if (!entry) continue;
      if (entry.type !== "blob" || (entry.mode !== "100644" && entry.mode !== "100755")) {
        throw new Error(`Approved patch cannot modify a symbolic link, submodule, or special file: ${file}`);
      }
      const size = Number(entry.size);
      if (Number.isFinite(size) && size > maxFileBytes) throw new Error(`Approved source file exceeds 2 MiB: ${file}`);
      const blob = await this.request(`/repos/${repository}/git/blobs/${text(entry.sha, "GitHub blob SHA")}`);
      if (blob?.encoding !== "base64") throw new Error(`GitHub returned an unsupported encoding for ${file}`);
      const content = Buffer.from(text(blob.content, "GitHub blob content").replace(/\s/g, ""), "base64");
      if (content.byteLength > maxFileBytes) throw new Error(`Approved source file exceeds 2 MiB: ${file}`);
      sources.set(file, { path: file, mode: entry.mode, content });
    }
    const materialized = await materializePatch(publication.proposal, sources);
    const newTree: Array<Record<string, unknown>> = [];
    for (const entry of materialized) {
      if (entry.sha === null) {
        newTree.push({ path: entry.path, mode: entry.mode, type: entry.type, sha: null });
        continue;
      }
      const blob = await this.request(`/repos/${repository}/git/blobs`, {
        method: "POST",
        body: JSON.stringify({ content: entry.sha, encoding: "base64" }),
      });
      newTree.push({ ...entry, sha: text(blob?.sha, "Created GitHub blob SHA") });
    }
    const createdTree = await this.request(`/repos/${repository}/git/trees`, {
      method: "POST",
      body: JSON.stringify({ base_tree: baseTreeSha, tree: newTree }),
    });
    const createdCommit = await this.request(`/repos/${repository}/git/commits`, {
      method: "POST",
      body: JSON.stringify({
        message: `Fix ${publication.proposal.finding_id}\n\nApproved by ${publication.approval.approved_by} (${publication.approval.approval_id}).`,
        tree: text(createdTree?.sha, "Created GitHub tree SHA"),
        parents: [baseSha],
      }),
    });
    const commitSha = text(createdCommit?.sha, "Created GitHub commit SHA");
    await this.request(`/repos/${repository}/git/refs`, {
      method: "POST",
      body: JSON.stringify({ ref: `refs/heads/${branch}`, sha: commitSha }),
    });
    const title = `Fix ${publication.plan.finding.plain_summary}`.replace(/[\r\n]+/g, " ").slice(0, 240);
    const tests = publication.proposal.test_plan.map((item) => `- \`${item.replaceAll("`", "'")}\``).join("\n");
    const pull = await this.request(`/repos/${repository}/pulls`, {
      method: "POST",
      body: JSON.stringify({
        title,
        head: branch,
        base: installation.defaultBranch,
        draft: true,
        body: [
          "## RepoRook remediation",
          "",
          publication.proposal.risk_explanation,
          "",
          `Behavior impact: ${publication.proposal.behavior_impact}`,
          "",
          `Approval: \`${publication.approval.approval_id}\` by ${publication.approval.approved_by}`,
          `Finding: \`${publication.proposal.finding_id}\``,
          "",
          "### Approved tests",
          "",
          tests,
          "",
          "> Draft only. Review the exact diff and let CI complete before merging.",
        ].join("\n"),
      }),
    });
    return {
      repository: this.repository,
      number: Number(pull?.number),
      url: text(pull?.html_url, "GitHub pull request URL"),
      branch,
      commit: commitSha,
      draft: true,
    };
  }
}
