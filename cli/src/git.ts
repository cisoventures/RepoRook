import { runCommand } from "./process.js";

export async function gitCommit(target: string): Promise<string | null> {
  const result = await runCommand("git", ["rev-parse", "HEAD"], { cwd: target, timeoutMs: 15_000 });
  return result.code === 0 ? result.stdout.trim() || null : null;
}

async function resolveRevision(target: string, revision: string): Promise<string> {
  if (!revision || revision.includes("\0") || /[\r\n]/.test(revision)) throw new Error("Git revision must be a single non-empty value");
  const result = await runCommand("git", ["rev-parse", "--verify", "--end-of-options", `${revision}^{commit}`], {
    cwd: target,
    timeoutMs: 15_000,
  });
  const commit = result.stdout.trim();
  if (result.code !== 0 || !/^[a-f0-9]{40,64}$/i.test(commit)) {
    throw new Error(`Invalid Git revision ${JSON.stringify(revision)}: ${result.stderr.trim() || "not a commit"}`);
  }
  return commit;
}

export async function gitChangedFiles(target: string, base?: string, head = "HEAD"): Promise<string[]> {
  const effectiveBase = base ?? "HEAD~1";
  const [baseCommit, headCommit] = await Promise.all([
    resolveRevision(target, effectiveBase),
    resolveRevision(target, head),
  ]);
  const result = await runCommand("git", ["diff", "--name-only", "-z", "--diff-filter=ACMR", `${baseCommit}...${headCommit}`, "--"], {
    cwd: target,
    timeoutMs: 30_000,
    maxOutputBytes: 10 * 1024 * 1024,
  });
  if (result.code !== 0) throw new Error(`Could not determine changed files: ${result.stderr.trim()}`);
  const files = result.stdout.split("\0").filter(Boolean);
  if (files.length > 50_000) throw new Error("Changed-file scan supports at most 50,000 files");
  if (files.some((path) => path.length > 10_000)) throw new Error("Changed-file scan encountered an invalid path longer than 10,000 characters");
  return files;
}
