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
  const result = await runCommand("git", ["diff", "--name-only", "--diff-filter=ACMR", `${baseCommit}...${headCommit}`, "--"], {
    cwd: target,
    timeoutMs: 30_000,
  });
  if (result.code !== 0) throw new Error(`Could not determine changed files: ${result.stderr.trim()}`);
  return result.stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}
