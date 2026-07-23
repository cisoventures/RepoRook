import { runCommand } from "./process.js";

export async function gitCommit(target: string): Promise<string | null> {
  const result = await runCommand("git", ["rev-parse", "HEAD"], { cwd: target, timeoutMs: 15_000 });
  return result.code === 0 ? result.stdout.trim() || null : null;
}

export async function gitChangedFiles(target: string, base?: string, head = "HEAD"): Promise<string[]> {
  const effectiveBase = base ?? "HEAD~1";
  const result = await runCommand("git", ["diff", "--name-only", "--diff-filter=ACMR", `${effectiveBase}...${head}`], {
    cwd: target,
    timeoutMs: 30_000,
  });
  if (result.code !== 0) throw new Error(`Could not determine changed files: ${result.stderr.trim()}`);
  return result.stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}
