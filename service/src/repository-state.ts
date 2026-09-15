import { execFile } from "node:child_process";
import { existsSync, realpathSync, statSync } from "node:fs";
import { delimiter, isAbsolute, relative, resolve, sep } from "node:path";

const maxGitOutputBytes = 1024 * 1024;
export type EvidenceFreshnessStatus = "current" | "stale" | "dirty" | "unverifiable";

export interface RepositoryState {
  head: string | null;
  clean: boolean;
  error: string | null;
}

export interface EvidenceFreshness {
  status: EvidenceFreshnessStatus;
  current_commit: string | null;
  reason: string | null;
}

function inside(root: string, candidate: string): boolean {
  const traversal = relative(root, candidate);
  return traversal === "" || (traversal !== ".." && !traversal.startsWith(`..${sep}`) && !isAbsolute(traversal));
}

function gitExecutable(target: string): string {
  const pathValue = process.platform === "win32" ? process.env.Path ?? process.env.PATH ?? "" : process.env.PATH ?? "";
  const extensions = process.platform === "win32"
    ? (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean)
    : [""];
  for (const entry of pathValue.split(process.platform === "win32" ? ";" : delimiter)) {
    if (!entry || !isAbsolute(entry)) continue;
    for (const extension of extensions) {
      const candidate = resolve(entry, `git${extension.toLowerCase()}`);
      try {
        if (!existsSync(candidate) || !statSync(candidate).isFile()) continue;
        const canonical = realpathSync.native(candidate);
        if (!inside(target, canonical)) return canonical;
      } catch {
        // Try the next absolute PATH entry.
      }
    }
  }
  throw new Error("Git is not available on the sanitized executable search path");
}

function gitEnvironment(): NodeJS.ProcessEnv {
  const environment = { ...process.env };
  for (const name of Object.keys(environment)) {
    if (name.toUpperCase().startsWith("GIT_")) delete environment[name];
  }
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  return environment;
}

async function git(target: string, args: string[]): Promise<string> {
  const executable = gitExecutable(target);
  return await new Promise<string>((resolvePromise, reject) => {
    execFile(
      executable,
      ["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", ...args],
      { cwd: target, encoding: "utf8", env: gitEnvironment(), maxBuffer: maxGitOutputBytes, timeout: 15_000 },
      (error, stdout, stderr) => {
        if (!error) return resolvePromise(stdout);
        reject(new Error((stderr || error.message).trim().slice(0, 1_000)));
      },
    );
  });
}

export async function readRepositoryState(target: string): Promise<RepositoryState> {
  try {
    const before = (await git(target, ["rev-parse", "--verify", "HEAD"])).trim().toLowerCase();
    if (!/^[a-f0-9]{40,64}$/.test(before)) throw new Error("Git returned an invalid HEAD commit");
    const changes = await git(target, ["status", "--porcelain=v1", "--untracked-files=all", "--"]);
    const after = (await git(target, ["rev-parse", "--verify", "HEAD"])).trim().toLowerCase();
    if (before !== after) return { head: after, clean: false, error: "Repository HEAD changed while freshness was being checked" };
    return { head: after, clean: changes.length === 0, error: null };
  } catch {
    return { head: null, clean: false, error: "Repository Git state could not be verified" };
  }
}

export function evidenceFreshness(sourceCommit: string | null, state: RepositoryState): EvidenceFreshness {
  if (!sourceCommit || !/^[a-f0-9]{40,64}$/i.test(sourceCommit)) {
    return {
      status: "unverifiable",
      current_commit: state.head,
      reason: "Security evidence does not claim a verifiable clean source commit. Run a new scan before approving or publishing.",
    };
  }
  if (state.error || !state.head) {
    return {
      status: "unverifiable",
      current_commit: state.head,
      reason: "The repository Git state could not be verified. Resolve the Git state and run a new scan before approving or publishing.",
    };
  }
  if (!state.clean) {
    return {
      status: "dirty",
      current_commit: state.head,
      reason: "The repository has uncommitted changes. Commit or discard them, then run a new scan before approving or publishing.",
    };
  }
  if (sourceCommit.toLowerCase() !== state.head) {
    return {
      status: "stale",
      current_commit: state.head,
      reason: "Security evidence was produced for a different repository commit. Run a new scan before approving or publishing.",
    };
  }
  return { status: "current", current_commit: state.head, reason: null };
}

export function requireCurrentEvidence(sourceCommit: string | null, state: RepositoryState, label: string): void {
  const freshness = evidenceFreshness(sourceCommit, state);
  if (freshness.status !== "current") throw new Error(`${label} is not current. ${freshness.reason}`);
}
