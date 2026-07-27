import { lstat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { matchesAny } from "./path-utils.js";
import type { RepoRookConfig, ScannerContext } from "./types.js";

function normalized(path: string): string { return path.replaceAll("\\", "/").replace(/^\.\//, ""); }

export function inConfiguredScope(pathInput: string, config: RepoRookConfig): boolean {
  const path = normalized(pathInput);
  if (matchesAny(path, config.ignore)) return false;
  if (!config.paths.length || config.paths.includes(".")) return true;
  const patterns = config.paths.flatMap((candidate) => {
    const path = normalized(candidate).replace(/\/$/, "");
    return path.endsWith("/**") ? [path] : [path, `${path}/**`];
  });
  return matchesAny(path, patterns);
}

export async function scopedChangedFiles(
  context: ScannerContext,
  predicate: (path: string) => boolean,
): Promise<string[]> {
  const root = resolve(context.target);
  const selected: string[] = [];
  for (const candidate of context.changedFiles ?? []) {
    const path = normalized(candidate);
    if (!path || isAbsolute(path) || path === ".." || path.startsWith("../") || !inConfiguredScope(path, context.config) || !predicate(path)) continue;
    const absolute = resolve(root, path);
    const traversal = relative(root, absolute);
    if (!traversal || traversal === ".." || traversal.startsWith(`..${sep}`) || isAbsolute(traversal)) continue;
    const metadata = await lstat(absolute).catch(() => null);
    if (metadata?.isFile() && !metadata.isSymbolicLink()) selected.push(path);
  }
  return [...new Set(selected)].sort((left, right) => left.localeCompare(right));
}
