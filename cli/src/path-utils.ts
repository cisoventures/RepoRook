import { relative, resolve, sep } from "node:path";

export function repoRelative(target: string, input: string | undefined, fallback = "unknown"): string {
  if (!input) return fallback;
  const absolute = resolve(target, input);
  const rel = relative(resolve(target), absolute).split(sep).join("/");
  if (!rel || rel.startsWith("../")) return input.split(sep).join("/");
  return rel;
}

function escapeRegex(value: string): string {
  return value.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
}

export function globToRegex(glob: string): RegExp {
  let pattern = escapeRegex(glob.replaceAll("\\", "/"));
  pattern = pattern.replaceAll("**/", "(?:.*/)?").replaceAll("**", ".*").replaceAll("*", "[^/]*");
  return new RegExp(`^${pattern}$`);
}

export function matchesAny(path: string, globs: string[]): boolean {
  const normalized = path.replaceAll("\\", "/").replace(/^\.\//, "");
  return globs.some((glob) => globToRegex(glob.replace(/^\.\//, "")).test(normalized));
}
