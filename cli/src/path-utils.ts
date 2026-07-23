import { relative, resolve, sep } from "node:path";

export function repoRelative(target: string, input: string | undefined, fallback = "unknown"): string {
  if (!input) return fallback;
  const absolute = resolve(target, input);
  const rel = relative(resolve(target), absolute).split(sep).join("/");
  if (!rel || rel.startsWith("../")) return input.split(sep).join("/");
  return rel;
}

function segmentMatches(value: string, pattern: string): boolean {
  let previous = new Array<boolean>(pattern.length + 1).fill(false);
  previous[0] = true;
  for (let patternIndex = 1; patternIndex <= pattern.length; patternIndex += 1) {
    if (pattern[patternIndex - 1] === "*") previous[patternIndex] = previous[patternIndex - 1] ?? false;
  }

  for (const character of value) {
    const current = new Array<boolean>(pattern.length + 1).fill(false);
    for (let patternIndex = 1; patternIndex <= pattern.length; patternIndex += 1) {
      const patternCharacter = pattern[patternIndex - 1] ?? "";
      current[patternIndex] = patternCharacter === "*"
        ? (current[patternIndex - 1] ?? false) || (previous[patternIndex] ?? false)
        : (previous[patternIndex - 1] ?? false) && patternCharacter === character;
    }
    previous = current;
  }

  return previous[pattern.length] ?? false;
}

function globMatches(path: string, glob: string): boolean {
  const pathSegments = path.replaceAll("\\", "/").split("/").filter(Boolean);
  const globSegments = glob.replaceAll("\\", "/").split("/").filter(Boolean);
  let previous = new Array<boolean>(globSegments.length + 1).fill(false);
  previous[0] = true;
  for (let globIndex = 1; globIndex <= globSegments.length; globIndex += 1) {
    if (globSegments[globIndex - 1] === "**") previous[globIndex] = previous[globIndex - 1] ?? false;
  }

  for (const pathSegment of pathSegments) {
    const current = new Array<boolean>(globSegments.length + 1).fill(false);
    for (let globIndex = 1; globIndex <= globSegments.length; globIndex += 1) {
      const globSegment = globSegments[globIndex - 1] ?? "";
      current[globIndex] = globSegment === "**"
        ? (current[globIndex - 1] ?? false) || (previous[globIndex] ?? false)
        : (previous[globIndex - 1] ?? false) && segmentMatches(pathSegment, globSegment);
    }
    previous = current;
  }

  return previous[globSegments.length] ?? false;
}

export function matchesAny(path: string, globs: string[]): boolean {
  const normalized = path.replaceAll("\\", "/").replace(/^\.\//, "");
  return globs.some((glob) => globMatches(normalized, glob.replace(/^\.\//, "")));
}
