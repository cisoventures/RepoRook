import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { sha256 } from "./fingerprint.js";
import { severities, type RepoRookConfig, type Severity } from "./types.js";

export const defaultConfig: RepoRookConfig = {
  failOn: "high",
  outputDir: ".reporook",
  semgrepConfig: "p/default",
  paths: ["."],
  ignore: ["node_modules/**", "dist/**", "build/**", ".git/**", ".reporook/**"],
  requiredScanners: [],
  scanners: {},
  baselineFile: "reporook-baseline.json",
  suppressionsFile: "reporook-suppressions.json",
  pathPolicies: {},
  containerImages: [],
  gitHistory: false,
};

export const scannerNames = ["semgrep", "gitleaks", "npm-audit", "pip-audit", "osv-scanner", "checkov", "trivy-image"] as const;
const scannerNameSet = new Set<string>(scannerNames);
const topLevelKeys = new Set([
  "failOn", "fail-on", "outputDir", "output-dir", "semgrepConfig", "semgrep-config",
  "paths", "ignore", "requiredScanners", "required-scanners", "scanners",
  "baseline", "baselineFile", "suppressions", "suppressionsFile", "pathPolicies", "path-policies",
  "containerImages", "container-images", "gitHistory", "git-history",
]);

function scalar(value: string): string | boolean | number | null {
  const unquoted = value.replace(/^['\"]|['\"]$/g, "");
  if (unquoted === "true") return true;
  if (unquoted === "false") return false;
  if (unquoted === "null") return null;
  if (/^-?\d+(\.\d+)?$/.test(unquoted)) return Number(unquoted);
  return unquoted;
}

export function parseSimpleYaml(text: string): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  const stack: Array<{ indent: number; value: Record<string, unknown> }> = [{ indent: -1, value: root }];
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index] ?? "";
    if (!raw.trim() || raw.trimStart().startsWith("#")) continue;
    const indent = raw.length - raw.trimStart().length;
    const trimmed = raw.trim();
    while (stack.length > 1 && indent <= (stack.at(-1)?.indent ?? -1)) stack.pop();
    const parent = stack.at(-1)?.value ?? root;
    const separator = trimmed.indexOf(":");
    if (separator < 0) throw new Error(`Invalid configuration at line ${index + 1}`);
    const key = trimmed.slice(0, separator).trim();
    if (!key) throw new Error(`Configuration key is missing at line ${index + 1}`);
    if (Object.hasOwn(parent, key)) throw new Error(`Duplicate configuration key ${key} at line ${index + 1}`);
    const rest = trimmed.slice(separator + 1).trim();
    if (rest) {
      if (rest.startsWith("[") && rest.endsWith("]")) {
        const contents = rest.slice(1, -1).trim();
        parent[key] = contents ? contents.split(",").map((entry) => scalar(entry.trim())) : [];
      } else {
        parent[key] = scalar(rest);
      }
      continue;
    }
    const following = lines.slice(index + 1).find((line) => line.trim() && !line.trimStart().startsWith("#"));
    if (following?.trimStart().startsWith("- ")) {
      const items: unknown[] = [];
      for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
        const candidate = lines[cursor] ?? "";
        const candidateIndent = candidate.length - candidate.trimStart().length;
        if (!candidate.trim()) continue;
        if (candidateIndent <= indent) break;
        if (candidate.trimStart().startsWith("- ")) {
          items.push(scalar(candidate.trimStart().slice(2).trim()));
          index = cursor;
        }
      }
      parent[key] = items;
    } else {
      const child: Record<string, unknown> = {};
      parent[key] = child;
      stack.push({ indent, value: child });
    }
  }
  return root;
}

function configObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("RepoRook configuration must be an object");
  return value as Record<string, unknown>;
}

function aliased(parsed: Record<string, unknown>, canonical: string, dashed: string): unknown {
  if (Object.hasOwn(parsed, canonical) && Object.hasOwn(parsed, dashed)) {
    throw new Error(`Configuration cannot contain both ${canonical} and ${dashed}`);
  }
  return parsed[canonical] ?? parsed[dashed];
}

function stringValue(value: unknown, name: string, fallback: string): string {
  if (value === undefined) return fallback;
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} must be a non-empty string`);
  return value;
}

function stringList(value: unknown, name: string, fallback: string[]): string[] {
  if (value === undefined) return [...fallback];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !item.trim())) {
    throw new Error(`${name} must be a list of non-empty strings`);
  }
  return [...value];
}

function booleanValue(value: unknown, name: string, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new Error(`${name} must be true or false`);
  return value;
}

function containerImageList(value: unknown): string[] {
  const images = stringList(value, "containerImages", defaultConfig.containerImages);
  if (images.length > 20) throw new Error("containerImages supports at most 20 explicit image references");
  for (const image of images) {
    const atCount = (image.match(/@/g) ?? []).length;
    if (image.length > 512
      || !/^[A-Za-z0-9][A-Za-z0-9._/:@+\-]{0,511}$/.test(image)
      || image.includes("..")
      || image.includes("//")
      || image.endsWith("/")
      || atCount > 1) {
      throw new Error(`Invalid container image reference: ${image}`);
    }
  }
  if (new Set(images).size !== images.length) throw new Error("containerImages must not contain duplicates");
  return images;
}

function scannerSettings(value: unknown): Record<string, boolean> {
  if (value === undefined) return {};
  const settings = configObject(value);
  const normalized: Record<string, boolean> = {};
  for (const [name, enabled] of Object.entries(settings)) {
    if (!scannerNameSet.has(name)) throw new Error(`Unknown scanner in scanners: ${name}`);
    if (typeof enabled !== "boolean") throw new Error(`scanners.${name} must be true or false`);
    normalized[name] = enabled;
  }
  return normalized;
}

function pathPolicySettings(value: unknown): Record<string, Severity> {
  if (value === undefined) return {};
  const settings = configObject(value);
  const normalized: Record<string, Severity> = {};
  for (const [pattern, thresholdValue] of Object.entries(settings).sort(([left], [right]) => left.localeCompare(right))) {
    if (!pattern.trim()) throw new Error("pathPolicies patterns must be non-empty");
    if (typeof thresholdValue !== "string") throw new Error(`pathPolicies.${pattern} must be a severity string`);
    const threshold = thresholdValue.toLowerCase() as Severity;
    if (!severities.includes(threshold)) throw new Error(`Invalid path policy severity for ${pattern}: ${thresholdValue}`);
    normalized[pattern] = threshold;
  }
  return normalized;
}

export function normalizeConfig(parsedValue: unknown): RepoRookConfig {
  const parsed = configObject(parsedValue);
  const unknown = Object.keys(parsed).filter((key) => !topLevelKeys.has(key));
  if (unknown.length) throw new Error(`Unknown RepoRook configuration key${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`);

  const failOnRaw = aliased(parsed, "failOn", "fail-on");
  if (failOnRaw !== undefined && typeof failOnRaw !== "string") throw new Error("failOn must be a severity string");
  const failOn = String(failOnRaw ?? defaultConfig.failOn).toLowerCase() as Severity;
  if (!severities.includes(failOn)) throw new Error(`Invalid fail-on severity: ${failOn}`);

  const requiredScanners = stringList(
    aliased(parsed, "requiredScanners", "required-scanners"),
    "requiredScanners",
    defaultConfig.requiredScanners,
  );
  for (const name of requiredScanners) {
    if (!scannerNameSet.has(name)) throw new Error(`Unknown required scanner: ${name}`);
  }
  const scanners = scannerSettings(parsed.scanners);
  for (const name of requiredScanners) {
    if (scanners[name] === false) throw new Error(`Scanner ${name} cannot be both required and disabled`);
  }
  const pathPolicies = pathPolicySettings(aliased(parsed, "pathPolicies", "path-policies"));
  for (const [pattern, threshold] of Object.entries(pathPolicies)) {
    if (severities.indexOf(threshold) < severities.indexOf(failOn)) {
      throw new Error(`Path policy ${pattern} cannot weaken the global failOn threshold (${threshold} is weaker than ${failOn})`);
    }
  }
  const containerImages = containerImageList(aliased(parsed, "containerImages", "container-images"));
  if (requiredScanners.includes("trivy-image") && !containerImages.length) {
    throw new Error("trivy-image cannot be required without at least one containerImages entry");
  }

  return {
    failOn,
    outputDir: stringValue(aliased(parsed, "outputDir", "output-dir"), "outputDir", defaultConfig.outputDir),
    semgrepConfig: stringValue(aliased(parsed, "semgrepConfig", "semgrep-config"), "semgrepConfig", defaultConfig.semgrepConfig),
    paths: stringList(parsed.paths, "paths", defaultConfig.paths),
    ignore: stringList(parsed.ignore, "ignore", defaultConfig.ignore),
    requiredScanners,
    scanners,
    baselineFile: stringValue(aliased(parsed, "baseline", "baselineFile"), "baseline", defaultConfig.baselineFile),
    suppressionsFile: stringValue(aliased(parsed, "suppressions", "suppressionsFile"), "suppressions", defaultConfig.suppressionsFile),
    pathPolicies,
    containerImages,
    gitHistory: booleanValue(aliased(parsed, "gitHistory", "git-history"), "gitHistory", defaultConfig.gitHistory),
  };
}

export async function loadConfig(target: string, requestedPath?: string): Promise<{ config: RepoRookConfig; hash: string; path: string | null }> {
  const candidates = requestedPath ? [requestedPath] : ["reporook.yml", "reporook.yaml", ".reporook.yml", ".reporook.json"];
  let parsed: Record<string, unknown> = {};
  let loadedPath: string | null = null;
  for (const candidate of candidates) {
    try {
      loadedPath = resolve(target, candidate);
      const text = await readFile(loadedPath, "utf8");
      parsed = candidate.endsWith(".json") ? configObject(JSON.parse(text)) : parseSimpleYaml(text);
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      loadedPath = null;
    }
  }
  const config = normalizeConfig(parsed);
  return { config, hash: sha256(JSON.stringify(config)), path: loadedPath };
}
