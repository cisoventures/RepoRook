import { existsSync } from "node:fs";
import { lstat, readFile, realpath, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
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
  cacheEnabled: true,
  cacheTtlMinutes: 15,
  scannerRetries: 1,
  organizationPolicyFile: null,
  organizationPolicy: null,
};

export const scannerNames = ["semgrep", "gitleaks", "npm-audit", "pip-audit", "osv-scanner", "checkov", "trivy-image"] as const;
const scannerNameSet = new Set<string>(scannerNames);
const topLevelKeys = new Set([
  "failOn", "fail-on", "outputDir", "output-dir", "semgrepConfig", "semgrep-config",
  "paths", "ignore", "requiredScanners", "required-scanners", "scanners",
  "baseline", "baselineFile", "suppressions", "suppressionsFile", "pathPolicies", "path-policies",
  "containerImages", "container-images", "gitHistory", "git-history",
  "cacheEnabled", "cache-enabled", "cacheTtlMinutes", "cache-ttl-minutes", "scannerRetries", "scanner-retries",
  "organizationPolicy", "organization-policy",
]);
const organizationPolicyKeys = new Set(["schemaVersion", "name", "failOn", "requiredScanners", "pathPolicies"]);
const maximumOrganizationPolicyBytes = 256 * 1024;
const maximumConfigurationBytes = 1024 * 1024;
const unsafeMappingKeys = new Set(["__proto__", "prototype", "constructor"]);

export interface OrganizationPolicyProfile {
  schemaVersion: "1.0";
  name: string;
  failOn: Severity;
  requiredScanners: string[];
  pathPolicies: Record<string, Severity>;
}

function assertSafeMappingKey(key: string, context: string): void {
  if (unsafeMappingKeys.has(key)) throw new Error(`${context} contains an unsafe mapping key: ${key}`);
}

function scalar(value: string): string | boolean | number | null {
  let quote: "\"" | "'" | null = null;
  let commentAt = -1;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (quote) {
      if (character === quote && value[index - 1] !== "\\") quote = null;
      continue;
    }
    if (character === "\"" || character === "'") quote = character;
    else if (character === "#" && (index === 0 || /\s/.test(value[index - 1] ?? ""))) {
      commentAt = index;
      break;
    }
  }
  const withoutComment = (commentAt >= 0 ? value.slice(0, commentAt) : value).trim();
  const quoted = (withoutComment.startsWith("\"") && withoutComment.endsWith("\""))
    || (withoutComment.startsWith("'") && withoutComment.endsWith("'"));
  const parsed = quoted ? withoutComment.slice(1, -1) : withoutComment;
  if (quoted) return parsed;
  if (parsed === "true") return true;
  if (parsed === "false") return false;
  if (parsed === "null") return null;
  if (/^-?\d+(\.\d+)?$/.test(parsed)) return Number(parsed);
  return parsed;
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
    assertSafeMappingKey(key, `Configuration at line ${index + 1}`);
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
    let following: string | undefined;
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const candidate = lines[cursor];
      if (candidate?.trim() && !candidate.trimStart().startsWith("#")) {
        following = candidate;
        break;
      }
    }
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

function optionalString(value: unknown, name: string): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} must be a non-empty string or null`);
  return value.trim();
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

function boundedInteger(value: unknown, name: string, fallback: number, minimum: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return Number(value);
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
    assertSafeMappingKey(pattern, "pathPolicies");
    if (typeof thresholdValue !== "string") throw new Error(`pathPolicies.${pattern} must be a severity string`);
    const threshold = thresholdValue.toLowerCase() as Severity;
    if (!severities.includes(threshold)) throw new Error(`Invalid path policy severity for ${pattern}: ${thresholdValue}`);
    normalized[pattern] = threshold;
  }
  return normalized;
}

export function parseOrganizationPolicy(value: unknown): OrganizationPolicyProfile {
  const parsed = configObject(value);
  const unknown = Object.keys(parsed).filter((key) => !organizationPolicyKeys.has(key));
  if (unknown.length) throw new Error(`Organization policy contains unknown field${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`);
  if (parsed.schemaVersion !== "1.0") throw new Error("Organization policy schemaVersion must be 1.0");
  if (typeof parsed.name !== "string" || !parsed.name.trim()) throw new Error("Organization policy name must be a non-empty string");
  const name = parsed.name.trim();
  const failOnRaw = parsed.failOn;
  if (typeof failOnRaw !== "string") throw new Error("Organization policy failOn must be a severity string");
  const failOn = failOnRaw.toLowerCase() as Severity;
  if (!severities.includes(failOn)) throw new Error(`Invalid organization policy failOn severity: ${failOnRaw}`);
  const requiredScanners = stringList(parsed.requiredScanners, "Organization policy requiredScanners", []);
  for (const scanner of requiredScanners) {
    if (!scannerNameSet.has(scanner)) throw new Error(`Unknown organization policy required scanner: ${scanner}`);
  }
  if (new Set(requiredScanners).size !== requiredScanners.length) throw new Error("Organization policy requiredScanners must not contain duplicates");
  const pathPolicies = pathPolicySettings(parsed.pathPolicies);
  for (const [pattern, threshold] of Object.entries(pathPolicies)) {
    if (severities.indexOf(threshold) < severities.indexOf(failOn)) {
      throw new Error(`Organization path policy ${pattern} cannot weaken its global failOn threshold`);
    }
  }
  return { schemaVersion: "1.0", name, failOn, requiredScanners, pathPolicies };
}

async function repositoryRoot(target: string): Promise<string> {
  const selected = await realpath(resolve(target));
  let root = selected;
  while (!existsSync(resolve(root, ".git")) && resolve(root, "..") !== root) root = resolve(root, "..");
  return existsSync(resolve(root, ".git")) ? root : selected;
}

async function configurationPath(target: string, requested: string, required: boolean): Promise<string | null> {
  const selected = await realpath(resolve(target));
  const root = await repositoryRoot(selected);
  const path = resolve(selected, requested);
  const traversal = relative(root, path);
  if (!traversal || traversal === ".." || traversal.startsWith(`..${sep}`) || isAbsolute(traversal)) {
    throw new Error("Configuration path must resolve to a file inside the repository");
  }
  let current = root;
  for (const segment of traversal.split(sep).filter(Boolean)) {
    current = resolve(current, segment);
    const metadata = await lstat(current).catch((error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return null;
      throw error;
    });
    if (!metadata) {
      if (required) throw new Error(`Configuration file does not exist: ${requested}`);
      return null;
    }
    if (metadata.isSymbolicLink()) throw new Error(`Configuration path contains a symbolic link: ${requested}`);
  }
  const metadata = await lstat(path);
  if (!metadata.isFile()) throw new Error("Configuration path must be a regular file");
  if (metadata.size > maximumConfigurationBytes) throw new Error("Configuration file exceeds 1 MiB");
  return path;
}

async function organizationPolicyPath(target: string, requested: string): Promise<string> {
  if (isAbsolute(requested)) throw new Error("organizationPolicy must be repository-relative");
  const root = await repositoryRoot(target);
  const path = resolve(root, requested);
  const traversal = relative(root, path);
  if (!traversal || traversal === ".." || traversal.startsWith(`..${sep}`) || isAbsolute(traversal)) {
    throw new Error("organizationPolicy must resolve to a file inside the repository");
  }
  let current = root;
  for (const segment of traversal.split(sep).filter(Boolean)) {
    current = resolve(current, segment);
    const metadata = await lstat(current).catch((error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") throw new Error(`Organization policy file does not exist: ${requested}`);
      throw error;
    });
    if (metadata.isSymbolicLink()) throw new Error(`Organization policy path contains a symbolic link: ${requested}`);
  }
  const metadata = await stat(path);
  if (!metadata.isFile()) throw new Error("Organization policy path must be a regular file");
  if (metadata.size > maximumOrganizationPolicyBytes) throw new Error("Organization policy file exceeds 256 KiB");
  return path;
}

async function applyOrganizationPolicy(target: string, config: RepoRookConfig): Promise<RepoRookConfig> {
  if (!config.organizationPolicyFile) return config;
  const path = await organizationPolicyPath(target, config.organizationPolicyFile);
  const contents = await readFile(path, "utf8");
  if (Buffer.byteLength(contents, "utf8") > maximumOrganizationPolicyBytes) throw new Error("Organization policy file exceeds 256 KiB");
  const raw = path.endsWith(".json") ? configObject(JSON.parse(contents)) : parseSimpleYaml(contents);
  const profile = parseOrganizationPolicy(raw);
  if (severities.indexOf(config.failOn) < severities.indexOf(profile.failOn)) {
    throw new Error(`Local failOn ${config.failOn} is weaker than organization policy ${profile.failOn}`);
  }
  for (const scanner of profile.requiredScanners) {
    if (config.scanners[scanner] === false) throw new Error(`Scanner ${scanner} is required by organization policy and cannot be disabled locally`);
  }
  if (profile.requiredScanners.includes("trivy-image") && !config.containerImages.length) {
    throw new Error("trivy-image is required by organization policy but containerImages is empty");
  }
  for (const [pattern, threshold] of Object.entries(config.pathPolicies)) {
    const required = profile.pathPolicies[pattern];
    if (required && severities.indexOf(threshold) < severities.indexOf(required)) {
      throw new Error(`Local path policy ${pattern} is weaker than organization policy (${threshold} is weaker than ${required})`);
    }
  }
  return {
    ...config,
    requiredScanners: scannerNames.filter((name) => profile.requiredScanners.includes(name) || config.requiredScanners.includes(name)),
    pathPolicies: { ...profile.pathPolicies, ...config.pathPolicies },
    organizationPolicy: {
      name: profile.name,
      path: config.organizationPolicyFile,
      hash: `sha256:${sha256(contents)}`,
    },
  };
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
    cacheEnabled: booleanValue(aliased(parsed, "cacheEnabled", "cache-enabled"), "cacheEnabled", defaultConfig.cacheEnabled),
    cacheTtlMinutes: boundedInteger(aliased(parsed, "cacheTtlMinutes", "cache-ttl-minutes"), "cacheTtlMinutes", defaultConfig.cacheTtlMinutes, 1, 1_440),
    scannerRetries: boundedInteger(aliased(parsed, "scannerRetries", "scanner-retries"), "scannerRetries", defaultConfig.scannerRetries, 0, 3),
    organizationPolicyFile: optionalString(aliased(parsed, "organizationPolicy", "organization-policy"), "organizationPolicy"),
    organizationPolicy: null,
  };
}

export async function loadConfig(target: string, requestedPath?: string): Promise<{ config: RepoRookConfig; hash: string; path: string | null }> {
  const candidates = requestedPath ? [requestedPath] : ["reporook.yml", "reporook.yaml", ".reporook.yml", ".reporook.json"];
  let parsed: Record<string, unknown> = {};
  let loadedPath: string | null = null;
  for (const candidate of candidates) {
    loadedPath = await configurationPath(target, candidate, requestedPath !== undefined);
    if (!loadedPath) continue;
    const text = await readFile(loadedPath, "utf8");
    if (Buffer.byteLength(text, "utf8") > maximumConfigurationBytes) throw new Error("Configuration file exceeds 1 MiB");
    parsed = loadedPath.endsWith(".json") ? configObject(JSON.parse(text)) : parseSimpleYaml(text);
    break;
  }
  const config = await applyOrganizationPolicy(target, normalizeConfig(parsed));
  return { config, hash: sha256(JSON.stringify(config)), path: loadedPath };
}
