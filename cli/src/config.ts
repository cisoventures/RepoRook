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
};

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
    const rest = trimmed.slice(separator + 1).trim();
    if (rest) {
      if (rest.startsWith("[") && rest.endsWith("]")) {
        parent[key] = rest.slice(1, -1).split(",").map((entry) => String(scalar(entry.trim())));
      } else {
        parent[key] = scalar(rest);
      }
      continue;
    }
    const following = lines.slice(index + 1).find((line) => line.trim() && !line.trimStart().startsWith("#"));
    if (following?.trimStart().startsWith("- ")) {
      const items: string[] = [];
      for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
        const candidate = lines[cursor] ?? "";
        const candidateIndent = candidate.length - candidate.trimStart().length;
        if (!candidate.trim()) continue;
        if (candidateIndent <= indent) break;
        if (candidate.trimStart().startsWith("- ")) {
          items.push(String(scalar(candidate.trimStart().slice(2).trim())));
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

function asStrings(value: unknown, fallback: string[]): string[] {
  return Array.isArray(value) ? value.map(String) : fallback;
}

export async function loadConfig(target: string, requestedPath?: string): Promise<{ config: RepoRookConfig; hash: string; path: string | null }> {
  const candidates = requestedPath ? [requestedPath] : ["reporook.yml", "reporook.yaml", ".reporook.yml", ".reporook.json"];
  let parsed: Record<string, unknown> = {};
  let loadedPath: string | null = null;
  for (const candidate of candidates) {
    try {
      loadedPath = resolve(target, candidate);
      const text = await readFile(loadedPath, "utf8");
      parsed = candidate.endsWith(".json") ? (JSON.parse(text) as Record<string, unknown>) : parseSimpleYaml(text);
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      loadedPath = null;
    }
  }
  const failOn = String(parsed.failOn ?? parsed["fail-on"] ?? defaultConfig.failOn).toLowerCase() as Severity;
  if (!severities.includes(failOn)) throw new Error(`Invalid fail-on severity: ${failOn}`);
  const scannerSettings = parsed.scanners && typeof parsed.scanners === "object" ? parsed.scanners as Record<string, unknown> : {};
  const config: RepoRookConfig = {
    failOn,
    outputDir: String(parsed.outputDir ?? parsed["output-dir"] ?? defaultConfig.outputDir),
    semgrepConfig: String(parsed.semgrepConfig ?? parsed["semgrep-config"] ?? defaultConfig.semgrepConfig),
    paths: asStrings(parsed.paths, defaultConfig.paths),
    ignore: asStrings(parsed.ignore, defaultConfig.ignore),
    requiredScanners: asStrings(parsed.requiredScanners ?? parsed["required-scanners"], defaultConfig.requiredScanners),
    scanners: Object.fromEntries(Object.entries(scannerSettings).map(([key, value]) => [key, value !== false])),
  };
  return { config, hash: sha256(JSON.stringify(config)), path: loadedPath };
}
