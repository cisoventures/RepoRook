import { createHash, randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { lstat, mkdir, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { VERSION } from "./engine.js";
import { readBoundedJsonFile, readBoundedTextFile } from "./input.js";

export const integrationHosts = ["claude", "codex", "cursor", "copilot", "gemini", "windsurf"] as const;
export type IntegrationHost = (typeof integrationHosts)[number];
export type IntegrationOperation = "install" | "update" | "doctor" | "uninstall";
type EntryKind = "file" | "json-member" | "json-array-item";
type ActionStatus = "create" | "update" | "ready" | "outdated" | "missing" | "remove" | "modified" | "unmanaged";

interface FileSpec {
  id: string;
  host: IntegrationHost;
  kind: EntryKind;
  path: string;
  source?: string;
  jsonPath?: string[];
  arrayMatch?: { key: string; value: string };
  value?: unknown;
}

interface ReceiptEntry {
  id: string;
  kind: EntryKind;
  path: string;
  hash: string;
  json_path?: string[];
  array_match?: { key: string; value: string };
  container_created: boolean;
}

interface HostReceipt {
  version: string;
  installed_at: string;
  updated_at: string;
  entries: ReceiptEntry[];
}

interface IntegrationReceipt {
  schema_version: "1.0";
  tool: { name: "reporook"; version: string };
  hosts: Partial<Record<IntegrationHost, HostReceipt>>;
}

export interface IntegrationAction {
  host: IntegrationHost;
  id: string;
  path: string;
  kind: EntryKind;
  status: ActionStatus;
  detail: string;
}

export interface IntegrationResult {
  operation: IntegrationOperation;
  target: string;
  hosts: IntegrationHost[];
  applied: boolean;
  actions: IntegrationAction[];
  receipt_path: string;
  next_commands: string[];
}

const receiptName = ".reporook/integrations.json";
const maximumIntegrationBytes = 2 * 1024 * 1024;
const maximumReceiptBytes = 1024 * 1024;
const mcpValue = { command: "npx", args: ["--yes", "@reporook/mcp-server"] };
const copilotMcpValue = { type: "local", command: "npx", args: ["--yes", "@reporook/mcp-server"], tools: ["*"] };
const codexMarketplaceEntry = {
  name: "reporook",
  source: { source: "local", path: "./.agents/plugins/reporook" },
  policy: { installation: "INSTALLED_BY_DEFAULT", authentication: "ON_INSTALL" },
  category: "Security",
};

const file = (host: IntegrationHost, source: string, path: string): FileSpec => ({ host, source, path, id: path, kind: "file" });
const jsonMember = (host: IntegrationHost, path: string, value: unknown): FileSpec => ({
  host, path, value, id: `${path}#mcpServers.reporook`, kind: "json-member", jsonPath: ["mcpServers", "reporook"],
});

const specs: Record<IntegrationHost, FileSpec[]> = {
  claude: [
    file("claude", "claude/reporook/skills/reporook-security/SKILL.md", ".claude/skills/reporook-security/SKILL.md"),
    file("claude", "claude/reporook/agents/reporook-reviewer.md", ".claude/agents/reporook-reviewer.md"),
    file("claude", "claude/reporook/agents/reporook-fixer.md", ".claude/agents/reporook-fixer.md"),
    jsonMember("claude", ".mcp.json", mcpValue),
  ],
  codex: [
    file("codex", "codex/reporook/.codex-plugin/plugin.json", ".agents/plugins/reporook/.codex-plugin/plugin.json"),
    file("codex", "codex/reporook/.mcp.json", ".agents/plugins/reporook/.mcp.json"),
    file("codex", "codex/reporook/skills/reporook-security/SKILL.md", ".agents/plugins/reporook/skills/reporook-security/SKILL.md"),
    file("codex", "codex/reporook/skills/reporook-security/agents/openai.yaml", ".agents/plugins/reporook/skills/reporook-security/agents/openai.yaml"),
    {
      host: "codex", path: ".agents/plugins/marketplace.json", value: codexMarketplaceEntry,
      id: ".agents/plugins/marketplace.json#plugins[name=reporook]", kind: "json-array-item",
      jsonPath: ["plugins"], arrayMatch: { key: "name", value: "reporook" },
    },
  ],
  cursor: [
    file("cursor", "cursor/reporook/skills/reporook-security/SKILL.md", ".cursor/skills/reporook-security/SKILL.md"),
    file("cursor", "cursor/reporook/.cursor/agents/reporook-reviewer.md", ".cursor/agents/reporook-reviewer.md"),
    file("cursor", "cursor/reporook/.cursor/agents/reporook-fixer.md", ".cursor/agents/reporook-fixer.md"),
    file("cursor", "cursor/reporook/.cursor/rules/reporook.mdc", ".cursor/rules/reporook.mdc"),
    jsonMember("cursor", ".cursor/mcp.json", mcpValue),
  ],
  copilot: [
    file("copilot", "copilot/reporook/skills/reporook-security/SKILL.md", ".github/skills/reporook-security/SKILL.md"),
    file("copilot", "copilot/reporook/agents/reporook-reviewer.agent.md", ".github/agents/reporook-reviewer.agent.md"),
    file("copilot", "copilot/reporook/agents/reporook-fixer.agent.md", ".github/agents/reporook-fixer.agent.md"),
    jsonMember("copilot", ".github/mcp.json", copilotMcpValue),
  ],
  gemini: [
    file("gemini", "gemini/reporook/skills/reporook-security/SKILL.md", ".gemini/skills/reporook-security/SKILL.md"),
    file("gemini", "gemini/reporook/agents/security-auditor.md", ".gemini/agents/security-auditor.md"),
    file("gemini", "gemini/reporook/agents/security-fixer.md", ".gemini/agents/security-fixer.md"),
    jsonMember("gemini", ".gemini/settings.json", mcpValue),
  ],
  windsurf: [
    file("windsurf", "windsurf/reporook/.windsurf/skills/reporook-security/SKILL.md", ".windsurf/skills/reporook-security/SKILL.md"),
    file("windsurf", "windsurf/reporook/.windsurf/rules/reporook.md", ".windsurf/rules/reporook.md"),
    file("windsurf", "windsurf/reporook/.windsurf/workflows/reporook-security.md", ".windsurf/workflows/reporook-security.md"),
  ],
};

function assetRoot(): string { return resolve(dirname(fileURLToPath(import.meta.url)), "integrations"); }
function hash(value: string | unknown): string {
  const serialized = typeof value === "string" ? value : JSON.stringify(value);
  return `sha256:${createHash("sha256").update(serialized ?? "").digest("hex")}`;
}
function equal(left: unknown, right: unknown): boolean { return JSON.stringify(left) === JSON.stringify(right); }
function isRecord(value: unknown): value is Record<string, unknown> { return !!value && typeof value === "object" && !Array.isArray(value); }

async function repositoryRoot(targetInput: string): Promise<string> {
  const selected = await realpath(resolve(targetInput)).catch(() => resolve(targetInput));
  const stats = await lstat(selected).catch(() => null);
  if (!stats?.isDirectory()) throw new Error(`Integration target is not a directory: ${selected}`);
  let root = selected;
  while (!existsSync(join(root, ".git")) && dirname(root) !== root) root = dirname(root);
  return existsSync(join(root, ".git")) ? root : selected;
}

function safePath(root: string, path: string): string {
  const absolute = resolve(root, path);
  const traversal = relative(root, absolute);
  if (traversal === ".." || traversal.startsWith(`..${sep}`) || isAbsolute(traversal)) throw new Error(`Integration path escapes the repository: ${path}`);
  return absolute;
}

async function rejectSymbolicPath(root: string, absolute: string): Promise<void> {
  let current = root;
  for (const segment of relative(root, absolute).split(sep).filter(Boolean)) {
    current = join(current, segment);
    const stats = await lstat(current).catch(() => null);
    if (stats?.isSymbolicLink()) throw new Error(`Refusing to manage a path containing a symbolic link: ${current}`);
  }
}

async function atomicWrite(path: string, contents: string, mode = 0o644): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = join(dirname(path), `.${basename(path)}.reporook-${process.pid}-${randomBytes(6).toString("hex")}.tmp`);
  try {
    await writeFile(temporary, contents, { encoding: "utf8", mode, flag: "wx" });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

async function expectedValue(spec: FileSpec): Promise<string | unknown> {
  if (spec.kind !== "file") return spec.value;
  if (!spec.source) throw new Error(`Missing packaged source for ${spec.id}`);
  return await readFile(resolve(assetRoot(), spec.source), "utf8");
}

function getPath(object: Record<string, unknown>, path: string[]): unknown {
  let current: unknown = object;
  for (const key of path) {
    if (!isRecord(current)) throw new Error(`Integration JSON path is not an object: ${path.join(".")}`);
    if (!Object.hasOwn(current, key)) return undefined;
    current = current[key];
  }
  return current;
}

function setPath(object: Record<string, unknown>, path: string[], value: unknown): void {
  let current = object;
  for (const key of path.slice(0, -1)) {
    if (current[key] === undefined) current[key] = {};
    else if (!isRecord(current[key])) throw new Error(`Integration JSON path is not an object: ${path.join(".")}`);
    current = current[key] as Record<string, unknown>;
  }
  current[path.at(-1) ?? ""] = value;
}

function deletePath(object: Record<string, unknown>, path: string[]): void {
  const parents: Array<{ object: Record<string, unknown>; key: string }> = [];
  let current = object;
  for (const key of path.slice(0, -1)) {
    if (!isRecord(current[key])) return;
    parents.push({ object: current, key });
    current = current[key] as Record<string, unknown>;
  }
  delete current[path.at(-1) ?? ""];
  for (const parent of parents.reverse()) {
    const value = parent.object[parent.key];
    if (isRecord(value) && Object.keys(value).length === 0) delete parent.object[parent.key];
  }
}

function receiptEntry(spec: FileSpec, expected: string | unknown, containerCreated: boolean, previous?: ReceiptEntry): ReceiptEntry {
  return {
    id: spec.id, kind: spec.kind, path: spec.path, hash: hash(expected),
    ...(spec.jsonPath ? { json_path: spec.jsonPath } : {}),
    ...(spec.arrayMatch ? { array_match: spec.arrayMatch } : {}),
    container_created: previous?.container_created ?? containerCreated,
  };
}

async function readReceipt(root: string): Promise<IntegrationReceipt> {
  const path = safePath(root, receiptName);
  const stats = await lstat(path).catch(() => null);
  if (!stats) return { schema_version: "1.0", tool: { name: "reporook", version: VERSION }, hosts: {} };
  if (!stats.isFile() || stats.isSymbolicLink()) throw new Error("RepoRook integration receipt is not a regular file");
  const parsed = await readBoundedJsonFile(path, "RepoRook integration receipt", maximumReceiptBytes);
  if (!isRecord(parsed) || parsed.schema_version !== "1.0" || !isRecord(parsed.tool) || parsed.tool.name !== "reporook" || !isRecord(parsed.hosts)) {
    throw new Error("RepoRook integration receipt is invalid");
  }
  for (const [hostName, value] of Object.entries(parsed.hosts)) {
    if (!integrationHosts.includes(hostName as IntegrationHost) || !isRecord(value) || !Array.isArray(value.entries)) {
      throw new Error("RepoRook integration receipt contains an invalid host");
    }
    const host = hostName as IntegrationHost;
    const allowed = new Map(specs[host].map((spec) => [spec.id, spec]));
    const seen = new Set<string>();
    for (const candidate of value.entries) {
      if (!isRecord(candidate) || typeof candidate.id !== "string" || seen.has(candidate.id)) throw new Error(`RepoRook integration receipt contains an invalid ${host} entry`);
      seen.add(candidate.id);
      const spec = allowed.get(candidate.id);
      if (!spec
        || candidate.kind !== spec.kind
        || candidate.path !== spec.path
        || typeof candidate.hash !== "string"
        || !/^sha256:[a-f0-9]{64}$/.test(candidate.hash)
        || typeof candidate.container_created !== "boolean"
        || !equal(candidate.json_path, spec.jsonPath)
        || !equal(candidate.array_match, spec.arrayMatch)) {
        throw new Error(`RepoRook integration receipt entry is outside the ${host} allowlist: ${candidate.id}`);
      }
    }
  }
  return parsed as unknown as IntegrationReceipt;
}

async function currentEntry(root: string, entry: Pick<ReceiptEntry, "kind" | "path" | "json_path" | "array_match">): Promise<{ exists: boolean; containerExists: boolean; value?: unknown }> {
  const absolute = safePath(root, entry.path);
  await rejectSymbolicPath(root, absolute);
  const stats = await lstat(absolute).catch(() => null);
  if (!stats) return { exists: false, containerExists: false };
  if (!stats.isFile()) throw new Error(`Integration destination is not a regular file: ${entry.path}`);
  if (entry.kind === "file") return { exists: true, containerExists: true, value: await readBoundedTextFile(absolute, "Integration destination", maximumIntegrationBytes) };
  const parsed = await readBoundedJsonFile(absolute, "Integration JSON", maximumIntegrationBytes);
  if (!isRecord(parsed)) throw new Error(`Integration JSON must contain an object: ${entry.path}`);
  const selected = getPath(parsed, entry.json_path ?? []);
  if (entry.kind === "json-member") return { exists: selected !== undefined, containerExists: true, value: selected };
  if (selected === undefined) return { exists: false, containerExists: true };
  if (!Array.isArray(selected)) throw new Error(`Integration JSON path must contain an array: ${(entry.json_path ?? []).join(".")}`);
  const match = entry.array_match;
  const value = selected.find((item) => match && isRecord(item) && item[match.key] === match.value);
  return { exists: value !== undefined, containerExists: true, value };
}

function action(host: IntegrationHost, spec: Pick<FileSpec, "id" | "path" | "kind">, status: ActionStatus, detail: string): IntegrationAction {
  return { host, id: spec.id, path: spec.path, kind: spec.kind, status, detail };
}

async function planCurrentSpec(root: string, operation: IntegrationOperation, spec: FileSpec, prior?: ReceiptEntry): Promise<{ action: IntegrationAction; expected: string | unknown; entry: ReceiptEntry }> {
  const expected = await expectedValue(spec);
  const current = await currentEntry(root, {
    kind: spec.kind,
    path: spec.path,
    ...(spec.jsonPath ? { json_path: spec.jsonPath } : {}),
    ...(spec.arrayMatch ? { array_match: spec.arrayMatch } : {}),
  });
  const entry = receiptEntry(spec, expected, !current.containerExists, prior);
  if (operation === "doctor") {
    if (!current.exists) return { action: action(spec.host, spec, "missing", "not configured"), expected, entry };
    if (equal(current.value, expected)) return { action: action(spec.host, spec, "ready", "current RepoRook configuration"), expected, entry };
    if (prior && hash(current.value) === prior.hash) return { action: action(spec.host, spec, "outdated", `managed by RepoRook ${prior.hash === entry.hash ? VERSION : "an earlier version"}`), expected, entry };
    return { action: action(spec.host, spec, "modified", "existing content is not owned by the current receipt"), expected, entry };
  }
  if (!current.exists) return { action: action(spec.host, spec, "create", spec.kind === "file" ? "create file" : "add managed JSON entry"), expected, entry };
  if (equal(current.value, expected)) return { action: action(spec.host, spec, "ready", "already current"), expected, entry };
  if (prior && hash(current.value) === prior.hash) return { action: action(spec.host, spec, "update", "replace prior RepoRook-managed content"), expected, entry };
  return { action: action(spec.host, spec, "modified", "would overwrite content not owned by the current receipt"), expected, entry };
}

async function planReceiptRemoval(root: string, host: IntegrationHost, entry: ReceiptEntry): Promise<IntegrationAction> {
  const current = await currentEntry(root, entry);
  if (!current.exists) return action(host, entry, "missing", "already absent");
  if (hash(current.value) === entry.hash) return action(host, entry, "remove", "remove unchanged RepoRook-managed content");
  return action(host, entry, "modified", "managed content changed after installation; refusing to remove it");
}

async function writeSpec(root: string, spec: FileSpec, expected: string | unknown): Promise<void> {
  const absolute = safePath(root, spec.path);
  await rejectSymbolicPath(root, absolute);
  if (spec.kind === "file") {
    const stats = await lstat(absolute).catch(() => null);
    await atomicWrite(absolute, String(expected), stats ? stats.mode & 0o777 : 0o644);
    return;
  }
  const stats = await lstat(absolute).catch(() => null);
  const object = stats ? await readBoundedJsonFile(absolute, "Integration JSON", maximumIntegrationBytes) : {};
  if (!isRecord(object)) throw new Error(`Integration JSON must contain an object: ${spec.path}`);
  if (spec.kind === "json-member") setPath(object, spec.jsonPath ?? [], expected);
  else {
    const path = spec.jsonPath ?? [];
    const current = getPath(object, path);
    if (current !== undefined && !Array.isArray(current)) throw new Error(`Integration JSON path must contain an array: ${(spec.jsonPath ?? []).join(".")}`);
    const values = Array.isArray(current) ? [...current] : [];
    const match = spec.arrayMatch;
    const index = values.findIndex((item) => match && isRecord(item) && item[match.key] === match.value);
    if (index >= 0) values[index] = expected;
    else values.push(expected);
    setPath(object, path, values);
    if (spec.path === ".agents/plugins/marketplace.json") {
      if (!Object.hasOwn(object, "name")) object.name = "reporook-local";
      if (!Object.hasOwn(object, "interface")) object.interface = { displayName: "Repository plugins" };
    }
  }
  await atomicWrite(absolute, `${JSON.stringify(object, null, 2)}\n`, stats ? stats.mode & 0o777 : 0o644);
}

async function removeEntry(root: string, entry: ReceiptEntry): Promise<void> {
  const absolute = safePath(root, entry.path);
  await rejectSymbolicPath(root, absolute);
  if (entry.kind === "file") {
    await rm(absolute, { force: true });
    return;
  }
  const parsed = await readBoundedJsonFile(absolute, "Integration JSON", maximumIntegrationBytes);
  if (!isRecord(parsed)) throw new Error(`Integration JSON must contain an object: ${entry.path}`);
  if (entry.kind === "json-member") deletePath(parsed, entry.json_path ?? []);
  else {
    const path = entry.json_path ?? [];
    const current = getPath(parsed, path);
    if (Array.isArray(current)) {
      const match = entry.array_match;
      const remaining = current.filter((item) => !(match && isRecord(item) && item[match.key] === match.value));
      if (remaining.length) setPath(parsed, path, remaining);
      else deletePath(parsed, path);
    }
  }
  if (entry.container_created && Object.keys(parsed).length === 0) await rm(absolute, { force: true });
  else {
    const stats = await lstat(absolute);
    await atomicWrite(absolute, `${JSON.stringify(parsed, null, 2)}\n`, stats.mode & 0o777);
  }
}

async function pruneEmptyDirectories(root: string, path: string): Promise<void> {
  let current = dirname(safePath(root, path));
  while (current !== root) {
    const removed = await rm(current, { recursive: false }).then(() => true).catch(() => false);
    if (!removed) break;
    current = dirname(current);
  }
}

export function parseIntegrationHosts(value: string | undefined): IntegrationHost[] {
  if (!value || value === "all") return [...integrationHosts];
  const selected = value.split(",").map((item) => item.trim().toLowerCase()).filter(Boolean);
  const invalid = selected.filter((item) => !integrationHosts.includes(item as IntegrationHost));
  if (invalid.length) throw new Error(`Unknown integration host: ${invalid.join(", ")}. Use ${integrationHosts.join(", ")}, or all.`);
  return [...new Set(selected as IntegrationHost[])];
}

export async function manageIntegrations(options: {
  target: string;
  operation: IntegrationOperation;
  hosts: IntegrationHost[];
  apply?: boolean;
}): Promise<IntegrationResult> {
  const root = await repositoryRoot(options.target);
  const receipt = await readReceipt(root);
  const actions: IntegrationAction[] = [];
  const expectedById = new Map<string, string | unknown>();
  const entriesByHost = new Map<IntegrationHost, ReceiptEntry[]>();

  for (const host of options.hosts) {
    const priorEntries = new Map((receipt.hosts[host]?.entries ?? []).map((entry) => [entry.id, entry]));
    if (options.operation === "uninstall") {
      if (!receipt.hosts[host]) {
        actions.push({ host, id: host, path: "", kind: "file", status: "unmanaged", detail: "no RepoRook receipt exists for this host" });
        continue;
      }
      for (const entry of receipt.hosts[host]?.entries ?? []) actions.push(await planReceiptRemoval(root, host, entry));
      continue;
    }

    const currentEntries: ReceiptEntry[] = [];
    for (const spec of specs[host]) {
      const planned = await planCurrentSpec(root, options.operation, spec, priorEntries.get(spec.id));
      actions.push(planned.action);
      expectedById.set(`${host}:${spec.id}`, planned.expected);
      currentEntries.push(planned.entry);
      priorEntries.delete(spec.id);
    }
    if (options.operation === "update") {
      for (const retired of priorEntries.values()) actions.push(await planReceiptRemoval(root, host, retired));
    } else if (options.operation === "doctor") {
      for (const retired of priorEntries.values()) actions.push(action(host, retired, "outdated", "managed path is no longer part of this host adapter"));
    }
    entriesByHost.set(host, currentEntries);
  }

  const conflicts = actions.filter((item) => item.status === "modified");
  const mutating = options.operation !== "doctor";
  if (options.apply && mutating && conflicts.length) {
    return {
      operation: options.operation, target: root, hosts: options.hosts, applied: false, actions,
      receipt_path: safePath(root, receiptName),
      next_commands: ["Resolve or move the modified files, then rerun the same command."],
    };
  }

  if (options.apply && mutating) {
    if (options.operation === "uninstall") {
      for (const host of options.hosts) {
        const hostReceipt = receipt.hosts[host];
        if (!hostReceipt) continue;
        for (const entry of hostReceipt.entries) {
          const planned = actions.find((item) => item.host === host && item.id === entry.id);
          if (planned?.status === "remove") { await removeEntry(root, entry); await pruneEmptyDirectories(root, entry.path); }
        }
        delete receipt.hosts[host];
      }
    } else {
      for (const host of options.hosts) {
        const previous = receipt.hosts[host];
        for (const spec of specs[host]) {
          const planned = actions.find((item) => item.host === host && item.id === spec.id);
          if (["create", "update"].includes(planned?.status ?? "")) await writeSpec(root, spec, expectedById.get(`${host}:${spec.id}`));
        }
        if (options.operation === "update") {
          const currentIds = new Set(specs[host].map((spec) => spec.id));
          for (const retired of previous?.entries ?? []) {
            if (currentIds.has(retired.id)) continue;
            const planned = actions.find((item) => item.host === host && item.id === retired.id);
            if (planned?.status === "remove") { await removeEntry(root, retired); await pruneEmptyDirectories(root, retired.path); }
          }
        }
        const now = new Date().toISOString();
        receipt.hosts[host] = {
          version: VERSION,
          installed_at: previous?.installed_at ?? now,
          updated_at: now,
          entries: entriesByHost.get(host) ?? [],
        };
      }
    }
    receipt.tool.version = VERSION;
    const receiptPath = safePath(root, receiptName);
    if (Object.keys(receipt.hosts).length) await atomicWrite(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, 0o600);
    else { await rm(receiptPath, { force: true }); await pruneEmptyDirectories(root, receiptName); }
  }

  const hostFlag = options.hosts.length === integrationHosts.length ? "all" : options.hosts.join(",");
  const nextCommands = options.operation === "doctor"
    ? actions.some((item) => ["missing", "outdated"].includes(item.status))
      ? [`reporook integrate update ${root} --host ${hostFlag} --apply`]
      : []
    : !options.apply
      ? [`reporook integrate ${options.operation} ${root} --host ${hostFlag} --apply`]
      : options.operation === "uninstall"
        ? []
        : [
            `reporook integrate doctor ${root} --host ${hostFlag}`,
            "Restart the agent host so it reloads repository integrations.",
          ];
  return {
    operation: options.operation, target: root, hosts: options.hosts,
    applied: Boolean(options.apply && mutating), actions,
    receipt_path: safePath(root, receiptName), next_commands: nextCommands,
  };
}

export function renderIntegration(result: IntegrationResult): string {
  const title = result.operation === "doctor" ? "RepoRook agent integration check" : `RepoRook agent integration ${result.applied ? result.operation : `${result.operation} preview`}`;
  const lines = [title, `Repository: ${result.target}`, `Hosts: ${result.hosts.join(", ")}`, ""];
  for (const host of result.hosts) {
    lines.push(`${host}:`);
    const hostActions = result.actions.filter((item) => item.host === host);
    for (const item of hostActions) lines.push(`  ${item.status.padEnd(9)} ${item.path || "(receipt)"} — ${item.detail}`);
  }
  if (result.hosts.includes("windsurf")) lines.push("", "Windsurf note: project skills, rules, and workflow are configured. Its MCP configuration is global-only, so RepoRook leaves it untouched.");
  if (!result.applied && result.operation !== "doctor") lines.push("", "No files changed.");
  if (result.next_commands.length) lines.push("", "Next:", ...result.next_commands.map((command) => `  ${command}`));
  return lines.join("\n");
}

export function integrationExitCode(result: IntegrationResult): number {
  if (result.actions.some((item) => item.status === "modified")) return 2;
  if (result.operation === "doctor" && result.actions.some((item) => ["missing", "outdated"].includes(item.status))) return 1;
  return 0;
}
