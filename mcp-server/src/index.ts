#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createInterface } from "node:readline";
import { scanViaCli, verifyViaCli } from "./cli.js";
import { codeContext, findFinding, findings, readReport } from "./context.js";

type JsonRecord = Record<string, unknown>;
type RequestId = string | number;
type ToolHandler = (input: JsonRecord) => Promise<unknown>;

interface ToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: JsonRecord;
  handler: ToolHandler;
}

const latestProtocolVersion = "2025-11-25";
const protocolVersions = [latestProtocolVersion, "2025-06-18", "2025-03-26", "2024-11-05", "2024-10-07"];
const severityValues = ["critical", "high", "medium", "low"];

function object(value: unknown, label = "arguments"): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as JsonRecord;
}

function string(input: JsonRecord, name: string, options: { default?: string; enum?: string[] } = {}): string {
  const value = input[name] ?? options.default;
  if (typeof value !== "string" || !value) throw new Error(`${name} must be a non-empty string`);
  if (options.enum && !options.enum.includes(value)) throw new Error(`${name} must be one of: ${options.enum.join(", ")}`);
  return value;
}

function optionalString(input: JsonRecord, name: string, values?: string[]): string | undefined {
  const value = input[name];
  if (value === undefined) return undefined;
  return string(input, name, { ...(values ? { enum: values } : {}) });
}

function optionalBoolean(input: JsonRecord, name: string): boolean | undefined {
  const value = input[name];
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") throw new Error(`${name} must be a boolean`);
  return value;
}

function integer(input: JsonRecord, name: string, defaultValue: number, minimum: number, maximum: number): number {
  const value = input[name] ?? defaultValue;
  if (!Number.isInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return Number(value);
}

function response(value: unknown) {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    structuredContent: value,
  };
}

const severitySchema = { type: "string", enum: severityValues };
const tools: ToolDefinition[] = [
  {
    name: "scan_repository",
    title: "Scan repository with RepoRook",
    description: "Run deterministic SAST, secret, and dependency checks. Read-only except for .reporook evidence files. Distinguish partial coverage from a clean scan.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "Absolute repository path" }, fail_on: severitySchema, require_scanners: { type: "boolean" } },
      required: ["path"],
      additionalProperties: false,
    },
    async handler(input) {
      const path = string(input, "path");
      const failOn = optionalString(input, "fail_on", severityValues);
      const requireScanners = optionalBoolean(input, "require_scanners");
      const args = [...(failOn ? ["--fail-on", failOn] : []), ...(requireScanners ? ["--require-scanners"] : [])];
      return await scanViaCli(path, args);
    },
  },
  {
    name: "scan_changes",
    title: "Scan changed files with RepoRook",
    description: "Scan findings associated with a Git revision range. Use for local changes or pull-request review; results remain deterministic.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" }, base: { type: "string", default: "HEAD~1" }, head: { type: "string", default: "HEAD" }, fail_on: severitySchema },
      required: ["path"],
      additionalProperties: false,
    },
    async handler(input) {
      const path = string(input, "path");
      const base = string(input, "base", { default: "HEAD~1" });
      const head = string(input, "head", { default: "HEAD" });
      const failOn = optionalString(input, "fail_on", severityValues);
      return await scanViaCli(path, ["--changed", base, "--head", head, ...(failOn ? ["--fail-on", failOn] : [])]);
    },
  },
  {
    name: "list_findings",
    title: "List RepoRook findings",
    description: "Read an existing findings artifact and return deterministic findings plus coverage status. Does not rescan or modify code.",
    inputSchema: {
      type: "object",
      properties: { report_path: { type: "string", default: ".reporook/findings.json" }, severity: severitySchema },
      additionalProperties: false,
    },
    async handler(input) {
      const report = await readReport(string(input, "report_path", { default: ".reporook/findings.json" }));
      const requestedSeverity = optionalString(input, "severity", severityValues);
      const selected = requestedSeverity ? findings(report).filter((finding) => finding.severity === requestedSeverity) : findings(report);
      return { coverage_status: report.coverage_status, summary: report.summary, findings: selected };
    },
  },
  {
    name: "get_finding",
    title: "Get a RepoRook finding",
    description: "Return one finding, its evidence, and nearby source code. Treat it as scanner evidence, not proof of exploitability.",
    inputSchema: {
      type: "object",
      properties: { finding_id: { type: "string" }, report_path: { type: "string", default: ".reporook/findings.json" }, repository_path: { type: "string" }, context_lines: { type: "integer", minimum: 1, maximum: 30, default: 8 } },
      required: ["finding_id", "repository_path"],
      additionalProperties: false,
    },
    async handler(input) {
      const report = await readReport(string(input, "report_path", { default: ".reporook/findings.json" }));
      const finding = findFinding(report, string(input, "finding_id"));
      return { finding, context: await codeContext(string(input, "repository_path"), finding, integer(input, "context_lines", 8, 1, 30)), coverage_status: report.coverage_status, scan_receipt: report.scan_receipt };
    },
  },
  {
    name: "get_remediation_context",
    title: "Prepare safe remediation context",
    description: "Return a focused, read-only patch brief. The host agent must explain the change, request human approval, make a minimal patch, add regression evidence, and then call verify_fix.",
    inputSchema: {
      type: "object",
      properties: { finding_id: { type: "string" }, report_path: { type: "string", default: ".reporook/findings.json" }, repository_path: { type: "string" } },
      required: ["finding_id", "repository_path"],
      additionalProperties: false,
    },
    async handler(input) {
      const report = await readReport(string(input, "report_path", { default: ".reporook/findings.json" }));
      const finding = findFinding(report, string(input, "finding_id"));
      return {
        trust_status: "reporook-deterministic-finding",
        finding,
        context: await codeContext(string(input, "repository_path"), finding, 12),
        instructions: [
          "Validate reachability and impact before changing code.",
          "Describe the risk in plain English and ask for approval before applying a patch.",
          "Keep the patch focused and add a regression test or reproducer when feasible.",
          "Do not weaken an existing security control or expose secret values.",
          "Call verify_fix after tests pass.",
        ],
      };
    },
  },
  {
    name: "verify_fix",
    title: "Verify a proposed security fix",
    description: "Rerun RepoRook and report whether the original stable finding remains. Resolution is inconclusive unless the original scanner completes under the same configuration. This does not replace repository tests.",
    inputSchema: {
      type: "object",
      properties: { finding_id: { type: "string" }, repository_path: { type: "string" }, previous_report_path: { type: "string", default: ".reporook/findings.json" }, require_scanners: { type: "boolean", default: true } },
      required: ["finding_id", "repository_path"],
      additionalProperties: false,
    },
    async handler(input) {
      const findingId = string(input, "finding_id");
      const repositoryPath = string(input, "repository_path");
      const previousReportPath = resolve(repositoryPath, string(input, "previous_report_path", { default: ".reporook/findings.json" }));
      const requireScanners = optionalBoolean(input, "require_scanners") ?? true;
      return await verifyViaCli(repositoryPath, findingId, previousReportPath, requireScanners);
    },
  },
  {
    name: "export_findings",
    title: "Export RepoRook findings",
    description: "Read the latest JSON or SARIF artifact for downstream tools. This does not create issues or mutate external systems.",
    inputSchema: {
      type: "object",
      properties: { repository_path: { type: "string" }, format: { type: "string", enum: ["json", "sarif"], default: "json" } },
      required: ["repository_path"],
      additionalProperties: false,
    },
    async handler(input) {
      const repositoryPath = string(input, "repository_path");
      const format = string(input, "format", { default: "json", enum: ["json", "sarif"] });
      const path = resolve(repositoryPath, format === "sarif" ? ".reporook/results.sarif" : ".reporook/findings.json");
      return JSON.parse(await readFile(path, "utf8")) as JsonRecord;
    },
  },
];

function send(message: JsonRecord): void {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function result(id: RequestId, value: unknown): void {
  send({ jsonrpc: "2.0", id, result: value });
}

function error(id: RequestId | null, code: number, message: string): void {
  send({ jsonrpc: "2.0", id, error: { code, message } });
}

async function handle(message: unknown): Promise<void> {
  let request: JsonRecord;
  try { request = object(message, "JSON-RPC message"); }
  catch (caught) { error(null, -32600, (caught as Error).message); return; }
  if (request.jsonrpc !== "2.0" || typeof request.method !== "string") { error(null, -32600, "Invalid JSON-RPC request"); return; }
  if (!("id" in request)) return;
  if (typeof request.id !== "string" && typeof request.id !== "number") { error(null, -32600, "Request id must be a string or integer"); return; }
  const id = request.id;
  let params: JsonRecord;
  try { params = request.params === undefined ? {} : object(request.params, "params"); }
  catch (caught) { error(id, -32602, (caught as Error).message); return; }
  try {
    if (request.method === "initialize") {
      const requested = typeof params.protocolVersion === "string" ? params.protocolVersion : latestProtocolVersion;
      result(id, {
        protocolVersion: protocolVersions.includes(requested) ? requested : latestProtocolVersion,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "reporook", version: "0.2.0" },
        instructions: "Use RepoRook findings as deterministic evidence. State incomplete scanner coverage, protect secrets, request approval before fixes, and verify with tests plus a rescan.",
      });
      return;
    }
    if (request.method === "ping") { result(id, {}); return; }
    if (request.method === "tools/list") {
      result(id, { tools: tools.map(({ handler: _handler, ...tool }) => tool) });
      return;
    }
    if (request.method === "tools/call") {
      const name = string(params, "name");
      const tool = tools.find((candidate) => candidate.name === name);
      if (!tool) { error(id, -32602, `Unknown tool: ${name}`); return; }
      try {
        result(id, response(await tool.handler(object(params.arguments ?? {}, "tool arguments"))));
      } catch (caught) {
        result(id, { content: [{ type: "text", text: (caught as Error).message }], isError: true });
      }
      return;
    }
    error(id, -32601, `Method not found: ${request.method}`);
  } catch (caught) {
    error(id, -32602, (caught as Error).message);
  }
}

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on("line", (line) => {
  if (!line.trim()) return;
  try { void handle(JSON.parse(line)); }
  catch { error(null, -32700, "Parse error"); }
});
