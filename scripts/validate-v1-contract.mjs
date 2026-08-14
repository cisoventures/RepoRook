import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const contract = await readJson("contracts/v1.json");
let checks = 0;

function normalized(value) {
  if (Array.isArray(value)) return [...value].sort();
  return value;
}

function assertEqual(label, actual, expected) {
  checks += 1;
  if (isDeepStrictEqual(actual, expected)) return;
  throw new Error(`${label} changed outside the v1 contract:\nexpected ${JSON.stringify(expected, null, 2)}\nactual   ${JSON.stringify(actual, null, 2)}`);
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

async function readText(path) {
  return readFile(resolve(root, path), "utf8");
}

async function readJson(path) {
  return JSON.parse(await readText(path));
}

function unquote(value) {
  const trimmed = value.trim();
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

const packageManifests = new Map();
for (const expected of contract.packages) {
  const manifest = await readJson(expected.path);
  packageManifests.set(expected.name, manifest);
  const publicShape = {
    path: expected.path,
    name: manifest.name,
    type: manifest.type,
    bin: manifest.bin,
    main: manifest.main,
    exports: manifest.exports ?? null,
    files: manifest.files,
    engines: manifest.engines,
  };
  const expectedShape = { ...expected };
  delete expectedShape.runtime_exports;
  assertEqual(`${expected.name} package entry points`, publicShape, expectedShape);

  for (const [subpath, expectedExports] of Object.entries(expected.runtime_exports)) {
    const target = manifest.exports?.[subpath];
    if (typeof target !== "string") throw new Error(`${expected.name} ${subpath} has no importable target`);
    const module = await import(pathToFileURL(resolve(root, dirname(expected.path), target)).href);
    assertEqual(`${expected.name} ${subpath} runtime exports`, Object.keys(module).sort(), normalized(expectedExports));
  }
}

const rootManifest = await readJson("package.json");
const cliManifest = packageManifests.get("reporook");
const mcpManifest = packageManifests.get("@reporook/mcp-server");
const serviceManifest = packageManifests.get("@reporook/service");
assertEqual("workspace package versions", [rootManifest.version, cliManifest.version, mcpManifest.version, serviceManifest.version], Array(4).fill(rootManifest.version));
assertEqual("MCP CLI dependency version", mcpManifest.dependencies?.reporook, cliManifest.version);
assertEqual("service CLI dependency version", serviceManifest.dependencies?.reporook, cliManifest.version);

const cliEntry = resolve(root, "cli/dist/index.js");
const cliHelp = execFileSync(process.execPath, [cliEntry, "--help"], { encoding: "utf8" });
const shortHelp = execFileSync(process.execPath, [cliEntry, "-h"], { encoding: "utf8" });
const cliVersion = execFileSync(process.execPath, [cliEntry, "--version"], { encoding: "utf8" }).trim();
const shortVersion = execFileSync(process.execPath, [cliEntry, "-v"], { encoding: "utf8" }).trim();
const commands = [...cliHelp.matchAll(/^  reporook ([a-z-]+)/gm)].map((match) => match[1]);
const flags = [...new Set(cliHelp.match(/--[a-z][a-z0-9-]*/g) ?? [])].sort();
assertEqual("CLI commands", commands.sort(), normalized(contract.cli.commands));
assertEqual("CLI flags", flags, normalized(contract.cli.flags));
assertEqual("CLI -h alias", shortHelp, cliHelp);
assertEqual("CLI --version", cliVersion, cliManifest.version);
assertEqual("CLI -v alias", shortVersion, cliVersion);
for (const [code, meaning] of Object.entries(contract.cli.exit_codes)) {
  if (!cliHelp.includes(`  ${code}  ${meaning}`)) throw new Error(`CLI help no longer documents exit code ${code}: ${meaning}`);
  checks += 1;
}

const mcpInput = [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "contract-validator", version: "1" } } },
  { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
].map((message) => JSON.stringify(message)).join("\n") + "\n";
const mcpOutput = execFileSync(process.execPath, [resolve(root, "mcp-server/dist/index.js")], { input: mcpInput, encoding: "utf8" })
  .trim().split(/\r?\n/).map((line) => JSON.parse(line));
const initialization = mcpOutput.find((message) => message.id === 1)?.result;
const tools = mcpOutput.find((message) => message.id === 2)?.result?.tools;
if (!Array.isArray(tools)) throw new Error("MCP tools/list did not return a tool array");
assertEqual("MCP server name", initialization?.serverInfo?.name, contract.mcp.server_name);
assertEqual("MCP server version", initialization?.serverInfo?.version, mcpManifest.version);
const toolContracts = tools.map((tool) => ({ name: tool.name, input_schema_sha256: sha256(tool.inputSchema) }))
  .sort((left, right) => left.name.localeCompare(right.name));
assertEqual("MCP tool names and input schemas", toolContracts, contract.mcp.tools);

const readme = await readText("README.md");
const mcpReadmeSection = readme.match(/The local MCP server exposes:\n([\s\S]*?)\nRun it directly:/)?.[1];
if (!mcpReadmeSection) throw new Error("README MCP tool section is missing");
const documentedTools = [...mcpReadmeSection.matchAll(/^- `([^`]+)`/gm)].map((match) => match[1]).sort();
assertEqual("README MCP tool list", documentedTools, toolContracts.map((tool) => tool.name));

const configModule = await import(pathToFileURL(resolve(root, "cli/dist/config.js")).href);
assertEqual("configuration keys", [...configModule.acceptedConfigKeys].sort(), normalized(contract.configuration.accepted_keys));
assertEqual("configuration defaults", configModule.defaultConfig, contract.configuration.defaults);
assertEqual("scanner names", [...configModule.scannerNames].sort(), normalized(contract.configuration.scanners));

const schemaFiles = (await readdir(resolve(root, "schemas")))
  .filter((name) => name.endsWith(".schema.json"))
  .map((name) => `schemas/${name}`)
  .sort();
assertEqual("schema file set", schemaFiles, contract.schemas.map((schema) => schema.path).sort());
for (const expected of contract.schemas) {
  const schema = await readJson(expected.path);
  assertEqual(`${expected.path} identifier`, schema.$id, expected.id);
  assertEqual(`${expected.path} normalized content`, sha256(schema), expected.sha256);
}

const action = await readText("action.yml");
function yamlSection(name) {
  const lines = action.split(/\r?\n/);
  const start = lines.findIndex((line) => line === `${name}:`);
  if (start < 0) throw new Error(`action.yml has no ${name} section`);
  const result = [];
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line && !line.startsWith(" ")) break;
    result.push(line);
  }
  return result;
}

const actionInputs = {};
let currentInput;
for (const line of yamlSection("inputs")) {
  const key = line.match(/^  ([a-z0-9-]+):\s*$/)?.[1];
  if (key) {
    currentInput = key;
    actionInputs[key] = undefined;
    continue;
  }
  const defaultValue = line.match(/^    default:\s*(.*)$/)?.[1];
  if (currentInput && defaultValue !== undefined) actionInputs[currentInput] = unquote(defaultValue);
}
assertEqual("GitHub Action input defaults", actionInputs, contract.github_action.inputs);
const actionOutputs = yamlSection("outputs").flatMap((line) => line.match(/^  ([a-z0-9-]+):\s*$/)?.[1] ?? []).sort();
assertEqual("GitHub Action outputs", actionOutputs, normalized(contract.github_action.outputs));

const ci = await readText(".github/workflows/ci.yml");
const operatingSystems = ci.match(/\bos:\s*\[([^\]]+)\]/)?.[1].split(",").map((value) => value.trim()).sort();
const nodeVersions = ci.match(/\bnode:\s*\[([^\]]+)\]/)?.[1].split(",").map((value) => Number(value.trim())).sort((left, right) => left - right);
assertEqual("CI operating-system matrix", operatingSystems, normalized(contract.compatibility.ci_operating_systems));
assertEqual("CI Node.js matrix", nodeVersions, contract.compatibility.ci_node_versions);
assertEqual("root Node.js engine", rootManifest.engines?.node, contract.compatibility.node_engine);
for (const manifest of packageManifests.values()) assertEqual(`${manifest.name} Node.js engine`, manifest.engines?.node, contract.compatibility.node_engine);

process.stdout.write(`RepoRook v1 release-candidate contract passed ${checks} compatibility checks.\n`);
