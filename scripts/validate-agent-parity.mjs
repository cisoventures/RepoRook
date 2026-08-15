import { readFile, readdir } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const contract = await readJson("contracts/native-agent-parity.json");
const canonicalSkill = await readText(contract.canonical_skill);
let checks = 0;

function assert(condition, message) {
  checks += 1;
  if (!condition) throw new Error(message);
}

function assertEqual(label, actual, expected) {
  assert(isDeepStrictEqual(actual, expected), `${label} drifted:\nexpected ${JSON.stringify(expected, null, 2)}\nactual   ${JSON.stringify(actual, null, 2)}`);
}

function absolute(path) {
  const target = resolve(root, path);
  const traversal = relative(root, target);
  if (traversal === ".." || traversal.startsWith(`..${sep}`)) throw new Error(`Parity contract path escapes the repository: ${path}`);
  return target;
}

async function readText(path) {
  return readFile(absolute(path), "utf8");
}

async function readJson(path) {
  return JSON.parse(await readText(path));
}

async function filesUnder(path) {
  const entries = await readdir(absolute(path), { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const child = `${path}/${entry.name}`;
    if (entry.isDirectory()) files.push(...await filesUnder(child));
    else if (entry.isFile()) files.push(child);
    else throw new Error(`Agent package contains a non-regular path: ${child}`);
  }
  return files.sort();
}

function jsonPointer(value, pointer) {
  let current = value;
  for (const encoded of pointer.split("/").slice(1)) {
    const segment = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    if (current === null || typeof current !== "object" || !Object.hasOwn(current, segment)) {
      throw new Error(`Missing JSON pointer ${pointer}`);
    }
    current = current[segment];
  }
  return current;
}

for (const assertion of contract.required_skill_assertions) {
  assert(canonicalSkill.includes(assertion), `Canonical agent workflow lost required assertion: ${assertion}`);
}

const integrationSource = await readText("cli/src/integrations.ts");
const hostLiteral = integrationSource.match(/export const integrationHosts = (\[[^\]]+\]) as const/)?.[1];
if (!hostLiteral) throw new Error("Could not read integrationHosts from cli/src/integrations.ts");
const implementationHosts = JSON.parse(hostLiteral);
const contractHosts = contract.hosts.map((host) => host.id);
assertEqual("agent host list", implementationHosts, contractHosts);
assertEqual("unique agent host list", [...new Set(contractHosts)], contractHosts);

const forbiddenPatterns = contract.forbidden_executable_bootstrap_patterns.map((pattern) => new RegExp(pattern, "i"));
for (const host of contract.hosts) {
  const packagedSkill = await readText(host.skill_path);
  assertEqual(`${host.name} canonical skill`, packagedSkill, canonicalSkill);

  const packageFiles = await filesUnder(host.package_root);
  assert(packageFiles.includes(host.skill_path), `${host.name} package does not contain its declared skill`);
  for (const path of [...host.validation_surfaces, ...host.remediation_surfaces]) {
    assert(packageFiles.includes(path), `${host.name} package does not contain declared surface ${path}`);
  }

  const packageText = (await Promise.all(packageFiles.map((path) => readText(path)))).join("\n");
  for (const pattern of forbiddenPatterns) {
    assert(!pattern.test(packageText), `${host.name} package may bootstrap executable software: ${pattern}`);
  }

  const validationText = [canonicalSkill, ...await Promise.all(host.validation_surfaces.map((path) => readText(path)))].join("\n");
  assert(/(?:deterministic|RepoRook) evidence/i.test(validationText), `${host.name} validation surface lost deterministic evidence provenance`);
  assert(/coverage/i.test(validationText), `${host.name} validation surface lost coverage handling`);
  assert(/(?:uncertainty|proof gap|hypothesis)/i.test(validationText), `${host.name} validation surface lost uncertainty handling`);
  assert(/(?:secret material|secret value|detected secret)/i.test(validationText), `${host.name} validation surface lost secret redaction`);

  const remediationText = [canonicalSkill, ...await Promise.all(host.remediation_surfaces.map((path) => readText(path)))].join("\n");
  assert(/approv/i.test(remediationText), `${host.name} remediation surface lost explicit approval`);
  assert(/exact (?:diff|patch|proposal)/i.test(remediationText), `${host.name} remediation surface lost exact proposal binding`);
  assert(/verif/i.test(remediationText), `${host.name} remediation surface lost verification`);
  assert(/(?:inconclusive|scanner resolution)/i.test(remediationText), `${host.name} remediation surface lost fail-closed resolution reporting`);

  const mcpConfiguration = await readJson(host.mcp.path);
  const mcpServer = host.mcp.format === "direct" ? mcpConfiguration.reporook : mcpConfiguration.mcpServers?.reporook;
  assertEqual(`${host.name} MCP command`, mcpServer?.command, "reporook-mcp");
  assertEqual(`${host.name} MCP arguments`, mcpServer?.args, []);

  for (const gate of host.automatic_gates) {
    const gateConfiguration = await readJson(gate.path);
    assertEqual(`${host.name} automatic gate ${gate.json_pointer}`, jsonPointer(gateConfiguration, gate.json_pointer), contract.automatic_gate_command);
  }

  const installedPaths = [...host.installed_paths].sort();
  assertEqual(`${host.name} unique installed paths`, [...new Set(installedPaths)], installedPaths);
  assert(installedPaths.every((path) => !path.startsWith("/") && !path.split("/").includes("..")), `${host.name} has a non-repository-local install path`);
}

process.stdout.write(`Validated ${contract.hosts.length} native agent packages across ${checks} parity checks.\n`);
