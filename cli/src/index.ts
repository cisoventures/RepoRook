#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs, stringFlag } from "./args.js";
import { writeArtifacts } from "./artifacts.js";
import { loadConfig } from "./config.js";
import { diagnose, renderDoctor } from "./doctor.js";
import { scanExitCode, scanRepository, VERSION } from "./engine.js";
import { renderFinding, renderTerminal } from "./render.js";
import { toSarif } from "./sarif.js";
import { setupInstructions } from "./setup.js";
import { severities, type ScanReport, type Severity } from "./types.js";

export { scanRepository, toSarif };
export * from "./types.js";

const help = `RepoRook ${VERSION}

Usage:
  reporook scan [path] [--fail-on high] [--changed BASE] [--head HEAD]
  reporook verify [path] [scan options]
  reporook explain <finding-id> [--input .reporook/findings.json]
  reporook doctor [path]
  reporook setup

Scan options:
  --config PATH          Configuration file (default: reporook.yml when present)
  --version, -v          Print the RepoRook version
  --fail-on SEVERITY     critical, high, medium, or low
  --output PATH          Findings JSON output
  --sarif-output PATH    SARIF output
  --format FORMAT        terminal, json, or sarif
  --changed [BASE]       Keep findings in files changed since BASE (default HEAD~1)
  --head REVISION        Changed-mode head (default HEAD)
  --require-scanners     Treat unavailable applicable scanners as a tool error
  --allow-no-coverage    Allow exit 0 when no applicable scanner completes (unsafe; explicit opt-in)
  --no-sarif             Do not write SARIF
  --quiet                Suppress terminal summary
`;

async function runScan(parsed: ReturnType<typeof parseArgs>): Promise<number> {
  const target = resolve(parsed.positionals[0] ?? ".");
  const loaded = await loadConfig(target, stringFlag(parsed.flags, "config"));
  const failOnValue = stringFlag(parsed.flags, "fail-on")?.toLowerCase() as Severity | undefined;
  if (failOnValue && !severities.includes(failOnValue)) throw new Error(`Invalid --fail-on value: ${failOnValue}`);
  if (failOnValue) loaded.config.failOn = failOnValue;
  const changedRequested = Object.hasOwn(parsed.flags, "changed");
  const changedValue = parsed.flags.changed;
  const report = await scanRepository({
    target,
    config: loaded.config,
    ...(changedRequested ? { changedBase: typeof changedValue === "string" ? changedValue : "" } : {}),
    changedHead: stringFlag(parsed.flags, "head"),
    requireScanners: parsed.flags["require-scanners"] === true,
  });
  const artifacts = await writeArtifacts(target, report, {
    output: stringFlag(parsed.flags, "output") ?? `${loaded.config.outputDir}/findings.json`,
    sarifOutput: stringFlag(parsed.flags, "sarif-output") ?? `${loaded.config.outputDir}/results.sarif`,
    writeSarif: parsed.flags.sarif !== false,
  });
  const format = stringFlag(parsed.flags, "format") ?? "terminal";
  if (parsed.flags.quiet !== true) {
    if (format === "json") process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    else if (format === "sarif") process.stdout.write(`${JSON.stringify(toSarif(report), null, 2)}\n`);
    else process.stdout.write(`${renderTerminal(report)}\n\nArtifacts: ${artifacts.findingsPath}${artifacts.sarifPath ? `, ${artifacts.sarifPath}` : ""}\n`);
  }
  return scanExitCode(
    report,
    loaded.config.failOn,
    loaded.config.requiredScanners,
    parsed.flags["require-scanners"] === true,
    parsed.flags["allow-no-coverage"] === true,
  );
}

async function main(): Promise<number> {
  const parsed = parseArgs(process.argv.slice(2));
  if (["help", "--help", "-h"].includes(parsed.command) || parsed.flags.help) { process.stdout.write(help); return 0; }
  if (parsed.command === "version" || parsed.flags.version) { process.stdout.write(`${VERSION}\n`); return 0; }
  if (["scan", "verify"].includes(parsed.command)) return await runScan(parsed);
  if (parsed.command === "doctor") {
    const checks = await diagnose(parsed.positionals[0] ?? ".");
    process.stdout.write(`${renderDoctor(checks)}\n`);
    return checks.some((check) => check.needed && !check.available) ? 1 : 0;
  }
  if (parsed.command === "setup") { process.stdout.write(`${setupInstructions()}\n`); return 0; }
  if (parsed.command === "explain") {
    const id = parsed.positionals[0];
    if (!id) throw new Error("explain requires a finding ID");
    const input = resolve(stringFlag(parsed.flags, "input") ?? ".reporook/findings.json");
    const report = JSON.parse(await readFile(input, "utf8")) as ScanReport;
    const finding = report.findings.find((item) => item.id === id);
    if (!finding) throw new Error(`Finding not found: ${id}`);
    process.stdout.write(`${renderFinding(finding)}\n`);
    return 0;
  }
  process.stderr.write(help);
  throw new Error(`Unknown command: ${parsed.command}`);
}

function isEntryPoint(): boolean {
  if (!process.argv[1]) return false;
  try { return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href; }
  catch { return false; }
}

if (isEntryPoint()) {
  main().then((code) => { process.exitCode = code; }).catch((error: Error) => {
    process.stderr.write(`RepoRook error: ${error.message}\n`);
    process.exitCode = 2;
  });
}
