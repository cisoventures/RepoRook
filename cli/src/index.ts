#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs, stringFlag } from "./args.js";
import { artifactPath, writeArtifacts, writePrioritizationArtifact, writeRemediationArtifacts, writeVerificationArtifact } from "./artifacts.js";
import { loadConfig } from "./config.js";
import { diagnose, renderDoctor } from "./doctor.js";
import { requiredScannerFailure, scanExitCode, scanRepository, VERSION } from "./engine.js";
import { initializeRepository, renderInitialization } from "./initializer.js";
import { prioritizeFindings } from "./prioritization.js";
import { createRemediationPlan } from "./remediation.js";
import { renderFinding, renderPrioritization, renderRemediationPlan, renderTerminal, renderVerification } from "./render.js";
import { toSarif } from "./sarif.js";
import { setupInstructions } from "./setup.js";
import { severities, type ScanReport, type Severity, type VerificationReport } from "./types.js";
import { verifyFindingResolution } from "./verification.js";

export { scanRepository, toSarif };
export { verifyFindingResolution };
export { initializeRepository, prioritizeFindings, createRemediationPlan };
export { detectProject } from "./initializer.js";
export * from "./types.js";

const help = `RepoRook ${VERSION}

Usage:
  reporook scan [path] [--fail-on high] [--changed BASE] [--head HEAD]
  reporook init [path] [--force]
  reporook prioritize [path] [--input .reporook/findings.json]
  reporook plan <finding-id> [path] [--input .reporook/findings.json]
  reporook verify <finding-id> [path] [--input .reporook/findings.json]
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

Verify options:
  --input PATH           Baseline findings JSON (default: .reporook/findings.json)
  --verification-output  Verification receipt output

Guided-fix options:
  --input PATH           Baseline findings JSON
  --output PATH          Priorities or remediation-plan JSON output
  --prompt-output PATH   Remediation prompt output
  --force                Replace an existing RepoRook configuration during init
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
    else process.stdout.write(`${renderTerminal(report)}\n\nArtifacts: ${artifacts.findingsPath}${artifacts.sarifPath ? `, ${artifacts.sarifPath}` : ""}, ${artifacts.prioritiesPath}, ${artifacts.promptPath}\n`);
  }
  return scanExitCode(
    report,
    loaded.config.failOn,
    loaded.config.requiredScanners,
    parsed.flags["require-scanners"] === true,
    parsed.flags["allow-no-coverage"] === true,
  );
}

async function baselineReport(target: string, input: string): Promise<{ report: ScanReport; path: string }> {
  const path = artifactPath(target, input);
  const report = JSON.parse(await readFile(path, "utf8")) as ScanReport;
  if (resolve(report.scan_receipt?.target ?? "") !== target) throw new Error("The baseline report belongs to a different repository path");
  if (!Array.isArray(report.findings) || !report.scan_receipt?.config_hash) throw new Error("The baseline report is not a valid RepoRook findings artifact");
  return { report, path };
}

async function runPrioritize(parsed: ReturnType<typeof parseArgs>): Promise<number> {
  const target = resolve(parsed.positionals[0] ?? ".");
  const loaded = await loadConfig(target, stringFlag(parsed.flags, "config"));
  const input = stringFlag(parsed.flags, "input") ?? `${loaded.config.outputDir}/findings.json`;
  const { report, path: inputPath } = await baselineReport(target, input);
  const priorities = prioritizeFindings(report);
  const output = stringFlag(parsed.flags, "output") ?? `${loaded.config.outputDir}/priorities.json`;
  const outputPath = artifactPath(target, output);
  if (outputPath === inputPath) throw new Error("Priorities must not overwrite the baseline findings artifact");
  await writePrioritizationArtifact(target, priorities, output);
  const format = stringFlag(parsed.flags, "format") ?? "terminal";
  if (!["terminal", "json"].includes(format)) throw new Error("prioritize format must be terminal or json");
  if (parsed.flags.quiet !== true) process.stdout.write(format === "json" ? `${JSON.stringify(priorities, null, 2)}\n` : `${renderPrioritization(priorities)}\n\nArtifact: ${outputPath}\n`);
  return 0;
}

async function runPlan(parsed: ReturnType<typeof parseArgs>): Promise<number> {
  const findingId = parsed.positionals[0];
  if (!findingId || !/^rr-[a-f0-9]{12}$/.test(findingId)) throw new Error("plan requires a valid finding ID such as rr-0123456789ab");
  const target = resolve(parsed.positionals[1] ?? ".");
  const loaded = await loadConfig(target, stringFlag(parsed.flags, "config"));
  const input = stringFlag(parsed.flags, "input") ?? `${loaded.config.outputDir}/findings.json`;
  const { report, path: inputPath } = await baselineReport(target, input);
  const plan = createRemediationPlan(report, findingId);
  const directory = `${loaded.config.outputDir}/remediations/${findingId}`;
  const planOutput = stringFlag(parsed.flags, "output") ?? `${directory}/plan.json`;
  const promptOutput = stringFlag(parsed.flags, "prompt-output") ?? `${directory}/fix-prompt.txt`;
  if ([artifactPath(target, planOutput), artifactPath(target, promptOutput)].includes(inputPath)) {
    throw new Error("Remediation artifacts must not overwrite the baseline findings artifact");
  }
  const artifacts = await writeRemediationArtifacts(target, plan, { planOutput, promptOutput, findingsReference: input });
  const format = stringFlag(parsed.flags, "format") ?? "terminal";
  if (!["terminal", "json"].includes(format)) throw new Error("plan format must be terminal or json");
  if (parsed.flags.quiet !== true) process.stdout.write(format === "json" ? `${JSON.stringify(plan, null, 2)}\n` : `${renderRemediationPlan(plan)}\n\nArtifacts: ${artifacts.planPath}, ${artifacts.promptPath}\n`);
  return 0;
}

async function runVerify(parsed: ReturnType<typeof parseArgs>): Promise<number> {
  const findingId = parsed.positionals[0];
  if (!findingId || !/^rr-[a-f0-9]{12}$/.test(findingId)) throw new Error("verify requires a valid finding ID such as rr-0123456789ab");
  const target = resolve(parsed.positionals[1] ?? ".");
  const loaded = await loadConfig(target, stringFlag(parsed.flags, "config"));
  const previousPath = artifactPath(target, stringFlag(parsed.flags, "input") ?? `${loaded.config.outputDir}/findings.json`);
  const previous = JSON.parse(await readFile(previousPath, "utf8")) as ScanReport;
  if (resolve(previous.scan_receipt.target) !== target) throw new Error("The baseline report belongs to a different repository path");
  const original = previous.findings.find((finding) => finding.id === findingId);
  if (!original) throw new Error(`Finding not found: ${findingId}`);

  const format = stringFlag(parsed.flags, "format") ?? "terminal";
  if (!["terminal", "json"].includes(format)) throw new Error("verify format must be terminal or json");
  const verificationDir = `${loaded.config.outputDir}/verifications/${findingId}`;
  const currentOutput = stringFlag(parsed.flags, "output") ?? `${verificationDir}/findings.json`;
  const sarifOutput = stringFlag(parsed.flags, "sarif-output") ?? `${verificationDir}/results.sarif`;
  const verificationOutput = stringFlag(parsed.flags, "verification-output") ?? `${dirname(currentOutput)}/verification.json`;
  const outputPaths = [
    artifactPath(target, currentOutput),
    artifactPath(target, `${dirname(currentOutput)}/scan-receipt.json`),
    artifactPath(target, `${dirname(currentOutput)}/priorities.json`),
    artifactPath(target, `${dirname(currentOutput)}/agent-prompt.txt`),
    artifactPath(target, verificationOutput),
    ...(parsed.flags.sarif === false ? [] : [artifactPath(target, sarifOutput)]),
  ];
  if (outputPaths.includes(previousPath)) throw new Error("Verification artifacts must not overwrite the baseline report");
  if (new Set(outputPaths).size !== outputPaths.length) throw new Error("Verification artifact paths must be distinct");

  const current = await scanRepository({
    target,
    config: loaded.config,
    requireScanners: parsed.flags["require-scanners"] === true,
  });
  const verification = verifyFindingResolution(previous, current, findingId, requiredScannerFailure(
    current,
    loaded.config.requiredScanners,
    parsed.flags["require-scanners"] === true,
  ));
  const artifacts = await writeArtifacts(target, current, {
    output: currentOutput,
    sarifOutput,
    writeSarif: parsed.flags.sarif !== false,
  });
  const report: VerificationReport = {
    schema_version: "1.0",
    tool: { name: "reporook", version: VERSION },
    finding_id: findingId,
    generated_at: new Date().toISOString(),
    scanner_resolution: verification.scanner_resolution,
    reason: verification.reason,
    config_unchanged: verification.config_unchanged,
    original_finding: original,
    remaining_finding: verification.remaining_finding,
    original_scanner_status: verification.original_scanner_status,
    source_scan: previous.scan_receipt,
    verification_scan: current.scan_receipt,
    functional_tests: {
      status: "not-recorded",
      reminder: "Run the focused regression test and relevant project tests before calling the fix verified.",
    },
  };
  const verificationPath = await writeVerificationArtifact(target, report, verificationOutput);
  if (parsed.flags.quiet !== true) {
    if (format === "json") process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    else process.stdout.write(`${renderVerification(report)}\n\nArtifacts: ${verificationPath}, ${artifacts.findingsPath}${artifacts.sarifPath ? `, ${artifacts.sarifPath}` : ""}, ${artifacts.prioritiesPath}\n`);
  }
  return report.scanner_resolution === "passed" ? 0 : report.scanner_resolution === "failed" ? 1 : 2;
}

async function main(): Promise<number> {
  const parsed = parseArgs(process.argv.slice(2));
  if (["help", "--help", "-h"].includes(parsed.command) || parsed.flags.help) { process.stdout.write(help); return 0; }
  if (parsed.command === "version" || parsed.flags.version) { process.stdout.write(`${VERSION}\n`); return 0; }
  if (parsed.command === "init") {
    const result = await initializeRepository(parsed.positionals[0] ?? ".", parsed.flags.force === true);
    const format = stringFlag(parsed.flags, "format") ?? "terminal";
    if (!["terminal", "json"].includes(format)) throw new Error("init format must be terminal or json");
    process.stdout.write(format === "json" ? `${JSON.stringify(result, null, 2)}\n` : `${renderInitialization(result)}\n`);
    return 0;
  }
  if (parsed.command === "scan") return await runScan(parsed);
  if (parsed.command === "prioritize") return await runPrioritize(parsed);
  if (parsed.command === "plan") return await runPlan(parsed);
  if (parsed.command === "verify") return await runVerify(parsed);
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
