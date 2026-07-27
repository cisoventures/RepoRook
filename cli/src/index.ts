#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs, stringFlag } from "./args.js";
import { artifactPath, writeApprovalArtifact, writeArtifacts, writeFindingBaselineArtifact, writePrioritizationArtifact, writeRemediationArtifacts, writeSuppressionArtifact, writeVerificationArtifact } from "./artifacts.js";
import { approvalMatches, createApprovalReceipt, parseApprovalReceipt } from "./approval.js";
import { loadConfig } from "./config.js";
import { diagnose, renderDoctor } from "./doctor.js";
import { requiredScannerFailure, scanExitCode, scanRepository, VERSION } from "./engine.js";
import { initializeRepository, renderInitialization } from "./initializer.js";
import { readBoundedJsonFile } from "./input.js";
import { integrationExitCode, manageIntegrations, parseIntegrationHosts, renderIntegration, type IntegrationOperation } from "./integrations.js";
import { prioritizeFindings } from "./prioritization.js";
import { createFindingBaseline, createFindingSuppression, readSuppressionFile } from "./policy.js";
import { createRemediationPlan } from "./remediation.js";
import { renderFinding, renderPrioritization, renderRemediationPlan, renderTerminal, renderVerification } from "./render.js";
import { toSarif } from "./sarif.js";
import { setupInstructions } from "./setup.js";
import { severities, type ScanReport, type Severity, type VerificationReport } from "./types.js";
import { verifyFindingResolution } from "./verification.js";

export { scanRepository, toSarif };
export { VERSION };
export { verifyFindingResolution };
export { initializeRepository, prioritizeFindings, createRemediationPlan };
export { createFindingBaseline, createFindingSuppression };
export { approvalMatches, createApprovalReceipt, parseApprovalReceipt };
export { parseRemediationProposal } from "./approval.js";
export { manageIntegrations, parseIntegrationHosts };
export { detectProject } from "./initializer.js";
export * from "./types.js";

const help = `RepoRook ${VERSION}

Usage:
  reporook scan [path] [--fail-on high] [--changed BASE] [--head HEAD]
  reporook init [path] [--force]
  reporook prioritize [path] [--input .reporook/findings.json]
  reporook baseline [path] [--input .reporook/findings.json]
  reporook suppress <finding-id> [path] --owner OWNER --reason REASON --expires DATE
  reporook approve <finding-id> [path] --approved-by NAME --reason TEXT
  reporook plan <finding-id> [path] [--input .reporook/findings.json]
  reporook verify <finding-id> [path] [--input .reporook/findings.json]
  reporook explain <finding-id> [--input .reporook/findings.json]
  reporook doctor [path]
  reporook setup
  reporook integrate <install|update|doctor|uninstall> [path] [--host all] [--apply]

Scan options:
  --config PATH          Repository-local configuration file (default: reporook.yml when present)
  --version, -v          Print the RepoRook version
  --fail-on SEVERITY     critical, high, medium, or low
  --output PATH          Findings JSON output
  --sarif-output PATH    SARIF output
  --format FORMAT        terminal, json, or sarif
  --changed [BASE]       Keep findings in files changed since BASE (default HEAD~1)
  --head REVISION        Changed-mode head (default HEAD)
  --require-scanners     Treat unavailable applicable scanners as a tool error
  --no-cache             Disable scanner cache reads and writes for this scan
  --refresh-cache        Run every scanner and replace successful cache entries
  --cache-ttl MINUTES    Override cache freshness (1-1440 minutes)
  --allow-no-coverage    Allow exit 0 when no applicable scanner completes (unsafe; explicit opt-in)
  --no-sarif             Do not write SARIF
  --quiet                Suppress terminal summary

Verify options:
  --input PATH           Baseline findings JSON (default: .reporook/findings.json)
  --verification-output  Verification receipt output
  --approval PATH        Validate and attach a durable approval receipt when present

Guided-fix options:
  --input PATH           Baseline findings JSON
  --output PATH          Priorities or remediation-plan JSON output
  --prompt-output PATH   Remediation prompt output
  --proposal-output PATH Exact proposal template output
  --force                Replace an existing RepoRook configuration during init

Team-policy options:
  --input PATH           Findings JSON used to create a baseline or suppression
  --output PATH          Baseline or suppression JSON output
  --owner OWNER          Person or team accountable for a suppression
  --reason TEXT          Auditable reason for accepting the finding temporarily
  --expires DATE         Future ISO timestamp or YYYY-MM-DD expiry
  --proposal PATH        Exact remediation proposal JSON
  --approved-by NAME     Human or accountable identity granting approval
  --approval-output PATH Durable approval receipt output

Agent integration options:
  --host HOSTS           Comma-separated hosts or all (default: all)
  --apply                Apply the displayed install, update, or uninstall plan
`;

function boundedIntegerFlag(parsed: ReturnType<typeof parseArgs>, name: string, minimum: number, maximum: number): number | undefined {
  const raw = parsed.flags[name];
  if (raw === undefined) return undefined;
  if (typeof raw !== "string" || !/^\d+$/.test(raw)) throw new Error(`--${name} requires an integer from ${minimum} to ${maximum}`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`--${name} requires an integer from ${minimum} to ${maximum}`);
  return value;
}

async function runScan(parsed: ReturnType<typeof parseArgs>): Promise<number> {
  const target = resolve(parsed.positionals[0] ?? ".");
  const loaded = await loadConfig(target, stringFlag(parsed.flags, "config"));
  const failOnValue = stringFlag(parsed.flags, "fail-on")?.toLowerCase() as Severity | undefined;
  if (failOnValue && !severities.includes(failOnValue)) throw new Error(`Invalid --fail-on value: ${failOnValue}`);
  if (failOnValue) loaded.config.failOn = failOnValue;
  const changedRequested = Object.hasOwn(parsed.flags, "changed");
  const changedValue = parsed.flags.changed;
  const cacheTtlMinutes = boundedIntegerFlag(parsed, "cache-ttl", 1, 1_440);
  const report = await scanRepository({
    target,
    config: loaded.config,
    ...(changedRequested ? { changedBase: typeof changedValue === "string" ? changedValue : "" } : {}),
    changedHead: stringFlag(parsed.flags, "head"),
    requireScanners: parsed.flags["require-scanners"] === true,
    ...(parsed.flags.cache === false ? { cacheEnabled: false } : {}),
    refreshCache: parsed.flags["refresh-cache"] === true,
    ...(cacheTtlMinutes !== undefined ? { cacheTtlMs: cacheTtlMinutes * 60_000 } : {}),
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
  const report = await readBoundedJsonFile(path, "Findings artifact") as ScanReport;
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

async function runBaseline(parsed: ReturnType<typeof parseArgs>): Promise<number> {
  const target = resolve(parsed.positionals[0] ?? ".");
  const loaded = await loadConfig(target, stringFlag(parsed.flags, "config"));
  const input = stringFlag(parsed.flags, "input") ?? `${loaded.config.outputDir}/findings.json`;
  const { report, path: inputPath } = await baselineReport(target, input);
  if (report.coverage_status !== "complete") throw new Error("Refusing to create a baseline from incomplete scanner coverage");
  const baseline = createFindingBaseline(report);
  const output = stringFlag(parsed.flags, "output") ?? loaded.config.baselineFile;
  const outputPath = artifactPath(target, output);
  if (outputPath === inputPath) throw new Error("Baseline must not overwrite the findings artifact");
  await writeFindingBaselineArtifact(target, baseline, output);
  const format = stringFlag(parsed.flags, "format") ?? "terminal";
  if (!["terminal", "json"].includes(format)) throw new Error("baseline format must be terminal or json");
  if (parsed.flags.quiet !== true) {
    process.stdout.write(format === "json"
      ? `${JSON.stringify(baseline, null, 2)}\n`
      : `RepoRook baseline created\nFindings accepted as existing: ${baseline.findings.length}\nArtifact: ${outputPath}\n`);
  }
  return 0;
}

async function runSuppress(parsed: ReturnType<typeof parseArgs>): Promise<number> {
  const findingId = parsed.positionals[0];
  if (!findingId || !/^rr-[a-f0-9]{12}$/.test(findingId)) throw new Error("suppress requires a valid finding ID such as rr-0123456789ab");
  const target = resolve(parsed.positionals[1] ?? ".");
  const loaded = await loadConfig(target, stringFlag(parsed.flags, "config"));
  const input = stringFlag(parsed.flags, "input") ?? `${loaded.config.outputDir}/findings.json`;
  const { report, path: inputPath } = await baselineReport(target, input);
  const owner = stringFlag(parsed.flags, "owner");
  const reason = stringFlag(parsed.flags, "reason");
  const expires = stringFlag(parsed.flags, "expires");
  if (!owner || !reason || !expires) throw new Error("suppress requires --owner, --reason, and --expires");
  const suppression = createFindingSuppression(report, findingId, owner, reason, expires);
  const output = stringFlag(parsed.flags, "output") ?? loaded.config.suppressionsFile;
  const outputPath = artifactPath(target, output);
  if (outputPath === inputPath) throw new Error("Suppressions must not overwrite the findings artifact");
  const existing = await readSuppressionFile(target, output);
  const suppressions = {
    schema_version: "1.0" as const,
    suppressions: [...existing.suppressions.filter((item) => item.finding_id !== findingId), suppression]
      .sort((left, right) => left.id.localeCompare(right.id)),
  };
  await writeSuppressionArtifact(target, suppressions, output);
  const format = stringFlag(parsed.flags, "format") ?? "terminal";
  if (!["terminal", "json"].includes(format)) throw new Error("suppress format must be terminal or json");
  if (parsed.flags.quiet !== true) {
    process.stdout.write(format === "json"
      ? `${JSON.stringify(suppression, null, 2)}\n`
      : `RepoRook suppression recorded\nFinding: ${findingId}\nOwner: ${suppression.owner}\nExpires: ${suppression.expires_at}\nArtifact: ${outputPath}\n`);
  }
  return 0;
}

async function runApprove(parsed: ReturnType<typeof parseArgs>): Promise<number> {
  const findingId = parsed.positionals[0];
  if (!findingId || !/^rr-[a-f0-9]{12}$/.test(findingId)) throw new Error("approve requires a valid finding ID such as rr-0123456789ab");
  const target = resolve(parsed.positionals[1] ?? ".");
  const loaded = await loadConfig(target, stringFlag(parsed.flags, "config"));
  const directory = `${loaded.config.outputDir}/remediations/${findingId}`;
  const planPath = artifactPath(target, stringFlag(parsed.flags, "plan-input") ?? `${directory}/plan.json`);
  const proposalPath = artifactPath(target, stringFlag(parsed.flags, "proposal") ?? `${directory}/proposal.json`);
  const approvedBy = stringFlag(parsed.flags, "approved-by");
  const reason = stringFlag(parsed.flags, "reason");
  if (!approvedBy || !reason) throw new Error("approve requires --approved-by and --reason");
  const plan = await readBoundedJsonFile(planPath, "Remediation plan");
  const proposal = await readBoundedJsonFile(proposalPath, "Remediation proposal");
  const receipt = createApprovalReceipt(plan, proposal, approvedBy, reason);
  const output = stringFlag(parsed.flags, "approval-output") ?? `${directory}/approval.json`;
  const outputPath = artifactPath(target, output);
  if ([planPath, proposalPath].includes(outputPath)) throw new Error("Approval receipt must not overwrite the plan or proposal");
  await writeApprovalArtifact(target, receipt, output);
  const format = stringFlag(parsed.flags, "format") ?? "terminal";
  if (!["terminal", "json"].includes(format)) throw new Error("approve format must be terminal or json");
  if (parsed.flags.quiet !== true) {
    process.stdout.write(format === "json"
      ? `${JSON.stringify(receipt, null, 2)}\n`
      : `RepoRook approval recorded\nApproval: ${receipt.approval_id}\nFinding: ${findingId}\nApproved by: ${receipt.approved_by}\nArtifact: ${outputPath}\n${receipt.invalidation_rule}\n`);
  }
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
  const proposalOutput = stringFlag(parsed.flags, "proposal-output") ?? `${directory}/proposal.json`;
  if ([artifactPath(target, planOutput), artifactPath(target, promptOutput), artifactPath(target, proposalOutput)].includes(inputPath)) {
    throw new Error("Remediation artifacts must not overwrite the baseline findings artifact");
  }
  const artifacts = await writeRemediationArtifacts(target, plan, { planOutput, promptOutput, proposalOutput, findingsReference: input });
  const format = stringFlag(parsed.flags, "format") ?? "terminal";
  if (!["terminal", "json"].includes(format)) throw new Error("plan format must be terminal or json");
  if (parsed.flags.quiet !== true) process.stdout.write(format === "json" ? `${JSON.stringify(plan, null, 2)}\n` : `${renderRemediationPlan(plan)}\n\nArtifacts: ${artifacts.planPath}, ${artifacts.promptPath}, ${artifacts.proposalPath}\n`);
  return 0;
}

async function runVerify(parsed: ReturnType<typeof parseArgs>): Promise<number> {
  const findingId = parsed.positionals[0];
  if (!findingId || !/^rr-[a-f0-9]{12}$/.test(findingId)) throw new Error("verify requires a valid finding ID such as rr-0123456789ab");
  const target = resolve(parsed.positionals[1] ?? ".");
  const loaded = await loadConfig(target, stringFlag(parsed.flags, "config"));
  const previousPath = artifactPath(target, stringFlag(parsed.flags, "input") ?? `${loaded.config.outputDir}/findings.json`);
  const previous = await readBoundedJsonFile(previousPath, "Baseline findings artifact") as ScanReport;
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

  const remediationDir = `${loaded.config.outputDir}/remediations/${findingId}`;
  const requestedApproval = stringFlag(parsed.flags, "approval");
  const approvalPath = artifactPath(target, requestedApproval ?? `${remediationDir}/approval.json`);
  let approval: VerificationReport["approval"] = { status: "not-recorded", receipt: null };
  let approvalReceiptLoaded = false;
  try {
    const receipt = parseApprovalReceipt(await readBoundedJsonFile(approvalPath, "Approval receipt"));
    approvalReceiptLoaded = true;
    const planPath = artifactPath(target, stringFlag(parsed.flags, "plan-input") ?? `${remediationDir}/plan.json`);
    const proposalPath = artifactPath(target, stringFlag(parsed.flags, "proposal") ?? `${remediationDir}/proposal.json`);
    const plan = await readBoundedJsonFile(planPath, "Remediation plan");
    const proposal = await readBoundedJsonFile(proposalPath, "Remediation proposal");
    if (!approvalMatches(receipt, plan, proposal)) throw new Error("Approval receipt no longer matches the exact plan, patch, files, and test plan");
    approval = { status: "approved", receipt };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT" || requestedApproval || approvalReceiptLoaded) throw error;
  }

  const current = await scanRepository({
    target,
    config: loaded.config,
    requireScanners: parsed.flags["require-scanners"] === true,
    refreshCache: true,
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
    approval,
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
  if (parsed.command === "baseline") return await runBaseline(parsed);
  if (parsed.command === "suppress") return await runSuppress(parsed);
  if (parsed.command === "approve") return await runApprove(parsed);
  if (parsed.command === "plan") return await runPlan(parsed);
  if (parsed.command === "verify") return await runVerify(parsed);
  if (parsed.command === "doctor") {
    const checks = await diagnose(parsed.positionals[0] ?? ".", stringFlag(parsed.flags, "config"));
    process.stdout.write(`${renderDoctor(checks)}\n`);
    return checks.some((check) => check.needed && !check.available) ? 1 : 0;
  }
  if (parsed.command === "setup") { process.stdout.write(`${setupInstructions()}\n`); return 0; }
  if (parsed.command === "integrate") {
    const operation = (parsed.positionals[0] ?? "doctor") as IntegrationOperation;
    if (!["install", "update", "doctor", "uninstall"].includes(operation)) throw new Error("integrate requires install, update, doctor, or uninstall");
    if (operation === "doctor" && parsed.flags.apply === true) throw new Error("integrate doctor is read-only and does not accept --apply");
    const result = await manageIntegrations({
      operation,
      target: parsed.positionals[1] ?? ".",
      hosts: parseIntegrationHosts(stringFlag(parsed.flags, "host")),
      apply: parsed.flags.apply === true,
    });
    const format = stringFlag(parsed.flags, "format") ?? "terminal";
    if (!["terminal", "json"].includes(format)) throw new Error("integrate format must be terminal or json");
    process.stdout.write(format === "json" ? `${JSON.stringify(result, null, 2)}\n` : `${renderIntegration(result)}\n`);
    return integrationExitCode(result);
  }
  if (parsed.command === "explain") {
    const id = parsed.positionals[0];
    if (!id) throw new Error("explain requires a finding ID");
    const input = artifactPath(resolve("."), stringFlag(parsed.flags, "input") ?? ".reporook/findings.json");
    const report = await readBoundedJsonFile(input, "Findings artifact") as ScanReport;
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
