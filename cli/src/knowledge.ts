const cweSummaries: Record<string, string> = {
  "CWE-22": "Untrusted input can influence a file path. An attacker may be able to escape the intended directory and access other files.",
  "CWE-78": "Untrusted input can reach a system command. An attacker may be able to add commands and run them on the server.",
  "CWE-79": "Untrusted input can be inserted into a web page. An attacker may be able to run script in another user's browser.",
  "CWE-89": "Untrusted input can influence a database query. An attacker may be able to read, change, or delete data.",
  "CWE-94": "Text can be executed as code. If an attacker controls that text, they may be able to run their own code.",
  "CWE-95": "A string is evaluated as code. Untrusted content here may let an attacker execute arbitrary code.",
  "CWE-259": "A password appears directly in the code. Move it to a secret store and change it because it may already be exposed.",
  "CWE-295": "TLS certificate verification is disabled or weakened. Attackers may be able to impersonate the remote service.",
  "CWE-311": "Sensitive information may be stored or transmitted without adequate encryption.",
  "CWE-319": "Sensitive information may cross the network without encryption and could be read in transit.",
  "CWE-326": "The encryption strength may be too weak to protect the data as intended.",
  "CWE-327": "The code uses an obsolete or broken cryptographic algorithm that may not protect the data.",
  "CWE-328": "The code uses a weak hash such as MD5 or SHA-1 for a security-sensitive purpose.",
  "CWE-330": "A predictable random source is used for something security-sensitive, so an attacker may be able to guess the result.",
  "CWE-352": "Another site may be able to trigger this action using a logged-in user's session without their consent.",
  "CWE-502": "Untrusted saved data is deserialized. A crafted value may be able to execute code or alter application behavior.",
  "CWE-611": "The XML parser may follow external references, which can expose local files or internal services.",
  "CWE-798": "A password, API key, or token appears directly in the code. Anyone who can read the code may be able to use it.",
  "CWE-1004": "A session cookie can be read by page scripts. An injected script may be able to steal the user's session.",
};

function cwe(key: string): string {
  return cweSummaries[key] ?? "A security-sensitive code pattern was found and should be reviewed before shipping.";
}

const keywordSummaries: Array<[string, string]> = [
  ["command-injection", cwe("CWE-78")],
  ["subprocess", cwe("CWE-78")],
  ["shell", cwe("CWE-78")],
  ["sql", cwe("CWE-89")],
  ["xss", cwe("CWE-79")],
  ["eval", cwe("CWE-94")],
  ["deserial", cwe("CWE-502")],
  ["pickle", cwe("CWE-502")],
  ["yaml.load", cwe("CWE-502")],
  ["md5", cwe("CWE-328")],
  ["sha1", cwe("CWE-328")],
  ["verify=false", cwe("CWE-295")],
  ["hardcoded", cwe("CWE-798")],
  ["secret", cwe("CWE-798")],
  ["path-traversal", cwe("CWE-22")],
];

export interface PlainSummaryInput {
  scanner: string;
  rule: string;
  cwes?: string[];
  packageName?: string | null;
  description?: string;
}

export function plainSummary(input: PlainSummaryInput): string {
  if (input.packageName) {
    return `The ${input.packageName} package used by this project has a known security flaw. Updating it to a fixed version closes the known issue.`;
  }
  for (const cwe of input.cwes ?? []) {
    const normalized = cwe.toUpperCase().match(/CWE-\d+/)?.[0];
    const summary = normalized ? cweSummaries[normalized] : undefined;
    if (summary) return summary;
  }
  const searchable = `${input.rule} ${input.description ?? ""}`.toLowerCase();
  for (const [keyword, summary] of keywordSummaries) {
    if (searchable.includes(keyword)) return summary;
  }
  if (input.scanner === "gitleaks") return cwe("CWE-798");
  if (input.scanner === "semgrep") return "A risky code pattern was found. Review how untrusted input can reach this operation before shipping.";
  return input.description?.trim() || "A potential security issue was found and should be reviewed before shipping.";
}
