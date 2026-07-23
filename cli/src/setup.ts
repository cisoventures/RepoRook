import { platform } from "node:os";

export function setupInstructions(): string {
  const current = platform();
  const lines = [
    "RepoRook scanner setup",
    "",
    "Review these commands before running them. RepoRook never installs system software without your explicit action.",
    "",
  ];
  if (current === "darwin") {
    lines.push("macOS (Homebrew):", "  brew install semgrep gitleaks pip-audit osv-scanner");
  } else if (current === "win32") {
    lines.push("Windows:", "  python -m pip install --user semgrep pip-audit", "  winget install Gitleaks.Gitleaks", "  winget install Google.OSVScanner");
  } else {
    lines.push("Linux:", "  python3 -m pip install --user semgrep pip-audit", "  Install Gitleaks and OSV-Scanner from their signed releases or your distribution package manager.");
  }
  lines.push("", "Node dependency auditing uses the npm executable bundled with Node.js.", "After installation, run `reporook doctor`.");
  return lines.join("\n");
}
