import { platform } from "node:os";

export function setupInstructions(): string {
  const current = platform();
  const lines = [
    "RepoRook scanner setup",
    "",
    "DISPLAY ONLY — NO COMMANDS WERE RUN.",
    "Review these commands and run only what you explicitly choose. RepoRook never downloads, installs, or updates executable software.",
    "",
  ];
  if (current === "darwin") {
    lines.push("macOS (Homebrew):", "  brew install semgrep gitleaks pip-audit osv-scanner checkov trivy");
  } else if (current === "win32") {
    lines.push("Windows:", "  python -m pip install --user semgrep pip-audit checkov", "  winget install Gitleaks.Gitleaks", "  winget install Google.OSVScanner", "  winget install AquaSecurity.Trivy");
  } else {
    lines.push("Linux:", "  python3 -m pip install --user semgrep pip-audit checkov", "  Install Gitleaks, OSV-Scanner, and Trivy from their signed releases or your distribution package manager.");
  }
  lines.push("", "Node dependency auditing uses the npm executable bundled with Node.js.", "RepoRook does not run any command shown above. After your own installation, run `reporook doctor`.");
  return lines.join("\n");
}
