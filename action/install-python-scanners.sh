#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
lock_file="$script_dir/python-scanners.requirements.txt"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf '%s\n' 'REPOROOK_PYTHON_SCANNERS_VERIFIED=false' >> "$GITHUB_ENV"
fi

if [[ -L "$lock_file" ]]; then
  echo "RepoRook: refusing a symbolic-link Python scanner lock file." >&2
  exit 2
fi

if [[ ! -f "$lock_file" ]]; then
  message="RepoRook did not install Semgrep, pip-audit, or Checkov because this release has no repository-owned hash lock. Applicable missing scanners will make required coverage fail closed."
  echo "$message" >&2
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo "::notice title=RepoRook Python scanners not installed::$message"
  fi
  exit 0
fi

if [[ ! -s "$lock_file" ]] || (( $(wc -c < "$lock_file") > 5242880 )); then
  echo "RepoRook: the Python scanner lock must be a non-empty regular file no larger than 5 MiB." >&2
  exit 2
fi

require_pin() {
  local requirement="$1"
  local pattern="$2"
  if ! grep -E -q "$pattern" "$lock_file"; then
    echo "RepoRook: the Python scanner lock is missing required pin $requirement." >&2
    exit 2
  fi
}

require_pin 'semgrep==1.171.0' '^[[:space:]]*semgrep==1[.]171[.]0([[:space:]\\;]|$)'
require_pin 'pip-audit==2.10.1' '^[[:space:]]*pip-audit==2[.]10[.]1([[:space:]\\;]|$)'
require_pin 'checkov==3.3.8' '^[[:space:]]*checkov==3[.]3[.]8([[:space:]\\;]|$)'

python3 -m pip install \
  --disable-pip-version-check \
  --force-reinstall \
  --no-input \
  --only-binary=:all: \
  --require-hashes \
  --requirement "$lock_file"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf '%s\n' 'REPOROOK_PYTHON_SCANNERS_VERIFIED=true' >> "$GITHUB_ENV"
fi
