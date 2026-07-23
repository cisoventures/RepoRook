#!/usr/bin/env bash
set -euo pipefail

python3 -m pip install --disable-pip-version-check --no-input "semgrep==1.171.0" "pip-audit==2.10.1"

GITLEAKS_VERSION="8.28.0"
case "$(uname -m)" in
  x86_64)
    gitleaks_arch="x64"
    gitleaks_sha256="a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb"
    ;;
  aarch64|arm64)
    gitleaks_arch="arm64"
    gitleaks_sha256="eff65261156100e5d94a6b3dec313d532fddfe19ae1590bf7a2b4f2699128356"
    ;;
  *) echo "Unsupported runner architecture: $(uname -m)" >&2; exit 2 ;;
esac

gitleaks_dir="${RUNNER_TEMP:-/tmp}/reporook-gitleaks"
mkdir -p "$gitleaks_dir"
archive="$gitleaks_dir/gitleaks.tar.gz"
curl --fail --silent --show-error --location \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gitleaks_arch}.tar.gz" \
  --output "$archive"
(
  cd "$gitleaks_dir"
  actual="$(sha256sum gitleaks.tar.gz | awk '{print $1}')"
  test "$gitleaks_sha256" = "$actual"
  tar -xzf gitleaks.tar.gz gitleaks
)
chmod +x "$gitleaks_dir/gitleaks"
echo "$gitleaks_dir" >> "$GITHUB_PATH"
