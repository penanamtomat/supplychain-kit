#!/usr/bin/env bash
# Bootstrap a developer machine: install scanner CLIs and fetch Go modules.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "[1/3] Installing scanner CLIs (syft, grype, gitleaks, semgrep)..."
if ! command -v syft >/dev/null;     then curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b "${HOME}/.local/bin"; fi
if ! command -v grype >/dev/null;    then curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "${HOME}/.local/bin"; fi
if ! command -v gitleaks >/dev/null; then curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/install.sh | sh -s -- -b "${HOME}/.local/bin" || true; fi
if ! command -v semgrep >/dev/null;  then pipx install semgrep || pip install --user semgrep; fi

echo "[2/3] Fetching Go modules..."
( cd "$ROOT" && go mod download )

echo "[3/3] Building supplychain-kit..."
( cd "$ROOT" && go build -o bin/supplychain-kit ./cmd/supplychain-kit/ )

echo "Done. Try: ./bin/supplychain-kit scan --repo https://github.com/OWASP/NodeGoat"
