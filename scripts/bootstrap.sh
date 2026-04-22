#!/usr/bin/env bash
# Bootstrap a developer machine: install scanner CLIs, prepare the Python
# virtualenv, fetch Go modules, and apply database migrations.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "[1/4] Installing scanner CLIs (syft, grype, gitleaks, semgrep)..."
if ! command -v syft >/dev/null;     then curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b "${HOME}/.local/bin"; fi
if ! command -v grype >/dev/null;    then curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "${HOME}/.local/bin"; fi
if ! command -v gitleaks >/dev/null; then curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/install.sh | sh -s -- -b "${HOME}/.local/bin" || true; fi
if ! command -v semgrep >/dev/null;  then pipx install semgrep || pip install --user semgrep; fi

echo "[2/4] Fetching Go modules..."
( cd "$ROOT" && go mod download )

echo "[3/4] Creating Python virtualenv..."
( cd "$ROOT" && python -m venv .venv && . .venv/bin/activate && pip install -U pip && pip install -r remediation/requirements.txt )

echo "[4/4] Bringing up dev stack and applying migrations..."
( cd "$ROOT" && docker compose -f deployments/docker/docker-compose.yml up -d postgres redis )
sleep 3
( cd "$ROOT" && PGPASSWORD=aspm psql -h localhost -U aspm -d aspm -f migrations/0001_init.sql )

echo "Done. Try: ./bin/supplychain-kit scan --repo https://github.com/OWASP/NodeGoat"
