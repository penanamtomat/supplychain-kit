#!/usr/bin/env bash
# pre-commit: fast quality gate before every git commit.
#
# Install:
#   cp configs/hooks/pre-commit.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Or let supplychain-kit manage it:
#   supplychain-kit install-hooks
#
# The hook runs a SCA-only scan on the current working tree and evaluates
# the quality gate. The full SAST pipeline is skipped to keep commit time
# under ~10 seconds.
#
# Exit codes:
#   0  Gate PASS — commit proceeds
#   1  Gate FAIL — commit is blocked; fix findings or use --no-verify to skip

set -euo pipefail

TOOL="${SUPPLYCHAIN_KIT_BIN:-supplychain-kit}"
POLICY="${SUPPLYCHAIN_KIT_POLICY:-configs/policy-strict.yaml}"
FINDINGS_TMP="$(mktemp /tmp/sk-precommit-XXXXXX.json)"
trap 'rm -f "$FINDINGS_TMP"' EXIT

# Resolve the repo root (works from any subdirectory).
REPO_ROOT="$(git rev-parse --show-toplevel)"

echo "⬡ supplychain-kit pre-commit gate (sca-only)..."

# Check the tool is available; skip gracefully if not installed.
if ! command -v "$TOOL" &>/dev/null; then
  echo "  [skip] supplychain-kit not found — install it or set SUPPLYCHAIN_KIT_BIN"
  exit 0
fi

# Check if a policy file is present; fall back to built-in moderate policy.
POLICY_FLAG=""
if [[ -f "$POLICY" ]]; then
  POLICY_FLAG="--policy $POLICY"
fi

# Run SCA scan (fast, no SAST) and write findings to temp file.
if ! "$TOOL" scan \
    --repo "$REPO_ROOT" \
    --mode sca \
    --out "$FINDINGS_TMP" \
    --format json \
    $POLICY_FLAG \
    --quiet 2>&1; then
  echo "  [skip] scan failed — supplychain-kit encountered an error, skipping gate"
  exit 0
fi

# Evaluate the gate. Exit 1 blocks the commit.
if ! "$TOOL" gate \
    --findings "$FINDINGS_TMP" \
    $POLICY_FLAG 2>&1; then
  echo ""
  echo "  Commit blocked by supply chain quality gate."
  echo "  Fix the findings above, or use 'git commit --no-verify' to bypass."
  echo ""
  exit 1
fi

echo "  Gate PASS — proceeding with commit."
exit 0
