#!/usr/bin/env bash
# claude-stop: Claude Code Stop hook — fires when Claude ends a session.
#
# Registered in .claude/settings.json as a Stop hook.
#
# Summarises the engagement state for any active engagements in results/,
# so the user has a clear picture of what was completed and what's pending
# before the session closes.
#
# Environment variables injected by Claude Code (Stop):
#   $CLAUDE_PROJECT_DIR   — project root

set -euo pipefail

RESULTS_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}/results"

if [[ ! -d "$RESULTS_DIR" ]]; then
  exit 0
fi

# Find engagements with a state.json modified in the last 24 hours.
RECENT=()
while IFS= read -r state_file; do
  eng_dir="$(dirname "$state_file")"
  engagement="$(basename "$eng_dir")"
  RECENT+=("$engagement:$state_file")
done < <(find "$RESULTS_DIR" -name "state.json" -newer "$RESULTS_DIR" -maxdepth 2 2>/dev/null || true)

if [[ ${#RECENT[@]} -eq 0 ]]; then
  exit 0
fi

echo ""
echo "═══════════════════════════════════════════════"
echo "  supplychain-kit — session summary"
echo "═══════════════════════════════════════════════"

for entry in "${RECENT[@]}"; do
  engagement="${entry%%:*}"
  state_file="${entry#*:}"

  if ! command -v jq &>/dev/null; then
    echo "  $engagement — (install jq for phase details)"
    continue
  fi

  echo ""
  echo "  Engagement: $engagement"

  # Print phase status.
  while IFS= read -r phase_line; do
    echo "    $phase_line"
  done < <(jq -r '.phases | to_entries[] | "  \(.key | ascii_upcase)\t\(.value)"' "$state_file" 2>/dev/null \
    | column -t || true)

  # Pending phases → suggest next command.
  PENDING="$(jq -r '.phases | to_entries[] | select(.value == "pending") | .key' "$state_file" 2>/dev/null | head -1 || true)"
  if [[ -n "$PENDING" ]]; then
    case "$PENDING" in
      sbom)   echo "    → Next: supplychain-kit sbom --repo . --engagement $engagement" ;;
      scan)   echo "    → Next: supplychain-kit run $engagement --repo ." ;;
      gate)   echo "    → Next: supplychain-kit gate --findings results/$engagement/findings/findings.json" ;;
      report) echo "    → Next: supplychain-kit report --engagement $engagement --format all" ;;
    esac
  else
    echo "    ✓ All phases complete"
  fi
done

echo ""
echo "═══════════════════════════════════════════════"
echo ""

exit 0
