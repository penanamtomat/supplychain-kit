#!/usr/bin/env bash
# post-scan: Claude Code PostToolUse hook — fires after scan_repository MCP tool.
#
# Registered in .claude/settings.json as a PostToolUse hook matching
# the MCP tool pattern for scan_repository.
#
# Reads the MCP tool result from stdin (JSON) and:
#   1. Prints a severity summary to the terminal
#   2. Prints the top-3 highest-risk findings
#   3. Suggests next steps based on gate decision
#
# Environment variables injected by Claude Code (PostToolUse):
#   $CLAUDE_PROJECT_DIR   — project root

set -euo pipefail

INPUT="$(cat)"   # JSON from Claude Code: {tool_name, tool_input, tool_response, ...}

# Parse the tool response data field (jq required; skip gracefully if absent).
if ! command -v jq &>/dev/null; then
  exit 0
fi

TOOL_NAME="$(echo "$INPUT" | jq -r '.tool_name // ""')"
STATUS="$(echo "$INPUT" | jq -r '.tool_response.content[0].text // "{}"' | jq -r '.status // "unknown"' 2>/dev/null || echo "unknown")"
SUMMARY="$(echo "$INPUT" | jq -r '.tool_response.content[0].text // "{}"' | jq -r '.summary // ""' 2>/dev/null || echo "")"

# Only act on scan_repository results.
if [[ "$TOOL_NAME" != *"scan_repository"* ]]; then
  exit 0
fi

echo ""
echo "═══════════════════════════════════════════════"
echo "  supplychain-kit — scan complete"
echo "═══════════════════════════════════════════════"

if [[ "$STATUS" == "ok" ]]; then
  echo "  Status  : PASS"
else
  echo "  Status  : FAIL"
fi

if [[ -n "$SUMMARY" ]]; then
  echo "  Summary : $SUMMARY"
fi

# Parse top-3 findings from the data field.
TOP3="$(echo "$INPUT" \
  | jq -r '.tool_response.content[0].text // "{}"' \
  | jq -r '
      .data.findings // [] |
      sort_by(-.risk_score) |
      .[0:3][] |
      "  [\(.severity | ascii_upcase)] \(.rule_id) — risk \(.risk_score // 0 | floor) — \(.package // "—")"
    ' 2>/dev/null || true)"

if [[ -n "$TOP3" ]]; then
  echo ""
  echo "  Top findings:"
  echo "$TOP3"
fi

echo ""
echo "  Next steps:"
echo "    supplychain-kit report --engagement <name> --format all"
echo "    supplychain-kit remediate results/<name>/findings/findings.json"
echo "═══════════════════════════════════════════════"
echo ""

exit 0
