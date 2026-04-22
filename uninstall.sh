#!/usr/bin/env bash
# uninstall.sh — supplychain-kit uninstaller
#
# What this script removes:
#   • aspm-cli binary from INSTALL_DIR
#   • Scanner tools (syft, grype, gitleaks, semgrep) — optional, with --tools
#   • Build artifacts in ./bin/
#
# Usage:
#   bash uninstall.sh            # remove aspm-cli only
#   bash uninstall.sh --tools    # remove aspm-cli + all scanner tools
#   bash uninstall.sh --help

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
BINARY_NAME="aspm-cli"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
removed() { echo -e "${RED}[–]${RESET} Removed: $*"; }
section() { echo -e "\n${CYAN}${BOLD}── $* ${RESET}"; }
check()   { command -v "$1" &>/dev/null; }

# ── flags ─────────────────────────────────────────────────────────────────────
REMOVE_TOOLS=false

for arg in "$@"; do
  case "$arg" in
    --tools) REMOVE_TOOLS=true ;;
    --help|-h)
      echo "Usage: bash uninstall.sh [--tools] [--help]"
      echo ""
      echo "Options:"
      echo "  --tools    Also remove scanner tools (syft, grype, gitleaks, semgrep)"
      echo "  --help     Show this help"
      echo ""
      echo "Environment variables:"
      echo "  INSTALL_DIR    Directory where aspm-cli was installed (default: ~/.local/bin)"
      exit 0
      ;;
  esac
done

# ── detect OS ─────────────────────────────────────────────────────────────────
EXT=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXT=".exe" ;; esac

# ── remove aspm-cli binary ────────────────────────────────────────────────────
section "Removing aspm-cli"

BINARY_PATH="${INSTALL_DIR}/${BINARY_NAME}${EXT}"
if [ -f "$BINARY_PATH" ]; then
  rm -f "$BINARY_PATH"
  removed "$BINARY_PATH"
else
  warn "aspm-cli not found at $BINARY_PATH (already removed?)"
fi

# Also remove from ./bin/ if it exists.
LOCAL_BIN="${SCRIPT_DIR}/bin/${BINARY_NAME}${EXT}"
if [ -f "$LOCAL_BIN" ]; then
  rm -f "$LOCAL_BIN"
  removed "$LOCAL_BIN"
fi

# Remove ./bin/ if empty.
if [ -d "${SCRIPT_DIR}/bin" ] && [ -z "$(ls -A "${SCRIPT_DIR}/bin" 2>/dev/null)" ]; then
  rmdir "${SCRIPT_DIR}/bin"
  removed "${SCRIPT_DIR}/bin/ (empty directory)"
fi

# ── optionally remove scanner tools ───────────────────────────────────────────
if $REMOVE_TOOLS; then
  section "Removing scanner tools"

  for bin in syft grype gitleaks; do
    if check "$bin"; then
      BIN_PATH="$(command -v "$bin")"
      rm -f "$BIN_PATH"
      removed "$BIN_PATH"
    else
      warn "$bin not found, skipping"
    fi
  done

  if check semgrep; then
    if command -v pip3 &>/dev/null; then
      pip3 uninstall -y semgrep 2>/dev/null && removed "semgrep (via pip3)"
    elif command -v pip &>/dev/null; then
      pip uninstall -y semgrep 2>/dev/null && removed "semgrep (via pip)"
    else
      BIN_PATH="$(command -v semgrep)"
      rm -f "$BIN_PATH"
      removed "$BIN_PATH"
    fi
  else
    warn "semgrep not found, skipping"
  fi
else
  warn "Scanner tools (syft, grype, gitleaks, semgrep) were NOT removed."
  warn "Run with --tools to also remove them: bash uninstall.sh --tools"
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${RED}════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${RED}  supplychain-kit uninstalled               ${RESET}"
echo -e "${BOLD}${RED}════════════════════════════════════════════${RESET}"
echo ""
echo -e "Remaining files (source code, configs) are at:"
echo -e "  ${CYAN}$SCRIPT_DIR${RESET}"
echo ""
echo -e "To reinstall: ${GREEN}bash install.sh${RESET}"
echo ""
