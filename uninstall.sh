#!/usr/bin/env bash
# uninstall.sh — supplychain-kit uninstaller
#
# Supported platforms: Linux, macOS, Windows (Git Bash / MSYS2)
#
# What this script removes:
#   • supplychain-kit binary from INSTALL_DIR and ./bin/
#   • Scanner tools (syft, grype, gitleaks, semgrep) — only with --tools flag
#
# Usage:
#   bash uninstall.sh            # remove supplychain-kit only
#   bash uninstall.sh --tools    # remove supplychain-kit + all scanner tools
#   bash uninstall.sh --help

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-}"   # resolved after OS detection
BINARY_NAME="supplychain-kit"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── colours ───────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

info()    { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
removed() { echo -e "${RED}[–]${RESET} Removed: $*"; }
skipped() { echo -e "${YELLOW}[-]${RESET} Skipped: $* (not found)"; }
section() { echo -e "\n${CYAN}${BOLD}── $* ${RESET}"; }
check()   { command -v "$1" &>/dev/null; }

# ── flags ─────────────────────────────────────────────────────────────────────
REMOVE_TOOLS=false

for arg in "$@"; do
  case "$arg" in
    --tools) REMOVE_TOOLS=true ;;
    --help|-h)
      cat <<EOF
Usage: bash uninstall.sh [OPTIONS]

Options:
  --tools     Also remove scanner tools (syft, grype, gitleaks, semgrep)
  --help      Show this help

Environment variables:
  INSTALL_DIR    Directory where supplychain-kit was installed
                 (default: ~/.local/bin on Linux/Windows,
                           /usr/local/bin on macOS if it was writable)
EOF
      exit 0
      ;;
  esac
done

# ── OS detection ──────────────────────────────────────────────────────────────
case "$(uname -s)" in
  Darwin)                OS="darwin"  ;;
  Linux)                 OS="linux"   ;;
  MINGW*|MSYS*|CYGWIN*)  OS="windows" ;;
  *)                     OS="linux"   ;;  # best-effort fallback
esac

EXT=""
[ "$OS" = "windows" ] && EXT=".exe"

# Mirror install.sh default INSTALL_DIR logic.
if [ -z "$INSTALL_DIR" ]; then
  if [ "$OS" = "darwin" ] && [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi

# ── helper: remove a binary, trying both PATH and INSTALL_DIR ─────────────────
remove_binary() {
  local name="$1"
  local removed_any=false

  # Remove from INSTALL_DIR (where install.sh placed it).
  for candidate in \
      "${INSTALL_DIR}/${name}" \
      "${INSTALL_DIR}/${name}.exe"; do
    if [ -f "$candidate" ]; then
      rm -f "$candidate"
      removed "$candidate"
      removed_any=true
    fi
  done

  # Also remove from PATH if found elsewhere (e.g. manual installs).
  if check "$name"; then
    local bin_path
    bin_path="$(command -v "$name")"
    # Only delete if it's not inside a package-manager–managed directory
    # (homebrew cellar, /usr/bin, etc.) that we should not touch.
    case "$bin_path" in
      /opt/homebrew/Cellar/*|/usr/local/Cellar/*|\
      /usr/bin/*|/bin/*|/usr/sbin/*|/sbin/*)
        warn "Skipping $bin_path — managed by system/Homebrew (use --tools with brew)"
        ;;
      *)
        rm -f "$bin_path"
        removed "$bin_path"
        removed_any=true
        ;;
    esac
  fi

  $removed_any || skipped "$name"
}

# ── helper: uninstall semgrep via the method it was installed ─────────────────
remove_semgrep() {
  local removed_any=false

  # Homebrew (macOS primarily).
  if [ "$OS" = "darwin" ] && check brew && brew list semgrep &>/dev/null 2>&1; then
    brew uninstall semgrep --quiet && removed "semgrep (brew)" && removed_any=true

  # pipx.
  elif check pipx && pipx list 2>/dev/null | grep -q semgrep; then
    pipx uninstall semgrep && removed "semgrep (pipx)" && removed_any=true

  # pip3 / pip.
  elif check pip3 && pip3 show semgrep &>/dev/null 2>&1; then
    pip3 uninstall -y semgrep 2>/dev/null && removed "semgrep (pip3)" && removed_any=true

  elif check pip && pip show semgrep &>/dev/null 2>&1; then
    pip uninstall -y semgrep 2>/dev/null && removed "semgrep (pip)" && removed_any=true

  # Last resort: delete the binary directly.
  elif check semgrep; then
    local bin_path; bin_path="$(command -v semgrep)"
    rm -f "$bin_path" && removed "$bin_path" && removed_any=true
  fi

  $removed_any || skipped "semgrep"
}

# ── step 1: remove supplychain-kit ───────────────────────────────────────────────────
section "Removing supplychain-kit"

# From INSTALL_DIR.
BINARY_PATH="${INSTALL_DIR}/${BINARY_NAME}${EXT}"
if [ -f "$BINARY_PATH" ]; then
  rm -f "$BINARY_PATH"
  removed "$BINARY_PATH"
else
  warn "supplychain-kit not found at $BINARY_PATH — already removed?"
fi

# From local ./bin/ build directory.
LOCAL_BIN="${SCRIPT_DIR}/bin/${BINARY_NAME}${EXT}"
if [ -f "$LOCAL_BIN" ]; then
  rm -f "$LOCAL_BIN"
  removed "$LOCAL_BIN"
fi

# Clean up empty ./bin/ directory.
if [ -d "${SCRIPT_DIR}/bin" ] && [ -z "$(ls -A "${SCRIPT_DIR}/bin" 2>/dev/null)" ]; then
  rmdir "${SCRIPT_DIR}/bin"
  removed "${SCRIPT_DIR}/bin/ (empty)"
fi

# ── step 2: scanner tools (optional) ─────────────────────────────────────────
if $REMOVE_TOOLS; then
  section "Removing scanner tools"

  # syft and grype: simple binary removal.
  for bin in syft grype gitleaks; do
    remove_binary "$bin"
  done

  # semgrep: package-manager-aware removal.
  remove_semgrep

else
  echo ""
  warn "Scanner tools were NOT removed."
  warn "To also remove them, run: bash uninstall.sh --tools"
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${RED}════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${RED}  supplychain-kit uninstalled               ${RESET}"
echo -e "${BOLD}${RED}════════════════════════════════════════════${RESET}"
echo ""
echo -e "Source code remains at: ${CYAN}${SCRIPT_DIR}${RESET}"
echo -e "To reinstall:           ${GREEN}bash install.sh${RESET}"
echo ""
