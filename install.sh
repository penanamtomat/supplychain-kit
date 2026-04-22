#!/usr/bin/env bash
# install.sh — supplychain-kit one-shot installer
#
# What this script does:
#   1. Check prerequisites (Go, git, curl)
#   2. Install scanner tools: syft, grype, gitleaks, semgrep
#   3. Build the aspm-cli binary from source
#   4. Install aspm-cli to a directory on PATH
#
# Usage:
#   bash install.sh              # full install
#   bash install.sh --no-semgrep # skip semgrep (if Python unavailable)
#   bash install.sh --help

set -euo pipefail

SEMGREP_VERSION="${SEMGREP_VERSION:-1.75.0}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.21.2}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
BINARY_NAME="aspm-cli"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*" >&2; }
section() { echo -e "\n${CYAN}${BOLD}── $* ${RESET}"; }
check()   { command -v "$1" &>/dev/null; }

SKIP_SEMGREP=false

for arg in "$@"; do
  case "$arg" in
    --no-semgrep) SKIP_SEMGREP=true ;;
    --help|-h)
      echo "Usage: bash install.sh [--no-semgrep] [--help]"
      echo ""
      echo "Options:"
      echo "  --no-semgrep   Skip semgrep installation"
      echo "  --help         Show this help"
      echo ""
      echo "Environment variables:"
      echo "  INSTALL_DIR      Where to install aspm-cli (default: ~/.local/bin)"
      echo "  GITLEAKS_VERSION Override gitleaks version (default: ${GITLEAKS_VERSION})"
      echo "  SEMGREP_VERSION  Override semgrep version (default: ${SEMGREP_VERSION})"
      exit 0
      ;;
  esac
done

# ── OS / arch detection ───────────────────────────────────────────────────────
case "$(uname -s)" in
  Darwin)              OS="darwin" ;;
  Linux)               OS="linux"  ;;
  MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
  *)                   OS="unsupported" ;;
esac

case "$(uname -m)" in
  x86_64|amd64)   ARCH="amd64" ;;
  arm64|aarch64)  ARCH="arm64" ;;
  *)              ARCH="unsupported" ;;
esac

EXT=""
[ "$OS" = "windows" ] && EXT=".exe"

if [ "$OS" = "unsupported" ] || [ "$ARCH" = "unsupported" ]; then
  error "Unsupported OS/arch: $(uname -s)/$(uname -m)"
  exit 1
fi

# ── helpers ───────────────────────────────────────────────────────────────────
ensure_install_dir() {
  mkdir -p "$INSTALL_DIR"
  if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    warn "$INSTALL_DIR is not on your PATH."
    warn "Add this line to your shell profile (~/.bashrc or ~/.zshrc):"
    warn "  export PATH=\"\$PATH:$INSTALL_DIR\""
  fi
}

copy_bin() {
  # Portable copy: prefer install(1), fall back to cp.
  if check install; then
    install -m 0755 "$1" "$2"
  else
    cp "$1" "$2" && chmod 0755 "$2"
  fi
}

# Download a zip or tar.gz and extract a named binary.
download_extract() {
  local url="$1" binary="$2" dest="$3"
  local tmpdir; tmpdir="$(mktemp -d)"
  local archive="$tmpdir/archive"

  echo "    Downloading $(basename "$url")"
  if ! curl -fsSL "$url" -o "$archive"; then
    error "Download failed: $url"
    rm -rf "$tmpdir"
    return 1
  fi

  # Detect format by URL suffix.
  if [[ "$url" == *.zip ]]; then
    if check unzip; then
      unzip -q "$archive" -d "$tmpdir/extracted"
    else
      error "unzip not found — cannot extract .zip archive"
      rm -rf "$tmpdir"
      return 1
    fi
  else
    tar -xzf "$archive" -C "$tmpdir" 2>/dev/null
    mv "$tmpdir" "$tmpdir/extracted" 2>/dev/null || true
    tmpdir="$(dirname "$tmpdir/extracted")"
  fi

  local found
  found="$(find "$tmpdir" -type f \( -name "$binary" -o -name "${binary}.exe" \) | head -1)"
  if [ -z "$found" ]; then
    error "Binary '$binary' not found inside archive"
    rm -rf "$tmpdir"
    return 1
  fi
  copy_bin "$found" "$dest"
  rm -rf "$tmpdir"
}

# ── step 1: prerequisites ─────────────────────────────────────────────────────
section "Step 1/4 — Checking prerequisites"

MISSING=()
check go   || MISSING+=("go  → https://go.dev/dl")
check git  || MISSING+=("git → https://git-scm.com")
check curl || MISSING+=("curl")

if [ ${#MISSING[@]} -gt 0 ]; then
  error "Missing required tools:"
  for m in "${MISSING[@]}"; do error "  • $m"; done
  exit 1
fi

info "Go         : $(go version | awk '{print $3}')"
info "Git        : $(git --version | awk '{print $3}')"
info "OS / Arch  : $OS / $ARCH"
info "Install dir: $INSTALL_DIR"

# ── step 2: scanner tools ─────────────────────────────────────────────────────
section "Step 2/4 — Installing scanner tools"

# syft — use official install script (handles all platforms automatically)
if check syft; then
  info "syft already installed: $(syft version 2>/dev/null | head -1 || echo 'ok')"
else
  echo "  Installing syft (latest)..."
  if [ "$OS" = "darwin" ] && check brew; then
    brew install anchore/grype/syft -q && info "syft installed"
  elif curl -sSfL "https://raw.githubusercontent.com/anchore/syft/main/install.sh" \
       | sh -s -- -b "$INSTALL_DIR" 2>&1 | grep -v '^$'; then
    info "syft installed"
  else
    warn "syft installation failed — SCA (dependency scanning) will be unavailable"
  fi
fi

# grype — use official install script
if check grype; then
  info "grype already installed: $(grype version 2>/dev/null | head -1 || echo 'ok')"
else
  echo "  Installing grype (latest)..."
  if [ "$OS" = "darwin" ] && check brew; then
    brew install anchore/grype/grype -q && info "grype installed"
  elif curl -sSfL "https://raw.githubusercontent.com/anchore/grype/main/install.sh" \
       | sh -s -- -b "$INSTALL_DIR" 2>&1 | grep -v '^$'; then
    info "grype installed"
  else
    warn "grype installation failed — vulnerability matching will be unavailable"
  fi
fi

# gitleaks — manual download (no official install script)
if check gitleaks; then
  info "gitleaks already installed: $(gitleaks version 2>/dev/null || echo 'ok')"
else
  echo "  Installing gitleaks v${GITLEAKS_VERSION}..."
  ensure_install_dir

  GL_ARCH="$ARCH"
  [ "$GL_ARCH" = "amd64" ] && GL_ARCH="x64"

  if [ "$OS" = "darwin" ] && check brew; then
    brew install gitleaks -q && info "gitleaks installed"
  else
    if [ "$OS" = "windows" ]; then
      URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_windows_${GL_ARCH}.zip"
    else
      URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${OS}_${GL_ARCH}.tar.gz"
    fi
    if download_extract "$URL" "gitleaks" "${INSTALL_DIR}/gitleaks${EXT}"; then
      info "gitleaks installed"
    else
      warn "gitleaks installation failed — secret scanning will be unavailable"
    fi
  fi
fi

# semgrep — via pip / brew
if $SKIP_SEMGREP; then
  warn "Skipping semgrep (--no-semgrep flag set)"
elif check semgrep; then
  info "semgrep already installed: $(semgrep --version 2>/dev/null || echo 'ok')"
else
  echo "  Installing semgrep ${SEMGREP_VERSION}..."
  SEMGREP_OK=false
  if check pip3; then
    pip3 install --quiet "semgrep==${SEMGREP_VERSION}" 2>&1 | grep -v notice && SEMGREP_OK=true
  elif check pip; then
    pip install --quiet "semgrep==${SEMGREP_VERSION}" 2>&1 | grep -v notice && SEMGREP_OK=true
  elif [ "$OS" = "darwin" ] && check brew; then
    brew install semgrep -q && SEMGREP_OK=true
  fi

  if $SEMGREP_OK; then
    info "semgrep installed"
  else
    warn "Could not install semgrep — Python/pip not found"
    warn "Install manually: pip3 install semgrep==${SEMGREP_VERSION}"
  fi
fi

# ── step 3: build aspm-cli ────────────────────────────────────────────────────
section "Step 3/4 — Building aspm-cli from source"

cd "$SCRIPT_DIR"
echo "  go mod download..."
go mod download

echo "  go build ./cmd/aspm-cli..."
mkdir -p "${SCRIPT_DIR}/bin"
BINARY_PATH="${SCRIPT_DIR}/bin/${BINARY_NAME}${EXT}"
go build -ldflags="-s -w" -o "$BINARY_PATH" ./cmd/aspm-cli/...
info "Binary built: $BINARY_PATH"

# ── step 4: install to PATH ───────────────────────────────────────────────────
section "Step 4/4 — Installing aspm-cli to PATH"

ensure_install_dir
copy_bin "$BINARY_PATH" "${INSTALL_DIR}/${BINARY_NAME}${EXT}"
info "aspm-cli installed → ${INSTALL_DIR}/${BINARY_NAME}${EXT}"

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  supplychain-kit installed successfully!   ${RESET}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${RESET}"
echo ""
echo -e "${BOLD}Scanner tools:${RESET}"
for bin in syft grype gitleaks semgrep; do
  # Check both PATH and INSTALL_DIR (session PATH may not be updated yet).
  if check "$bin" || [ -f "${INSTALL_DIR}/${bin}" ] || [ -f "${INSTALL_DIR}/${bin}.exe" ]; then
    echo -e "  ${GREEN}✓${RESET} $bin"
  else
    echo -e "  ${YELLOW}✗${RESET} $bin  ← not installed (that scanner will be skipped)"
  fi
done
echo -e "  ${GREEN}✓${RESET} aspm-cli → ${INSTALL_DIR}/${BINARY_NAME}${EXT}"
echo ""
echo -e "${BOLD}Quick start:${RESET}"
echo -e "  ${CYAN}aspm-cli scan --repo /path/to/project --mode sca${RESET}   # supply chain scan"
echo -e "  ${CYAN}aspm-cli scan --repo /path/to/project --mode sast${RESET}  # code + secret scan"
echo -e "  ${CYAN}aspm-cli scan --repo /path/to/project --out findings.json${RESET}  # save results"
echo -e "  ${CYAN}aspm-cli gate --findings findings.json${RESET}              # quality gate"
echo ""
echo -e "Uninstall: ${YELLOW}bash uninstall.sh${RESET}"
echo ""
