#!/usr/bin/env bash
# install.sh — supplychain-kit one-shot installer
#
# Supported platforms:
#   Linux   (amd64, arm64) — via official install scripts + pip
#   macOS   (amd64, arm64) — via Homebrew (preferred) or official scripts
#   Windows (amd64)        — via Git Bash / MSYS2 / WSL
#
# What this script does:
#   1. Verify prerequisites  (Go, git, curl)
#   2. Install scanner tools (syft, grype, gitleaks, semgrep)
#   3. Build supplychain-kit binary from source
#   4. Install supplychain-kit into a directory on PATH
#   5. Print PATH setup instructions when needed
#
# Usage:
#   bash install.sh                        # full install
#   bash install.sh --no-semgrep           # skip semgrep (no Python)
#   bash install.sh --prefix /usr/local    # custom install prefix
#   bash install.sh --help
#
# Environment overrides:
#   INSTALL_DIR      destination for supplychain-kit  (default: ~/.local/bin)
#   GITLEAKS_VERSION gitleaks release to fetch (default: 8.21.2)
#   SEMGREP_VERSION  semgrep release to install (default: 1.75.0)

set -euo pipefail

# ── defaults ──────────────────────────────────────────────────────────────────
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.21.2}"
SEMGREP_VERSION="${SEMGREP_VERSION:-1.75.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_NAME="supplychain-kit"

# ── colours ───────────────────────────────────────────────────────────────────
# Disable colours when not writing to a terminal.
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

info()    { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*" >&2; }
section() { echo -e "\n${CYAN}${BOLD}── $* ${RESET}"; }
check()   { command -v "$1" &>/dev/null; }

# ── flags ─────────────────────────────────────────────────────────────────────
SKIP_SEMGREP=false
INSTALL_DIR="${INSTALL_DIR:-}"   # resolved after OS detection

for arg in "$@"; do
  case "$arg" in
    --no-semgrep)   SKIP_SEMGREP=true ;;
    --prefix)       shift; INSTALL_DIR="$1" ;;
    --prefix=*)     INSTALL_DIR="${arg#--prefix=}" ;;
    --help|-h)
      cat <<EOF
Usage: bash install.sh [OPTIONS]

Options:
  --no-semgrep        Skip semgrep installation (requires Python/pip)
  --prefix <dir>      Install supplychain-kit and scanner tools to <dir>
                      (default: ~/.local/bin on Linux/Windows,
                                /usr/local/bin on macOS if writable)
  --help              Show this help

Environment variables:
  INSTALL_DIR         Same as --prefix
  GITLEAKS_VERSION    gitleaks version to download (default: ${GITLEAKS_VERSION})
  SEMGREP_VERSION     semgrep version to install  (default: ${SEMGREP_VERSION})

Examples:
  bash install.sh
  bash install.sh --no-semgrep
  INSTALL_DIR=/opt/aspm bash install.sh
EOF
      exit 0
      ;;
  esac
done

# ── OS / arch detection ───────────────────────────────────────────────────────
_uname_s="$(uname -s)"
_uname_m="$(uname -m)"

case "$_uname_s" in
  Darwin)                OS="darwin"  ;;
  Linux)                 OS="linux"   ;;
  MINGW*|MSYS*|CYGWIN*)  OS="windows" ;;
  *)
    error "Unsupported OS: $_uname_s"
    error "Supported: Linux, macOS (Darwin), Windows (Git Bash / MSYS2)"
    exit 1
    ;;
esac

case "$_uname_m" in
  x86_64|amd64)  ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)
    error "Unsupported architecture: $_uname_m"
    error "Supported: x86_64 (amd64), arm64 (aarch64)"
    exit 1
    ;;
esac

# Windows binaries carry .exe; archives use .zip instead of .tar.gz.
EXT=""
ARCHIVE_EXT="tar.gz"
[ "$OS" = "windows" ] && { EXT=".exe"; ARCHIVE_EXT="zip"; }

# Resolve INSTALL_DIR default per-OS.
if [ -z "$INSTALL_DIR" ]; then
  if [ "$OS" = "darwin" ] && [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi

# ── shell-profile detection (for PATH hint) ───────────────────────────────────
detect_shell_profile() {
  local sh
  sh="$(basename "${SHELL:-bash}")"
  case "$sh" in
    zsh)  echo "${ZDOTDIR:-$HOME}/.zshrc" ;;
    fish) echo "$HOME/.config/fish/config.fish" ;;
    *)
      # bash: macOS uses ~/.bash_profile, Linux/Windows use ~/.bashrc
      [ "$OS" = "darwin" ] && echo "$HOME/.bash_profile" || echo "$HOME/.bashrc"
      ;;
  esac
}

SHELL_PROFILE="$(detect_shell_profile)"

# ── helpers ───────────────────────────────────────────────────────────────────
ensure_install_dir() {
  mkdir -p "$INSTALL_DIR"
  # Warn once if not already on PATH.
  if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    warn "$INSTALL_DIR is not on your PATH."
    if [ "$OS" = "windows" ]; then
      warn "Add it permanently via Windows Settings → System → Environment Variables,"
      warn "or add this line to $SHELL_PROFILE for Git Bash:"
      warn "  export PATH=\"\$PATH:$INSTALL_DIR\""
    elif [ "$(basename "${SHELL:-bash}")" = "fish" ]; then
      warn "Add it to Fish:"
      warn "  fish_add_path $INSTALL_DIR"
    else
      warn "Add this line to $SHELL_PROFILE:"
      warn "  export PATH=\"\$PATH:$INSTALL_DIR\""
      warn "Then reload: source $SHELL_PROFILE"
    fi
  fi
}

# Portable binary copy with executable bit.
copy_bin() {
  local src="$1" dst="$2"
  cp "$src" "$dst"
  chmod 0755 "$dst"
}

# Download a release archive (zip or tar.gz) and extract a named binary.
# Usage: download_extract <url> <binary-name> <destination-path>
download_extract() {
  local url="$1" binary="$2" dest="$3"
  local tmpdir; tmpdir="$(mktemp -d)"
  local archive="$tmpdir/archive"
  local extract_dir="$tmpdir/extracted"
  mkdir -p "$extract_dir"

  echo "    Downloading $(basename "$url")"
  if ! curl -fsSL --retry 3 "$url" -o "$archive"; then
    error "Download failed: $url"
    rm -rf "$tmpdir"
    return 1
  fi

  # Extract based on archive type.
  if [[ "$url" == *.zip ]]; then
    if check unzip; then
      unzip -q "$archive" -d "$extract_dir"
    else
      error "unzip is required to extract .zip archives."
      error "  Linux : sudo apt install unzip  /  sudo dnf install unzip"
      error "  macOS : brew install unzip"
      error "  Windows (Git Bash): unzip is usually bundled — update Git for Windows"
      rm -rf "$tmpdir"
      return 1
    fi
  else
    tar -xzf "$archive" -C "$extract_dir"
  fi

  # Find the binary (with or without .exe extension).
  local found
  found="$(find "$extract_dir" -type f \( -name "$binary" -o -name "${binary}.exe" \) 2>/dev/null | head -1)"
  if [ -z "$found" ]; then
    error "Binary '$binary' not found inside archive from $url"
    rm -rf "$tmpdir"
    return 1
  fi

  copy_bin "$found" "$dest"
  rm -rf "$tmpdir"
}

# Run an official Anchore install script (syft or grype).
# Falls back gracefully if the install script itself fails.
anchore_install() {
  local tool="$1"   # syft | grype
  local url="https://raw.githubusercontent.com/anchore/${tool}/main/install.sh"
  echo "  Downloading official ${tool} installer..."
  # Pipe output through cat to prevent set -e from triggering on stderr lines.
  if curl -sSfL --retry 3 "$url" | sh -s -- -b "$INSTALL_DIR" 2>&1; then
    return 0
  else
    return 1
  fi
}

# ── step 1: prerequisites ─────────────────────────────────────────────────────
section "Step 1/4 — Checking prerequisites"

MISSING=()
check go   || MISSING+=("go   → https://go.dev/dl")
check git  || MISSING+=("git  → https://git-scm.com")
check curl || MISSING+=("curl → https://curl.se")

if [ ${#MISSING[@]} -gt 0 ]; then
  error "The following required tools are missing:"
  for m in "${MISSING[@]}"; do error "  • $m"; done
  exit 1
fi

info "Go         : $(go version | awk '{print $3}')"
info "Git        : $(git --version | awk '{print $3}')"
info "OS / Arch  : ${OS} / ${ARCH}"
info "Install dir: ${INSTALL_DIR}"

# ── step 2: scanner tools ─────────────────────────────────────────────────────
section "Step 2/4 — Installing scanner tools"

# ── syft ──────────────────────────────────────────────────────────────────────
if check syft || [ -f "${INSTALL_DIR}/syft${EXT}" ]; then
  info "syft already installed"
else
  echo "  Installing syft (latest stable)..."
  ensure_install_dir
  SYFT_OK=false

  if [ "$OS" = "darwin" ] && check brew; then
    brew install anchore/grype/syft --quiet 2>&1 | tail -1 && SYFT_OK=true
  elif anchore_install syft; then
    SYFT_OK=true
  fi

  $SYFT_OK && info "syft installed" \
           || warn "syft installation failed — SCA (SBOM generation) will be unavailable"
fi

# ── grype ─────────────────────────────────────────────────────────────────────
if check grype || [ -f "${INSTALL_DIR}/grype${EXT}" ]; then
  info "grype already installed"
else
  echo "  Installing grype (latest stable)..."
  ensure_install_dir
  GRYPE_OK=false

  if [ "$OS" = "darwin" ] && check brew; then
    brew install anchore/grype/grype --quiet 2>&1 | tail -1 && GRYPE_OK=true
  elif anchore_install grype; then
    GRYPE_OK=true
  fi

  $GRYPE_OK && info "grype installed" \
            || warn "grype installation failed — vulnerability matching will be unavailable"
fi

# ── gitleaks ──────────────────────────────────────────────────────────────────
if check gitleaks || [ -f "${INSTALL_DIR}/gitleaks${EXT}" ]; then
  info "gitleaks already installed"
else
  echo "  Installing gitleaks v${GITLEAKS_VERSION}..."
  ensure_install_dir
  GITLEAKS_OK=false

  if [ "$OS" = "darwin" ] && check brew; then
    brew install gitleaks --quiet 2>&1 | tail -1 && GITLEAKS_OK=true
  else
    # gitleaks uses x64 (not amd64) in its release filenames.
    GL_ARCH="$ARCH"
    [ "$GL_ARCH" = "amd64" ] && GL_ARCH="x64"

    case "$OS" in
      windows) GL_ARCHIVE="gitleaks_${GITLEAKS_VERSION}_windows_${GL_ARCH}.zip" ;;
      darwin)  GL_ARCHIVE="gitleaks_${GITLEAKS_VERSION}_darwin_${GL_ARCH}.tar.gz" ;;
      linux)   GL_ARCHIVE="gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" ;;
    esac

    GL_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${GL_ARCHIVE}"
    if download_extract "$GL_URL" "gitleaks" "${INSTALL_DIR}/gitleaks${EXT}"; then
      GITLEAKS_OK=true
    fi
  fi

  $GITLEAKS_OK && info "gitleaks installed" \
               || warn "gitleaks installation failed — secret scanning will be unavailable"
fi

# ── semgrep ───────────────────────────────────────────────────────────────────
# semgrep_works: returns 0 if the installed semgrep binary actually executes.
semgrep_works() {
  semgrep --version >/dev/null 2>&1
}

# ensure_pip3: try to install pip3 automatically on Linux if missing.
ensure_pip3() {
  check pip3 && return 0
  check pip  && return 0
  if [ "$OS" != "linux" ]; then return 1; fi

  echo "  pip3 not found — attempting automatic install..."
  if check apt-get; then
    apt-get install -y python3-pip >/dev/null 2>&1 && check pip3 && return 0
  elif check dnf; then
    dnf install -y python3-pip >/dev/null 2>&1 && check pip3 && return 0
  elif check yum; then
    yum install -y python3-pip >/dev/null 2>&1 && check pip3 && return 0
  elif check apk; then
    apk add --no-cache py3-pip >/dev/null 2>&1 && check pip3 && return 0
  fi

  # Fallback: bootstrap pip via ensurepip (available in Python 3.4+).
  if check python3; then
    python3 -m ensurepip --upgrade >/dev/null 2>&1 && check pip3 && return 0
  fi

  return 1
}

if $SKIP_SEMGREP; then
  warn "Skipping semgrep (--no-semgrep)"
elif semgrep_works; then
  info "semgrep already installed: $(semgrep --version 2>/dev/null)"
else
  echo "  Installing semgrep v${SEMGREP_VERSION}..."
  SEMGREP_OK=false

  # macOS: prefer brew (includes native binary).
  # Linux: auto-install pip3 if needed, then use pip3/pip/pipx.
  # Windows: pip wheel installs but semgrep-core native binary is absent —
  #   use WSL or Docker. See: https://semgrep.dev/docs/getting-started/
  if [ "$OS" = "darwin" ] && check brew; then
    brew install semgrep --quiet 2>&1 | tail -1 && SEMGREP_OK=true
  elif [ "$OS" = "windows" ]; then
    : # handled below after post-install check
  elif ensure_pip3; then
    # Prefer --break-system-packages on modern Debian/Ubuntu (PEP 668).
    if check pip3; then
      pip3 install --quiet --break-system-packages "semgrep==${SEMGREP_VERSION}" 2>/dev/null \
        || pip3 install --quiet "semgrep==${SEMGREP_VERSION}" 2>/dev/null
      semgrep_works && SEMGREP_OK=true
    elif check pip; then
      pip install --quiet "semgrep==${SEMGREP_VERSION}" 2>/dev/null
      semgrep_works && SEMGREP_OK=true
    fi
  fi

  # pipx fallback (any OS).
  if ! $SEMGREP_OK && check pipx; then
    pipx install "semgrep==${SEMGREP_VERSION}" >/dev/null 2>&1 && semgrep_works && SEMGREP_OK=true
  fi

  # Post-install sanity check: pip install may succeed but semgrep may not run
  # (known issue on Windows where the native semgrep-core binary is absent).
  if $SEMGREP_OK && ! semgrep_works; then
    SEMGREP_OK=false
    if [ "$OS" = "windows" ]; then
      warn "semgrep installed via pip but cannot run on Windows (native binary missing)."
      warn "Workaround — use WSL and run semgrep from there:"
      warn "  wsl bash install.sh"
      warn "SAST code analysis will be skipped on native Windows."
    fi
  fi

  if $SEMGREP_OK; then
    info "semgrep installed: $(semgrep --version 2>/dev/null)"
  else
    if [ "$OS" = "windows" ]; then
      warn "semgrep is not supported on native Windows."
      warn "Run install.sh inside WSL for full SAST support."
    else
      warn "semgrep installation failed — SAST code analysis will be unavailable."
      warn "Install manually: pip3 install semgrep==${SEMGREP_VERSION}"
    fi
  fi
fi

# ── step 3: build supplychain-kit from source ───────────────────────────────────────
section "Step 3/4 — Building supplychain-kit from source"

cd "$SCRIPT_DIR"

echo "  Downloading Go modules..."
go mod download

echo "  Compiling supplychain-kit..."
mkdir -p "${SCRIPT_DIR}/bin"
BINARY_PATH="${SCRIPT_DIR}/bin/${BINARY_NAME}${EXT}"
go build -ldflags="-s -w" -o "$BINARY_PATH" ./cmd/supplychain-kit/...
info "Binary built → ${BINARY_PATH}"

# ── step 4: install supplychain-kit to PATH ─────────────────────────────────────────
section "Step 4/4 — Installing supplychain-kit"

ensure_install_dir
copy_bin "$BINARY_PATH" "${INSTALL_DIR}/${BINARY_NAME}${EXT}"
info "supplychain-kit installed → ${INSTALL_DIR}/${BINARY_NAME}${EXT}"

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  supplychain-kit installed successfully!   ${RESET}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${RESET}"
echo ""
echo -e "${BOLD}Scanner tools:${RESET}"
for bin in syft grype gitleaks semgrep; do
  # Accept both PATH resolution and direct presence in INSTALL_DIR.
  if check "$bin" || [ -f "${INSTALL_DIR}/${bin}" ] || [ -f "${INSTALL_DIR}/${bin}.exe" ]; then
    echo -e "  ${GREEN}✓${RESET} ${bin}"
  else
    echo -e "  ${YELLOW}✗${RESET} ${bin}  (not installed — that scanner will be skipped)"
  fi
done
echo -e "  ${GREEN}✓${RESET} supplychain-kit → ${INSTALL_DIR}/${BINARY_NAME}${EXT}"

# PATH setup hint — only shown when needed.
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
  echo ""
  echo -e "${YELLOW}${BOLD}PATH setup required:${RESET}"
  if [ "$OS" = "windows" ]; then
    echo -e "  Option A — add to Git Bash profile (${SHELL_PROFILE}):"
    echo -e "    ${CYAN}echo 'export PATH=\"\$PATH:${INSTALL_DIR}\"' >> ${SHELL_PROFILE}${RESET}"
    echo -e "  Option B — add via Windows Settings:"
    echo -e "    System → Advanced → Environment Variables → Path → New → ${INSTALL_DIR}"
  elif [ "$(basename "${SHELL:-bash}")" = "fish" ]; then
    echo -e "  Run: ${CYAN}fish_add_path ${INSTALL_DIR}${RESET}"
  else
    echo -e "  Run: ${CYAN}echo 'export PATH=\"\$PATH:${INSTALL_DIR}\"' >> ${SHELL_PROFILE}${RESET}"
    echo -e "  Then reload: ${CYAN}source ${SHELL_PROFILE}${RESET}"
  fi
fi

echo ""
echo -e "${BOLD}Quick start (after reloading shell):${RESET}"
echo -e "  ${CYAN}supplychain-kit scan --repo /path/to/project --mode sca${RESET}"
echo -e "  ${CYAN}supplychain-kit scan --repo /path/to/project --mode sast${RESET}"
echo -e "  ${CYAN}supplychain-kit scan --repo /path/to/project --mode all --target myapp${RESET}"
echo -e "  ${CYAN}supplychain-kit scan --repo /path/to/project --out findings.json${RESET}"
echo -e "  ${CYAN}supplychain-kit sbom --repo /path/to/project --out sbom.json${RESET}"
echo -e "  ${CYAN}supplychain-kit sbom --repo /path/to/project --target myapp${RESET}"
echo -e "  ${CYAN}supplychain-kit gate --findings findings.json${RESET}"
echo ""
echo -e "To uninstall: ${YELLOW}bash uninstall.sh${RESET}"
echo ""
