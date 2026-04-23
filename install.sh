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
#   2. Install scanner tools (syft, grype, trivy, osv-scanner, gitleaks, semgrep, joern)
#   3. Build supplychain-kit binary from source
#   4. Install supplychain-kit into a directory on PATH
#   5. Print PATH setup instructions when needed
#
# Usage:
#   bash install.sh                        # full install (always fetches latest versions)
#   bash install.sh --no-semgrep           # skip semgrep (no Python)
#   bash install.sh --no-trivy             # skip trivy
#   bash install.sh --no-osv               # skip osv-scanner
#   bash install.sh --no-joern             # skip joern (large download, Java required)
#   bash install.sh --prefix /usr/local    # custom install prefix
#   bash install.sh --help
#
# All scanner tools are installed at their LATEST release automatically.
# Override a specific version via environment variables if needed:
#   GITLEAKS_VERSION=8.21.2 bash install.sh
#   TRIVY_VERSION=0.70.0 bash install.sh

set -euo pipefail

# ── colours ───────────────────────────────────────────────────────────────────
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
SKIP_TRIVY=false
SKIP_OSV=false
SKIP_JOERN=false
INSTALL_DIR="${INSTALL_DIR:-}"

for arg in "$@"; do
  case "$arg" in
    --no-semgrep)   SKIP_SEMGREP=true ;;
    --no-trivy)     SKIP_TRIVY=true ;;
    --no-osv)       SKIP_OSV=true ;;
    --no-joern)     SKIP_JOERN=true ;;
    --prefix)       shift; INSTALL_DIR="$1" ;;
    --prefix=*)     INSTALL_DIR="${arg#--prefix=}" ;;
    --help|-h)
      cat <<EOF
Usage: bash install.sh [OPTIONS]

Options:
  --no-semgrep        Skip semgrep installation (requires Python/pip)
  --no-trivy          Skip trivy installation
  --no-osv            Skip osv-scanner installation
  --no-joern          Skip joern installation (large ~500MB download, requires Java)
  --prefix <dir>      Install supplychain-kit and scanner tools to <dir>
                      (default: ~/.local/bin on Linux/Windows,
                                /usr/local/bin on macOS if writable)
  --help              Show this help

Environment variables:
  INSTALL_DIR         Same as --prefix
  GITLEAKS_VERSION    Pin gitleaks version  (default: latest)
  TRIVY_VERSION       Pin trivy version     (default: latest)
  OSV_VERSION         Pin osv-scanner version (default: latest)
  SEMGREP_VERSION     Pin semgrep version   (default: latest)

By default all tools are fetched at their latest release.
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

EXT=""
ARCHIVE_EXT="tar.gz"
[ "$OS" = "windows" ] && { EXT=".exe"; ARCHIVE_EXT="zip"; }

if [ -z "$INSTALL_DIR" ]; then
  if [ "$OS" = "darwin" ] && [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_NAME="supplychain-kit"

# ── shell-profile detection ───────────────────────────────────────────────────
detect_shell_profile() {
  local sh
  sh="$(basename "${SHELL:-bash}")"
  case "$sh" in
    zsh)  echo "${ZDOTDIR:-$HOME}/.zshrc" ;;
    fish) echo "$HOME/.config/fish/config.fish" ;;
    *)
      [ "$OS" = "darwin" ] && echo "$HOME/.bash_profile" || echo "$HOME/.bashrc"
      ;;
  esac
}
SHELL_PROFILE="$(detect_shell_profile)"

# ── helpers ───────────────────────────────────────────────────────────────────
ensure_install_dir() {
  mkdir -p "$INSTALL_DIR"
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

copy_bin() {
  local src="$1" dst="$2"
  cp "$src" "$dst"
  chmod 0755 "$dst"
}

# Fetch latest release tag from GitHub API.
# Usage: latest_release <owner/repo>
# Respects env override: variable name derived from repo name.
latest_release() {
  local repo="$1"
  local tag
  tag="$(curl -fsSL --retry 3 "https://api.github.com/repos/${repo}/releases/latest" \
    | grep '"tag_name"' | head -1 \
    | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\?\([^"]*\)".*/\1/')"
  if [ -z "$tag" ]; then
    error "Could not resolve latest release for ${repo}"
    return 1
  fi
  echo "$tag"
}

# Download a release archive (zip or tar.gz) and extract a named binary.
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

  if [[ "$url" == *.zip ]]; then
    if check unzip; then
      unzip -q "$archive" -d "$extract_dir"
    else
      error "unzip is required to extract .zip archives."
      rm -rf "$tmpdir"
      return 1
    fi
  else
    tar -xzf "$archive" -C "$extract_dir"
  fi

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
anchore_install() {
  local tool="$1"
  local url="https://raw.githubusercontent.com/anchore/${tool}/main/install.sh"
  echo "  Downloading official ${tool} installer..."
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
  info "syft already installed ($(syft version 2>/dev/null | grep Version | awk '{print $2}' || echo '?'))"
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
  info "grype already installed ($(grype version 2>/dev/null | grep Version | awk '{print $2}' || echo '?'))"
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

# ── trivy ─────────────────────────────────────────────────────────────────────
# Uses the official Trivy install script (https://trivy.dev/docs/latest/getting-started/installation/)
# which auto-detects OS, architecture, and always installs the latest release.
if $SKIP_TRIVY; then
  warn "Skipping trivy (--no-trivy)"
elif check trivy || [ -f "${INSTALL_DIR}/trivy${EXT}" ]; then
  info "trivy already installed ($(trivy --version 2>/dev/null | grep Version | awk '{print $2}' || echo '?'))"
else
  echo "  Installing trivy (latest stable via official script)..."
  ensure_install_dir
  TRIVY_OK=false

  if [ "$OS" = "darwin" ] && check brew; then
    brew install aquasecurity/trivy/trivy --quiet 2>&1 | tail -1 && TRIVY_OK=true
  elif [ "$OS" = "linux" ]; then
    # Prefer apt/rpm package managers for proper system integration.
    if check apt-get && check wget; then
      echo "    Setting up Trivy apt repository..."
      wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor \
        | tee /usr/share/keyrings/trivy.gpg >/dev/null 2>&1
      echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        | tee /etc/apt/sources.list.d/trivy.list >/dev/null
      apt-get update -qq 2>/dev/null
      apt-get install -y trivy >/dev/null 2>&1 && TRIVY_OK=true
    elif check dnf || check yum; then
      PKG_MGR="dnf"; check dnf || PKG_MGR="yum"
      cat >/etc/yum.repos.d/trivy.repo <<'REPO'
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
REPO
      $PKG_MGR install -y trivy >/dev/null 2>&1 && TRIVY_OK=true
    fi

    # Fallback: official install script (works on any Linux).
    if ! $TRIVY_OK; then
      echo "    Falling back to official Trivy install script..."
      if curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
          | sh -s -- -b "$INSTALL_DIR" 2>&1; then
        TRIVY_OK=true
      fi
    fi
  elif [ "$OS" = "windows" ]; then
    # On Windows: resolve latest version then download zip.
    TV_VERSION="${TRIVY_VERSION:-$(latest_release aquasecurity/trivy)}"
    TV_ARCHIVE="trivy_${TV_VERSION}_windows-64bit.zip"
    TV_URL="https://github.com/aquasecurity/trivy/releases/download/v${TV_VERSION}/${TV_ARCHIVE}"
    if download_extract "$TV_URL" "trivy" "${INSTALL_DIR}/trivy${EXT}"; then
      TRIVY_OK=true
    fi
  fi

  $TRIVY_OK && info "trivy installed ($(trivy --version 2>/dev/null | grep Version | awk '{print $2}'))" \
            || warn "trivy installation failed — extended CVE coverage will be unavailable"
fi

# ── osv-scanner ───────────────────────────────────────────────────────────────
if $SKIP_OSV; then
  warn "Skipping osv-scanner (--no-osv)"
elif check osv-scanner || [ -f "${INSTALL_DIR}/osv-scanner${EXT}" ]; then
  info "osv-scanner already installed"
else
  OSV_VERSION="${OSV_VERSION:-$(latest_release google/osv-scanner)}"
  echo "  Installing osv-scanner v${OSV_VERSION}..."
  ensure_install_dir
  OSV_OK=false

  if [ "$OS" = "darwin" ] && check brew; then
    brew install osv-scanner --quiet 2>&1 | tail -1 && OSV_OK=true
  else
    case "$OS-$ARCH" in
      linux-amd64)   OSV_BIN="osv-scanner_linux_amd64" ;;
      linux-arm64)   OSV_BIN="osv-scanner_linux_arm64" ;;
      darwin-amd64)  OSV_BIN="osv-scanner_darwin_amd64" ;;
      darwin-arm64)  OSV_BIN="osv-scanner_darwin_arm64" ;;
      windows-amd64) OSV_BIN="osv-scanner_windows_amd64.exe" ;;
      *)
        warn "No osv-scanner binary for ${OS}-${ARCH}"
        OSV_BIN=""
        ;;
    esac

    if [ -n "$OSV_BIN" ]; then
      OSV_URL="https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/${OSV_BIN}"
      echo "    Downloading ${OSV_BIN}"
      if curl -fsSL --retry 3 "$OSV_URL" -o "${INSTALL_DIR}/osv-scanner${EXT}"; then
        chmod 0755 "${INSTALL_DIR}/osv-scanner${EXT}"
        OSV_OK=true
      fi
    fi
  fi

  $OSV_OK && info "osv-scanner installed (v${OSV_VERSION})" \
           || warn "osv-scanner installation failed — Google OSV database scan will be unavailable"
fi

# ── gitleaks ──────────────────────────────────────────────────────────────────
if check gitleaks || [ -f "${INSTALL_DIR}/gitleaks${EXT}" ]; then
  info "gitleaks already installed ($(gitleaks version 2>/dev/null || echo '?'))"
else
  GITLEAKS_VERSION="${GITLEAKS_VERSION:-$(latest_release gitleaks/gitleaks)}"
  echo "  Installing gitleaks v${GITLEAKS_VERSION}..."
  ensure_install_dir
  GITLEAKS_OK=false

  if [ "$OS" = "darwin" ] && check brew; then
    brew install gitleaks --quiet 2>&1 | tail -1 && GITLEAKS_OK=true
  else
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

  $GITLEAKS_OK && info "gitleaks installed (v${GITLEAKS_VERSION})" \
               || warn "gitleaks installation failed — secret scanning will be unavailable"
fi

# ── semgrep ───────────────────────────────────────────────────────────────────
semgrep_works() {
  semgrep --version >/dev/null 2>&1
}

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
  # Install latest semgrep (no version pin — pip resolves latest by default).
  SEMGREP_INSTALL_ARG="semgrep"
  # Allow pinning via env var for reproducible installs.
  [ -n "${SEMGREP_VERSION:-}" ] && SEMGREP_INSTALL_ARG="semgrep==${SEMGREP_VERSION}"

  echo "  Installing semgrep (latest stable)..."
  SEMGREP_OK=false

  if [ "$OS" = "darwin" ] && check brew; then
    brew install semgrep --quiet 2>&1 | tail -1 && SEMGREP_OK=true
  elif [ "$OS" = "windows" ]; then
    : # handled in post-install check below
  elif ensure_pip3; then
    if check pip3; then
      pip3 install --quiet --break-system-packages "$SEMGREP_INSTALL_ARG" 2>/dev/null \
        || pip3 install --quiet "$SEMGREP_INSTALL_ARG" 2>/dev/null
      semgrep_works && SEMGREP_OK=true
    elif check pip; then
      pip install --quiet "$SEMGREP_INSTALL_ARG" 2>/dev/null
      semgrep_works && SEMGREP_OK=true
    fi
  fi

  if ! $SEMGREP_OK && check pipx; then
    pipx install "$SEMGREP_INSTALL_ARG" >/dev/null 2>&1 && semgrep_works && SEMGREP_OK=true
  fi

  if $SEMGREP_OK && ! semgrep_works; then
    SEMGREP_OK=false
    if [ "$OS" = "windows" ]; then
      warn "semgrep installed via pip but cannot run on Windows (native binary missing)."
      warn "Workaround — use WSL: wsl bash install.sh"
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
      warn "Install manually: pip3 install semgrep"
    fi
  fi
fi

# ── joern ─────────────────────────────────────────────────────────────────────
# Joern provides static reachability analysis (CPG traversal).
# Requires Java 11+. Large download (~500MB). Skip with --no-joern.
joern_works() {
  command -v joern-parse >/dev/null 2>&1 && command -v joern-export >/dev/null 2>&1
}

if $SKIP_JOERN; then
  warn "Skipping joern (--no-joern) — reachability engine will use fallback (unknown)"
elif joern_works; then
  info "joern already installed (joern-parse + joern-export on PATH)"
else
  echo "  Installing joern (latest stable — requires Java 11+)..."
  JOERN_OK=false

  # Verify Java is available (Joern is JVM-based).
  if ! check java; then
    warn "Java not found — joern requires Java 11+."
    if [ "$OS" = "linux" ] && check apt-get; then
      echo "    Installing Java 17 (headless)..."
      apt-get install -y openjdk-17-jre-headless >/dev/null 2>&1 && check java || true
    elif [ "$OS" = "darwin" ] && check brew; then
      brew install --quiet openjdk@17 2>&1 | tail -1 || true
    fi
    if ! check java; then
      warn "Could not install Java automatically."
      warn "Install Java 11+ manually, then re-run: bash install.sh"
      warn "Reachability engine will fall back to unknown until joern is available."
    fi
  fi

  # joern-install.sh also requires unzip.
  if check java && ! check unzip; then
    echo "    Installing unzip (required by joern)..."
    if check apt-get; then
      apt-get install -y unzip >/dev/null 2>&1 || true
    elif check dnf || check yum; then
      ${DNF_OR_YUM:-yum} install -y unzip >/dev/null 2>&1 || true
    fi
  fi

  if check java; then
    # Use the official joern-install.sh — always fetches the latest release.
    JOERN_INSTALL_DIR="${HOME}/.local/share/joern"
    echo "    Downloading joern-install.sh..."
    if curl -fsSL --retry 3 \
        https://raw.githubusercontent.com/joernio/joern/master/joern-install.sh \
        -o /tmp/joern-install.sh; then
      chmod +x /tmp/joern-install.sh
      # Install joern to a fixed directory so we can symlink the binaries.
      if bash /tmp/joern-install.sh --install-dir="$JOERN_INSTALL_DIR" 2>&1; then
        JOERN_CLI="${JOERN_INSTALL_DIR}/joern-cli"
        # Symlink joern-parse and joern-export into INSTALL_DIR.
        ensure_install_dir
        for bin in joern-parse joern-export joern; do
          BIN_PATH="${JOERN_CLI}/${bin}"
          if [ -f "$BIN_PATH" ]; then
            ln -sf "$BIN_PATH" "${INSTALL_DIR}/${bin}"
            chmod 0755 "${INSTALL_DIR}/${bin}"
          fi
        done
        joern_works && JOERN_OK=true
      fi
    fi
    rm -f /tmp/joern-install.sh
  fi

  if $JOERN_OK; then
    info "joern installed (joern-parse + joern-export)"
  else
    warn "joern installation failed — reachability engine will use fallback (unknown)"
    warn "Install manually: curl -fsSL https://raw.githubusercontent.com/joernio/joern/master/joern-install.sh | bash"
    warn "Then add joern-cli/ to your PATH."
  fi
fi

# ── step 3: build supplychain-kit from source ──────────────────────────────────
section "Step 3/4 — Building supplychain-kit from source"

cd "$SCRIPT_DIR"

echo "  Downloading Go modules..."
go mod download

echo "  Compiling supplychain-kit..."
mkdir -p "${SCRIPT_DIR}/bin"
BINARY_PATH="${SCRIPT_DIR}/bin/${BINARY_NAME}${EXT}"
go build -ldflags="-s -w" -o "$BINARY_PATH" ./cmd/supplychain-kit/...
info "Binary built → ${BINARY_PATH}"

# ── step 4: install supplychain-kit to PATH ─────────────────────────────────────
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
for bin in syft grype trivy osv-scanner gitleaks semgrep joern-parse joern-export; do
  if check "$bin" || [ -f "${INSTALL_DIR}/${bin}" ] || [ -f "${INSTALL_DIR}/${bin}.exe" ]; then
    echo -e "  ${GREEN}✓${RESET} ${bin}"
  else
    echo -e "  ${YELLOW}✗${RESET} ${bin}  (not installed — that scanner will be skipped)"
  fi
done
echo -e "  ${GREEN}✓${RESET} supplychain-kit → ${INSTALL_DIR}/${BINARY_NAME}${EXT}"

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
echo -e "  ${CYAN}supplychain-kit gate --findings findings.json${RESET}"
echo ""
echo -e "To uninstall: ${YELLOW}bash uninstall.sh${RESET}"
echo ""
