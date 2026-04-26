#!/usr/bin/env bash
# install.sh — supplychain-kit one-shot installer
#
# Supported platforms:
#   Linux  (amd64, arm64) — via official install scripts + pip
#   macOS  (amd64, arm64) — via Homebrew (preferred) or official scripts
#
# Windows is NOT supported natively. semgrep, joern, and several scanner
# tools do not run on Windows. Use WSL2:
#   wsl --install && wsl bash install.sh
#
# What this script does:
#   1. Verify prerequisites  (Go, git, curl)
#   2. Install scanner tools (syft, grype, trivy, osv-scanner, gitleaks, semgrep, joern)
#   3. Install pandoc        (optional, required for --format docx report generation)
#   4. Build supplychain-kit binary from source (version-stamped via git describe)
#   5. Install supplychain-kit into a directory on PATH
#   6. Install Claude Code skill to ~/.claude/skills/supplychain-kit
#   7. Run go test ./... as verification
#
# Usage:
#   bash install.sh                        # full install
#   bash install.sh --symlink              # symlink skill dir (live edits for dev)
#   bash install.sh --no-semgrep           # skip semgrep (no Python)
#   bash install.sh --no-trivy             # skip trivy
#   bash install.sh --no-osv               # skip osv-scanner
#   bash install.sh --no-joern             # skip joern (large download, Java required)
#   bash install.sh --no-pandoc            # skip pandoc
#   bash install.sh --skip-test            # skip go test verification
#   bash install.sh --prefix /usr/local    # custom binary install prefix
#   bash install.sh --help
#
# Environment variables:
#   CLAUDE_HOME=~/.claude          Override Claude Code home (default: auto-detect)
#   CLAUDE_HOME=~/.claude,~/.claude-work  Install skill to multiple homes
#   GITLEAKS_VERSION=8.21.2        Pin specific tool versions
#   TRIVY_VERSION=0.70.0

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
SKIP_PANDOC=false
SKIP_TEST=false
USE_SYMLINK=false
INSTALL_DIR="${INSTALL_DIR:-}"

while [[ $# -gt 0 ]]; do
  arg="$1"; shift
  case "$arg" in
    --no-semgrep)   SKIP_SEMGREP=true ;;
    --no-trivy)     SKIP_TRIVY=true ;;
    --no-osv)       SKIP_OSV=true ;;
    --no-joern)     SKIP_JOERN=true ;;
    --no-pandoc)    SKIP_PANDOC=true ;;
    --skip-test)    SKIP_TEST=true ;;
    --symlink)      USE_SYMLINK=true ;;
    --prefix)       INSTALL_DIR="$1"; shift ;;
    --prefix=*)     INSTALL_DIR="${arg#--prefix=}" ;;
    --help|-h)
      cat <<EOF
Usage: bash install.sh [OPTIONS]

Options:
  --symlink           Symlink skill dir to repo (live edits — for supplychain-kit developers)
  --no-semgrep        Skip semgrep installation (requires Python/pip)
  --no-trivy          Skip trivy installation
  --no-osv            Skip osv-scanner installation
  --no-joern          Skip joern installation (large ~500MB download, requires Java)
  --no-pandoc         Skip pandoc installation (only needed for --format docx reports)
  --skip-test         Skip go test verification at the end
  --prefix <dir>      Install supplychain-kit binary to <dir>
                      (default: ~/.local/bin on Linux, /usr/local/bin on macOS if writable)
  --help              Show this help

Environment variables:
  INSTALL_DIR         Same as --prefix
  CLAUDE_HOME         Claude Code home dir(s), comma-separated (default: auto-detect)
  GITLEAKS_VERSION    Pin gitleaks version  (default: latest)
  TRIVY_VERSION       Pin trivy version     (default: latest)
  OSV_VERSION         Pin osv-scanner version (default: latest)
  SEMGREP_VERSION     Pin semgrep version   (default: latest)

Windows users: this tool requires Linux or macOS. On Windows, use WSL2:
  wsl --install
  wsl bash install.sh
EOF
      exit 0
      ;;
    *)
      error "Unknown option: $arg"
      echo "Run 'bash install.sh --help' for usage."
      exit 1
      ;;
  esac
done

# ── OS / arch detection ───────────────────────────────────────────────────────
_uname_s="$(uname -s)"
_uname_m="$(uname -m)"

case "$_uname_s" in
  Darwin) OS="darwin" ;;
  Linux)  OS="linux"  ;;
  MINGW*|MSYS*|CYGWIN*)
    error "Windows is not supported natively."
    error "semgrep, joern, and several scanner tools do not run on Windows."
    error ""
    error "Use WSL2 instead:"
    error "  1. wsl --install          (in PowerShell as Administrator)"
    error "  2. wsl bash install.sh    (from this directory inside WSL)"
    exit 1
    ;;
  *)
    error "Unsupported OS: $_uname_s"
    exit 1
    ;;
esac

case "$_uname_m" in
  x86_64|amd64)  ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)
    error "Unsupported architecture: $_uname_m"
    exit 1
    ;;
esac

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
    *)    [ "$OS" = "darwin" ] && echo "$HOME/.bash_profile" || echo "$HOME/.bashrc" ;;
  esac
}
SHELL_PROFILE="$(detect_shell_profile)"

# ── helpers ───────────────────────────────────────────────────────────────────
ensure_install_dir() {
  mkdir -p "$INSTALL_DIR"
  if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    warn "$INSTALL_DIR is not on your PATH."
    if [ "$(basename "${SHELL:-bash}")" = "fish" ]; then
      warn "Add it to Fish:  fish_add_path $INSTALL_DIR"
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
  found="$(find "$extract_dir" -type f -name "$binary" 2>/dev/null | head -1)"
  if [ -z "$found" ]; then
    error "Binary '$binary' not found inside archive from $url"
    rm -rf "$tmpdir"
    return 1
  fi

  copy_bin "$found" "$dest"
  rm -rf "$tmpdir"
}

anchore_install() {
  local tool="$1"
  local version="${2:-}"
  local url="https://raw.githubusercontent.com/anchore/${tool}/main/install.sh"
  local tmpdir
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' RETURN

  local attempts=3
  for i in $(seq 1 $attempts); do
    echo "  Downloading ${tool} installer (attempt $i/$attempts)..."
    if curl -sSfL --retry 2 --retry-delay 3 --connect-timeout 15 \
         -o "${tmpdir}/${tool}_install.sh" "$url" 2>&1; then
      echo "  Running ${tool} installer..."
      if sh "${tmpdir}/${tool}_install.sh" -b "$INSTALL_DIR" ${version:+"$version"} 2>&1; then
        rm -rf "$tmpdir"
        trap - RETURN
        return 0
      fi
    fi
    [ "$i" -lt "$attempts" ] && sleep 5
  done

  warn "  Official installer failed for ${tool}, trying direct binary download..."
  if anchore_direct_download "$tool" "$version"; then
    rm -rf "$tmpdir"
    trap - RETURN
    return 0
  fi

  rm -rf "$tmpdir"
  trap - RETURN
  return 1
}

anchore_direct_download() {
  local tool="$1"
  local version="${2:-}"
  local api_url="https://api.github.com/repos/anchore/${tool}/releases/latest"
  local download_url asset_name tmpdir

  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' RETURN

  if [ -n "$version" ]; then
    api_url="https://api.github.com/repos/anchore/${tool}/releases/tags/${version}"
  fi

  local release_json
  release_json=$(curl -sSfL --retry 2 --connect-timeout 15 "$api_url" 2>&1) || {
    warn "  Could not fetch ${tool} release info from GitHub API"
    return 1
  }

  local tag
  tag=$(echo "$release_json" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
  [ -z "$tag" ] && { warn "  Could not determine ${tool} latest version"; return 1; }

  local suffix="${OS}_${ARCH}"
  asset_name="${tool}_${tag#v}_${suffix}.tar.gz"

  local browser_url
  browser_url=$(echo "$release_json" | grep -o "\"browser_download_url\": *\"${asset_name}\"" || true)
  if [ -z "$browser_url" ]; then
    browser_url=$(echo "$release_json" \
      | grep "browser_download_url" \
      | grep "${OS}" | grep "${ARCH}" \
      | head -1 \
      | sed 's/.*"browser_download_url": *"//;s/".*//')
  fi
  [ -z "$browser_url" ] && { warn "  No binary found for ${tool} on ${OS}/${ARCH}"; return 1; }

  echo "  Downloading ${tool} ${tag} binary..."
  if curl -sSfL --retry 2 --retry-delay 3 --connect-timeout 15 \
       -o "${tmpdir}/${asset_name}" "$browser_url" 2>&1; then
    if tar xzf "${tmpdir}/${asset_name}" -C "$tmpdir" 2>&1; then
      local bin="${tmpdir}/${tool}"
      [ -f "$bin" ] && chmod +x "$bin" && cp "$bin" "${INSTALL_DIR}/${tool}" && {
        rm -rf "$tmpdir"
        trap - RETURN
        echo "  ${tool} ${tag} installed via direct download"
        return 0
      }
    fi
  fi

  warn "  Direct download failed for ${tool}"
  return 1
}

# ── step 1: prerequisites ─────────────────────────────────────────────────────
section "Step 1/5 — Checking prerequisites"

MISSING=()
check go   || MISSING+=("go   → https://go.dev/dl")
check git  || MISSING+=("git  → https://git-scm.com")
check curl || MISSING+=("curl → https://curl.se")
check tar  || MISSING+=("tar  → install via package manager")

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
section "Step 2/5 — Installing scanner tools"

# ── syft ──────────────────────────────────────────────────────────────────────
if check syft || [ -f "${INSTALL_DIR}/syft" ]; then
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
if check grype || [ -f "${INSTALL_DIR}/grype" ]; then
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
if $SKIP_TRIVY; then
  warn "Skipping trivy (--no-trivy)"
elif check trivy || [ -f "${INSTALL_DIR}/trivy" ]; then
  info "trivy already installed ($(trivy --version 2>/dev/null | grep Version | awk '{print $2}' || echo '?'))"
else
  echo "  Installing trivy (latest stable)..."
  ensure_install_dir
  TRIVY_OK=false

  if [ "$OS" = "darwin" ] && check brew; then
    brew install aquasecurity/trivy/trivy --quiet 2>&1 | tail -1 && TRIVY_OK=true
  elif [ "$OS" = "linux" ]; then
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
    if ! $TRIVY_OK; then
      echo "    Falling back to official Trivy install script..."
      if curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
          | sh -s -- -b "$INSTALL_DIR" 2>&1; then
        TRIVY_OK=true
      fi
    fi
  fi

  $TRIVY_OK && info "trivy installed" \
            || warn "trivy installation failed — extended CVE coverage will be unavailable"
fi

# ── osv-scanner ───────────────────────────────────────────────────────────────
if $SKIP_OSV; then
  warn "Skipping osv-scanner (--no-osv)"
elif check osv-scanner || [ -f "${INSTALL_DIR}/osv-scanner" ]; then
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
      linux-amd64)  OSV_BIN="osv-scanner_linux_amd64" ;;
      linux-arm64)  OSV_BIN="osv-scanner_linux_arm64" ;;
      darwin-amd64) OSV_BIN="osv-scanner_darwin_amd64" ;;
      darwin-arm64) OSV_BIN="osv-scanner_darwin_arm64" ;;
      *)            warn "No osv-scanner binary for ${OS}-${ARCH}"; OSV_BIN="" ;;
    esac
    if [ -n "$OSV_BIN" ]; then
      OSV_URL="https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/${OSV_BIN}"
      echo "    Downloading ${OSV_BIN}"
      if curl -fsSL --retry 3 "$OSV_URL" -o "${INSTALL_DIR}/osv-scanner"; then
        chmod 0755 "${INSTALL_DIR}/osv-scanner"
        OSV_OK=true
      fi
    fi
  fi

  $OSV_OK && info "osv-scanner installed (v${OSV_VERSION})" \
           || warn "osv-scanner installation failed"
fi

# ── gitleaks ──────────────────────────────────────────────────────────────────
if check gitleaks || [ -f "${INSTALL_DIR}/gitleaks" ]; then
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
      darwin) GL_ARCHIVE="gitleaks_${GITLEAKS_VERSION}_darwin_${GL_ARCH}.tar.gz" ;;
      linux)  GL_ARCHIVE="gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" ;;
    esac
    GL_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${GL_ARCHIVE}"
    if download_extract "$GL_URL" "gitleaks" "${INSTALL_DIR}/gitleaks"; then
      GITLEAKS_OK=true
    fi
  fi

  $GITLEAKS_OK && info "gitleaks installed (v${GITLEAKS_VERSION})" \
               || warn "gitleaks installation failed — secret scanning will be unavailable"
fi

# ── semgrep ───────────────────────────────────────────────────────────────────
semgrep_works() { semgrep --version >/dev/null 2>&1; }

ensure_pip3() {
  check pip3 && return 0
  check pip  && return 0
  if ! check python3; then return 1; fi
  if check apt-get; then
    apt-get install -y python3-pip >/dev/null 2>&1 && check pip3 && return 0
  elif check dnf; then
    dnf install -y python3-pip >/dev/null 2>&1 && check pip3 && return 0
  elif check yum; then
    yum install -y python3-pip >/dev/null 2>&1 && check pip3 && return 0
  elif check apk; then
    apk add --no-cache py3-pip >/dev/null 2>&1 && check pip3 && return 0
  fi
  python3 -m ensurepip --upgrade >/dev/null 2>&1 && check pip3 && return 0
  return 1
}

if $SKIP_SEMGREP; then
  warn "Skipping semgrep (--no-semgrep)"
elif semgrep_works; then
  info "semgrep already installed: $(semgrep --version 2>/dev/null)"
else
  SEMGREP_INSTALL_ARG="semgrep"
  [ -n "${SEMGREP_VERSION:-}" ] && SEMGREP_INSTALL_ARG="semgrep==${SEMGREP_VERSION}"
  echo "  Installing semgrep (latest stable)..."
  SEMGREP_OK=false

  if [ "$OS" = "darwin" ] && check brew; then
    brew install semgrep --quiet 2>&1 | tail -1 && SEMGREP_OK=true
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

  $SEMGREP_OK && info "semgrep installed: $(semgrep --version 2>/dev/null)" \
              || { warn "semgrep installation failed — SAST code analysis will be unavailable."; warn "Install manually: pip3 install semgrep"; }
fi

# ── joern ─────────────────────────────────────────────────────────────────────
joern_works() {
  command -v joern-parse >/dev/null 2>&1 && command -v joern-export >/dev/null 2>&1
}

if $SKIP_JOERN; then
  warn "Skipping joern (--no-joern) — reachability engine will use fallback (unknown)"
elif joern_works; then
  info "joern already installed"
else
  echo "  Installing joern (latest stable — requires Java 11+)..."
  JOERN_OK=false

  if ! check java; then
    warn "Java not found — joern requires Java 11+."
    if [ "$OS" = "linux" ] && check apt-get; then
      echo "    Installing Java 17 (headless)..."
      apt-get install -y openjdk-17-jre-headless >/dev/null 2>&1 && check java || true
    elif [ "$OS" = "darwin" ] && check brew; then
      brew install --quiet openjdk@17 2>&1 | tail -1 || true
    fi
  fi

  if check java && ! check unzip; then
    echo "    Installing unzip (required by joern)..."
    if check apt-get; then apt-get install -y unzip >/dev/null 2>&1 || true; fi
  fi

  if check java; then
    JOERN_INSTALL_DIR="${HOME}/.local/share/joern"
    echo "    Downloading joern-install.sh..."
    if curl -fsSL --retry 3 \
        https://raw.githubusercontent.com/joernio/joern/master/joern-install.sh \
        -o /tmp/joern-install.sh; then
      chmod +x /tmp/joern-install.sh
      if bash /tmp/joern-install.sh --install-dir="$JOERN_INSTALL_DIR" 2>&1; then
        JOERN_CLI="${JOERN_INSTALL_DIR}/joern-cli"
        ensure_install_dir
        for bin in joern-parse joern-export joern; do
          BIN_PATH="${JOERN_CLI}/${bin}"
          if [ -f "$BIN_PATH" ]; then
            ln -sf "$BIN_PATH" "${INSTALL_DIR}/${bin}"
          fi
        done
        joern_works && JOERN_OK=true
      fi
    fi
    rm -f /tmp/joern-install.sh
  fi

  $JOERN_OK && info "joern installed" \
            || warn "joern installation failed — reachability engine will use fallback (unknown)"
fi

# ── pandoc ────────────────────────────────────────────────────────────────────
if $SKIP_PANDOC; then
  warn "Skipping pandoc (--no-pandoc) — DOCX report generation will be unavailable"
elif check pandoc; then
  info "pandoc already installed ($(pandoc --version | head -1))"
else
  echo "  Installing pandoc (latest stable)..."
  PANDOC_OK=false

  if [ "$OS" = "darwin" ] && check brew; then
    brew install pandoc --quiet 2>&1 | tail -1 && PANDOC_OK=true
  elif [ "$OS" = "linux" ]; then
    if check apt-get; then
      PANDOC_VERSION="$(latest_release jgm/pandoc)"
      PANDOC_DEB="pandoc-${PANDOC_VERSION}-1-amd64.deb"
      PANDOC_URL="https://github.com/jgm/pandoc/releases/download/${PANDOC_VERSION}/${PANDOC_DEB}"
      echo "    Downloading ${PANDOC_DEB}..."
      if curl -fsSL --retry 3 "$PANDOC_URL" -o "/tmp/${PANDOC_DEB}"; then
        dpkg -i "/tmp/${PANDOC_DEB}" >/dev/null 2>&1 && PANDOC_OK=true
        rm -f "/tmp/${PANDOC_DEB}"
      fi
      ! $PANDOC_OK && apt-get install -y pandoc >/dev/null 2>&1 && PANDOC_OK=true
    elif check dnf; then
      dnf install -y pandoc >/dev/null 2>&1 && PANDOC_OK=true
    elif check yum; then
      yum install -y pandoc >/dev/null 2>&1 && PANDOC_OK=true
    elif check apk; then
      apk add --no-cache pandoc >/dev/null 2>&1 && PANDOC_OK=true
    fi
    if ! $PANDOC_OK; then
      PANDOC_VERSION="${PANDOC_VERSION:-$(latest_release jgm/pandoc)}"
      PANDOC_TAR="pandoc-${PANDOC_VERSION}-linux-amd64.tar.gz"
      [ "$ARCH" = "arm64" ] && PANDOC_TAR="pandoc-${PANDOC_VERSION}-linux-arm64.tar.gz"
      PANDOC_URL="https://github.com/jgm/pandoc/releases/download/${PANDOC_VERSION}/${PANDOC_TAR}"
      download_extract "$PANDOC_URL" "pandoc" "${INSTALL_DIR}/pandoc" && PANDOC_OK=true
    fi
  fi

  $PANDOC_OK && info "pandoc installed ($(pandoc --version 2>/dev/null | head -1))" \
             || { warn "pandoc installation failed — DOCX reports unavailable"; warn "Install manually: https://pandoc.org/installing.html"; }
fi

# ── step 3: install supplychain-kit binary ────────────────────────────────────
section "Step 3/5 — Installing supplychain-kit"

GIT_VERSION=""
SKT_INSTALLED=false
BINARY_PATH=""

# Try downloading pre-built binary from GitHub Releases first.
_install_version="${VERSION:-}"
if [ -z "$_install_version" ]; then
  echo "  Fetching latest release version from GitHub..."
  _install_version="$(latest_release penanamtomat/supplychain-kit 2>/dev/null)" || true
fi

if [ -n "$_install_version" ]; then
  _archive="supplychain-kit_${_install_version}_${OS}_${ARCH}.tar.gz"
  _dl_url="https://github.com/penanamtomat/supplychain-kit/releases/download/v${_install_version}/${_archive}"
  _cs_url="https://github.com/penanamtomat/supplychain-kit/releases/download/v${_install_version}/checksums.txt"
  _tmpdir="$(mktemp -d)"
  _archive_path="${_tmpdir}/${_archive}"

  echo "  Downloading ${_archive}..."
  if curl -fsSL --retry 3 "$_dl_url" -o "$_archive_path" 2>/dev/null; then
    # Checksum verification
    _cs_file="${_tmpdir}/checksums.txt"
    if curl -fsSL --retry 3 "$_cs_url" -o "$_cs_file" 2>/dev/null; then
      echo "  Verifying checksum..."
      if [ "$OS" = "darwin" ]; then
        _verify_cmd="shasum -a 256"
      else
        _verify_cmd="sha256sum"
      fi
      _expected="$(grep "${_archive}" "$_cs_file" | awk '{print $1}')"
      if [ -n "$_expected" ]; then
        _actual="$($_verify_cmd "$_archive_path" | awk '{print $1}')"
        if [ "$_expected" = "$_actual" ]; then
          info "Checksum verified"
        else
          error "Checksum mismatch for ${_archive}"
          error "  expected: ${_expected}"
          error "  got:      ${_actual}"
          rm -rf "$_tmpdir"
          exit 1
        fi
      else
        warn "No checksum entry for ${_archive} — skipping verification"
      fi
    else
      warn "Could not download checksums.txt — skipping checksum verification"
    fi

    tar -xzf "$_archive_path" -C "$_tmpdir"
    _found="$(find "$_tmpdir" -type f -name "supplychain-kit" | head -1)"
    if [ -n "$_found" ]; then
      BINARY_PATH="$_found"
      GIT_VERSION="v${_install_version}"
      SKT_INSTALLED=true
      info "Release binary ready (v${_install_version})"
    else
      warn "Binary not found inside archive — falling back to source build"
    fi
  else
    warn "Could not download release binary — falling back to source build"
  fi
  # _tmpdir cleaned up after install below
fi

if ! $SKT_INSTALLED; then
  # Fallback: build from source
  echo "  Building supplychain-kit from source..."
  cd "$SCRIPT_DIR"
  GIT_VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo "dev")"
  echo "  Version : ${GIT_VERSION}"
  echo "  Downloading Go modules..."
  go mod download
  mkdir -p "${SCRIPT_DIR}/bin"
  BINARY_PATH="${SCRIPT_DIR}/bin/${BINARY_NAME}"
  go build \
    -ldflags="-s -w -X main.version=${GIT_VERSION}" \
    -trimpath \
    -o "$BINARY_PATH" \
    ./cmd/supplychain-kit/...
  info "Binary built → ${BINARY_PATH} (${GIT_VERSION})"
fi

# ── step 4: install supplychain-kit binary to PATH ────────────────────────────
section "Step 4/5 — Installing supplychain-kit binary"

ensure_install_dir

# Prefer /usr/local/bin, fallback to INSTALL_DIR with PATH hint.
if [ -w "/usr/local/bin" ]; then
  copy_bin "$BINARY_PATH" "/usr/local/bin/${BINARY_NAME}"
  info "supplychain-kit installed → /usr/local/bin/${BINARY_NAME}"
elif check sudo; then
  sudo cp "$BINARY_PATH" "/usr/local/bin/${BINARY_NAME}"
  sudo chmod 0755 "/usr/local/bin/${BINARY_NAME}"
  info "supplychain-kit installed → /usr/local/bin/${BINARY_NAME} (via sudo)"
else
  copy_bin "$BINARY_PATH" "${INSTALL_DIR}/${BINARY_NAME}"
  info "supplychain-kit installed → ${INSTALL_DIR}/${BINARY_NAME}"
  if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    warn "${INSTALL_DIR} is not in PATH."
    warn "Add it: export PATH=\"\$PATH:${INSTALL_DIR}\""
    warn "Then:   source ${SHELL_PROFILE}"
  fi
fi

# Clean up temp dir from release download if used.
if ${SKT_INSTALLED} && [ -n "${_tmpdir:-}" ]; then
  rm -rf "$_tmpdir"
fi

# ── step 5: install Claude Code skill ─────────────────────────────────────────
section "Step 5/5 — Installing Claude Code skill"

SKILL_SRC="${SCRIPT_DIR}/.claude/skills/supplychain-kit"

if [ ! -d "$SKILL_SRC" ]; then
  warn "Skill source not found at $SKILL_SRC — skipping skill install"
else
  # Detect Claude Code home(s).
  detect_claude_homes() {
    local homes=()
    for d in "$HOME/.claude" "$HOME"/.claude-*; do
      if [ -d "$d" ] && { [ -f "$d/settings.json" ] || [ -f "$d/settings.local.json" ] || [ -d "$d/skills" ]; }; then
        homes+=("$d")
      fi
    done
    if [ ${#homes[@]} -eq 0 ] && [ -d "$HOME/.claude" ]; then
      homes=("$HOME/.claude")
    elif [ ${#homes[@]} -eq 0 ]; then
      # Claude Code not yet run — create default home.
      mkdir -p "$HOME/.claude/skills"
      homes=("$HOME/.claude")
    fi
    printf '%s\n' "${homes[@]}"
  }

  if [ -n "${CLAUDE_HOME:-}" ]; then
    IFS=',' read -ra SELECTED_HOMES <<< "$CLAUDE_HOME"
  else
    mapfile -t SELECTED_HOMES < <(detect_claude_homes)
  fi

  for claude_home in "${SELECTED_HOMES[@]}"; do
    skill_dir="${claude_home}/skills/supplychain-kit"
    agents_dir="${claude_home}/agents"
    mkdir -p "$(dirname "$skill_dir")" "$agents_dir"

    # Backup if exists and is not already our symlink.
    if [ -d "$skill_dir" ] && [ ! -L "$skill_dir" ]; then
      backup_base="${HOME}/.supplychain-kit/backups"
      mkdir -p "$backup_base"
      backup_name="skill.backup.$(date +%s)"
      mv "$skill_dir" "${backup_base}/${backup_name}"
      warn "Previous skill backed up → ${backup_base}/${backup_name}"
    elif [ -L "$skill_dir" ]; then
      rm "$skill_dir"
    fi

    if $USE_SYMLINK; then
      ln -sf "$SKILL_SRC" "$skill_dir"
      info "Skill → $skill_dir (symlink to repo — live edits enabled)"
    else
      mkdir -p "$skill_dir"
      cp -r "${SKILL_SRC}/"* "$skill_dir/"
      info "Skill → $skill_dir (copied)"
    fi

    # Install agents.
    agents_src="${SCRIPT_DIR}/.claude/agents"
    if [ -d "$agents_src" ]; then
      for agent in "${agents_src}/"*.md; do
        [ -f "$agent" ] || continue
        name="$(basename "$agent")"
        dst="${agents_dir}/${name}"
        # Avoid overwriting non-supplychain-kit agents.
        if [ -f "$dst" ] && ! grep -qi "supplychain-kit" "$dst" 2>/dev/null; then
          dst="${agents_dir}/supplychain-kit-${name}"
        fi
        cp "$agent" "$dst"
      done
      info "Agents → ${agents_dir}"
    fi

    # Write install metadata.
    cat > "${skill_dir}/.install-info.json" <<INFOEOF
{
  "installed_at": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "version": "${GIT_VERSION}",
  "method": "$([ "$USE_SYMLINK" = true ] && echo 'symlink' || echo 'copy')",
  "source": "${SCRIPT_DIR}",
  "claude_home": "${claude_home}"
}
INFOEOF
  done
fi

# ── step 6: verify ────────────────────────────────────────────────────────────
echo ""
echo "  Verifying installation..."
if command -v supplychain-kit >/dev/null 2>&1; then
  _ver_out="$(supplychain-kit --version 2>&1 || true)"
  info "supplychain-kit --version: ${_ver_out}"
else
  warn "supplychain-kit not found on PATH — check PATH setup above"
fi

if ! $SKIP_TEST; then
  echo "  Running go test ./... (pass --skip-test to skip)..."
  if go test ./... -count=1 2>&1 | tail -10; then
    info "All tests pass"
  else
    warn "Some tests failed — check output above"
  fi
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  supplychain-kit installed successfully!   ${RESET}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${RESET}"
echo ""
echo -e "${BOLD}Version:${RESET} ${GIT_VERSION}"
echo ""
echo -e "${BOLD}Scanner tools:${RESET}"
for bin in syft grype trivy osv-scanner gitleaks semgrep joern-parse joern-export pandoc; do
  if check "$bin" || [ -f "${INSTALL_DIR}/${bin}" ]; then
    echo -e "  ${GREEN}✓${RESET} ${bin}"
  else
    echo -e "  ${YELLOW}✗${RESET} ${bin}  (not installed — that scanner will be skipped)"
  fi
done
echo -e "  ${GREEN}✓${RESET} supplychain-kit"
echo ""
echo -e "${BOLD}Claude Code skill:${RESET}"
if [ -n "${SELECTED_HOMES[*]:-}" ]; then
  for h in "${SELECTED_HOMES[@]}"; do
    mode="$([ "$USE_SYMLINK" = true ] && echo 'symlink' || echo 'copy')"
    echo -e "  ${GREEN}✓${RESET} $h/skills/supplychain-kit  (${mode})"
  done
else
  echo -e "  ${YELLOW}✗${RESET} Skill not installed (skill source missing)"
fi

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
  echo ""
  echo -e "${YELLOW}${BOLD}PATH setup required:${RESET}"
  if [ "$(basename "${SHELL:-bash}")" = "fish" ]; then
    echo -e "  Run: ${CYAN}fish_add_path ${INSTALL_DIR}${RESET}"
  else
    echo -e "  Run: ${CYAN}echo 'export PATH=\"\$PATH:${INSTALL_DIR}\"' >> ${SHELL_PROFILE}${RESET}"
    echo -e "  Then reload: ${CYAN}source ${SHELL_PROFILE}${RESET}"
  fi
fi

echo ""
echo -e "${BOLD}Quick start:${RESET}"
echo -e "  1. Open a new terminal (or reload shell profile)"
echo -e "  2. In any project directory: ${CYAN}claude${RESET}"
echo -e "  3. Run the skill: ${CYAN}/supplychain-kit${RESET}"
echo -e "     → Follow the prompts to scan your repository"
echo ""
echo -e "  CLI direct usage:"
echo -e "  ${CYAN}supplychain-kit scan --repo /path/to/project --mode all${RESET}"
echo -e "  ${CYAN}supplychain-kit report --engagement myapp --format all${RESET}"
echo ""
echo -e "To uninstall: ${YELLOW}bash uninstall.sh${RESET}"
echo ""
