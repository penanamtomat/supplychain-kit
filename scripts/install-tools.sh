#!/usr/bin/env bash
# install-tools.sh — install all scanner binaries required by supplychain-kit
# Supports: Linux (apt/dnf/apk) and macOS (Homebrew)
# Usage: bash scripts/install-tools.sh

set -euo pipefail

SYFT_VERSION="${SYFT_VERSION:-v1.4.1}"
GRYPE_VERSION="${GRYPE_VERSION:-v0.111.0}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-v8.18.4}"
SEMGREP_VERSION="${SEMGREP_VERSION:-1.75.0}"

# ---------- helpers ----------

info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*" >&2; }
check() { command -v "$1" &>/dev/null; }

os() {
  case "$(uname -s)" in
    Darwin) echo "darwin" ;;
    Linux)  echo "linux"  ;;
    *)      echo "unsupported" ;;
  esac
}

arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) echo "unsupported" ;;
  esac
}

need_sudo() {
  [ "$(id -u)" -ne 0 ] && echo "sudo" || echo ""
}

install_bin() {
  local url="$1" name="$2"
  local tmp; tmp="$(mktemp -d)"
  info "Downloading $name from $url"
  curl -fsSL "$url" -o "$tmp/$name.tar.gz"
  tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
  $(need_sudo) install -m 0755 "$tmp/$name" /usr/local/bin/"$name"
  rm -rf "$tmp"
  info "$name installed → $(command -v "$name")"
}

# ---------- syft ----------

install_syft() {
  if check syft; then
    info "syft already installed: $(syft version 2>/dev/null | head -1)"
    return
  fi
  info "Installing syft ${SYFT_VERSION}..."
  if [[ "$(os)" == "darwin" ]] && check brew; then
    brew install anchore/grype/syft
  else
    local url="https://github.com/anchore/syft/releases/download/${SYFT_VERSION}/syft_${SYFT_VERSION#v}_$(os)_$(arch).tar.gz"
    install_bin "$url" syft
  fi
}

# ---------- grype ----------

install_grype() {
  if check grype; then
    info "grype already installed: $(grype version 2>/dev/null | head -1)"
    return
  fi
  info "Installing grype ${GRYPE_VERSION}..."
  if [[ "$(os)" == "darwin" ]] && check brew; then
    brew install anchore/grype/grype
  else
    local url="https://github.com/anchore/grype/releases/download/${GRYPE_VERSION}/grype_${GRYPE_VERSION#v}_$(os)_$(arch).tar.gz"
    install_bin "$url" grype
  fi
}

# ---------- gitleaks ----------

install_gitleaks() {
  if check gitleaks; then
    info "gitleaks already installed: $(gitleaks version 2>/dev/null)"
    return
  fi
  info "Installing gitleaks ${GITLEAKS_VERSION}..."
  if [[ "$(os)" == "darwin" ]] && check brew; then
    brew install gitleaks
  else
    local url="https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_$(os)_$(arch).tar.gz"
    install_bin "$url" gitleaks
  fi
}

# ---------- semgrep ----------

install_semgrep() {
  if check semgrep; then
    info "semgrep already installed: $(semgrep --version 2>/dev/null)"
    return
  fi
  info "Installing semgrep ${SEMGREP_VERSION}..."
  if check pip3; then
    pip3 install --quiet "semgrep==${SEMGREP_VERSION}"
  elif check pip; then
    pip install --quiet "semgrep==${SEMGREP_VERSION}"
  elif [[ "$(os)" == "darwin" ]] && check brew; then
    brew install semgrep
  else
    warn "pip/pip3 not found. Install Python 3 then run: pip3 install semgrep==${SEMGREP_VERSION}"
    return 1
  fi
  info "semgrep installed → $(command -v semgrep)"
}

# ---------- joern (optional) ----------

install_joern() {
  if check joern-parse; then
    info "joern already installed: $(joern-parse --version 2>/dev/null | head -1)"
    return
  fi
  info "Joern is optional and requires Java 11+. See https://docs.joern.io/installation/"
  info "Skipping automatic joern install. Reachability analysis will be unavailable."
}

# ---------- verify ----------

verify() {
  local ok=1
  for bin in syft grype gitleaks semgrep; do
    if check "$bin"; then
      info "✓ $bin"
    else
      warn "✗ $bin — not found"
      ok=0
    fi
  done
  if check joern-parse; then
    info "✓ joern-parse (optional)"
  else
    info "- joern-parse not installed (optional — needed for reachability analysis)"
  fi
  return $ok
}

# ---------- main ----------

main() {
  if [[ "$(os)" == "unsupported" ]]; then
    warn "Unsupported OS: $(uname -s). Install tools manually."
    exit 1
  fi

  install_syft
  install_grype
  install_gitleaks
  install_semgrep
  install_joern

  echo ""
  info "=== Verification ==="
  verify && info "All required tools installed successfully." || {
    warn "Some tools are missing. See messages above."
    exit 1
  }
}

main "$@"
