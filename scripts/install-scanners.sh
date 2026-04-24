#!/usr/bin/env bash
# scripts/install-scanners.sh — install the /security-audit scanner bundle.
#
# Supports macOS (Homebrew), Debian/Ubuntu (apt), Fedora (dnf), Arch (pacman).
# Windows is not supported — run inside WSL or a container.
#
# Usage:
#   scripts/install-scanners.sh              # install required set
#   scripts/install-scanners.sh --check      # report current state
#   scripts/install-scanners.sh --with-optional
#   scripts/install-scanners.sh --help
#
# Design constraints (see docs/V2-SCOPE.md):
#   - bash 3.2+ compatible (macOS default). No associative arrays.
#   - Never hard-fail: unreachable tools become warnings.
#   - No sudo unless the OS package manager requires it. Honors SUDO env var.
#   - Download URLs sourced from vendor releases; no curl-to-sh without
#     printing the URL first.
#
# The skill calls this script; it can also be run standalone by users.

set -u
REQUIRED_TOOLS="semgrep osv-scanner gitleaks trufflehog trivy hadolint"
OPTIONAL_TOOLS="brakeman checkov kube-linter grype govulncheck psalm zizmor"

# --- logging helpers ---------------------------------------------------------
log()  { printf "[install-scanners] %s\n" "$*"; }
warn() { printf "[install-scanners] WARN: %s\n" "$*" >&2; }
err()  { printf "[install-scanners] ERROR: %s\n" "$*" >&2; }

# --- OS detection ------------------------------------------------------------
OS=""
case "$(uname -s)" in
  Darwin) OS="macos" ;;
  Linux)
    if command -v apt-get >/dev/null 2>&1; then OS="debian"; fi
    if command -v dnf     >/dev/null 2>&1; then OS="fedora"; fi
    if command -v pacman  >/dev/null 2>&1; then OS="arch";   fi
    if [ -z "$OS" ]; then OS="linux-generic"; fi
    ;;
  *) OS="unsupported" ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) warn "Unrecognized arch $ARCH — binaries may fail to download" ;;
esac

# Allow callers to override the install prefix. Default /usr/local/bin (or
# $HOME/.local/bin if the user can't write to /usr/local).
PREFIX="${PREFIX:-}"
if [ -z "$PREFIX" ]; then
  if [ -w "/usr/local/bin" ]; then
    PREFIX="/usr/local/bin"
    SUDO="${SUDO:-}"
  else
    PREFIX="$HOME/.local/bin"
    mkdir -p "$PREFIX"
    SUDO=""
  fi
fi

# --- usage -------------------------------------------------------------------
usage() {
  cat <<'USAGE'
install-scanners.sh — install the /security-audit scanner bundle

Options:
  --check             Report which scanners are present; do not install.
  --with-optional     Also install optional scanners (by detected context).
  --help              Show this message.
  (no args)           Install the required scanner set.

Required:  semgrep osv-scanner gitleaks trufflehog trivy hadolint
Optional:  brakeman checkov kube-linter grype govulncheck psalm zizmor

Environment:
  PREFIX   Install location (default /usr/local/bin or ~/.local/bin).
  SUDO     Prefix for package-manager commands (default: sudo if non-root).

Supported OS: macOS (Homebrew), Debian/Ubuntu (apt), Fedora (dnf), Arch (pacman).
Windows: not supported; run inside WSL or a container.

See docs/V2-SCOPE.md for the full spec.
USAGE
}

# --- --check mode ------------------------------------------------------------
check_only() {
  echo "=== /security-audit scanner preflight ==="
  echo "OS: $OS   Arch: $ARCH   Prefix: $PREFIX"
  echo
  printf "Required:\n"
  for tool in $REQUIRED_TOOLS; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf "  [OK]      %-14s (%s)\n" "$tool" "$(command -v "$tool")"
    else
      printf "  [MISSING] %-14s\n" "$tool"
    fi
  done
  echo
  printf "Optional:\n"
  for tool in $OPTIONAL_TOOLS; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf "  [OK]      %-14s (%s)\n" "$tool" "$(command -v "$tool")"
    else
      printf "  [absent]  %-14s\n" "$tool"
    fi
  done
}

# --- install routines --------------------------------------------------------
# Each `install_<tool>` routine returns 0 on success, non-zero otherwise.
# If the tool is already installed, return 0 without doing anything.

need_sudo() {
  if [ -n "${SUDO:-}" ]; then return; fi
  if [ "$(id -u)" = "0" ]; then SUDO=""; else SUDO="sudo"; fi
}

install_semgrep() {
  command -v semgrep >/dev/null 2>&1 && return 0
  log "Installing semgrep via pip..."
  if command -v pipx >/dev/null 2>&1; then
    pipx install semgrep && return 0
  fi
  if command -v pip3 >/dev/null 2>&1; then
    pip3 install --user semgrep || pip3 install --break-system-packages semgrep
    return $?
  fi
  warn "semgrep: pip3 and pipx both missing; install Python first"
  return 1
}

download_binary() {
  # download_binary <url> <dest>
  local url="$1" dest="$2"
  log "Downloading $(basename "$dest") from $url"
  if command -v curl >/dev/null 2>&1; then
    curl -sSfL "$url" -o "$dest"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
  else
    err "neither curl nor wget available"
    return 1
  fi
}

install_osv_scanner() {
  command -v osv-scanner >/dev/null 2>&1 && return 0
  local v="1.9.2"
  local os="linux"; [ "$OS" = "macos" ] && os="darwin"
  local url="https://github.com/google/osv-scanner/releases/download/v${v}/osv-scanner_${os}_${ARCH}"
  log "Installing osv-scanner v$v..."
  download_binary "$url" "$PREFIX/osv-scanner" || return 1
  chmod +x "$PREFIX/osv-scanner"
}

install_gitleaks() {
  command -v gitleaks >/dev/null 2>&1 && return 0
  local v="8.21.2"
  local os="linux"; [ "$OS" = "macos" ] && os="darwin"
  local arch_s="$ARCH"; [ "$ARCH" = "amd64" ] && arch_s="x64"
  local tarball="/tmp/gitleaks.tgz"
  local url="https://github.com/gitleaks/gitleaks/releases/download/v${v}/gitleaks_${v}_${os}_${arch_s}.tar.gz"
  log "Installing gitleaks v$v..."
  download_binary "$url" "$tarball" || return 1
  tar -xzf "$tarball" -C /tmp gitleaks && mv /tmp/gitleaks "$PREFIX/gitleaks"
  rm -f "$tarball"
}

install_trufflehog() {
  command -v trufflehog >/dev/null 2>&1 && return 0
  log "Installing trufflehog via vendor installer (review at trufflesecurity/trufflehog before running on production hosts)..."
  if command -v curl >/dev/null 2>&1; then
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$PREFIX"
  else
    err "trufflehog install requires curl"
    return 1
  fi
}

install_trivy() {
  command -v trivy >/dev/null 2>&1 && return 0
  log "Installing trivy..."
  if [ "$OS" = "macos" ] && command -v brew >/dev/null 2>&1; then
    brew install trivy && return 0
  fi
  if command -v curl >/dev/null 2>&1; then
    curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$PREFIX"
    return $?
  fi
  err "trivy install requires curl"; return 1
}

install_hadolint() {
  command -v hadolint >/dev/null 2>&1 && return 0
  local v="2.12.0"
  local os="Linux"; [ "$OS" = "macos" ] && os="Darwin"
  local url="https://github.com/hadolint/hadolint/releases/download/v${v}/hadolint-${os}-x86_64"
  [ "$ARCH" = "arm64" ] && warn "hadolint lacks official arm64 binary; skipping" && return 1
  log "Installing hadolint v$v..."
  download_binary "$url" "$PREFIX/hadolint" || return 1
  chmod +x "$PREFIX/hadolint"
}

# Optional installers are delegated to their ecosystems and left as terse
# hints; they are gated at runtime by Phase 0 detection, so installing them
# in a one-shot bundle is overkill for most users.

install_optional_hints() {
  cat <<'HINTS'

--- Optional scanner install hints ---------------------------------------

  brakeman      (gate: Rails)       gem install brakeman
  checkov       (gate: Terraform)   pip install checkov
  kube-linter   (gate: Kubernetes)  https://github.com/stackrox/kube-linter/releases
  grype         (gate: Dockerfile)  https://github.com/anchore/grype/releases
  govulncheck   (gate: Go)          go install golang.org/x/vuln/cmd/govulncheck@latest
  psalm         (gate: PHP)         composer require --dev vimeo/psalm
  zizmor        (gate: GHA)         cargo install zizmor  OR  download binary
HINTS
}

# --- main --------------------------------------------------------------------
install_all() {
  need_sudo
  log "Install prefix: $PREFIX"
  log "OS: $OS   Arch: $ARCH"
  echo
  local failed=0
  for tool in semgrep osv-scanner gitleaks trufflehog trivy hadolint; do
    local fn="install_$(echo "$tool" | tr '-' '_')"
    if $fn; then
      log "  $tool OK"
    else
      warn "  $tool failed to install — the skill will run in degraded mode without it"
      failed=$((failed + 1))
    fi
    echo
  done

  if [ "$failed" -gt 0 ]; then
    warn "$failed scanner(s) failed to install."
  else
    log "All required scanners installed."
  fi

  check_only

  if [ "${1:-}" = "--with-optional" ]; then
    install_optional_hints
  fi
}

case "${1:-}" in
  --help|-h)         usage; exit 0 ;;
  --check)           check_only; exit 0 ;;
  --with-optional)   install_all --with-optional; exit 0 ;;
  "")                install_all; exit 0 ;;
  *) usage; exit 1 ;;
esac
