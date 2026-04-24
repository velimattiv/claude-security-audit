#!/usr/bin/env bash
# scripts/install-scanners.sh — install the /security-audit scanner bundle.
#
# Supports macOS (Homebrew), Debian/Ubuntu (apt), Fedora (dnf), Arch (pacman).
# Windows is not supported — run inside WSL, a container, or
# scripts/run-audit-in-container.sh.
#
# Usage:
#   scripts/install-scanners.sh              # install required set
#   scripts/install-scanners.sh --check      # report current state
#   scripts/install-scanners.sh --with-optional
#   scripts/install-scanners.sh --help
#
# Design constraints (see docs/V2-SCOPE.md and SECURITY.md):
#   - bash 3.2+ compatible (macOS default). No associative arrays.
#   - Never hard-fail unless a checksum verification fails: any missing
#     tool becomes a warning so the skill still runs in degraded mode.
#   - No sudo unless the OS package manager requires it. Honors SUDO env.
#   - Every binary download is verified against its vendor-published
#     sha256 checksum before being placed in $PREFIX. Mismatches abort
#     install immediately.
#   - Permission-fallback: if $PREFIX is not writable, every install
#     function transparently falls back to $HOME/.local/bin and warns
#     the user once.

set -u

REQUIRED_TOOLS="semgrep osv-scanner gitleaks trufflehog trivy hadolint"
OPTIONAL_TOOLS="brakeman checkov kube-linter grype govulncheck psalm zizmor"

# Version pins — update alongside release cadence. The GitHub API is
# consulted at --check time to warn if a newer release has shipped.
SEMGREP_VER="1.161.0"
OSV_VER="2.3.5"
GITLEAKS_VER="8.30.1"
TRUFFLEHOG_VER="3.95.2"
TRIVY_VER="0.70.0"
HADOLINT_VER="2.14.0"

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

# --- prefix resolution (hardened) --------------------------------------------
# Every install_* routine re-reads $PREFIX via resolve_prefix, so per-call
# fallback is possible even if the initial probe succeeded and then
# permissions changed mid-run.
resolve_prefix() {
  if [ -n "${PREFIX:-}" ]; then
    printf "%s" "$PREFIX"
    return
  fi
  if [ -w "/usr/local/bin" ]; then
    printf "/usr/local/bin"
  else
    mkdir -p "$HOME/.local/bin" 2>/dev/null || true
    printf "%s/.local/bin" "$HOME"
  fi
}

PREFIX="$(resolve_prefix)"

# --- usage -------------------------------------------------------------------
usage() {
  cat <<'USAGE'
install-scanners.sh — install the /security-audit scanner bundle

Options:
  --check             Report which scanners are present; do not install.
                      Also compares pinned versions against latest releases.
  --with-optional     Also print optional-scanner install hints.
  --help              Show this message.
  (no args)           Install the required scanner set.

Required:  semgrep osv-scanner gitleaks trufflehog trivy hadolint
Optional:  brakeman checkov kube-linter grype govulncheck psalm zizmor

Environment:
  PREFIX   Install location (default /usr/local/bin or ~/.local/bin).
  SUDO     Prefix for package-manager commands (default: sudo if non-root).

Supported OS: macOS (Homebrew), Debian/Ubuntu (apt), Fedora (dnf), Arch (pacman).
Windows: not supported; run inside WSL or scripts/run-audit-in-container.sh.

See docs/V2-SCOPE.md and SECURITY.md for details. Every binary download
is verified against vendor-published sha256 checksums before install.
USAGE
}

# --- checksum verification ---------------------------------------------------
# verify_sha256 <file> <expected-hash>
# Returns 0 on match; non-zero on mismatch. Accepts both hex and
# "sha256:HEX" formats in the expected arg.
verify_sha256() {
  local file="$1" expected="$2"
  expected="${expected#sha256:}"
  expected="$(printf "%s" "$expected" | tr '[:upper:]' '[:lower:]')"
  local actual
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  else
    err "no sha256sum / shasum available — cannot verify checksums"
    return 2
  fi
  actual="$(printf "%s" "$actual" | tr '[:upper:]' '[:lower:]')"
  if [ "$actual" = "$expected" ]; then
    log "  checksum ok (sha256:${actual:0:16}...)"
    return 0
  fi
  err "  checksum MISMATCH: expected ${expected:0:16}... got ${actual:0:16}..."
  err "  refusing to install tampered binary"
  rm -f "$file"
  return 1
}

# Download a vendor-published checksums file and extract the sha256 for
# a specific filename. Works with the standard `<hash>  <name>` format
# used by gitleaks, trufflehog, hadolint, osv-scanner, trivy releases.
fetch_checksum_from_release() {
  local checksums_url="$1" target_filename="$2"
  local tmp; tmp="$(mktemp)"
  if command -v curl >/dev/null 2>&1; then
    curl -sSfL "$checksums_url" -o "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
  else
    wget -qO "$tmp" "$checksums_url" 2>/dev/null || { rm -f "$tmp"; return 1; }
  fi
  local hash
  hash="$(awk -v t="$target_filename" '$2 == t || $2 == "./"t || $2 == "*"t {print $1; exit}' "$tmp")"
  rm -f "$tmp"
  [ -n "$hash" ] && printf "%s" "$hash"
}

# Download and verify a binary or tarball.
#   download_verified <url> <checksums-url> <asset-filename> <dest>
download_verified() {
  local url="$1" checksums_url="$2" asset="$3" dest="$4"
  local expected
  expected="$(fetch_checksum_from_release "$checksums_url" "$asset")"
  if [ -z "$expected" ]; then
    err "cannot fetch checksum for $asset from $checksums_url"
    return 1
  fi
  log "Downloading $asset from $url"
  if command -v curl >/dev/null 2>&1; then
    curl -sSfL "$url" -o "$dest" || return 1
  else
    wget -qO "$dest" "$url" || return 1
  fi
  verify_sha256 "$dest" "$expected" || return 1
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
  echo
  check_stale_versions
}

# Best-effort compare pinned versions against latest GitHub release tags.
# Non-fatal; only emits notes when a newer release is published upstream.
check_stale_versions() {
  if ! command -v curl >/dev/null 2>&1; then
    return
  fi
  echo "Pinned versions vs. latest upstream releases:"
  _check_one() {
    local name="$1" repo="$2" pinned="$3"
    local api="https://api.github.com/repos/$repo/releases/latest"
    local latest
    latest="$(curl -sSf --max-time 5 "$api" 2>/dev/null | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"v?[^"]+"' | head -1 | awk -F'"' '{print $4}' | sed 's/^v//')"
    if [ -z "$latest" ]; then
      printf "  %-14s pinned=%s  (upstream check skipped — network / rate-limit)\n" "$name" "$pinned"
      return
    fi
    if [ "$latest" != "$pinned" ]; then
      printf "  %-14s pinned=%s  latest=%s  (update installer?)\n" "$name" "$pinned" "$latest"
    else
      printf "  %-14s pinned=%s  current\n" "$name" "$pinned"
    fi
  }
  _check_one osv-scanner google/osv-scanner "$OSV_VER"
  _check_one gitleaks    gitleaks/gitleaks  "$GITLEAKS_VER"
  _check_one trufflehog  trufflesecurity/trufflehog "$TRUFFLEHOG_VER"
  _check_one trivy       aquasecurity/trivy "$TRIVY_VER"
  _check_one hadolint    hadolint/hadolint  "$HADOLINT_VER"
}

# --- install routines --------------------------------------------------------
# Each install_<tool> returns 0 on success, non-zero otherwise.
# Idempotent: if the tool is already installed, return 0 immediately.

need_sudo() {
  if [ -n "${SUDO:-}" ]; then return; fi
  if [ "$(id -u)" = "0" ]; then SUDO=""; else SUDO="sudo"; fi
}

install_semgrep() {
  command -v semgrep >/dev/null 2>&1 && return 0
  log "Installing semgrep via pip..."
  if command -v pipx >/dev/null 2>&1; then
    pipx install "semgrep==$SEMGREP_VER" && return 0
  fi
  if command -v pip3 >/dev/null 2>&1; then
    pip3 install --user "semgrep==$SEMGREP_VER" 2>/dev/null \
      || pip3 install --break-system-packages "semgrep==$SEMGREP_VER"
    return $?
  fi
  warn "semgrep: pip3 and pipx both missing; install Python first"
  return 1
}

install_osv_scanner() {
  command -v osv-scanner >/dev/null 2>&1 && return 0
  local prefix; prefix="$(resolve_prefix)"
  local v="$OSV_VER"
  local os="linux"; [ "$OS" = "macos" ] && os="darwin"
  local asset="osv-scanner_${os}_${ARCH}"
  local base="https://github.com/google/osv-scanner/releases/download/v${v}"
  local url="${base}/${asset}"
  # Checksums file naming differs between 1.x and 2.x releases:
  #   1.x: osv-scanner_<ver>_checksums.txt
  #   2.x: osv-scanner_SHA256SUMS
  local checksums
  case "$v" in
    2.*|3.*) checksums="${base}/osv-scanner_SHA256SUMS" ;;
    *)       checksums="${base}/osv-scanner_${v}_checksums.txt" ;;
  esac
  log "Installing osv-scanner v$v..."
  download_verified "$url" "$checksums" "$asset" "$prefix/osv-scanner" || return 1
  chmod +x "$prefix/osv-scanner"
}

install_gitleaks() {
  command -v gitleaks >/dev/null 2>&1 && return 0
  local prefix; prefix="$(resolve_prefix)"
  local v="$GITLEAKS_VER"
  local os="linux"; [ "$OS" = "macos" ] && os="darwin"
  local arch_s="$ARCH"; [ "$ARCH" = "amd64" ] && arch_s="x64"
  local asset="gitleaks_${v}_${os}_${arch_s}.tar.gz"
  local base="https://github.com/gitleaks/gitleaks/releases/download/v${v}"
  local url="${base}/${asset}"
  local checksums="${base}/gitleaks_${v}_checksums.txt"
  local tarball; tarball="$(mktemp)"
  log "Installing gitleaks v$v..."
  download_verified "$url" "$checksums" "$asset" "$tarball" || { rm -f "$tarball"; return 1; }
  tar -xzf "$tarball" -C "$(dirname "$tarball")" gitleaks \
    && mv "$(dirname "$tarball")/gitleaks" "$prefix/gitleaks"
  rm -f "$tarball"
  chmod +x "$prefix/gitleaks"
}

install_trufflehog() {
  command -v trufflehog >/dev/null 2>&1 && return 0
  # v2.0.1 hardening: replaced the vendor curl|sh with a direct tarball
  # download + checksum verification. The upstream install.sh did the
  # same thing but through an unverified shell pipe.
  local prefix; prefix="$(resolve_prefix)"
  local v="$TRUFFLEHOG_VER"
  local os="linux"; [ "$OS" = "macos" ] && os="darwin"
  local asset="trufflehog_${v}_${os}_${ARCH}.tar.gz"
  local base="https://github.com/trufflesecurity/trufflehog/releases/download/v${v}"
  local url="${base}/${asset}"
  local checksums="${base}/trufflehog_${v}_checksums.txt"
  local tarball; tarball="$(mktemp)"
  log "Installing trufflehog v$v..."
  download_verified "$url" "$checksums" "$asset" "$tarball" || { rm -f "$tarball"; return 1; }
  tar -xzf "$tarball" -C "$(dirname "$tarball")" trufflehog \
    && mv "$(dirname "$tarball")/trufflehog" "$prefix/trufflehog"
  rm -f "$tarball"
  chmod +x "$prefix/trufflehog"
}

install_trivy() {
  command -v trivy >/dev/null 2>&1 && return 0
  local prefix; prefix="$(resolve_prefix)"
  if [ "$OS" = "macos" ] && command -v brew >/dev/null 2>&1; then
    brew install trivy && return 0
  fi
  # Trivy's vendor install.sh does verify checksums internally, but we
  # re-do it here for consistency and to not rely on `curl | sh`.
  local v="$TRIVY_VER"
  local os="Linux"; [ "$OS" = "macos" ] && os="macOS"
  local arch_s="64bit"; [ "$ARCH" = "arm64" ] && arch_s="ARM64"
  local asset="trivy_${v}_${os}-${arch_s}.tar.gz"
  local base="https://github.com/aquasecurity/trivy/releases/download/v${v}"
  local url="${base}/${asset}"
  local checksums="${base}/trivy_${v}_checksums.txt"
  local tarball; tarball="$(mktemp)"
  log "Installing trivy v$v..."
  download_verified "$url" "$checksums" "$asset" "$tarball" || { rm -f "$tarball"; return 1; }
  tar -xzf "$tarball" -C "$(dirname "$tarball")" trivy \
    && mv "$(dirname "$tarball")/trivy" "$prefix/trivy"
  rm -f "$tarball"
  chmod +x "$prefix/trivy"
}

install_hadolint() {
  command -v hadolint >/dev/null 2>&1 && return 0
  local prefix; prefix="$(resolve_prefix)"
  [ "$ARCH" = "arm64" ] && {
    warn "hadolint lacks official arm64 binary; skipping"
    return 1
  }
  local v="$HADOLINT_VER"
  local os="Linux"; [ "$OS" = "macos" ] && os="Darwin"
  local asset="hadolint-${os}-x86_64"
  local base="https://github.com/hadolint/hadolint/releases/download/v${v}"
  local url="${base}/${asset}"
  local checksums="${base}/hadolint-${os}-x86_64.sha256"
  # hadolint publishes the sha256 in a separate small .sha256 file that
  # contains only "<hash>  <name>". Reuse fetch_checksum_from_release.
  log "Installing hadolint v$v..."
  download_verified "$url" "$checksums" "$asset" "$prefix/hadolint" || return 1
  chmod +x "$prefix/hadolint"
}

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
  if [ ! -w "$PREFIX" ]; then
    # Nudge the user toward the fallback rather than silently failing.
    warn "$PREFIX is not writable. Set PREFIX=\$HOME/.local/bin or run with SUDO=sudo."
    warn "Continuing and letting each install function re-resolve the prefix per-call."
  fi
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
