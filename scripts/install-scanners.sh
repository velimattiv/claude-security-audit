#!/usr/bin/env bash
# scripts/install-scanners.sh — install the /security-audit scanner bundle
# Supports: macOS (Homebrew), Debian/Ubuntu (apt), Fedora (dnf), Arch (pacman).
# Full implementation lands in M3. M1 ships this stub so milestone PRs and
# documentation can reference a stable path and the preflight check has
# something actionable to point users at.
#
# Usage:
#   scripts/install-scanners.sh           # install the required set
#   scripts/install-scanners.sh --check   # report what's already installed
#   scripts/install-scanners.sh --help
#
# Design constraints (see docs/V2-SCOPE.md):
#   - bash 3.2+ compatible (macOS default).
#   - No sudo unless the OS requires it for the chosen package manager.
#   - Never hard-fail: any missing tool becomes a warning so the skill can
#     still run in degraded mode.
#
# TODO(M3): implement per-OS install, version pinning, and --check mode.

set -u

REQUIRED_TOOLS="semgrep osv-scanner gitleaks trufflehog trivy hadolint"
OPTIONAL_TOOLS="brakeman checkov kube-linter govulncheck psalm zizmor"

usage() {
  cat <<'USAGE'
install-scanners.sh — install the /security-audit scanner bundle

Options:
  --check     Report which scanners are present; do not install.
  --help      Show this message.
  (no args)   Install the required scanner set for the detected OS.

Required scanners:  semgrep osv-scanner gitleaks trufflehog trivy hadolint
Optional scanners:  brakeman checkov kube-linter govulncheck psalm zizmor

Full implementation: milestone M3. See docs/V2-SCOPE.md.
USAGE
}

check_only() {
  echo "=== /security-audit scanner preflight ==="
  echo
  printf "Required:\n"
  for tool in $REQUIRED_TOOLS; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf "  [OK]      %s (%s)\n" "$tool" "$(command -v "$tool")"
    else
      printf "  [MISSING] %s\n" "$tool"
    fi
  done
  echo
  printf "Optional:\n"
  for tool in $OPTIONAL_TOOLS; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf "  [OK]      %s (%s)\n" "$tool" "$(command -v "$tool")"
    else
      printf "  [absent]  %s\n" "$tool"
    fi
  done
}

case "${1:-}" in
  --help|-h) usage; exit 0 ;;
  --check)   check_only; exit 0 ;;
  "")
    echo "install-scanners.sh: M3 milestone pending — full installer not yet implemented." >&2
    echo "Run with --check to see current scanner state." >&2
    echo "See docs/V2-SCOPE.md for the full spec." >&2
    exit 2
    ;;
  *) usage; exit 1 ;;
esac
