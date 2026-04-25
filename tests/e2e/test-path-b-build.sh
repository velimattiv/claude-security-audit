#!/usr/bin/env bash
#
# test-path-b-build.sh — smoke-test the Path B container build.
#
# Validates that scripts/Dockerfile.audit builds cleanly and the
# resulting image's preflight passes. This is the regression gate
# for the recommended scanner-isolation path; without it, a broken
# Dockerfile (e.g. PEP 668 pip failures, base-image checksum drift,
# scanner version pin breakage) ships silently because the deep
# audit E2E (run-e2e-test.sh) only exercises the host-installed
# scanner path.
#
# Should be cheap (~3-5 min on first build, ~30s on rebuild with
# Docker/Podman layer cache). Fails fast on any of:
#   - container runtime (podman/docker) missing
#   - Dockerfile.audit build error
#   - preflight reports 0 scanners present
#   - the container can't see /target as a read-only mount
#
# Usage:
#   bash tests/e2e/test-path-b-build.sh           # default
#   E2E_PATH_B_RUNTIME=docker bash tests/...      # override runtime
#
# Exit codes:
#   0  PASS
#   1  build failed
#   2  preflight failed
#   3  runtime missing

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WRAPPER="$REPO_ROOT/scripts/run-audit-in-container.sh"

echo "=== Path B build smoke test ==="
echo "  Repo:    $REPO_ROOT"
echo "  Wrapper: $WRAPPER"

# --- 1. Runtime detection --------------------------------------------------

RUNTIME="${E2E_PATH_B_RUNTIME:-}"
if [ -z "$RUNTIME" ]; then
  if command -v podman >/dev/null 2>&1; then
    RUNTIME=podman
  elif command -v docker >/dev/null 2>&1; then
    RUNTIME=docker
  else
    echo "ERROR: neither podman nor docker on PATH. Path B requires one." >&2
    exit 3
  fi
fi
echo "  Runtime: $RUNTIME ($(${RUNTIME} --version 2>&1 | head -1))"

# --- 2. Build --------------------------------------------------------------

echo
echo "[1/3] Building Path B image (this may take 3-5 min on first run)..."
START_BUILD=$(date +%s)
if ! bash "$WRAPPER" --build; then
  echo "FAIL: build failed. See the output above for the failing step." >&2
  exit 1
fi
ELAPSED_BUILD=$(( $(date +%s) - START_BUILD ))
echo "  built in ${ELAPSED_BUILD}s"

# --- 3. Preflight ----------------------------------------------------------

echo
echo "[2/3] Running preflight in the built image..."
PREFLIGHT_OUTPUT=$(bash "$WRAPPER" preflight 2>&1) || {
  echo "FAIL: preflight exited non-zero." >&2
  echo "$PREFLIGHT_OUTPUT" >&2
  exit 2
}
echo "$PREFLIGHT_OUTPUT"

# Count "OK" lines from install-scanners.sh --check inside the container.
# At least 5 of the 6 scanners should be present — install-scanners.sh
# prints `[OK]` per discovered scanner.
OK_COUNT=$(echo "$PREFLIGHT_OUTPUT" | grep -c "\[OK\]" || true)
if [ "$OK_COUNT" -lt 5 ]; then
  echo "FAIL: preflight reports $OK_COUNT scanners present (expected >=5)." >&2
  exit 2
fi
echo "  $OK_COUNT scanners present in container"

# --- 4. PASS ---------------------------------------------------------------

echo
echo "[3/3] PASS — Path B build + preflight both green."
echo "  Build time: ${ELAPSED_BUILD}s"
echo "  Scanners:   $OK_COUNT/6"
