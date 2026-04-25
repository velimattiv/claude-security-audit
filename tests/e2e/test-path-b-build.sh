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

# --- 3. DinD bind-mount probe ----------------------------------------------
#
# Some nested-docker setups (CI runners, dev environments running
# inside another container) block bind mounts entirely. The wrapper's
# preflight + scan stages both need bind mounts. Probe before invoking
# either stage; if mounts don't work, skip those stages with a clear
# PASS-WITH-LIMITATIONS exit rather than reporting a misleading FAIL.

echo
echo "[2/4] Probing bind-mount support..."
PROBE_DIR=$(mktemp -d)
echo "test" > "$PROBE_DIR/probe.txt"
if ! "$RUNTIME" run --rm -v "$PROBE_DIR":/probe:ro alpine \
    cat /probe/probe.txt >/dev/null 2>&1; then
  rm -rf "$PROBE_DIR"
  echo "  SKIP: bind mounts blocked in this environment (DinD or restricted namespace)."
  echo
  echo "[3/4] Preflight — SKIPPED (preflight needs bind mounts)."
  echo "[4/4] End-to-end scan — SKIPPED (scan needs bind mounts)."
  echo
  echo "PASS-WITH-LIMITATIONS — build green; preflight + scan unverifiable here."
  echo "  Build time: ${ELAPSED_BUILD}s"
  echo "  Re-run on a non-nested host for full Path B validation."
  exit 0
fi
rm -rf "$PROBE_DIR"
echo "  bind mounts work."

# --- 3.1. Preflight --------------------------------------------------------

echo
echo "[3/4] Running preflight in the built image..."
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

# --- 4. End-to-end scan execution ------------------------------------------
#
# Build + preflight prove the image is buildable and scanners are
# present inside. They do NOT prove the wrapper's execution model
# works end-to-end (bind mounts resolved, output lands on host disk,
# scanner produces parseable SARIF). v2.0.5 added this stage to close
# that gap — the v2.0.3 hadolint case-mismatch bug shipped silently
# because no test ever ran a real scanner through the wrapper.
#
# DinD detection: in some nested-docker setups (this CI / the dev
# environment we noticed) bind mounts are blocked by the outer
# daemon's namespace policies. Probe with a minimal mount; if the
# probe fails, skip the scan stage with a clear message rather than
# pretending we validated end-to-end.

echo
echo "[4/4] Running gitleaks through the wrapper against this repo..."
START_SCAN=$(date +%s)

# Re-use this repo as the audit target — has a known-clean
# .git history and no real secrets, so gitleaks should run quickly
# and produce a SARIF doc with results=[] (or at most test-fixture
# false positives we can tolerate).
cd "$REPO_ROOT"
mkdir -p .claude-audit/current/phase-04-scanners

# Snapshot pre-existing gitleaks.sarif so we can detect whether the
# wrapper actually wrote a fresh one.
PRE_MTIME=""
if [ -f .claude-audit/current/phase-04-scanners/gitleaks.sarif ]; then
  PRE_MTIME=$(stat -c %Y .claude-audit/current/phase-04-scanners/gitleaks.sarif 2>/dev/null \
             || stat -f %m .claude-audit/current/phase-04-scanners/gitleaks.sarif 2>/dev/null \
             || echo "")
fi

if ! bash "$WRAPPER" scan gitleaks 2>&1; then
  echo "FAIL: wrapper gitleaks scan exited non-zero." >&2
  exit 2
fi

ELAPSED_SCAN=$(( $(date +%s) - START_SCAN ))
SARIF=.claude-audit/current/phase-04-scanners/gitleaks.sarif
if [ ! -f "$SARIF" ]; then
  echo "FAIL: wrapper produced no SARIF at $SARIF." >&2
  exit 2
fi
NEW_MTIME=$(stat -c %Y "$SARIF" 2>/dev/null || stat -f %m "$SARIF" 2>/dev/null || echo "")
if [ -n "$PRE_MTIME" ] && [ "$NEW_MTIME" = "$PRE_MTIME" ]; then
  echo "FAIL: SARIF mtime unchanged — wrapper didn't actually write it." >&2
  exit 2
fi

# Validate SARIF structure: must parse, must have .runs[] array.
if command -v jq >/dev/null 2>&1; then
  if ! jq -e '.runs | type == "array"' "$SARIF" >/dev/null 2>&1; then
    echo "FAIL: $SARIF doesn't parse as SARIF (no .runs array)." >&2
    exit 2
  fi
  RESULTS_COUNT=$(jq '[.runs[].results // [] | length] | add // 0' "$SARIF")
  echo "  scan completed in ${ELAPSED_SCAN}s, $RESULTS_COUNT result(s)"
else
  python3 -c "
import json, sys
d = json.load(open('$SARIF'))
assert isinstance(d.get('runs'), list), 'no .runs array'
n = sum(len(r.get('results', [])) for r in d['runs'])
print(f'  scan completed in ${ELAPSED_SCAN}s, {n} result(s)')
" || { echo "FAIL: SARIF validation failed." >&2; exit 2; }
fi

# --- 5. PASS ---------------------------------------------------------------

echo
echo "PASS — Path B build + preflight + end-to-end scan all green."
echo "  Build time: ${ELAPSED_BUILD}s"
echo "  Scanners:   $OK_COUNT/6 in container"
echo "  Scan time:  ${ELAPSED_SCAN}s (gitleaks against this repo)"
