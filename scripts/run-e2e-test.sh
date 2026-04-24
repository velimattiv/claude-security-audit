#!/usr/bin/env bash
# scripts/run-e2e-test.sh — local-only end-to-end test of /security-audit.
#
# Runs the full skill orchestration against a pinned Juice Shop tag,
# then executes the assertion suite in tests/e2e/assertions.py.
#
# This script deliberately uses the USER'S HOST Claude Code (and thus
# the user's existing auth — whether API key or claude.ai OAuth /
# Claude Max subscription). It does NOT wrap Claude Code in a container
# because:
#   (1) A fresh container has no claude.ai OAuth session, breaking
#       Claude Max users.
#   (2) Headless OAuth for CI is not currently documented / verified.
#   (3) A dedicated pay-per-token API key for CI is a separate
#       operational decision, not a test-script concern.
#
# Scanners MAY run in the container-isolated path
# (scripts/run-audit-in-container.sh) if the user prefers; by default
# they run on the host via the scanners already installed by
# scripts/install-scanners.sh.
#
# Usage:
#   scripts/run-e2e-test.sh              # full E2E
#   scripts/run-e2e-test.sh --dry-run    # skip `claude` invocation; validate existing artifacts
#   scripts/run-e2e-test.sh --help
#
# Cost: expect $5-$20 per run on an API key, or no marginal cost on
# Claude Max (subject to your plan's usage limits).

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CFG="$REPO_ROOT/tests/e2e/config.env"

if [ ! -f "$CFG" ]; then
  echo "ERROR: $CFG not found — are you in the skill's repo root?" >&2
  exit 2
fi
# shellcheck disable=SC1090
. "$CFG"

DRY_RUN=0
case "${1:-}" in
  --dry-run) DRY_RUN=1 ;;
  --help|-h) sed -n '2,30p' "$0"; exit 0 ;;
  "") ;;
  *) echo "ERROR: unknown arg '$1'. Use --help." >&2; exit 1 ;;
esac

echo "=== /security-audit E2E ==="
echo "Target:         $TARGET_NAME @ $TARGET_TAG"
echo "Skill version:  $(cat "$REPO_ROOT/skills/security-audit/VERSION" | tr -d '[:space:]')"
echo "Target dir:     $TARGET_DIR"
echo "Artifacts:      $TARGET_DIR/.claude-audit (inside target clone)"
echo

# --- 1. Version gates --------------------------------------------------------
echo "[1/5] Version gates..."
if ! command -v claude >/dev/null 2>&1; then
  echo "ERROR: 'claude' CLI not found on PATH. Install Claude Code first." >&2
  echo "See: https://code.claude.com/docs — the installer choice affects" >&2
  echo "auth (OAuth vs API key), which is outside this script's scope." >&2
  exit 2
fi
CLAUDE_VER="$(claude --version 2>/dev/null | head -1 || echo 'unknown')"
echo "  claude --version: $CLAUDE_VER"
SKILL_VER="$(cat "$REPO_ROOT/skills/security-audit/VERSION" | tr -d '[:space:]')"
if [ "$SKILL_VER" != "$SKILL_VERSION_EXPECTED" ]; then
  echo "WARN: skill VERSION ($SKILL_VER) != fixture's expected ($SKILL_VERSION_EXPECTED). Fixtures may need re-calibration." >&2
fi

# --- 2. Clone target at pinned tag -------------------------------------------
echo
echo "[2/5] Cloning $TARGET_REPO @ $TARGET_TAG..."
if [ "$DRY_RUN" -eq 1 ] && [ -d "$TARGET_DIR/.git" ]; then
  echo "  --dry-run: reusing existing $TARGET_DIR"
else
  rm -rf "$TARGET_DIR"
  git clone --depth 1 --branch "$TARGET_TAG" "$TARGET_REPO" "$TARGET_DIR"
fi
CURRENT_TAG="$(git -C "$TARGET_DIR" describe --tags --always 2>/dev/null || echo unknown)"
echo "  checked out: $CURRENT_TAG"
if [ "$CURRENT_TAG" != "$TARGET_TAG" ]; then
  echo "NOTE: shallow clones often show only the SHA, not the tag. That's expected."
fi

# --- 3. Ensure skill is installed for Claude Code ---------------------------
echo
echo "[3/5] Installing skill into target's .claude/skills/ (project-local)..."
mkdir -p "$TARGET_DIR/.claude/skills"
rm -rf "$TARGET_DIR/.claude/skills/security-audit"
cp -R "$REPO_ROOT/skills/security-audit" "$TARGET_DIR/.claude/skills/"
echo "  installed: $TARGET_DIR/.claude/skills/security-audit ($(cat "$TARGET_DIR/.claude/skills/security-audit/VERSION"))"

# --- 4. Run the skill --------------------------------------------------------
echo
if [ "$DRY_RUN" -eq 1 ]; then
  echo "[4/5] --dry-run: skipping claude invocation. Using existing artifacts if present."
else
  echo "[4/5] Running /security-audit (wall-time advisory: ${E2E_TIMEOUT_MIN} min)..."
  echo "  Command: claude -p '$AUDIT_INVOCATION' --dangerously-skip-permissions"
  echo "  Working dir: $TARGET_DIR"
  echo
  START_TS=$(date +%s)
  ( cd "$TARGET_DIR" && claude -p "$AUDIT_INVOCATION" --dangerously-skip-permissions ) || {
    echo "WARN: claude -p exited non-zero. Continuing to assertions to capture partial state." >&2
  }
  ELAPSED=$(( $(date +%s) - START_TS ))
  echo
  echo "  Elapsed: ${ELAPSED}s ($(( ELAPSED / 60 ))m $(( ELAPSED % 60 ))s)"
fi

# --- 5. Run assertions -------------------------------------------------------
echo
echo "[5/5] Running assertion suite..."
set +e
python3 "$REPO_ROOT/tests/e2e/assertions.py" \
  --artifact-dir "$TARGET_DIR" \
  --repo-root "$REPO_ROOT" \
  --fixture "$REPO_ROOT/tests/e2e/expected-findings.json"
RC=$?
set -e

echo
if [ "$RC" -eq 0 ]; then
  echo "=== E2E PASS ==="
  echo "Report:    $TARGET_DIR/docs/security-audit-report.md  (or .claude-audit/current/phase-07-report.md)"
  echo "SARIF:     $TARGET_DIR/.claude-audit/current/findings.sarif"
  echo "Baseline:  $TARGET_DIR/docs/security-audit-baseline.json"
else
  echo "=== E2E FAIL (exit $RC) — see diff above ==="
fi
exit $RC
