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
#   scripts/run-e2e-test.sh --keep       # do NOT wipe the target dir (preserve baseline for delta-mode testing)
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
KEEP=0
while [ $# -gt 0 ]; do
  case "${1:-}" in
    --dry-run) DRY_RUN=1; shift ;;
    --keep)    KEEP=1; shift ;;
    --help|-h) sed -n '2,34p' "$0"; exit 0 ;;
    "")        break ;;
    *) echo "ERROR: unknown arg '$1'. Use --help." >&2; exit 1 ;;
  esac
done

echo "=== /security-audit E2E ==="
echo "Target:         $TARGET_NAME @ $TARGET_TAG"
echo "Skill version:  $(cat "$REPO_ROOT/skills/security-audit/VERSION" | tr -d '[:space:]')"
echo "Target dir:     $TARGET_DIR"
echo "Artifacts:      $TARGET_DIR/.claude-audit (inside target clone)"
echo

# --- 1. Version gates --------------------------------------------------------
echo "[1/5] Version gates + flag preflight..."
if ! command -v claude >/dev/null 2>&1; then
  echo "ERROR: 'claude' CLI not found on PATH. Install Claude Code first." >&2
  echo "See: https://code.claude.com/docs — the installer choice affects" >&2
  echo "auth (OAuth vs API key), which is outside this script's scope." >&2
  exit 2
fi
CLAUDE_VER="$(claude --version 2>/dev/null | head -1 || echo 'unknown')"
echo "  claude --version: $CLAUDE_VER"

# Hard fail if the pinned skill version differs from the fixture's expected
# calibration. Fixtures depend on CWE tags + file paths that come from the
# category instruction files — a mismatch means the fixture is validating
# against stale instructions.
SKILL_VER="$(cat "$REPO_ROOT/skills/security-audit/VERSION" | tr -d '[:space:]')"
if [ "$SKILL_VER" != "$SKILL_VERSION_EXPECTED" ]; then
  echo "ERROR: skill VERSION ($SKILL_VER) != fixture's expected ($SKILL_VERSION_EXPECTED)." >&2
  echo "       Update tests/e2e/config.env's SKILL_VERSION_EXPECTED + re-verify" >&2
  echo "       expected-findings.json against this skill version before running." >&2
  exit 2
fi

# Preflight: verify `claude` accepts the flags we'll use. A `claude --help`
# output that lacks `-p` or `--dangerously-skip-permissions` means the
# installed Claude Code is incompatible — fail early with actionable message.
HELP_OUT="$(claude --help 2>&1 || true)"
if ! printf "%s" "$HELP_OUT" | grep -qE -- '(-p|--print)'; then
  echo "ERROR: 'claude --help' does not advertise -p/--print flag." >&2
  echo "       Script needs Claude Code's non-interactive mode. Your installed" >&2
  echo "       version may be too old or too new. Documented minimum: $CLAUDE_CODE_VERSION_MIN." >&2
  exit 2
fi
if ! printf "%s" "$HELP_OUT" | grep -q -- '--dangerously-skip-permissions'; then
  echo "WARN: --dangerously-skip-permissions not advertised; may be gated behind an env var." >&2
  echo "      If the audit stalls waiting for a tool-permission prompt, export" >&2
  echo "      CLAUDE_CODE_DANGEROUSLY_SKIP_PERMISSIONS=1 and re-run." >&2
fi

# --- 2. Clone target at pinned tag -------------------------------------------
echo
echo "[2/5] Cloning $TARGET_REPO @ $TARGET_TAG..."
if [ "$DRY_RUN" -eq 1 ] && [ -d "$TARGET_DIR/.git" ]; then
  echo "  --dry-run: reusing existing $TARGET_DIR"
elif [ "$KEEP" -eq 1 ] && [ -d "$TARGET_DIR/.git" ]; then
  echo "  --keep: reusing existing $TARGET_DIR (preserves prior baseline for delta-mode testing)"
else
  if [ -d "$TARGET_DIR" ] && [ "$KEEP" -eq 0 ]; then
    # Preserve any existing baseline under a timestamped archive so an
    # accidental re-run doesn't silently discard delta-mode inputs.
    if [ -f "$TARGET_DIR/.claude-audit/baseline.json" ]; then
      archive="$TARGET_DIR/.claude-audit/history/pre-rerun-$(date -u +%Y%m%dT%H%M%SZ)"
      mkdir -p "$archive"
      cp -R "$TARGET_DIR/.claude-audit/current" "$archive/" 2>/dev/null || true
      cp "$TARGET_DIR/.claude-audit/baseline.json" "$archive/" 2>/dev/null || true
      echo "  archived prior baseline: $archive"
    fi
  fi
  rm -rf "$TARGET_DIR"
  git clone --depth 1 --branch "$TARGET_TAG" "$TARGET_REPO" "$TARGET_DIR" \
    || { echo "ERROR: git clone failed. Check that $TARGET_TAG exists upstream." >&2; exit 3; }
fi
CURRENT_TAG="$(git -C "$TARGET_DIR" describe --tags --always 2>/dev/null || echo unknown)"
echo "  checked out: $CURRENT_TAG"

# --- 3. Ensure skill is installed for Claude Code ---------------------------
#
# PRECEDENCE NOTE (discovered during v2.0.1 E2E self-dogfood):
#   Claude Code's skill resolution prefers ~/.claude/skills/ over the
#   project-local .claude/skills/. If the user has an older security-audit
#   at user-level, a project-local install does NOT override it.
#   To guarantee we test the skill under review, we install at user-level
#   (backing up any pre-existing install) and restore after the run via
#   a trap handler.
echo
echo "[3/5] Installing skill at user-level (~/.claude/skills/security-audit/)..."
echo "  Rationale: Claude Code prefers ~/.claude/skills/ over project-local."
USER_SKILLS="$HOME/.claude/skills"
USER_SKILL_DIR="$USER_SKILLS/security-audit"
BACKUP_DIR=""
mkdir -p "$USER_SKILLS"
if [ -d "$USER_SKILL_DIR" ]; then
  BACKUP_DIR="$USER_SKILLS/.e2e-backup-$(date -u +%Y%m%dT%H%M%SZ)-security-audit"
  mv "$USER_SKILL_DIR" "$BACKUP_DIR"
  echo "  backed up pre-existing user-level skill → $BACKUP_DIR"
fi
cp -R "$REPO_ROOT/skills/security-audit" "$USER_SKILL_DIR"
echo "  installed: $USER_SKILL_DIR ($(cat "$USER_SKILL_DIR/VERSION"))"

# Belt-and-braces: also install project-local in case Claude Code's
# resolution order changes in a future version.
mkdir -p "$TARGET_DIR/.claude/skills"
rm -rf "$TARGET_DIR/.claude/skills/security-audit"
cp -R "$REPO_ROOT/skills/security-audit" "$TARGET_DIR/.claude/skills/"
echo "  also installed (project-local): $TARGET_DIR/.claude/skills/security-audit"

# Restore on exit so an interrupted run doesn't leave the user's pre-
# existing skill displaced.
# shellcheck disable=SC2064
trap "
if [ -n '$BACKUP_DIR' ] && [ -d '$BACKUP_DIR' ]; then
  rm -rf '$USER_SKILL_DIR'
  mv '$BACKUP_DIR' '$USER_SKILL_DIR'
  echo '  [cleanup] restored original user-level skill' >&2
fi
" EXIT

# --- 4. Run the skill --------------------------------------------------------
echo
if [ "$DRY_RUN" -eq 1 ]; then
  echo "[4/5] --dry-run: skipping claude invocation. Using existing artifacts if present."
else
  echo "[4/5] Running /security-audit (hard wall-time cap: ${E2E_TIMEOUT_MIN} min via timeout(1))..."
  echo "  Command: claude -p '$AUDIT_INVOCATION' --dangerously-skip-permissions"
  echo "  Working dir: $TARGET_DIR"
  echo
  START_TS=$(date +%s)
  # Append a runtime system-prompt mandate. SKILL.md + workflow.md prose
  # alone proved insufficient (3 prior runs all produced report-only) —
  # the orchestrator LLM treats skill content as guidance. A system-prompt
  # appendage applies on every model turn and is harder to skim past.
  SYS_MANDATE="MANDATORY E2E CONTRACT: this run is being validated by an automated assertion suite that checks for specific files on disk after you exit. You MUST: (1) Make .claude-audit/current/ your FIRST tool action via mkdir -p. (2) For each phase 0 through 7 (8 if mode=full), write the documented artifact JSON file AND a phase-NN.done marker file to .claude-audit/current/ BEFORE moving to the next phase. (3) Write findings.sarif (SARIF 2.1.0) to .claude-audit/current/. EVERY SARIF result row MUST include in its .properties: 'security-severity' (e.g. '9.8'), 'cwe' (e.g. 'CWE-798' — the CWE id is REQUIRED for fixture matching; finding the CWE in lib/cwe-map.json is encouraged), AND optionally 'category' (one of: auth, idor, token_scope, mitm, crypto, secret_sprawl, deployment, injection, llm, config). The .ruleId can be your own short identifier — but the CWE goes in properties.cwe regardless of what the ruleId says. (4) Write the human report LAST, not first. Producing only docs/security-audit-report.md without the .claude-audit/current/ blackboard files is an INVALID run — the assertion suite will fail the test. If you find yourself reasoning 'the user just wants a summary' — STOP and write the artifacts first. The artifacts ARE the deliverable; the report is the cover page."

  TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
  if [ -z "$TIMEOUT_BIN" ]; then
    echo "WARN: no timeout/gtimeout on PATH — wall-time cap not enforced. Install coreutils." >&2
    ( cd "$TARGET_DIR" && claude -p "$AUDIT_INVOCATION" \
        --dangerously-skip-permissions \
        --append-system-prompt "$SYS_MANDATE" ) \
      || echo "WARN: claude -p exited non-zero. Continuing to assertions." >&2
  else
    ( cd "$TARGET_DIR" && "$TIMEOUT_BIN" -k 30s "${E2E_TIMEOUT_MIN}m" \
        claude -p "$AUDIT_INVOCATION" \
        --dangerously-skip-permissions \
        --append-system-prompt "$SYS_MANDATE" ) \
      || {
        rc=$?
        if [ "$rc" -eq 124 ]; then
          echo "WARN: claude -p killed by timeout at ${E2E_TIMEOUT_MIN}m. Continuing to assertions." >&2
        else
          echo "WARN: claude -p exited rc=$rc. Continuing to assertions." >&2
        fi
      }
  fi
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
  --fixture "$REPO_ROOT/tests/e2e/expected-findings.json" \
  --require-jsonschema-backend
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
