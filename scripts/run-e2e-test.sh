#!/usr/bin/env bash
# scripts/run-e2e-test.sh — local-only end-to-end test of /security-audit.
#
# Runs the full skill orchestration against a pinned Juice Shop tag,
# then executes the assertion suite in tests/e2e/assertions.py.
#
# This script deliberately uses the selected USER'S HOST agent harness and its
# existing auth. It does not put the harness itself in a container because
# headless auth and billing are operator concerns. Scanner execution can still
# use Path B.
#
# Scanners MAY run in the container-isolated path
# (scripts/run-audit-in-container.sh) if the user prefers; by default
# they run on the host via the scanners already installed by
# scripts/install-scanners.sh.
#
# Usage:
#   scripts/run-e2e-test.sh              # full E2E (Path A — host scanners)
#   scripts/run-e2e-test.sh --harness claude|copilot
#                                        # select agent harness (default: claude)
#   scripts/run-e2e-test.sh --target X   # select the E2E target / fixture:
#                                        #   juice-shop (default) → tests/e2e/expected-findings.json
#                                        #   dvwa                  → tests/e2e/dvwa-fixture.json
#                                        #   crapi                 → tests/e2e/crapi-fixture.json
#                                        # Repo + pinned ref come from the fixture's
#                                        # target_repo / target_ref fields (juice-shop
#                                        # still uses config.env for back-compat).
#   scripts/run-e2e-test.sh --path-b     # full E2E with Path B — scanners run in
#                                        # the isolated container, host PATH
#                                        # binaries (if any) are bypassed via
#                                        # AUDIT_FORCE_PATH_B=1
#   scripts/run-e2e-test.sh --dry-run    # skip harness invocation; validate existing artifacts
#   scripts/run-e2e-test.sh --keep       # do NOT wipe the target dir (preserve baseline for delta-mode testing)
#   scripts/run-e2e-test.sh --min-recall N --min-precision N --semantic-floor N
#                                        # opt-in scorecard floors (precision/recall/
#                                        # semantic-match; default 0.0 = report-only)
#   scripts/run-e2e-test.sh --help
#
# Cost depends on the selected harness, account, and model.

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
PATH_B=0
HARNESS="claude"
TARGET="${TARGET_NAME:-juice-shop}"   # default from config.env
MIN_RECALL=""
MIN_PRECISION=""
SEMANTIC_FLOOR=""
while [ $# -gt 0 ]; do
  case "${1:-}" in
    --dry-run) DRY_RUN=1; shift ;;
    --keep)    KEEP=1; shift ;;
    --path-b)  PATH_B=1; shift ;;
    --harness) HARNESS="${2:?--harness needs claude or copilot}"; shift 2 ;;
    --harness=*) HARNESS="${1#*=}"; shift ;;
    --target)  TARGET="${2:?--target needs a value (juice-shop|dvwa|crapi)}"; shift 2 ;;
    --target=*) TARGET="${1#*=}"; shift ;;
    --min-recall)    MIN_RECALL="${2:?--min-recall needs a value}"; shift 2 ;;
    --min-recall=*)  MIN_RECALL="${1#*=}"; shift ;;
    --min-precision)    MIN_PRECISION="${2:?--min-precision needs a value}"; shift 2 ;;
    --min-precision=*)  MIN_PRECISION="${1#*=}"; shift ;;
    --semantic-floor)    SEMANTIC_FLOOR="${2:?--semantic-floor needs a value}"; shift 2 ;;
    --semantic-floor=*)  SEMANTIC_FLOOR="${1#*=}"; shift ;;
    --help|-h) sed -n '2,/^set -eu/p' "$0" | sed '$d'; exit 0 ;;
    "")        break ;;
    *) echo "ERROR: unknown arg '$1'. Use --help." >&2; exit 1 ;;
  esac
done

case "$HARNESS" in
  claude|copilot) ;;
  *) echo "ERROR: --harness must be claude or copilot." >&2; exit 2 ;;
esac

# --- Target → fixture / repo / ref resolution --------------------------------
# juice-shop keeps reading config.env (back-compat); dvwa + crapi read their
# repo + pinned ref straight out of the fixture JSON's target_repo/target_ref
# fields so the pin lives in ONE place (the fixture).
read_fixture_field() {  # $1=fixture path, $2=top-level key
  python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2]) or '')" "$1" "$2"
}

case "$TARGET" in
  juice-shop|"")
    TARGET="juice-shop"
    FIXTURE="$REPO_ROOT/tests/e2e/expected-findings.json"
    # TARGET_REPO / TARGET_TAG / TARGET_NAME come from config.env.
    ;;
  dvwa)
    FIXTURE="$REPO_ROOT/tests/e2e/dvwa-fixture.json"
    TARGET_NAME="dvwa"
    TARGET_REPO="$(read_fixture_field "$FIXTURE" target_repo)"
    TARGET_TAG="$(read_fixture_field "$FIXTURE" target_ref)"
    TARGET_DIR="${TARGET_DIR}-dvwa"   # isolate target clones per target
    ;;
  crapi)
    FIXTURE="$REPO_ROOT/tests/e2e/crapi-fixture.json"
    TARGET_NAME="crapi"
    TARGET_REPO="$(read_fixture_field "$FIXTURE" target_repo)"
    TARGET_TAG="$(read_fixture_field "$FIXTURE" target_ref)"
    TARGET_DIR="${TARGET_DIR}-crapi"
    ;;
  *)
    echo "ERROR: unknown --target '$TARGET'. Valid: juice-shop, dvwa, crapi." >&2
    exit 1
    ;;
esac

if [ ! -f "$FIXTURE" ]; then
  echo "ERROR: fixture for target '$TARGET' not found: $FIXTURE" >&2
  exit 2
fi
if [ -z "${TARGET_REPO:-}" ] || [ -z "${TARGET_TAG:-}" ]; then
  echo "ERROR: target '$TARGET' has no repo/ref (fixture missing target_repo/target_ref?)." >&2
  exit 2
fi

echo "=== /security-audit E2E ==="
echo "Target:         $TARGET_NAME @ $TARGET_TAG"
echo "Fixture:        $FIXTURE"
echo "Harness:        $HARNESS"
echo "Skill version:  $(cat "$REPO_ROOT/skills/security-audit/VERSION" | tr -d '[:space:]')"
echo "Target dir:     $TARGET_DIR"
echo "Artifacts:      $TARGET_DIR/.claude-audit (inside target clone)"
echo

# --- 1. Version gates --------------------------------------------------------
echo "[1/5] Version gates + flag preflight..."
if ! command -v "$HARNESS" >/dev/null 2>&1; then
  echo "ERROR: '$HARNESS' CLI not found on PATH." >&2
  exit 2
fi
HARNESS_VER="$("$HARNESS" --version 2>/dev/null | head -1 || echo 'unknown')"
echo "  $HARNESS --version: $HARNESS_VER"

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

# Fail before cloning or replacing a skill when the installed CLI cannot run
# the headless command this script needs.
HELP_OUT="$("$HARNESS" --help 2>&1 || true)"
if [ "$HARNESS" = "claude" ]; then
  if ! printf "%s" "$HELP_OUT" | grep -qE -- '(-p|--print)'; then
    echo "ERROR: 'claude --help' does not advertise -p/--print." >&2
    echo "Documented minimum: $CLAUDE_CODE_VERSION_MIN." >&2
    exit 2
  fi
  if ! printf "%s" "$HELP_OUT" | grep -q -- '--dangerously-skip-permissions'; then
    echo "ERROR: 'claude --help' does not advertise --dangerously-skip-permissions." >&2
    exit 2
  fi
else
  for required_flag in \
    '--prompt' '--autopilot' '--max-autopilot-continues' '--allow-all' \
    '--no-ask-user' '--output-format' '--stream'; do
    if ! printf "%s" "$HELP_OUT" | grep -q -- "$required_flag"; then
      echo "ERROR: 'copilot --help' does not advertise $required_flag." >&2
      exit 2
    fi
  done
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

# --- 3. Ensure skill is installed for the selected harness -------------------
#
# Install at user level so the run cannot resolve a stale personal copy ahead
# of the project copy. AUDIT_SKILL_DIR below also pins workflow resource
# resolution to this exact installation.
if [ "$HARNESS" = "claude" ]; then
  USER_SKILLS="$HOME/.claude/skills"
  PROJECT_SKILLS="$TARGET_DIR/.claude/skills"
else
  USER_SKILLS="${COPILOT_HOME:-$HOME/.copilot}/skills"
  PROJECT_SKILLS="$TARGET_DIR/.github/skills"
fi
USER_SKILL_DIR="$USER_SKILLS/security-audit"
PROJECT_SKILL_DIR="$PROJECT_SKILLS/security-audit"
BACKUP_DIR=""
HAD_USER_SKILL=0

cleanup_user_skill() {
  if [ -e "$USER_SKILL_DIR" ] || [ -L "$USER_SKILL_DIR" ]; then
    case "$USER_SKILL_DIR" in
      "$USER_SKILLS"/security-audit) rm -rf -- "$USER_SKILL_DIR" ;;
      *) echo "WARN: refusing to remove unexpected user skill path: $USER_SKILL_DIR" >&2; return ;;
    esac
  fi
  if [ "$HAD_USER_SKILL" -eq 1 ] &&
     { [ -e "$BACKUP_DIR" ] || [ -L "$BACKUP_DIR" ]; }; then
    mv "$BACKUP_DIR" "$USER_SKILL_DIR"
    echo "  [cleanup] restored original $HARNESS user skill" >&2
  fi
}
trap cleanup_user_skill EXIT

echo
echo "[3/5] Installing skill for $HARNESS at $USER_SKILL_DIR..."
mkdir -p "$USER_SKILLS"
if [ -e "$USER_SKILL_DIR" ] || [ -L "$USER_SKILL_DIR" ]; then
  HAD_USER_SKILL=1
  BACKUP_DIR="$USER_SKILLS/.e2e-backup-$(date -u +%Y%m%dT%H%M%SZ)-$$-security-audit"
  mv "$USER_SKILL_DIR" "$BACKUP_DIR"
  echo "  backed up pre-existing user-level skill → $BACKUP_DIR"
fi
cp -R "$REPO_ROOT/skills/security-audit" "$USER_SKILL_DIR"
echo "  installed: $USER_SKILL_DIR ($(cat "$USER_SKILL_DIR/VERSION"))"

mkdir -p "$PROJECT_SKILLS"
if [ -e "$PROJECT_SKILL_DIR" ] || [ -L "$PROJECT_SKILL_DIR" ]; then
  case "$PROJECT_SKILL_DIR" in
    "$TARGET_DIR"/.claude/skills/security-audit|"$TARGET_DIR"/.github/skills/security-audit)
      rm -rf -- "$PROJECT_SKILL_DIR"
      ;;
    *) echo "ERROR: refusing to replace unexpected project skill path: $PROJECT_SKILL_DIR" >&2; exit 2 ;;
  esac
fi
cp -R "$REPO_ROOT/skills/security-audit" "$PROJECT_SKILL_DIR"
echo "  also installed (project-local): $PROJECT_SKILL_DIR"

export AUDIT_SKILL_DIR="$USER_SKILL_DIR"
export AUDIT_NONINTERACTIVE=1

# --- 3.5. Path B prep (optional) ---------------------------------------------
if [ "$PATH_B" -eq 1 ] && [ "$DRY_RUN" -eq 0 ]; then
  echo
  echo "[3.5/5] --path-b: building scanner-isolation container..."
  if ! command -v podman >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: --path-b requires podman or docker. Install one or run without --path-b." >&2
    exit 2
  fi
  bash "$REPO_ROOT/scripts/run-audit-in-container.sh" --build
  echo "  container ready"
  # AUDIT_SKILL_REPO tells Phase 4 where to find the wrapper.
  # AUDIT_FORCE_PATH_B=1 makes Phase 4 use the wrapper for every
  # scanner regardless of host PATH state — so a host with scanners
  # already installed (Path A leftover) still exercises Path B.
  export AUDIT_SKILL_REPO="$REPO_ROOT"
  export AUDIT_FORCE_PATH_B=1
  echo "  AUDIT_SKILL_REPO=$AUDIT_SKILL_REPO"
  echo "  AUDIT_FORCE_PATH_B=1"
fi

# --- 4. Run the skill --------------------------------------------------------
echo
if [ "$DRY_RUN" -eq 1 ]; then
  echo "[4/5] --dry-run: skipping $HARNESS invocation. Using existing artifacts if present."
else
  echo "[4/5] Running /security-audit (hard wall-time cap: ${E2E_TIMEOUT_MIN} min via timeout(1))..."
  echo "  Working dir: $TARGET_DIR"
  if [ "$PATH_B" -eq 1 ]; then
    echo "  Mode: Path B (scanners-in-container via run-audit-in-container.sh)"
  else
    echo "  Mode: Path A (scanners on host PATH)"
  fi
  echo
  START_TS=$(date +%s)
  # v2.0.2: the runtime --append-system-prompt mandate from v2.0.1 is gone.
  # The skill now self-mandates via SKILL.md's description field + the
  # MANDATORY EXECUTION RULES blocks at the top of every steps/phase-NN.md.
  # This E2E run is the regression gate proving that's sufficient — if the
  # skill regresses to report-only output, assertions fail and we re-add
  # the mandate here. Do NOT reintroduce --append-system-prompt without
  # first trying to tighten the in-skill contract.

  # Both harnesses emit JSONL events for live monitoring. Copilot's command
  # shape includes: --autopilot --max-autopilot-continues 100 --allow-all
  # --no-ask-user --output-format json --stream on.
  STREAM_LOG="$TARGET_DIR/.claude-audit/.${HARNESS}-events.jsonl"
  mkdir -p "$TARGET_DIR/.claude-audit"
  : > "$STREAM_LOG"  # truncate at start of each run
  echo "  Stream events: $STREAM_LOG (tail -f to monitor)"

  if [ "$HARNESS" = "claude" ]; then
    HARNESS_CMD=(
      claude -p "$AUDIT_INVOCATION"
      --dangerously-skip-permissions
      --output-format stream-json
      --verbose
    )
  else
    HARNESS_CMD=(
      copilot -p "Use $AUDIT_INVOCATION to audit this repository."
      --autopilot
      --max-autopilot-continues 100
      --allow-all
      --no-ask-user
      --output-format json
      --stream on
    )
  fi
  printf '  Command:'
  printf ' %q' "${HARNESS_CMD[@]}"
  printf '\n'

  TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
  if [ -z "$TIMEOUT_BIN" ]; then
    echo "WARN: no timeout/gtimeout on PATH — wall-time cap not enforced. Install coreutils." >&2
    ( set -o pipefail; cd "$TARGET_DIR" && "${HARNESS_CMD[@]}" | tee "$STREAM_LOG" >/dev/null ) \
      || echo "WARN: $HARNESS exited non-zero. Continuing to assertions." >&2
  else
    ( set -o pipefail; cd "$TARGET_DIR" && "$TIMEOUT_BIN" -k 30s "${E2E_TIMEOUT_MIN}m" \
        "${HARNESS_CMD[@]}" \
        | tee "$STREAM_LOG" >/dev/null ) \
      || {
        rc=$?
        if [ "$rc" -eq 124 ]; then
          echo "WARN: $HARNESS killed by timeout at ${E2E_TIMEOUT_MIN}m. Continuing to assertions." >&2
        else
          echo "WARN: $HARNESS exited rc=$rc. Continuing to assertions." >&2
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
# Scorecard is written next to the run artifacts (inside the target clone,
# which lives under /tmp and is gitignored), NOT into the repo's tests/e2e/,
# so a live run never dirties the working tree. The default scorecard-dir
# (the fixture's directory) is what a manual `python3 assertions.py` uses.
SCORECARD_DIR="$TARGET_DIR/.claude-audit/current"
ASSERT_ARGS=(
  --artifact-dir "$TARGET_DIR"
  --repo-root "$REPO_ROOT"
  --fixture "$FIXTURE"
  --scorecard-dir "$SCORECARD_DIR"
  --require-jsonschema-backend
)
[ -n "$MIN_RECALL" ]     && ASSERT_ARGS+=( --min-recall "$MIN_RECALL" )
[ -n "$MIN_PRECISION" ]  && ASSERT_ARGS+=( --min-precision "$MIN_PRECISION" )
[ -n "$SEMANTIC_FLOOR" ] && ASSERT_ARGS+=( --semantic-floor "$SEMANTIC_FLOOR" )
set +e
python3 "$REPO_ROOT/tests/e2e/assertions.py" "${ASSERT_ARGS[@]}"
RC=$?
set -e

echo
if [ "$RC" -eq 0 ]; then
  echo "=== E2E PASS ==="
  echo "Report:    $TARGET_DIR/docs/security-audit-output/security-audit-report.md  (or .claude-audit/current/phase-07-report.md)"
  echo "SARIF:     $TARGET_DIR/docs/security-audit-output/findings.sarif  (also .claude-audit/current/findings.sarif)"
  echo "Baseline:  $TARGET_DIR/docs/security-audit-output/security-audit-baseline.json"
  echo "Scorecard: $SCORECARD_DIR/scorecard.md  (+ scorecard.json — precision/recall/F1)"
else
  echo "=== E2E FAIL (exit $RC) — see diff above ==="
fi
exit $RC
