#!/usr/bin/env bash
#
# Deterministic dual-harness installation and orchestration contract tests.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$REPO_ROOT/scripts/install-skill.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/security-audit-harness-XXXXXX")"

cleanup() {
  case "$WORK" in
    "${TMPDIR:-/tmp}"/security-audit-harness-*) rm -rf -- "$WORK" ;;
    *) echo "WARN: refusing to remove unexpected test path: $WORK" >&2 ;;
  esac
}
trap cleanup EXIT

ok() { printf 'ok - %s\n' "$1"; }
bad() { printf 'not ok - %s\n' "$1" >&2; exit 1; }

assert_complete_skill() {
  root="$1"
  for required in SKILL.md VERSION manifest.yaml workflow.md lib/validate-findings.py templates/subagent-prompt.md; do
    [ -f "$root/$required" ] || bad "installed bundle missing $required at $root"
  done
}

HOME_DIR="$WORK/home with spaces"
COPILOT_DIR="$WORK/copilot home"
PROJECT_DIR="$WORK/project"
mkdir -p "$HOME_DIR" "$COPILOT_DIR" "$PROJECT_DIR"

HOME="$HOME_DIR" COPILOT_HOME="$COPILOT_DIR" \
  bash "$INSTALLER" --harness copilot >/dev/null
assert_complete_skill "$COPILOT_DIR/skills/security-audit"
ok "Copilot user install honors COPILOT_HOME and preserves resources"

python3 - "$COPILOT_DIR/skills/security-audit/SKILL.md" <<'PY'
import sys
from pathlib import Path

line = next(
    line for line in Path(sys.argv[1]).read_text().splitlines()
    if line.startswith("description:")
)
description = line.split(":", 1)[1].strip().strip('"')
if len(description) > 1024:
    raise SystemExit(f"skill description exceeds Copilot's 1024-char limit: {len(description)}")
PY
ok "Skill metadata fits Copilot's frontmatter limit"

printf 'old\n' > "$COPILOT_DIR/skills/security-audit/prior-install-marker"
HOME="$HOME_DIR" COPILOT_HOME="$COPILOT_DIR" \
  bash "$INSTALLER" --harness copilot >/dev/null
backup="$(find "$COPILOT_DIR/skills" -maxdepth 1 -type d -name '.security-audit.backup-*' -print -quit)"
[ -n "$backup" ] && [ -f "$backup/prior-install-marker" ] \
  || bad "Copilot reinstall did not back up the previous bundle"
ok "Copilot reinstall backs up the previous bundle"

rm -rf "$COPILOT_DIR/skills/security-audit"
printf 'legacy-file\n' > "$COPILOT_DIR/skills/security-audit"
HOME="$HOME_DIR" COPILOT_HOME="$COPILOT_DIR" \
  bash "$INSTALLER" --harness copilot >/dev/null
file_backup="$(find "$COPILOT_DIR/skills" -maxdepth 1 -type f -name '.security-audit.backup-*' -print -quit)"
[ -n "$file_backup" ] && grep -q '^legacy-file$' "$file_backup" \
  || bad "installer did not preserve a non-directory prior installation"
assert_complete_skill "$COPILOT_DIR/skills/security-audit"
ok "Installer preserves a non-directory prior path"

HOME="$HOME_DIR" bash "$INSTALLER" --harness claude >/dev/null
assert_complete_skill "$HOME_DIR/.claude/skills/security-audit"
ok "Claude user install remains supported"

HOME="$HOME_DIR" bash "$INSTALLER" --harness copilot --scope project \
  --project-root "$PROJECT_DIR" >/dev/null
assert_complete_skill "$PROJECT_DIR/.github/skills/security-audit"
ok "Copilot project install uses .github/skills"

HOME="$HOME_DIR" bash "$INSTALLER" --harness claude --scope project \
  --project-root "$PROJECT_DIR" >/dev/null
assert_complete_skill "$PROJECT_DIR/.claude/skills/security-audit"
ok "Claude project install remains supported"

WORKFLOW="$REPO_ROOT/skills/security-audit/workflow.md"
for location in \
  '${COPILOT_HOME:-$HOME/.copilot}/skills/security-audit' \
  '$HOME/.agents/skills/security-audit' \
  './.github/skills/security-audit' \
  './.agents/skills/security-audit' \
  '$HOME/.claude/skills/security-audit' \
  './.claude/skills/security-audit'; do
  grep -Fq "$location" "$WORKFLOW" || bad "workflow discovery omits $location"
done
grep -Fq 'AUDIT_SKILL_DIR' "$WORKFLOW" \
  || bad "workflow has no explicit skill-directory override"
grep -Fq 'different versions' "$WORKFLOW" \
  || bad "workflow does not fail on conflicting installed versions"
ok "Workflow discovers both harnesses and rejects version ambiguity"

grep -Fq 'AUDIT_NONINTERACTIVE' "$WORKFLOW" \
  || bad "workflow does not recognize explicit headless mode"
grep -Fq 'AUDIT_NONINTERACTIVE' "$REPO_ROOT/skills/security-audit/lib/output-routing.md" \
  || bad "output routing does not document explicit headless mode"
ok "Headless output routing is harness-neutral"

E2E="$REPO_ROOT/scripts/run-e2e-test.sh"
grep -Fq -- '--harness claude|copilot' "$E2E" \
  || bad "E2E help does not expose dual harness selection"
# Anchor flag assertions to the constructed Copilot command array, not the
# whole file, so a flag surviving only in a comment cannot pass.
copilot_cmd_block="$(awk '/copilot -p /,/^    \)/' "$E2E")"
[ -n "$copilot_cmd_block" ] || bad "E2E runner has no Copilot HARNESS_CMD block"
for flag in --autopilot --max-autopilot-continues --allow-all --no-ask-user \
  '--output-format json' '--stream on'; do
  printf '%s\n' "$copilot_cmd_block" | grep -Fq -- "$flag" \
    || bad "Copilot HARNESS_CMD omits $flag"
done
grep -Fq '[ -e "$USER_SKILL_DIR" ] || [ -L "$USER_SKILL_DIR" ]' "$E2E" \
  || bad "E2E backup ignores non-directory prior skill paths"
ok "E2E runner declares the Copilot headless contract"

grep -Fq 'Copilot CLI' "$REPO_ROOT/skills/security-audit/steps/phase-05-deepdives.md" \
  || bad "Phase 5 has no Copilot subagent adapter"
grep -Fq 'agent_type: "general-purpose"' "$REPO_ROOT/skills/security-audit/templates/subagent-prompt.md" \
  || bad "subagent template has no Copilot call shape"
if grep -Eq 'Opus-only|Model: `?opus`?|Claude Opus [0-9]' \
  "$REPO_ROOT/skills/security-audit/workflow.md" \
  "$REPO_ROOT/skills/security-audit/steps/phase-05-deepdives.md" \
  "$REPO_ROOT/skills/security-audit/steps/phase-06-config.md" \
  "$REPO_ROOT/skills/security-audit/templates/subagent-prompt.md"; then
  bad "orchestrator surfaces retain a Claude-only model mandate"
fi
ok "Subagent fan-out documents both harness adapters"

echo "PASS: dual-harness compatibility contract"
