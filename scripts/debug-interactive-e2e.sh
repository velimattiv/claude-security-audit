#!/usr/bin/env bash
#
# debug-interactive-e2e.sh — temporarily install this branch's v2.0.2
# skill at user-level, prompt you to drive a /security-audit run
# interactively in another terminal, then restore your original skill
# on exit.
#
# Usage:
#   bash scripts/debug-interactive-e2e.sh
#
# In a SECOND terminal (same container):
#   cd /tmp/e2e-target
#   claude               # interactive — NO --print
#   > /security-audit    # type this once Claude is ready
#   # watch the tool-call stream; report back what you see
#
# When you're done, return to THIS terminal and press Enter — the
# script will restore your original ~/.claude/skills/security-audit/.
# Ctrl-C also triggers restore.

set -euo pipefail

SKILL_SOURCE="/workspace/skills/security-audit"
USER_SKILL_DIR="$HOME/.claude/skills/security-audit"
# Backup goes OUTSIDE ~/.claude/skills/ — keeping it inside causes Claude
# Code's skill resolver to expose both versions as separate slash commands,
# leading to /security-audit accidentally invoking the backup.
BACKUP_PARENT="$HOME/.claude/.security-audit-debug-backups"
BACKUP_DIR=""

if [ ! -d "$SKILL_SOURCE" ]; then
  echo "ERROR: $SKILL_SOURCE not found — run from a checkout that has the v2.0.2 branch" >&2
  exit 1
fi

# --- 1. Back up + install ---------------------------------------------------

mkdir -p "$HOME/.claude/skills"
mkdir -p "$BACKUP_PARENT"

if [ -d "$USER_SKILL_DIR" ]; then
  BACKUP_DIR="$BACKUP_PARENT/security-audit-$(date -u +%Y%m%dT%H%M%SZ)"
  mv "$USER_SKILL_DIR" "$BACKUP_DIR"
  echo "[setup] backed up existing user-level skill → $BACKUP_DIR"
  echo "        (kept OUTSIDE ~/.claude/skills/ so Claude Code's resolver doesn't expose it as a separate slash command)"
else
  echo "[setup] no pre-existing user-level skill (nothing to back up)"
fi

cp -R "$SKILL_SOURCE" "$USER_SKILL_DIR"
INSTALLED_VER="$(cat "$USER_SKILL_DIR/VERSION" 2>/dev/null | tr -d '[:space:]')"
echo "[setup] installed v2.0.2 branch's skill → $USER_SKILL_DIR (VERSION: $INSTALLED_VER)"

# --- 2. Restore-on-exit trap ------------------------------------------------

RESTORED=0
restore() {
  # Guard against double-invocation: SIGINT + EXIT both fire, which
  # without this flag would run restore twice — first pass restores the
  # backup, second pass then deletes the freshly-restored skill.
  [ "$RESTORED" -eq 1 ] && return
  RESTORED=1
  echo
  echo "[cleanup] restoring original skill..."
  rm -rf "$USER_SKILL_DIR"
  if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
    mv "$BACKUP_DIR" "$USER_SKILL_DIR"
    echo "[cleanup] restored: $USER_SKILL_DIR (was $BACKUP_DIR)"
  else
    echo "[cleanup] no backup to restore (you had no pre-existing user-level skill)"
  fi
}
# shellcheck disable=SC2064
trap restore EXIT INT TERM

# --- 3. Instructions + wait -------------------------------------------------

cat <<EOF

==============================================================================
  v2.0.2 skill is now installed at $USER_SKILL_DIR
==============================================================================

In a SECOND terminal (same container, e.g. open a new tmux pane), run:

    cd /tmp/e2e-target
    claude --dangerously-skip-permissions   # interactive, no per-tool prompts
    > /security-audit                       # type this slash-command in the Claude session

The --dangerously-skip-permissions flag matches what the headless E2E
uses, so you observe the same behaviour without a permission prompt
on every Bash/Read/Write call.

Watch the tool-call stream. Things to note:

  1. Does Claude Code show the skill description on activation?
  2. First tool call: Read SKILL.md? Read workflow.md? Bash mkdir?
  3. Does the orchestrator emit the preflight Bash from workflow.md?
  4. If NOT — what does it do instead? Prose-summary? Direct file reads?

If /tmp/e2e-target does not exist (we killed the prior E2E run that
populated it), re-clone it first:

    git clone --depth 1 --branch v19.2.1 \\
      https://github.com/juice-shop/juice-shop.git /tmp/e2e-target

Press Enter here when you're done with the interactive session. Ctrl-C
also works. The trap will restore your original ~/.claude/skills/
security-audit/.

==============================================================================
EOF

read -r -p "Press Enter to restore original skill and exit: " _

# trap fires on exit
