#!/usr/bin/env bash
#
# Install the complete security-audit Agent Skill for Claude Code or Copilot CLI.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/install-skill.sh --harness claude|copilot [options]

Options:
  --scope user|project   Install for the user (default) or one project.
  --project-root PATH    Project root for --scope project (default: current dir).
  --help                 Show this help.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SOURCE="$REPO_ROOT/skills/security-audit"

HARNESS=""
SCOPE="user"
PROJECT_ROOT="$PWD"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --harness)
      HARNESS="${2:?--harness needs claude or copilot}"
      shift 2
      ;;
    --harness=*)
      HARNESS="${1#*=}"
      shift
      ;;
    --scope)
      SCOPE="${2:?--scope needs user or project}"
      shift 2
      ;;
    --scope=*)
      SCOPE="${1#*=}"
      shift
      ;;
    --project-root)
      PROJECT_ROOT="${2:?--project-root needs a path}"
      shift 2
      ;;
    --project-root=*)
      PROJECT_ROOT="${1#*=}"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument '$1'." >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$HARNESS" in
  claude|copilot) ;;
  *)
    echo "ERROR: --harness must be claude or copilot." >&2
    exit 2
    ;;
esac

case "$SCOPE" in
  user|project) ;;
  *)
    echo "ERROR: --scope must be user or project." >&2
    exit 2
    ;;
esac

if [ "$SCOPE" = "project" ]; then
  if [ ! -d "$PROJECT_ROOT" ]; then
    echo "ERROR: project root does not exist: $PROJECT_ROOT" >&2
    exit 2
  fi
  PROJECT_ROOT="$(cd "$PROJECT_ROOT" && pwd -P)"
fi

if [ "$HARNESS" = "claude" ]; then
  if [ "$SCOPE" = "user" ]; then
    DEST="${HOME:?HOME is required}/.claude/skills/security-audit"
  else
    DEST="$PROJECT_ROOT/.claude/skills/security-audit"
  fi
else
  if [ "$SCOPE" = "user" ]; then
    COPILOT_ROOT="${COPILOT_HOME:-${HOME:?HOME is required}/.copilot}"
    DEST="$COPILOT_ROOT/skills/security-audit"
  else
    DEST="$PROJECT_ROOT/.github/skills/security-audit"
  fi
fi

DEST_PARENT="$(dirname "$DEST")"
STAGE="$DEST_PARENT/.security-audit.install.$$"
BACKUP="$DEST_PARENT/.security-audit.backup-$(date -u +%Y%m%dT%H%M%SZ)-$$"
MOVED_OLD=0
ACTIVATED=0

cleanup() {
  rc=$?
  if [ -d "$STAGE" ]; then
    case "$STAGE" in
      "$DEST_PARENT"/.security-audit.install.*) rm -rf -- "$STAGE" ;;
      *) echo "WARN: refusing to remove unexpected staging path: $STAGE" >&2 ;;
    esac
  fi
  if [ "$rc" -ne 0 ] && [ "$MOVED_OLD" -eq 1 ] && [ "$ACTIVATED" -eq 0 ] &&
     [ ! -e "$DEST" ] && [ ! -L "$DEST" ] &&
     { [ -e "$BACKUP" ] || [ -L "$BACKUP" ]; }; then
    mv "$BACKUP" "$DEST"
    echo "Restored prior installation after failure: $DEST" >&2
  fi
  exit "$rc"
}
trap cleanup EXIT

mkdir -p "$DEST_PARENT"
mkdir "$STAGE"
cp -R "$SOURCE/." "$STAGE/"

for required in SKILL.md VERSION manifest.yaml lib/validate-findings.py; do
  if [ ! -f "$STAGE/$required" ]; then
    echo "ERROR: staged skill is incomplete, missing $required." >&2
    exit 1
  fi
done

if [ -e "$DEST" ] || [ -L "$DEST" ]; then
  mv "$DEST" "$BACKUP"
  MOVED_OLD=1
fi

mv "$STAGE" "$DEST"
ACTIVATED=1

echo "Installed security-audit $(tr -d '[:space:]' < "$DEST/VERSION") for $HARNESS ($SCOPE)."
echo "Location: $DEST"
if [ "$MOVED_OLD" -eq 1 ]; then
  echo "Previous installation: $BACKUP"
fi
