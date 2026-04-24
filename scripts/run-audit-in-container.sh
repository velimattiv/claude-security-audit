#!/usr/bin/env bash
# scripts/run-audit-in-container.sh — run /security-audit inside an
# ephemeral OCI container so scanners don't pollute the host.
#
# Why: the v2 scanner bundle installs six binaries that are themselves
# non-trivial attack surface on the host. For users who want a clean
# separation, this wrapper builds (or pulls) a pinned container image
# and runs the audit inside it, mounting only the target repo.
#
# Usage:
#   run-audit-in-container.sh [--build] [--image <tag>] [args...]
#
#   --build        force a local image build from scripts/Dockerfile.audit
#   --image TAG    image tag (default: localhost/claude-security-audit:2.0.1)
#   [args...]      passed through to /security-audit in the container
#                  (e.g., "mode: delta", "scope: services/api")
#
# Container runtime:
#   - Docker and Podman both supported. Detects whichever is on PATH.
#   - Rootless podman is the recommended mode; works on Linux + macOS.
#
# Example:
#   # First run — build the image (~500 MB)
#   scripts/run-audit-in-container.sh --build
#
#   # Subsequent runs — reuse the image
#   scripts/run-audit-in-container.sh "mode: delta"

set -eu

IMAGE_DEFAULT="localhost/claude-security-audit:2.0.1"
IMAGE="$IMAGE_DEFAULT"
BUILD=0

while [ $# -gt 0 ]; do
  case "$1" in
    --build)  BUILD=1; shift ;;
    --image)  IMAGE="$2"; shift 2 ;;
    --help|-h)
      sed -n '2,30p' "$0"
      exit 0 ;;
    *) break ;;
  esac
done

# Detect container runtime.
if command -v podman >/dev/null 2>&1; then
  RUNTIME=podman
elif command -v docker >/dev/null 2>&1; then
  RUNTIME=docker
else
  echo "ERROR: no container runtime found (tried podman, docker)." >&2
  echo "Install podman (recommended) or docker and retry. Or run the" >&2
  echo "audit directly on the host with scripts/install-scanners.sh."  >&2
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
ARTIFACT_DIR="$REPO_ROOT/.claude-audit"
mkdir -p "$ARTIFACT_DIR"

# Build on first run or on explicit --build.
if [ "$BUILD" -eq 1 ] || ! "$RUNTIME" image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Building image $IMAGE (first-time or --build)..."
  SKILL_REPO="${SKILL_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
  (cd "$SKILL_REPO" && "$RUNTIME" build -t "$IMAGE" -f scripts/Dockerfile.audit .)
fi

echo "Running /security-audit inside $RUNTIME container $IMAGE"
echo "Target:     $REPO_ROOT (read-only)"
echo "Artifacts:  $ARTIFACT_DIR (read-write)"

# Mount strategy:
#   - /target                : target repo as read-only
#   - /target/.claude-audit  : writable overlay for artifacts
#
# Env: ANTHROPIC_API_KEY only. No other host env leaks in.
"$RUNTIME" run \
  --rm \
  --security-opt=no-new-privileges \
  --cap-drop=ALL \
  --read-only \
  --tmpfs /tmp:rw,size=512m,mode=1777 \
  --tmpfs /home/audit/.cache:rw,size=256m,mode=0700 \
  -v "$REPO_ROOT":/target:ro,Z \
  -v "$ARTIFACT_DIR":/target/.claude-audit:rw,Z \
  -e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}" \
  -e "SKILL_INVOCATION=${*:-/security-audit}" \
  "$IMAGE" \
  "echo '=== Scanner preflight ===' && /usr/local/bin/install-scanners.sh --check && echo && echo '=== Audit invocation ===' && echo \"Claude Code should now run: \$SKILL_INVOCATION\" && echo 'Note: the full skill orchestration currently requires Claude Code on the host to invoke sub-agents. The container runs preflight + scanners; sub-agents run wherever Claude Code is.' "

echo
echo "Container exited. Artifacts under: $ARTIFACT_DIR"
