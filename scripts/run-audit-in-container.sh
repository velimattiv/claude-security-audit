#!/usr/bin/env bash
# scripts/run-audit-in-container.sh — isolate the SCANNER PHASE of
# /security-audit inside an ephemeral OCI container.
#
# SCOPE (read this before trusting the container):
#   - INSIDE the container: the six scanner binaries (semgrep,
#     osv-scanner, gitleaks, trufflehog, trivy, hadolint), Python
#     jsonschema for validators, and the skill's instruction files
#     (read-only copy for reference).
#   - OUTSIDE the container (on the host): Claude Code, the skill's
#     orchestrator LLM, and every deep-dive sub-agent. This wrapper
#     is NOT a full-audit sandbox.
#
# If you want full isolation of the LLM + orchestrator as well, that's
# a different architecture (e.g., Claude Code itself running in a
# container). This wrapper doesn't do that.
#
# Rationale: users can accept the scanner binaries' attack surface on
# an ephemeral container but prefer not to install them globally. The
# Claude Code harness is itself already installed for normal use; the
# scanners are the additional dependency the skill introduces.
#
# Usage:
#   run-audit-in-container.sh [--build] [--image TAG]
#   run-audit-in-container.sh scan semgrep           # run one scanner
#   run-audit-in-container.sh preflight              # just run --check
#   run-audit-in-container.sh shell                  # drop into container shell
#
# Runtime: Docker or Podman. Prefers rootless Podman.

set -eu

IMAGE_DEFAULT="localhost/claude-security-audit:2.0.1"
IMAGE="$IMAGE_DEFAULT"
BUILD=0

while [ $# -gt 0 ]; do
  case "$1" in
    --build)  BUILD=1; shift ;;
    --image)  IMAGE="$2"; shift 2 ;;
    --help|-h) sed -n '2,25p' "$0"; exit 0 ;;
    *) break ;;
  esac
done

# Subcommand (scan / preflight / shell). Default: preflight.
CMD="${1:-preflight}"
shift || true

# Detect container runtime.
if command -v podman >/dev/null 2>&1; then
  RUNTIME=podman
elif command -v docker >/dev/null 2>&1; then
  RUNTIME=docker
else
  echo "ERROR: no container runtime found (tried podman, docker)." >&2
  echo "Install podman (recommended, rootless) or docker and retry."  >&2
  echo "Alternatively, run scanners directly on the host with"        >&2
  echo "scripts/install-scanners.sh."                                  >&2
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

# Compose the inner command based on the subcommand.
# Extra args after the subcommand are passed through to the inner
# scanner command. Example:
#   run-audit-in-container.sh scan semgrep --config p/python
EXTRA_ARGS=("$@")

# Shell-quote each extra arg for safe passthrough into the inner
# /bin/bash -lc "<string>" invocation.
EXTRA_JOINED=""
for a in "${EXTRA_ARGS[@]}"; do
  # printf %q isn't POSIX-portable but bash is our floor.
  EXTRA_JOINED+=" $(printf '%q' "$a")"
done

case "$CMD" in
  preflight)
    INNER="install-scanners.sh --check$EXTRA_JOINED"
    ;;
  shell)
    INNER="bash$EXTRA_JOINED"
    ;;
  scan)
    # Usage: scan <scanner> [extra scanner args...]
    SCANNER="${EXTRA_ARGS[0]:-}"
    # Shift out scanner name; join remaining args.
    EXTRA_JOINED=""
    for a in "${EXTRA_ARGS[@]:1}"; do
      EXTRA_JOINED+=" $(printf '%q' "$a")"
    done
    case "$SCANNER" in
      semgrep)    INNER="semgrep scan --config p/security-audit --config p/owasp-top-ten --sarif -o /target/.claude-audit/current/phase-04-scanners/semgrep.sarif --metrics=off --timeout 600$EXTRA_JOINED /target" ;;
      osv-scanner) INNER="osv-scanner scan --recursive --format sarif --output /target/.claude-audit/current/phase-04-scanners/osv.sarif$EXTRA_JOINED /target" ;;
      gitleaks)   INNER="gitleaks detect --no-git --source /target --report-format sarif --report-path /target/.claude-audit/current/phase-04-scanners/gitleaks.sarif$EXTRA_JOINED" ;;
      trufflehog) INNER="trufflehog git file:///target --json --only-verified$EXTRA_JOINED > /target/.claude-audit/current/phase-04-scanners/trufflehog.jsonl" ;;
      trivy)      INNER="trivy fs --scanners vuln,secret,misconfig --format sarif --output /target/.claude-audit/current/phase-04-scanners/trivy.sarif$EXTRA_JOINED /target" ;;
      hadolint)   INNER="find /target -name Dockerfile -not -path '*/node_modules/*' | xargs -I {} hadolint --format sarif$EXTRA_JOINED {}" ;;
      "")
        echo "ERROR: 'scan' needs a scanner name: semgrep | osv-scanner | gitleaks | trufflehog | trivy | hadolint" >&2
        exit 1 ;;
      *)
        echo "ERROR: unknown scanner '$SCANNER'" >&2
        exit 1 ;;
    esac
    ;;
  *)
    echo "ERROR: unknown subcommand '$CMD'. Valid: preflight | scan | shell." >&2
    exit 1 ;;
esac

echo "Running: $RUNTIME / $IMAGE / $CMD ${SCANNER:-}"
echo "Target:     $REPO_ROOT (read-only)"
echo "Artifacts:  $ARTIFACT_DIR (read-write)"
echo

mkdir -p "$ARTIFACT_DIR/current/phase-04-scanners"

"$RUNTIME" run \
  --rm \
  --security-opt=no-new-privileges \
  --cap-drop=ALL \
  --read-only \
  --tmpfs /tmp:rw,size=512m,mode=1777 \
  --tmpfs /home/audit/.cache:rw,size=512m,mode=0700 \
  -v "$REPO_ROOT":/target:ro,Z \
  -v "$ARTIFACT_DIR":/target/.claude-audit:rw,Z \
  "$IMAGE" \
  /bin/bash -lc "$INNER"

echo
echo "Exit OK. Artifacts: $ARTIFACT_DIR/current/phase-04-scanners/"
