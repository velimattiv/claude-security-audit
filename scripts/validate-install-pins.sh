#!/usr/bin/env bash
#
# validate-install-pins.sh — guard against the VERSION/install-snippet
# drift that bit us in v2.0.3 (release shipped with INSTALL.md install
# commands still pinning v2.0.2). Asserts that every
# `git clone --branch v<X.Y.Z>` line in README.md and docs/INSTALL.md
# pins exactly the version that skills/security-audit/VERSION declares.
#
# Run from repo root. Exit 0 on PASS, 1 on any mismatch.
#
# Wired into .github/workflows/ci.yml so a release that bumps VERSION
# without also bumping install-snippet pins fails CI before merge.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="$REPO_ROOT/skills/security-audit/VERSION"

if [ ! -f "$VERSION_FILE" ]; then
  echo "ERROR: $VERSION_FILE not found." >&2
  exit 1
fi

EXPECTED="$(tr -d '[:space:]' < "$VERSION_FILE")"
if [ -z "$EXPECTED" ]; then
  echo "ERROR: $VERSION_FILE is empty." >&2
  exit 1
fi

echo "Expected pin: v${EXPECTED}"

# Look for `--branch v<digits.digits.digits>` patterns in install docs
# (README.md and docs/INSTALL.md). Each match must equal v$EXPECTED.
files=( "$REPO_ROOT/README.md" "$REPO_ROOT/docs/INSTALL.md" )
mismatches=0

for f in "${files[@]}"; do
  if [ ! -f "$f" ]; then
    continue
  fi
  rel="${f#$REPO_ROOT/}"
  while IFS= read -r line; do
    # Extract the pinned version from "--branch v<X.Y.Z>"
    pin="$(echo "$line" | sed -nE 's/.*--branch (v[0-9]+\.[0-9]+\.[0-9]+).*/\1/p')"
    if [ -n "$pin" ] && [ "$pin" != "v${EXPECTED}" ]; then
      echo "MISMATCH in $rel:" >&2
      echo "    pinned: $pin" >&2
      echo "    expect: v${EXPECTED}" >&2
      echo "    line:   $line" >&2
      mismatches=$((mismatches + 1))
    fi
  done < <(grep -E -- "--branch v[0-9]" "$f" || true)
done

if [ "$mismatches" -gt 0 ]; then
  echo
  echo "FAIL: $mismatches install-snippet(s) pin a different version than VERSION." >&2
  echo "Either bump VERSION or update the install snippets to match." >&2
  exit 1
fi

echo "PASS: all install-snippet pins match VERSION (v${EXPECTED})."
