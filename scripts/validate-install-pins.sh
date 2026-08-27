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

# v2.6.1: also check the `# -> X.Y.Z` verification comments in install docs.
# README.md carried `cat .../VERSION   # -> 2.6.0` through the 2.6.1 bump because
# this validator only looked at `--branch v` lines, so a reader following the
# install steps would have seen a mismatch the CI called PASS.
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  rel="${f#$REPO_ROOT/}"
  while IFS= read -r line; do
    # Match any arrow glyph by skipping non-digits after the `#`. An earlier
    # attempt spelled the U+2192 arrow as a hex escape inside the sed pattern;
    # sed does not interpret those escapes, so the check silently never fired
    # on the exact drift it was written to catch.
    cmt="$(echo "$line" | sed -nE 's/.*VERSION[[:space:]]*#[^0-9]*([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')"
    if [ -n "$cmt" ] && [ "$cmt" != "${EXPECTED}" ]; then
      echo "MISMATCH in $rel (VERSION comment):" >&2
      echo "    shows:  $cmt" >&2
      echo "    expect: ${EXPECTED}" >&2
      mismatches=$((mismatches + 1))
    fi
  done < <(grep -E "VERSION[[:space:]]*#" "$f" || true)
done

# The manifest stamps `skill_version` into EVERY artifact a run emits, and
# SKILL.md tells the operator to reason about cross-run comparability from it.
# A stale value there is worse than a stale README pin: the README is read once,
# the stamp is carried in every SARIF, baseline and JSONL a run produces, so a
# v2.6 run would label its own output v2.5 and a delta comparison would silently
# straddle two rule sets. v2.6 shipped this way and the release tag caught it by
# hand — which is exactly the kind of check that should not be by hand.
MANIFEST="$REPO_ROOT/skills/security-audit/manifest.yaml"
if [ -f "$MANIFEST" ]; then
  stamped="$(sed -nE 's/^skill_version:[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' "$MANIFEST" | head -1)"
  if [ -z "$stamped" ]; then
    echo "MISMATCH: manifest.yaml declares no top-level skill_version" >&2
    mismatches=$((mismatches + 1))
  elif [ "$stamped" != "$EXPECTED" ]; then
    echo "MISMATCH in skills/security-audit/manifest.yaml:" >&2
    echo "    skill_version: $stamped" >&2
    echo "    expect:        $EXPECTED" >&2
    mismatches=$((mismatches + 1))
  fi
fi

if [ "$mismatches" -gt 0 ]; then
  echo
  echo "FAIL: $mismatches version reference(s) disagree with VERSION." >&2
  echo "Either bump VERSION or update the reference(s) to match." >&2
  exit 1
fi

echo "PASS: install-snippet pins and manifest skill_version match VERSION (v${EXPECTED})."
