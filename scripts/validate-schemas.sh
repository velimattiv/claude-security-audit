#!/usr/bin/env bash
# scripts/validate-schemas.sh — repo-wide validation suite.
#
# Runs fast, read-only, deterministic checks that every PR must pass:
#   1. Every JSON file parses (jq empty).
#   2. Every JSON Schema declares $schema (draft 2020-12).
#   3. Every CWE ID referenced in steps/deepdive/ + steps/phase-*.md
#      + lib/*.md exists in lib/cwe-map.json.
#   4. Every shell script passes bash -n.
#   5. Every markdown reference to a sibling file resolves.
#   6. VERSION file is well-formed (semver).
#   7. Fixture jsonl (tests/fixtures/) validates against its matching
#      schema.
#
# Exit 0 = clean; 1 = one or more checks failed. Intended for
# .github/workflows/ci.yml.

set -u

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

errors=0
checks=0
note() { printf "  %s\n" "$*"; }
fail() { printf "  FAIL: %s\n" "$*" >&2; errors=$((errors + 1)); }
pass() { checks=$((checks + 1)); }

echo "=== /security-audit validation suite ==="
echo "Repo: $REPO_ROOT"
echo
echo "NOTE: markdown-ref check in §5 covers [text](path) syntax only."
echo "Reference-style links ([text][id]) and HTML <a href=...> are NOT"
echo "checked; pair with markdown-link-check for full coverage."
echo

# --- 1. JSON parse ----------------------------------------------------------
echo "[1/7] JSON parse..."
if ! command -v jq >/dev/null 2>&1; then
  fail "jq not installed — required for validation"
else
  while IFS= read -r f; do
    if jq empty "$f" 2>/dev/null; then
      pass
    else
      fail "JSON parse error in $f"
    fi
  done < <(find . -name "*.json" -not -path "./.git/*" -not -path "./node_modules/*" -not -path "./_bmad*" -not -path "./.claude-audit/*" -not -path "./.claude/*" -not -path "./tests/*")
fi
note "$checks JSON files parsed cleanly so far"

# --- 2. JSON Schemas have $schema -------------------------------------------
echo
echo "[2/7] JSON Schema declarations..."
for f in skills/security-audit/lib/*-schema.json; do
  [ -f "$f" ] || continue
  schema_id="$(jq -r '."$schema" // empty' "$f")"
  if [ -z "$schema_id" ]; then
    fail "missing \$schema declaration in $f"
  else
    pass
  fi
done
note "schemas validated"

# --- 3. CWE references ------------------------------------------------------
echo
echo "[3/7] CWE cross-references..."
if [ -f skills/security-audit/lib/cwe-map.json ]; then
  # Extract CWEs referenced anywhere in the spec + catalogs.
  referenced=$(grep -rhoE "CWE-[0-9]+" skills/security-audit/steps/ skills/security-audit/lib/ 2>/dev/null | sort -u)
  missing=0
  for cwe in $referenced; do
    if ! jq -e --arg c "$cwe" '.mappings | has($c)' skills/security-audit/lib/cwe-map.json >/dev/null 2>&1; then
      fail "$cwe referenced but not in cwe-map.json"
      missing=$((missing + 1))
    fi
  done
  if [ $missing -eq 0 ]; then
    pass
    note "all referenced CWEs present in map"
  fi
fi

# --- 4. Shell syntax --------------------------------------------------------
echo
echo "[4/7] Shell script syntax..."
for f in scripts/*.sh; do
  [ -f "$f" ] || continue
  if bash -n "$f" 2>/dev/null; then
    pass
  else
    fail "bash -n failed for $f"
  fi
done
note "shell scripts pass -n"

# --- 5. Markdown references -------------------------------------------------
echo
echo "[5/7] Markdown sibling-file references..."
broken=0
while IFS= read -r md; do
  # Extract [text](path.md#anchor) local refs, skip http(s):// and #
  while IFS= read -r ref; do
    # Strip any #anchor
    path="${ref%%#*}"
    [ -z "$path" ] && continue
    # Skip absolute URLs
    case "$path" in http*|mailto:*) continue ;; esac
    # Resolve relative to the md file's directory
    dir="$(dirname "$md")"
    resolved="$dir/$path"
    if [ ! -e "$resolved" ]; then
      fail "broken ref in $md → $path"
      broken=$((broken + 1))
    fi
  done < <(grep -oE '\]\(([^)]+\.md[^)]*)\)' "$md" 2>/dev/null | sed 's/^](//' | sed 's/)$//')
done < <(find . -name "*.md" -not -path "./.git/*" -not -path "./node_modules/*" -not -path "./_bmad*" -not -path "./.claude-audit/*" -not -path "./.claude/*" -not -path "./tests/*" -not -path "./docs/test-runs/*")
if [ $broken -eq 0 ]; then
  pass
  note "all markdown refs resolve"
fi

# --- 6. VERSION semver ------------------------------------------------------
echo
echo "[6/7] VERSION file..."
if [ -f skills/security-audit/VERSION ]; then
  ver="$(cat skills/security-audit/VERSION | tr -d '[:space:]')"
  if printf "%s" "$ver" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9]+)?$'; then
    pass
    note "VERSION = $ver (semver-compatible)"
  else
    fail "VERSION not semver: '$ver'"
  fi
else
  fail "VERSION file missing"
fi

# --- 7a. Regex pattern compile --------------------------------------------
echo
echo "[7a/8] Deepdive cat-*.md regex patterns..."
if python3 scripts/validate-patterns.py >/dev/null 2>&1; then
  pass
  note "all regex patterns in cat-*.md compile"
else
  fail "one or more regex patterns in cat-*.md failed to compile"
  python3 scripts/validate-patterns.py 2>&1 | head -20 >&2
fi

# --- 7. Fixture validation --------------------------------------------------
echo
echo "[7b/8] Test fixtures..."
if [ -d tests/fixtures ]; then
  for jsonl in tests/fixtures/*.jsonl; do
    [ -f "$jsonl" ] || continue
    # Match each fixture to its schema by filename prefix.
    case "$(basename "$jsonl")" in
      finding*) schema="skills/security-audit/lib/finding-schema.json" ;;
      *)        schema="" ;;
    esac
    if [ -z "$schema" ]; then
      note "no schema mapping for $(basename "$jsonl") — skipped"
      continue
    fi
    if python3 scripts/validate-findings.py --schema "$schema" --cwe-map skills/security-audit/lib/cwe-map.json "$jsonl" --quiet 2>&1; then
      pass
    else
      fail "fixture $jsonl failed schema+cwe-map validation"
    fi
  done
else
  note "tests/fixtures/ absent — skipping fixture check (not fatal)"
fi

# --- summary ----------------------------------------------------------------
echo
echo "=== Summary ==="
echo "Passes: $checks"
echo "Fails:  $errors"

if [ $errors -gt 0 ]; then
  exit 1
fi
exit 0
