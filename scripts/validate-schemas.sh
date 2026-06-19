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
#   8. Every "CWE-N / A##:2025" tag-pair in steps/deepdive/cat-*.md is a
#      canonical match (lib/cwe-owasp-map.json .canonical) or a documented
#      context override (.context_overrides); genuine mismaps fail.
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
echo "[1/8] JSON parse..."
if ! command -v jq >/dev/null 2>&1; then
  fail "jq not installed — required for validation"
else
  while IFS= read -r f; do
    if jq empty "$f" 2>/dev/null; then
      pass
    else
      fail "JSON parse error in $f"
    fi
  done < <(find . -name "*.json" -not -path "./.git/*" -not -path "./node_modules/*" -not -path "./docs/security-audit-output/*" -not -path "./.claude-audit/*" -not -path "./.claude/*" -not -path "./tests/*")
fi
note "$checks JSON files parsed cleanly so far"

# --- 2. JSON Schemas have $schema -------------------------------------------
echo
echo "[2/8] JSON Schema declarations..."
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
echo "[3/8] CWE cross-references..."
if [ -f skills/security-audit/lib/cwe-map.json ]; then
  # Extract CWEs referenced anywhere in the spec + catalogs.
  # Include E2E fixtures: a fixture CWE absent from the map hard-fails
  # validate-findings.py on that target (Gate-C R1 finding).
  referenced=$(grep -rhoE "CWE-[0-9]+" skills/security-audit/steps/ skills/security-audit/lib/ tests/e2e/ 2>/dev/null | sort -u)
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
echo "[4/8] Shell script syntax..."
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
echo "[5/8] Markdown sibling-file references..."
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
done < <(find . -name "*.md" -not -path "./.git/*" -not -path "./node_modules/*" -not -path "./docs/security-audit-output/*" -not -path "./.claude-audit/*" -not -path "./.claude/*" -not -path "./tests/*" -not -path "./docs/test-runs/*")
if [ $broken -eq 0 ]; then
  pass
  note "all markdown refs resolve"
fi

# --- 6. VERSION semver ------------------------------------------------------
echo
echo "[6/8] VERSION file..."
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

  # Validate *.json fixtures against their schemas too.
  for jf in tests/fixtures/*.json; do
    [ -f "$jf" ] || continue
    case "$(basename "$jf")" in
      surface*) sch="skills/security-audit/lib/surface-schema.json" ;;
      partition*) sch="skills/security-audit/lib/partitions-schema.json" ;;
      profile*) sch="skills/security-audit/lib/profile-schema.json" ;;
      keystone*) sch="skills/security-audit/lib/keystone-schema.json" ;;
      baseline*) sch="skills/security-audit/lib/baseline-schema.json" ;;
      *) sch="" ;;
    esac
    if [ -z "$sch" ]; then
      note "no schema mapping for $(basename "$jf") — skipped"
      continue
    fi
    # Use a tiny inline jsonschema check via python.
    if python3 -c "
import json, sys
try:
    import jsonschema
except ImportError:
    sys.exit(0)  # skip silently if unavailable
with open('$jf') as f: doc = json.load(f)
with open('$sch') as f: schema = json.load(f)
jsonschema.Draft202012Validator(schema).validate(doc)
" 2>/dev/null; then
      pass
    else
      fail "fixture $jf failed schema validation against $sch"
    fi
  done
else
  note "tests/fixtures/ absent — skipping fixture check (not fatal)"
fi

# --- 7c. Egress fixtures vs sink/credential schemas -------------------------
echo
echo "[7c/8] Egress fixtures (sink + credential schemas)..."
if [ -d tests/fixtures/egress ]; then
  while IFS= read -r ef; do
    case "$(basename "$ef")" in
      sinks.json)       esch="skills/security-audit/lib/sink-schema.json" ;;
      credentials.json) esch="skills/security-audit/lib/credential-ledger-schema.json" ;;
      surface.json)     esch="skills/security-audit/lib/surface-schema.json" ;;
      *)                esch="" ;;
    esac
    [ -z "$esch" ] && continue
    if python3 -c "
import json, sys
try:
    import jsonschema
except ImportError:
    sys.exit(0)
jsonschema.Draft202012Validator(json.load(open('$esch'))).validate(json.load(open('$ef')))
" 2>/dev/null; then
      pass
    else
      fail "egress fixture $ef failed schema validation against $esch"
    fi
  done < <(find tests/fixtures/egress -type f -name '*.json')
  note "egress fixtures validated"
else
  note "tests/fixtures/egress absent — skipped"
fi

# --- 8. CWE / A##:2025 tag-pair mapping ------------------------------------
# Guards the tag-mismap class both v2.1 adversarial rounds caught: a
# hand-authored "CWE-N / A##:2025" pairing that every other validator passed
# green. Each tag-pair in steps/deepdive/cat-*.md must be either a canonical
# CWE->A## match (lib/cwe-owasp-map.json .canonical) or a documented
# (cwe, owasp, cat) context override (.context_overrides). A CWE absent from
# the canonical web-Top-10 table (and not overridden) WARNs but does not fail;
# only a pair that is neither a canonical match nor a documented override
# (a genuine mismap) fails.
echo
echo "[8/8] CWE / A##:2025 tag-pair mapping..."
cwe_owasp_map="skills/security-audit/lib/cwe-owasp-map.json"
if [ ! -f "$cwe_owasp_map" ]; then
  fail "tag-pair map missing: $cwe_owasp_map"
elif ! command -v jq >/dev/null 2>&1; then
  fail "jq not installed — required for tag-pair validation"
elif ! jq empty "$cwe_owasp_map" >/dev/null 2>&1; then
  fail "tag-pair map is not valid JSON: $cwe_owasp_map"
else
  tagpair_bad=0
  tagpair_warn=0
  tagpair_ok=0
  # Extract (cat, cwe, owasp) triples. Handles same-line pairs and the
  # line-wrapped case where the A##:2025 tag wraps onto the following line.
  # Output: one "cat<TAB>CWE-N<TAB>A##:2025" per unique triple per file.
  while IFS="$(printf '\t')" read -r cat cwe owasp; do
    [ -n "$cwe" ] || continue
    [ -n "$owasp" ] || continue
    # 1. canonical match?
    canon="$(jq -r --arg c "$cwe" '.canonical[$c] // empty' "$cwe_owasp_map")"
    if [ -n "$canon" ] && [ "$canon" = "$owasp" ]; then
      tagpair_ok=$((tagpair_ok + 1))
      continue
    fi
    # 2. documented (cwe, owasp, cat) context override?
    if jq -e --arg c "$cwe" --arg o "$owasp" --arg f "$cat" \
        '.context_overrides[]? | select(.cwe == $c and .owasp == $o)
         | (.cats // []) | index($f)' "$cwe_owasp_map" >/dev/null 2>&1; then
      tagpair_ok=$((tagpair_ok + 1))
      note "override OK: $cat  $cwe / $owasp (documented context roll-up)"
      continue
    fi
    # 3. CWE absent from canonical table (and not overridden) → WARN, not fail.
    if [ -z "$canon" ]; then
      note "WARN: $cat  $cwe / $owasp — $cwe absent from canonical web-Top-10 table; not a documented override (add to .context_overrides if intentional)"
      tagpair_warn=$((tagpair_warn + 1))
      continue
    fi
    # 4. genuine mismap: CWE is canonical but tagged to the wrong A##.
    fail "tag-mismap: $cat  $cwe / $owasp — canonical for $cwe is $canon, and no documented context override authorises $owasp"
    tagpair_bad=$((tagpair_bad + 1))
  done < <(
    for f in skills/security-audit/steps/deepdive/cat-*.md; do
      [ -f "$f" ] || continue
      base="$(basename "$f")"
      # Extract ONLY genuine `CWE-N / A##:2025` ASSERTION adjacencies (the
      # finding-line format `→ **SEV** / CWE-N / A##:2025`). Anchoring on the
      # CWE-slash-A## adjacency — and iterating ALL matches per line — avoids
      # (a) mis-pairing when two assertions share a line, and (b) false pairs
      # from prose where a CWE and an A## merely co-occur. The line-wrap case
      # (CWE-N / at EOL, A##:2025 leading the next line) is handled separately.
      awk -v base="$base" '
        { line[NR] = $0 }
        END {
          for (i = 1; i <= NR; i++) {
            cur = line[i]
            # (a) same-line adjacent pairs — iterate every match
            s = cur
            while (match(s, /CWE-[0-9]+[[:space:]]*\/[[:space:]]*`?A(0[0-9]|10):2025/)) {
              tok = substr(s, RSTART, RLENGTH)
              match(tok, /CWE-[0-9]+/);        c = substr(tok, RSTART, RLENGTH)
              match(tok, /A(0[0-9]|10):2025/); o = substr(tok, RSTART, RLENGTH)
              emit(base, c, o)
              s = substr(s, RSTART + RLENGTH)
            }
            # (b) line-wrap: "... CWE-N /" at EOL, "A##:2025 ..." next line
            if (cur ~ /CWE-[0-9]+[[:space:]]*\/[[:space:]]*$/) {
              nxt = (i < NR ? line[i+1] : "")
              if (nxt ~ /^[[:space:]]*`?A(0[0-9]|10):2025/) {
                t = cur; c = ""
                while (match(t, /CWE-[0-9]+/)) { c = substr(t, RSTART, RLENGTH); t = substr(t, RSTART + RLENGTH) }
                match(nxt, /A(0[0-9]|10):2025/); o = substr(nxt, RSTART, RLENGTH)
                if (c != "") emit(base, c, o)
              }
            }
          }
        }
        function emit(b, c, o,   key) {
          key = b SUBSEP c SUBSEP o
          if (!(key in seen)) { seen[key] = 1; print b "\t" c "\t" o }
        }
      ' "$f"
    done
  )
  if [ "$tagpair_bad" -eq 0 ]; then
    pass
    note "all tag-pairs valid ($tagpair_ok matched canonical/override, $tagpair_warn warned)"
  else
    note "$tagpair_bad tag-mismap(s) found ($tagpair_ok valid, $tagpair_warn warned)"
  fi
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
