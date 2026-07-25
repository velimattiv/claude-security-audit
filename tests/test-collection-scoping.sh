#!/usr/bin/env bash
# tests/test-collection-scoping.sh — deterministic regression test for the
# collection-scoping reconciliation (lib/validate-collection-scoping.py) and the
# Phase-1 partition coverage gate (lib/validate-partition-coverage.py).
# CI-runnable, no Claude needed.
#
# The headline assertion is the handoff's acceptance test #1: the tree-bug
# fixture — a faithful reproduction of the handler that passed a full v2.4 audit
# with a clean bill — must produce a finding with NO operator hint about
# traversal, sharing, or enumeration.
#
# Asserts:
#   1. tree-bug is CAUGHT and PRECISE: C1 on both unscoped collections, C2 on the
#      decoration antipattern, C4 on the test that pins the bug, and ZERO
#      findings on the correctly-scoped and genuinely-public endpoints.
#   2. Findings carry the capability tags the Phase-7 severity gate needs.
#   3. An omitted collection FAILS the coverage gate fail-closed ("UNACCOUNTED").
#   4. A row that CLAIMS scoping it cannot evidence is rewritten to unscoped (C5)
#      — the inventory cannot launder a false claim into a pass.
#   5. Emitted findings validate against finding-schema.json.
#   6. Partition coverage FAILS on a directory that matches no partition glob.
#
# Exit 0 = all assertions pass.
set -u
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

LIB="skills/security-audit/lib"
V="python3 $LIB/validate-collection-scoping.py"
P="python3 $LIB/validate-partition-coverage.py"
FIX="tests/fixtures/collection-scoping"
fails=0
ok() { printf "  ok: %s\n" "$*"; }
bad() { printf "  FAIL: %s\n" "$*" >&2; fails=$((fails + 1)); }

echo "=== Collection-scoping deterministic test ==="

# --- 1. tree-bug: caught AND precise ----------------------------------------
out="$($V $FIX/tree-bug/collections.json $FIX/tree-bug/profile.json \
        --source-root $FIX/tree-bug/source-app --partition app \
        --out /tmp/cs-test.jsonl 2>&1)"
rc=$?
[ "$rc" -eq 1 ] && ok "tree-bug exits 1" || bad "tree-bug exit=$rc (want 1)"

total=$(grep -c . /tmp/cs-test.jsonl)
[ "$total" -eq 4 ] && ok "tree-bug exact finding count (4)" \
  || bad "tree-bug count=$total (want 4)"

c1=$(grep -c 'validate-collection-scoping.py:C1' /tmp/cs-test.jsonl)
[ "$c1" -eq 2 ] && ok "C1 fires on both unscoped collections" \
  || bad "C1=$c1 (want 2)"

grep -q 'validate-collection-scoping.py:C2' /tmp/cs-test.jsonl \
  && ok "C2 catches authorization-by-decoration" || bad "C2 missing"
grep -q 'validate-collection-scoping.py:C4' /tmp/cs-test.jsonl \
  && ok "C4 catches the test that pins the bug" || bad "C4 missing"

# The gate is PRESENT on the vulnerable handler — the finding must say so, or a
# triager reads "no auth" and closes it as a false positive.
grep -q 'Authentication was used where per-row authorization was required' /tmp/cs-test.jsonl \
  && ok "C1 names the actual defect shape (authn used for authz)" \
  || bad "C1 does not explain the gate-present case"

# PRECISION: the correctly-scoped endpoint and the public catalogue must produce
# nothing. A lens that flags these is a lens nobody keeps enabled.
me=$(grep -c 'me/decks' /tmp/cs-test.jsonl)
prod=$(grep -c 'products/index' /tmp/cs-test.jsonl)
[ "$me" -eq 0 ]   && ok "zero FPs on the caller-bound collection" \
  || bad "$me FP(s) on server/api/me/decks.get.ts"
[ "$prod" -eq 0 ] && ok "zero FPs on the public_resources catalogue" \
  || bad "$prod FP(s) on server/api/products/index.get.ts"

# --- 2. capability tags feed the Phase-7 severity gate -----------------------
if python3 - <<'EOF'
import json, sys
rows = [json.loads(l) for l in open('/tmp/cs-test.jsonl') if l.strip()]
c1 = [r for r in rows if r['sources'][0]['detail'].endswith('C1')]
assert c1, "no C1 rows"
for r in c1:
    assert any(p.startswith('knows:any_') for p in r['postconditions']), \
        f"C1 {r['id']} does not grant a knows: capability — the enumeration half " \
        "of the chain would be untagged and R1 could not discharge it"
EOF
then ok "C1 findings grant knows:any_* (chainable by compose-attack-paths)"
else bad "C1 findings missing knows:any_* postcondition"
fi

# --- 3. omitted collection trips the fail-closed coverage gate ---------------
out="$($V $FIX/omitted/collections.json $FIX/tree-bug/profile.json \
        --source-root $FIX/tree-bug/source-app --partition om 2>&1)"
rc=$?
[ "$rc" -eq 1 ] && ok "omitted exits 1" || bad "omitted exit=$rc (want 1)"
echo "$out" | grep -q "UNACCOUNTED" \
  && ok "omitted trips the coverage gate" || bad "omitted coverage gate silent"
echo "$out" | grep -qi "COLLECTION COVERAGE GATE (fail-closed)" \
  && ok "omitted reports fail-closed" || bad "omitted no fail-closed message"

# --- 4. a laundered scoping claim is refused (C5) ---------------------------
out="$($V $FIX/laundered/collections.json $FIX/laundered/profile.json \
        --source-root $FIX/laundered/source-app --partition la \
        --out /tmp/cs-laundered.jsonl 2>&1)"
rc=$?
c5=$(grep -c 'validate-collection-scoping.py:C5' /tmp/cs-laundered.jsonl)
c1l=$(grep -c 'validate-collection-scoping.py:C1' /tmp/cs-laundered.jsonl)
{ [ "$rc" -eq 1 ] && [ "$c5" -eq 1 ] && [ "$c1l" -eq 1 ]; } \
  && ok "C5 refuses an unevidenced scoping claim and C1 then fires" \
  || bad "laundered: rc=$rc c5=$c5 c1=$c1l (want rc1, 1 C5, 1 C1)"

# --- 4b. coverage:incomplete is fail-closed on its own ----------------------
# "We could not read the handler" is an open question, not a pass — it must fail
# even when no candidate set is supplied.
tmp_inc=$(mktemp /tmp/coll-inc-XXXX.json)
python3 - "$tmp_inc" <<'EOF'
import json, sys
d = json.load(open('tests/fixtures/collection-scoping/tree-bug/collections.json'))
d['collections'] = [dict(d['collections'][2], coverage='incomplete')]  # the SCOPED one
json.dump(d, open(sys.argv[1], 'w'))
EOF
out="$($V "$tmp_inc" $FIX/tree-bug/profile.json --partition inc 2>&1)"; rc=$?
{ [ "$rc" -eq 1 ] && echo "$out" | grep -q "coverage=incomplete"; } \
  && ok "coverage:incomplete fails the gate with no candidate set" \
  || bad "coverage:incomplete passed quietly (rc=$rc)"
rm -f "$tmp_inc"

# --- 4c. C2b: the inventory cannot deny decoration the source shows ---------
tmp_dec=$(mktemp /tmp/coll-dec-XXXX.json)
python3 - "$tmp_dec" <<'EOF'
import json, sys
d = json.load(open('tests/fixtures/collection-scoping/tree-bug/collections.json'))
row = dict(d['collections'][0], decorates_permission=False, decoration_fields=[])
d['collections'] = [row]
d['dismissed'] = [{"candidate": "server/api/decks/index.get.ts",
                   "reason": "out of scope for this assertion"},
                  {"candidate": "server/api/me/decks.get.ts", "reason": "ditto"},
                  {"candidate": "server/api/products/index.get.ts", "reason": "ditto"}]
json.dump(d, open(sys.argv[1], 'w'))
EOF
$V "$tmp_dec" $FIX/tree-bug/profile.json --source-root $FIX/tree-bug/source-app \
   --partition dec --out /tmp/cs-dec.jsonl --quiet
grep -q 'Permission-shaped field' /tmp/cs-dec.jsonl \
  && ok "C2b catches decoration the inventory denies" \
  || bad "C2b did not fire on a handler with canWrite and no filter"
rm -f "$tmp_dec"

# --- 5. schema conformance --------------------------------------------------
if python3 "$LIB/validate-findings.py" \
     --schema "$LIB/finding-schema.json" --cwe-map "$LIB/cwe-map.json" \
     /tmp/cs-test.jsonl --quiet 2>/dev/null; then
  ok "emitted findings validate against finding-schema"
else
  bad "emitted findings FAILED schema validation"
fi

# --- 6. partition coverage gate ---------------------------------------------
echo "  -- partition coverage --"
out="$($P tests/fixtures/partition-coverage/partitions.json \
        --source-root tests/fixtures/partition-coverage/repo \
        --ignore /dev/null 2>&1)"
rc=$?
[ "$rc" -eq 1 ] && ok "unmatched directory fails Phase 1" \
  || bad "partition coverage exit=$rc (want 1)"
echo "$out" | grep -q "server/api/content/tree.get.ts" \
  && ok "names the unpartitioned handler" || bad "unmatched file not named"
echo "$out" | grep -q "DEEP-DIVE CUT LINE" \
  && ok "reports the deep-dive cut line" || bad "cut line not reported"

# A manifest that DOES cover everything must pass — the gate must not be a
# permanent red light.
tmp_parts=$(mktemp /tmp/parts-XXXX.json)
python3 - "$tmp_parts" <<'EOF'
import json, sys
d = json.load(open('tests/fixtures/partition-coverage/partitions.json'))
d['partitions'].append({
    "id": "server-api", "kind": "service", "path": "server/api",
    "paths_included": ["server/api/**"],
    "risk": {"score": 8, "rationale": "public ingress"}, "depth": "full"})
json.dump(d, open(sys.argv[1], 'w'))
EOF
$P "$tmp_parts" --source-root tests/fixtures/partition-coverage/repo \
   --ignore /dev/null --quiet
[ $? -eq 0 ] && ok "a complete manifest passes (gate is not a permanent red)" \
  || bad "complete manifest still fails — gate is unusable"
rm -f "$tmp_parts"

echo
if [ "$fails" -eq 0 ]; then
  echo "=== PASS ==="
  exit 0
fi
echo "=== FAIL — $fails assertion(s) ===" >&2
exit 1
