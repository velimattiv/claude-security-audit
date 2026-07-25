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

# --- 4d. R1-F2: a FABRICATED scope_evidence predicate is refused -------------
# The release claims "a wrong inventory cannot launder a gap into a pass". Until
# R1 that was false: any non-empty `predicate` string was trusted verbatim and
# the source at the cited line was never read.
tmp_fab=$(mktemp /tmp/coll-fab-XXXX.json)
python3 - "$tmp_fab" <<'EOF'
import json, sys
d = json.load(open('tests/fixtures/collection-scoping/laundered/collections.json'))
d['collections'][0]['scope_evidence']['predicate'] = "eq(reports.authorId, session.user.id)"
json.dump(d, open(sys.argv[1], 'w'))
EOF
$V "$tmp_fab" $FIX/laundered/profile.json --source-root $FIX/laundered/source-app \
   --partition fab --out /tmp/cs-fab.jsonl --quiet
grep -q 'does NOT appear at' /tmp/cs-fab.jsonl \
  && ok "C5 refuses a predicate that is not at the cited file:line" \
  || bad "fabricated predicate accepted — laundering claim is false"
rm -f "$tmp_fab"

# --- 4e. R1-F3: caller-token matching is token-scoped, not substring ---------
if python3 - <<'EOF'
import importlib.util, sys
s = importlib.util.spec_from_file_location('vc','skills/security-audit/lib/validate-collection-scoping.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
# "scheme.name" contains "me.", "oracle.status" contains "acl". Substring
# matching scored both as caller-bound and silently suppressed C1.
assert not m.predicate_binds_caller("eq(scheme.name, 'x')"), "'me.' substring FP"
assert not m.predicate_binds_caller("eq(oracle.status,'live')"), "'acl' substring FP"
assert m.predicate_binds_caller("eq(decks.ownerId, session.user.id)")
assert m.predicate_binds_caller("where(userId = req.user.id)")
EOF
then ok "caller tokens match on token boundaries, not substrings"
else bad "substring fail-open in predicate_binds_caller"
fi

# --- 4f. R1-F6: Mongoose Model.find({}) yields a candidate ------------------
tmp_mongo=$(mktemp -d "${TMPDIR:-/tmp}/mongo-XXXXXX")
mkdir -p "$tmp_mongo/routes"
printf 'router.get("/users", async (req,res) => {\n  const all = await User.find({});\n  res.json(all);\n});\n' \
  > "$tmp_mongo/routes/users.js"
printf '{"schema_version":1,"collections":[],"dismissed":[]}\n' > "$tmp_mongo/collections.json"
out="$($V "$tmp_mongo/collections.json" --source-root "$tmp_mongo" --partition mg 2>&1)"
echo "$out" | grep -q "UNACCOUNTED.*users.js" \
  && ok "Mongoose Model.find() is a candidate (ecosystem not inert)" \
  || bad "Mongoose list query invisible to the extractor"
case "$tmp_mongo" in /tmp/mongo-*|"${TMPDIR%/}"/mongo-*) rm -rf "$tmp_mongo" ;; esac

# --- 4g. R2-F1: the evidence window must not absorb the auth gate above it ---
# The R1 fix read +/-3 lines around scope_evidence.line and scored the whole
# blur. In the motivating example the auth gate (`const session = ...`) sits two
# lines above the query, so "session" leaked in and the bug passed CLEAN again.
tmp_pw=$(mktemp -d "${TMPDIR:-/tmp}/pw-XXXXXX")
mkdir -p "$tmp_pw/server/api"
cat > "$tmp_pw/server/api/decks.get.ts" <<'EOF'
export default defineEventHandler(async (event) => {
  const session = await requireRole(event, 'reader')
  const rows = await db.select().from(decks)
    .where(and(eq(decks.scope, 'user'), isNull(decks.deletedAt)))
  return { data: rows }
})
EOF
cat > "$tmp_pw/collections.json" <<'EOF'
{"schema_version":1,"collections":[{"id":"c1","handler_file":"server/api/decks.get.ts","line":3,
 "entity":"Deck","returns":"collection","row_scope":"caller_bound",
 "scope_evidence":{"file":"server/api/decks.get.ts","line":4,"predicate":"eq(decks.scope, 'user')"},
 "endpoint_gate":"requireRole reader","coverage":"complete"}],"dismissed":[]}
EOF
out="$($V "$tmp_pw/collections.json" $FIX/tree-bug/profile.json --source-root "$tmp_pw" \
        --partition pw 2>&1)"; rc=$?
{ [ "$rc" -eq 1 ] && echo "$out" | grep -q "C1"; } \
  && ok "an auth gate above the query does not count as row scoping" \
  || bad "evidence window leaks the auth gate — motivating bug passes again (rc=$rc)"
case "$tmp_pw" in /tmp/pw-*|"${TMPDIR%/}"/pw-*) rm -rf "$tmp_pw" ;; esac

# --- 4h. R2-F5: camelCase caller identifiers must still count ---------------
if python3 - <<'EOF'
import importlib.util
s = importlib.util.spec_from_file_location('vc','skills/security-audit/lib/validate-collection-scoping.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
# Token-exact matching without camelCase splitting scored all four as NOT
# caller-bound, flagging correctly-scoped handlers as unscoped.
for p in ("eq(decks.owner, authUserId)", "eq(d.o, currentUserId)",
          "eq(d.o, viewerId)", "eq(d.o, callerId)"):
    assert m.predicate_binds_caller(p), p
# ...without reopening the substring fail-open.
for p in ("eq(scheme.name,'x')", "eq(oracle.status,'live')",
          "eq(reports.status,'published')"):
    assert not m.predicate_binds_caller(p), p
EOF
then ok "camelCase caller ids recognised; substring FPs still rejected"
else bad "caller-token matching regression"
fi

# --- 4i. R2-F6: the Mongoose anchor must not fire on an array .find() -------
tmp_noise=$(mktemp -d "${TMPDIR:-/tmp}/noise-XXXXXX")
mkdir -p "$tmp_noise/server/api"
printf 'export function label(dto: any) {\n  const role = Roles.find(r => r.id === dto.roleId)\n  return role?.label\n}\n' \
  > "$tmp_noise/server/api/roles.controller.ts"
printf '{"schema_version":1,"collections":[],"dismissed":[]}\n' > "$tmp_noise/collections.json"
out="$($V "$tmp_noise/collections.json" --source-root "$tmp_noise" --partition nz 2>&1)"; rc=$?
{ [ "$rc" -eq 0 ] && ! echo "$out" | grep -q "UNACCOUNTED"; } \
  && ok "capitalised-receiver array .find() is NOT a candidate (no FP storm)" \
  || bad "Roles.find(r => ...) trips the coverage gate — anchor too broad"
case "$tmp_noise" in /tmp/noise-*|"${TMPDIR%/}"/noise-*) rm -rf "$tmp_noise" ;; esac

# --- 4j. R2-F2: catch-all detection is behavioural, not a spelling list ------
if python3 - <<'EOF'
import importlib.util
s = importlib.util.spec_from_file_location('vp','skills/security-audit/lib/validate-partition-coverage.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
# `*/**` matches every file below any top-level dir but is not the literal "**".
assert m.is_catch_all("*/**"), "*/** evades catch-all detection"
assert m.is_catch_all("**")
assert not m.is_catch_all("src/**"), "src/** wrongly called a catch-all"
assert not m.is_catch_all("services/api/**")
EOF
then ok "catch-all detected behaviourally (*/** does not evade)"
else bad "catch-all detection is still a spelling allowlist"
fi

# --- 4k. R2-F8: a failed coverage gate is stamped INTO the artifact ---------
$V $FIX/omitted/collections.json $FIX/tree-bug/profile.json \
   --source-root $FIX/tree-bug/source-app --partition om \
   --out /tmp/cs-gate.jsonl --quiet
[ -f /tmp/cs-gate.jsonl.incomplete ] \
  && ok "a failed coverage gate leaves an .incomplete sidecar" \
  || bad "no in-artifact signal that the gate failed"

# --- 4l. R3-F1: a method-chain continuation must not be truncated -----------
# The R2 forward-only window stopped at the cited line when its own brackets
# balanced, dropping the .where() on the NEXT line and flagging a correctly
# scoped handler.
if python3 - <<'EOF'
import importlib.util
s = importlib.util.spec_from_file_location('vc','skills/security-audit/lib/validate-collection-scoping.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
chain = ["const rows = await db.select().from(decks)",
         "  .where(and(eq(decks.userId, session.user.id), isNull(decks.deletedAt)))"]
assert m.predicate_binds_caller(m._statement_at(chain, 0)), "chain continuation truncated"
# ...and the auth gate ABOVE the query still cannot leak in.
leak = ["  const session = await requireRole(event, 'reader')",
        "  const rows = await db.select().from(decks)",
        "    .where(and(eq(decks.scope, 'user'), isNull(decks.deletedAt)))"]
assert not m.predicate_binds_caller(m._statement_at(leak, 1)), "auth gate leaked"
EOF
then ok "method-chain predicate read forward; auth gate above still excluded"
else bad "statement window regression (truncation or leak)"
fi

# --- 4m. R3-F4: generic caller words need an identity token beside them ------
if python3 - <<'EOF'
import importlib.util
s = importlib.util.spec_from_file_location('vc','skills/security-audit/lib/validate-collection-scoping.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
# camelCase splitting made a bare generic word match unrelated compounds.
for p in ("eq(c.callerName,'x')", "eq(c.callerPhoneNumber,'x')",
          "eq(s.sessionType,'live')", "eq(s.sessionRegionId, 3)"):
    assert not m.predicate_binds_caller(p), p
for p in ("eq(decks.ownerId, session.user.id)", "eq(d.o, viewerId)",
          "eq(d.o, callerId)", "eq(decks.owner, authUserId)"):
    assert m.predicate_binds_caller(p), p
EOF
then ok "generic caller words require an adjacent identity token"
else bad "generic-word matching too permissive or too strict"
fi

# --- 4n. R3-F5: handler boundary covers the common Express/Lambda shapes ----
if python3 - <<'EOF'
import importlib.util
s = importlib.util.spec_from_file_location('vc','skills/security-audit/lib/validate-collection-scoping.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
for shape in ("export function list(req,res) {", "exports.handler = async (e) => {",
              "const handler = async (req,res) => {", "module.exports = async (r) => {"):
    assert m._NEXT_HANDLER_RE.search(shape), shape
EOF
then ok "C2b handler boundary matches export/exports/arrow-const shapes"
else bad "_NEXT_HANDLER_RE misses a common handler declaration"
fi

# --- 4o. R3-F6: a passing run clears a stale .incomplete sidecar ------------
$V $FIX/omitted/collections.json $FIX/tree-bug/profile.json \
   --source-root $FIX/tree-bug/source-app --partition om --out /tmp/cs-side.jsonl --quiet
$V $FIX/tree-bug/collections.json $FIX/tree-bug/profile.json \
   --source-root $FIX/tree-bug/source-app --partition ok --out /tmp/cs-side.jsonl --quiet
[ ! -f /tmp/cs-side.jsonl.incomplete ] \
  && ok "a later passing run clears the stale .incomplete sidecar" \
  || bad "stale .incomplete sidecar survives a clean run"

# --- 4p. R3-F3: a backend-heavy monorepo is not a catch-all -----------------
tmp_mono=$(mktemp -d "${TMPDIR:-/tmp}/mono-XXXXXX")
mkdir -p "$tmp_mono/src/a" "$tmp_mono/web"
i=1; while [ $i -le 24 ]; do printf 'export const x=%d\n' "$i" > "$tmp_mono/src/a/f$i.ts"; i=$((i+1)); done
printf 'export const w=1\n' > "$tmp_mono/web/app.ts"
cat > "$tmp_mono/parts.json" <<'EOF'
{"partitions":[{"id":"backend","path":"src","paths_included":["src/**"],"risk":{"score":7},"depth":"full"},
               {"id":"frontend","path":"web","paths_included":["web/**"],"risk":{"score":3},"depth":"full"}]}
EOF
$P "$tmp_mono/parts.json" --source-root "$tmp_mono" --ignore /dev/null --quiet
[ $? -eq 0 ] \
  && ok "a dominant but directory-anchored partition is not a catch-all" \
  || bad "95%-of-tree backstop misfires on a backend-heavy monorepo"
case "$tmp_mono" in /tmp/mono-*|"${TMPDIR%/}"/mono-*) rm -rf "$tmp_mono" ;; esac

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

# R1-F1: a catch-all glob alongside specific partitions must FAIL. Before R1 it
# made every file "matched", so the gate reported full coverage no matter what
# was omitted — passing in exactly the case its own docstring exists to prevent.
tmp_ca=$(mktemp /tmp/parts-ca-XXXX.json)
python3 - "$tmp_ca" <<'EOF'
import json, sys
d = json.load(open('tests/fixtures/partition-coverage/partitions.json'))
d['partitions'].append({"id": "catch-all", "kind": "repo", "path": ".",
                        "paths_included": ["**"],
                        "risk": {"score": 1, "rationale": "everything else"},
                        "depth": "inventory-only"})
json.dump(d, open(sys.argv[1], 'w'))
EOF
out="$($P "$tmp_ca" --source-root tests/fixtures/partition-coverage/repo --ignore /dev/null 2>&1)"
rc=$?
{ [ "$rc" -eq 1 ] && echo "$out" | grep -q "catch-all glob sits alongside"; } \
  && ok "a catch-all glob fails the gate instead of swallowing the tree" \
  || bad "catch-all still passes the coverage gate (rc=$rc)"
# The escape hatch is a full bypass by construction (a catch-all matches
# everything, so nothing can be unmatched). It must therefore stay LOUD: exit 0
# is allowed, silence is not.
out="$($P "$tmp_ca" --source-root tests/fixtures/partition-coverage/repo \
        --ignore /dev/null --allow-catch-all 2>&1)"; rc=$?
{ [ "$rc" -eq 0 ] && echo "$out" | grep -q "WARN: a catch-all glob" \
    && echo "$out" | grep -q "not evidence of anything"; } \
  && ok "--allow-catch-all passes but says the coverage proves nothing" \
  || bad "--allow-catch-all is a silent bypass (rc=$rc)"
rm -f "$tmp_ca"

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
