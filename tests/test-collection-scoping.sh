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
#      — the inventory cannot launder a false claim into a pass — while a merely
#      MIS-CITED predicate is C6, a separate claim with a separate follow-up.
#   5. The v2.6 truth table (§4u): raw-SQL scoping idioms bind the caller
#      (tagged templates, ${...} interpolation, Postgres RLS GUCs) WITHOUT
#      reopening the literal-laundering hole those blanks exist to close.
#   6. Capability tags are minted from the scoping DETERMINATION, never from the
#      entity name (§4w) — an unearned reads:*_pii escalates its neighbours.
#   7. Emitted findings validate against finding-schema.json.
#   8. Partition coverage FAILS on a directory that matches no partition glob.
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

# --- 4d. R1-F2: a MIS-CITED scope_evidence predicate is refused --------------
# The release claims "a wrong inventory cannot launder a gap into a pass". Until
# R1 that was false: any non-empty `predicate` string was trusted verbatim and
# the source at the cited line was never read.
#
# v2.6 splits the two claims that used to share this finding: C6 says the
# CITATION is wrong, C5 says there is NO caller predicate at the cited line.
# Here both hold (the inventory cites a predicate that isn't there, and what IS
# there filters on a literal), so both fire — and C1 follows from C5.
tmp_fab=$(mktemp /tmp/coll-fab-XXXX.json)
python3 - "$tmp_fab" <<'EOF'
import json, sys
d = json.load(open('tests/fixtures/collection-scoping/laundered/collections.json'))
d['collections'][0]['scope_evidence']['predicate'] = "eq(reports.authorId, session.user.id)"
json.dump(d, open(sys.argv[1], 'w'))
EOF
$V "$tmp_fab" $FIX/laundered/profile.json --source-root $FIX/laundered/source-app \
   --partition fab --out /tmp/cs-fab.jsonl --quiet
if python3 - <<'EOF'
import json
rows = [json.loads(l) for l in open('/tmp/cs-fab.jsonl') if l.strip()]
by = {r['sources'][0]['detail'].rsplit(':', 1)[-1]: r for r in rows}
assert set(by) == {"C5", "C6", "C1"}, sorted(by)
assert "does NOT appear there" in by["C6"]["description"], by["C6"]["description"]
# C6 is about the EVIDENCE, so it must not push a capability nobody proved into
# the composition graph.
assert by["C6"]["category"] == "methodology", by["C6"]["category"]
assert by["C6"]["postconditions"] == [], by["C6"]["postconditions"]
# ...and it must not be the one claiming there is no predicate. That conflation
# is what sent reviewers hunting for a missing WHERE clause on 9 of 14 sampled
# false positives whose predicate was real and one frame up.
assert "no caller-derived predicate" not in by["C6"]["title"]
assert "no caller-derived predicate" in by["C5"]["title"]
EOF
then ok "a mis-cited predicate yields C6 (citation) AND C5 (no predicate), split"
else bad "mis-cited predicate: laundering claim false, or C5/C6 still conflated"
fi
rm -f "$tmp_fab"

# --- 4d-bis. v2.6 2.3: a wrong CITATION to a line that DOES bind the caller is
# a bookkeeping defect, not a disclosure. This is the case the split exists for:
# before it, `fabricated` alone forced row_scope=unscoped and C1 fired HIGH on a
# handler that was correctly scoped all along.
tmp_cit=$(mktemp /tmp/coll-cit-XXXX.json)
python3 - "$tmp_cit" <<'EOF'
import json, sys
d = json.load(open('tests/fixtures/collection-scoping/tree-bug/collections.json'))
row = dict(d['collections'][2])                     # me-decks: correctly scoped
row['scope_evidence'] = dict(row['scope_evidence'],
                             predicate="eq(decks.ownerId, ctx.principal.id)")
d['collections'] = [row]
d['dismissed'] = [{"candidate": f, "reason": "out of scope for this assertion"}
                  for f in ("server/api/content/tree.get.ts",
                            "server/api/decks/index.get.ts",
                            "server/api/products/index.get.ts")]
json.dump(d, open(sys.argv[1], 'w'))
EOF
$V "$tmp_cit" $FIX/tree-bug/profile.json --source-root $FIX/tree-bug/source-app \
   --partition cit --out /tmp/cs-cit.jsonl --quiet
if python3 - <<'EOF'
import json
rules = [json.loads(l)['sources'][0]['detail'].rsplit(':', 1)[-1]
         for l in open('/tmp/cs-cit.jsonl') if l.strip()]
assert rules == ["C6"], rules   # the citation is wrong; the handler is not
EOF
then ok "a wrong citation to a caller-bound line yields C6 only (no C5, no C1)"
else bad "wrong citation still forces unscoped — C5/C6 split did not take"
fi
rm -f "$tmp_cit"

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

# --- 4q. R4: the three vectors round 4 found outside the suite's coverage ----
if python3 - <<'EOF'
import importlib.util
s = importlib.util.spec_from_file_location('vc','skills/security-audit/lib/validate-collection-scoping.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)

# R4-F1: an INDENTED local arrow helper is not a handler boundary. Treating it as
# one truncated C2b's window and flagged a correctly-filtered collection.
assert not m._NEXT_HANDLER_RE.search("  const formatDate = (d) => d.toISOString()")
assert m._NEXT_HANDLER_RE.search("const handler = async (req,res) => {")
assert m._NEXT_HANDLER_RE.search("exports.handler = async (e) => {")

# R4-F2: a bare generic word standing alone as an identifier IS the caller,
# whatever the column it is compared against is called.
for p in ("row.subject === jwt", "row.author === principal", "row.actor === claims",
          "row.editor === viewer", "row.creator === me", "row.requester === caller"):
    assert m.predicate_binds_caller(p), p
# ...but as a camelCase fragment it depends on what it modifies.
for p in ("eq(c.callerName,'x')", "eq(s.sessionType,'live')",
          "eq(c.callerPhoneNumber,'x')", "eq(s.sessionRegionId, 3)"):
    assert not m.predicate_binds_caller(p), p
for p in ("eq(d.o, viewerId)", "eq(d.o, callerId)", "eq(decks.owner, authUserId)",
          "eq(decks.ownerId, session.user.id)"):
    assert m.predicate_binds_caller(p), p

# R4-F3: a comma-continued SECOND declarator must not be absorbed into the
# statement being scored (it leaked session.user.id from unrelated code).
comma = ["const rows = db.select().from(decks).where(eq(decks.scope,'user'))",
         "  , unused = session.user.id;"]
assert not m.predicate_binds_caller(m._statement_at(comma, 0)), "comma leak"
# ...while a genuine method-chain continuation is still read.
chain = ["const rows = await db.select().from(decks)",
         "  .where(and(eq(decks.userId, session.user.id), isNull(decks.deletedAt)))"]
assert m.predicate_binds_caller(m._statement_at(chain, 0)), "chain truncated"
EOF
then ok "R4 vectors: indented helper, standalone generic word, comma declarator"
else bad "R4 regression (handler boundary / generic word / comma continuation)"
fi

# --- 4r. R5: string literals are data, not caller references ----------------
if python3 - <<'EOF'
import importlib.util
s = importlib.util.spec_from_file_location('vc','skills/security-audit/lib/validate-collection-scoping.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)

# R5-F1: the identifier-component split strips quotes, so a literal enum value
# scored as a real identifier — the founding `scope = 'user'` bug wearing a
# different literal. A quoted value can never bind the caller.
for p in ("eq(decks.scope, 'session')", 'eq(decks.status, "viewer")',
          "eq(d.role,'principal')", "eq(decks.scope,'user')", "eq(x, `caller`)"):
    assert not m.predicate_binds_caller(p), p
for p in ("eq(decks.ownerId, session.user.id)", "row.author === principal",
          "eq(d.o, viewerId)", "where(userId = req.user.id)"):
    assert m.predicate_binds_caller(p), p

# R5-F2: the Python def boundary kept the ^\s* that R4 removed everywhere else.
# Column 0 is a module-level handler; an indented def is a handler only when it
# takes self/cls (a class-based view), not when it is a local helper.
assert not m._NEXT_HANDLER_RE.search("    def format_row(row):")
assert m._NEXT_HANDLER_RE.search("def list_items(request):")
assert m._NEXT_HANDLER_RE.search("    def get(self, request):")
assert m._NEXT_HANDLER_RE.search("    async def post(self, req):")
EOF
then ok "quoted literals are not caller refs; python def boundary anchored"
else bad "R5 regression (literal laundering / python def boundary)"
fi

# --- 4s. R6: literal scanning must survive escapes, prose apostrophes -------
if python3 - <<'PYEOF'
import importlib.util
s = importlib.util.spec_from_file_location('vc','skills/security-audit/lib/validate-collection-scoping.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)

# A naive `'[^']*'` pairs a prose apostrophe with the next unrelated quote and
# blanks a genuine caller reference in between (false positive on safe code).
assert m.predicate_binds_caller("eq(a,'x') it's real eq(b, viewerId)")
assert m.predicate_binds_caller("eq(decks.ownerId, session.user.id) // don't scope")
assert m.predicate_binds_caller(r"eq(x, 'it's') eq(b, viewerId)")
# ...while a literal still never binds the caller.
assert not m.predicate_binds_caller("eq(decks.scope, 'session')")
assert not m.predicate_binds_caller("eq(decks.scope,'user')")

# A decorated indented member is a handler boundary even with no self
# (@action / @api_view are real DRF idioms). R7 narrowed this from a bare
# `@\w+` — which matched @property inside the current handler — to decorators
# that actually register a handler, plus @staticmethod when a def follows.
assert m._NEXT_HANDLER_RE.search("    @staticmethod\n    def get(request):")
assert m._NEXT_HANDLER_RE.search("    @action(detail=True)")
assert not m._NEXT_HANDLER_RE.search("    @property")
assert not m._NEXT_HANDLER_RE.search("    def format_row(row):")
PYEOF
then ok "literal scanner handles escapes/apostrophes; decorated handlers bound C2b"
else bad "R6 regression (literal scanning / decorated handler boundary)"
fi

# --- 4t. R7: comment stripping is line-scoped; decorators are route-scoped ---
if python3 - <<'PYEOF'
import importlib.util
s = importlib.util.spec_from_file_location('vc','skills/security-audit/lib/validate-collection-scoping.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)

# R7-F1: a trailing comment must blank to end of LINE. Blanking to end of string
# erased the .where() two lines below in a fluent chain.
chain = ["const rows = await db.select().from(decks) // active connection",
         "  .where(and(eq(decks.userId, session.user.id), isNull(decks.deletedAt)))"]
assert m.predicate_binds_caller(m._statement_at(chain, 0)), "comment ate the chain"
assert not m.predicate_binds_caller("eq(decks.scope, 'session')")

# R7-F2: only handler-REGISTERING decorators bound C2b. A bare @\w+ matched
# @property / @Input() inside the current handler and truncated the window.
for d in ("    @property", "    @cached_property", "    @Input()"):
    assert not m._NEXT_HANDLER_RE.search(d), d
for d in ("    @action(detail=True)", "    @api_view(['GET'])",
          "    @staticmethod\n    def get(request):",
          "    @app.route('/x')", "@router.get('/y')", "    @bp.route('/z')"):
    assert m._NEXT_HANDLER_RE.search(d), d
PYEOF
then ok "comment stripping line-scoped; only route decorators bound C2b"
else bad "R7 regression (comment overreach / decorator boundary too broad)"
fi

# --- 4u. v2.6 2.1+2.2: THE TRUTH TABLE ---------------------------------------
# The acceptance gate for the template/GUC work. A/B/G are the shapes v2.5 could
# not see; D/E/F are the shapes it must keep refusing. A patch that fixes the
# first three by also flipping the last three has traded one failure mode for
# another and does not pass — which is why they are asserted together.
#
# Neither half of the fix is sufficient alone, and the table proves it: B needs
# the template work (the ${...} was blanked with the rest of the body), A and G
# need the GUC pre-pass (the caller's identity is spelled inside a single-quoted
# literal, which _strip_literals blanks — correctly, per D).
if python3 - <<'PYEOF'
import importlib.util
s = importlib.util.spec_from_file_location('vc','skills/security-audit/lib/validate-collection-scoping.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)

TABLE = [
    ("A", "const ownerClause = sql`EXISTS (SELECT 1 FROM cou_owner co WHERE "
          "co.teammate_id = NULLIF(current_setting('app.user_teammate_id', true), "
          "'')::uuid)`", True),
    ("B", "const rows = await tx.execute(sql`SELECT * FROM t WHERE teammate_id = "
          "${session.teammateId}`)", True),
    ("C", "db.select().from(project).where(eq(project.teammateId, session.teammateId))", True),
    ("D", "db.select().from(decks).where(eq(decks.scope, 'session'))", False),
    ("E", "throw new Error(`session expired`)", False),
    ("F", "sql`SELECT * FROM posts WHERE status = 'published'`", False),
    ("G", "sql`path <@ current_setting('app.user_org_path')::ltree`", True),
]
for name, src, want in TABLE:
    got = m.predicate_binds_caller(src)
    assert got is want, f"case {name}: got {got}, want {want} — {src}"
    # LENGTH PRESERVATION. _statement_at hands this function text taken at real
    # source offsets; a transform that changes length silently misaligns every
    # citation downstream of it.
    assert len(m._strip_literals(src)) == len(src), f"case {name}: length changed"

# Length preservation is a property of the transform, not of these seven strings.
for src in ("", "`", "'", "a`b", "sql`x${", "sql`a${'b'}c`", "`${`${x}`}`",
            "x // ' unterminated\n.where(eq(a, viewerId))", "\\", "sql`a\\`b`",
            "${", "}", "sql`a${b}`", "'\\'", '"unclosed', "#c\nsql`${u.id}`"):
    assert len(m._strip_literals(src)) == len(src), repr(src)

# Templates nest and the scanners recurse into each other. The input is source
# from the repo under audit, so the depth is not ours to bound — past ~500 the
# Python stack overflows and an uncaught RecursionError kills the whole
# fail-closed gate instead of failing it.
for n in (24, 25, 600, 5000):
    deep = "sql`" + "${`" * n + "x" + "`}" * n + "`"
    assert len(m._strip_literals(deep)) == len(deep), n
# ...while ordinary one-level nesting is still read as code.
assert m.predicate_binds_caller("sql`a = ${sql`${session.userId}`}`")

# The template work must not become a new laundering channel: a tagged body is
# CODE, but the string literals inside it are still data.
assert not m.predicate_binds_caller("sql`SELECT * FROM d WHERE scope = 'session'`")
assert not m.predicate_binds_caller("sql`SELECT * FROM d WHERE role = 'viewer'`")
# ...and an untagged template is data whatever it says.
assert not m.predicate_binds_caller("`eq(decks.ownerId, session.user.id)`")
assert not m.predicate_binds_caller("eq(x, `caller`)")
# A KEYWORD before the backtick is not a tag. `return`/`throw`/`case` end in an
# identifier character, so without the keyword check a message template would be
# preserved as code — and a spurious "binds the caller" SUPPRESSES C1, which is
# the expensive direction.
for p in ("return `session expired`", "throw `no viewer for caller`",
          "case `principal`:", "typeof `me`", "await `claims`"):
    assert not m.predicate_binds_caller(p), p
# ...while a real tag application, including one on a call or index result, is.
for p in ("sql`x = ${session.userId}`", "db.raw()`${session.userId}`",
          "tags[0]`${session.userId}`", "await sql`${session.userId}`"):
    assert m.predicate_binds_caller(p), p
# A GUC that is not an identity GUC says nothing about who is calling.
assert not m.predicate_binds_caller("sql`x = current_setting('app.tenant_mode')`")
assert not m.predicate_binds_caller("sql`x = current_setting('statement_timeout')`")
PYEOF
then ok "truth table A/B/C/G bind, D/E/F do not; _strip_literals preserves length"
else bad "v2.6 truth table FAILED (template awareness / RLS GUC / length)"
fi

# --- 4v. v2.6 2.1+2.2 end to end: precision bought without a miss ------------
# Two correctly-scoped raw-SQL handlers (an RLS GUC and a ${...} interpolation)
# must produce ZERO findings, while their literal-only sibling — same tagged
# template shape — must still be caught.
$V $FIX/rls-scoped/collections.json $FIX/rls-scoped/profile.json \
   --source-root $FIX/rls-scoped/source-app --partition rls \
   --out /tmp/cs-rls.jsonl --quiet
rc=$?
if python3 - <<'EOF'
import json
rows = [json.loads(l) for l in open('/tmp/cs-rls.jsonl') if l.strip()]
files = {r['file'] for r in rows}
assert "server/api/orgs/index.get.ts" not in files, "FP on the RLS-scoped handler"
assert "server/api/tasks/index.get.ts" not in files, "FP on the interpolated handler"
rules = sorted(r['sources'][0]['detail'].rsplit(':', 1)[-1] for r in rows)
assert rules == ["C1", "C5"], rules
EOF
then ok "RLS/interpolated queries are silent; the literal-only sibling still fires"
else bad "rls-scoped fixture: precision lost, or the control stopped firing"
fi
[ "$rc" -eq 1 ] && ok "rls-scoped exits 1 on the literal-only handler" \
  || bad "rls-scoped exit=$rc (want 1)"

# --- 4w. v2.6 1.3: capability tags are minted from the determination ---------
# postconditions_for used to synthesise knows:any_<e>_id / reads:any_<e>_pii from
# the entity NAME for every row, scoped or not. 47% of all capability tags in the
# composition graph came from there, and 31 of 44 false HIGH+ findings carried a
# reads:*_pii they had not earned — which R1/R3 then composed, escalating their
# NEIGHBOURS (true findings included) to CRITICAL.
if python3 - <<'EOF'
import importlib.util
s = importlib.util.spec_from_file_location('vc','skills/security-audit/lib/validate-collection-scoping.py')
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
meta = {"owner_cols": ["ownerId"], "pii_cols": ["email"]}
earned = m.postconditions_for("Deck", meta, "tree", True)
assert earned == ["knows:any_deck_id", "reads:any_deck_metadata",
                  "knows:any_deck_path", "reads:any_deck_pii"], earned
unearned = m.postconditions_for("Deck", meta, "tree", False)
assert unearned == ["reads:own_deck_metadata"], unearned
# Non-empty: lib/capability-lexicon.md §5 requires it for collection_scope, and
# `own` cannot escalate a neighbour — containment flows any -> narrower only.
assert unearned and not any("any_" in c for c in unearned)
EOF
then ok "postconditions_for mints any_* only on a verified-unscoped determination"
else bad "capability tags still synthesised from the entity name"
fi

# End to end: a decoration finding on a CORRECTLY SCOPED collection of a
# PII-bearing entity must not walk away with reads:any_user_pii.
tmp_cap=$(mktemp /tmp/coll-cap-XXXX.json)
python3 - "$tmp_cap" <<'EOF'
import json, sys
d = json.load(open('tests/fixtures/collection-scoping/tree-bug/collections.json'))
row = dict(d['collections'][2], entity="User",      # User has pii_cols=['email']
           decorates_permission=True, decoration_fields=["canWrite"],
           filters_after_decoration=False)
unk = dict(d['collections'][1], id="unknown-scope", row_scope="unknown")
d['collections'] = [row, unk]
d['dismissed'] = [{"candidate": f, "reason": "out of scope for this assertion"}
                  for f in ("server/api/content/tree.get.ts",
                            "server/api/products/index.get.ts")]
json.dump(d, open(sys.argv[1], 'w'))
EOF
$V "$tmp_cap" $FIX/tree-bug/profile.json --source-root $FIX/tree-bug/source-app \
   --partition cap --out /tmp/cs-cap.jsonl --quiet
if python3 - <<'EOF'
import json
rows = [json.loads(l) for l in open('/tmp/cs-cap.jsonl') if l.strip()]
scoped = [r for r in rows if r['file'].endswith('me/decks.get.ts')]
assert scoped, "the C2 decoration finding disappeared"
for r in scoped:
    assert r['postconditions'] == ["reads:own_user_metadata"], r['postconditions']
# row_scope=unknown is NOT a verified-unscoped determination. C1 still fires on
# it (downgraded), but "we could not tell" must not grant knows:any_* — a
# POSSIBLE guess that escalates its neighbours to CRITICAL is the exact failure
# this gate exists for.
unk = [r for r in rows if r['file'].endswith('decks/index.get.ts')]
assert unk, "C1 stopped firing on row_scope=unknown"
for r in unk:
    assert not any(c.startswith(("knows:any_", "reads:any_")) for c in r['postconditions']), \
        r['postconditions']
EOF
then ok "a scoped/unknown collection grants no any_* capability it did not earn"
else bad "unearned any_* capability still minted for scoped or unknown rows"
fi
rm -f "$tmp_cap"

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
