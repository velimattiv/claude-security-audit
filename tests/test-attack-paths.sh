#!/usr/bin/env bash
# tests/test-attack-paths.sh — deterministic regression test for the Phase-7
# severity gate (lib/compose-attack-paths.py). CI-runnable, no Claude needed.
#
# These are the handoff's acceptance tests #2-#4 plus a negative control and the
# lifecycle gates. Each maps to an observed real-world failure, not a
# hypothetical:
#
#   chain      A(post=[knows:ids]) HIGH + B(pre=[knows:ids], post=[reads:content])
#              MEDIUM  ->  B escalates to CRITICAL, exit 1.        (R1 + R3)
#   prose      "Combined with H1, ..." with NO capability tags at all ->
#              M6 still escalates. Five lines of regex that alone would have
#              caught the historical case in March.                (R2)
#   precision  A LOW finding reachable by the same persona but contributing
#              nothing to the chain must NOT be escalated. The reference
#              implementation escalated bystanders; the backward slice does not.
#   ratchet    MEDIUM -> LOW with no reason FAILS; MEDIUM -> LOW WITH a recorded
#              fix_commit reason PASSES; a vanished HIGH is itself a finding. (R4)
#   lifecycle  96-day-old CONFIRMED HIGH with no fix and no acceptance FAILS;
#              the same finding with an owned, unexpired acceptance does not.
#                                                                   (L1/L2/L3)
#   clean      Real findings that chain to nothing must exit 0.
#
# Exit 0 = all assertions pass.
set -u
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

LIB="skills/security-audit/lib"
C="python3 $LIB/compose-attack-paths.py"
FIX="tests/fixtures/attack-paths"
NOW="2026-07-25T00:00:00Z"
PROFILE="tests/fixtures/collection-scoping/tree-bug/profile.json"
fails=0
ok() { printf "  ok: %s\n" "$*"; }
bad() { printf "  FAIL: %s\n" "$*" >&2; fails=$((fails + 1)); }

echo "=== Attack-path severity gate deterministic test ==="

# --- 1. chain: capability composition escalates (acceptance #2) -------------
out="$($C $FIX/chain/findings.jsonl --profile "$PROFILE" --now "$NOW" \
        --rewrite /tmp/ap-chain.jsonl --json-summary /tmp/ap-chain.json 2>&1)"
rc=$?
[ "$rc" -eq 1 ] && ok "chain exits 1" || bad "chain exit=$rc (want 1)"
echo "$out" | grep -q "app:idor:0002: MEDIUM -> CRITICAL" \
  && ok "the chained MEDIUM escalates to CRITICAL" \
  || bad "chained MEDIUM not escalated to CRITICAL"
echo "$out" | grep -q "CROWN JEWELS REACHED: reads:any_deck_content" \
  && ok "crown jewel reached from an unprivileged persona" \
  || bad "crown jewel not detected"

# PRECISION: the bystander LOW must survive untouched.
if python3 - <<'EOF'
import json
rows = {r['id']: r for r in (json.loads(l) for l in open('/tmp/ap-chain.jsonl') if l.strip())}
assert rows['app:crypto:0003']['severity'] == 'LOW', \
    "bystander finding was escalated — backward slice is not working"
assert rows['app:idor:0002']['severity_asserted'] == 'MEDIUM'
assert rows['app:idor:0002']['severity_computed'] == 'CRITICAL'
assert rows['app:idor:0002']['severity_history'][-1]['reason_kind'] == 'chain_escalation'
EOF
then ok "bystander not escalated; severity_asserted/computed/history stamped"
else bad "precision or rewrite-stamping regression"
fi

python3 -c "
import json,sys
s=json.load(open('/tmp/ap-chain.json'))
sys.exit(0 if s['blocking'] and s['escalations']==2 else 1)" \
  && ok "json-summary reports blocking + escalation count" \
  || bad "json-summary wrong"

# --- 2. prose-only chain (acceptance #3) ------------------------------------
# No preconditions, no postconditions anywhere — only an English sentence.
out="$($C $FIX/prose/findings.jsonl --now "$NOW" 2>&1)"; rc=$?
{ [ "$rc" -eq 1 ] && echo "$out" | grep -q "\[R2\] M6: MEDIUM -> HIGH"; } \
  && ok "prose-only chain escalates via R2 (no capability tags at all)" \
  || bad "prose-only chain MISSED — R2 regression"

# --- 3. severity ratchet (acceptance #4) ------------------------------------
out="$($C $FIX/ratchet/findings.jsonl --baseline $FIX/ratchet/baseline.json \
        --run-id run-2026-07-25 --now "$NOW" --out /tmp/ap-gov.jsonl 2>&1)"
rc=$?
[ "$rc" -eq 1 ] && ok "ratchet exits 1" || bad "ratchet exit=$rc (want 1)"
echo "$out" | grep -q "Unjustified severity downgrade: app:auth:0001 MEDIUM -> LOW" \
  && ok "R4 blocks the unjustified downgrade" || bad "R4 missed the downgrade"
grep -q "app:auth:0002" /tmp/ap-gov.jsonl \
  && bad "R4 flagged a downgrade that DID record a fix_commit reason" \
  || ok "R4 accepts a downgrade with a recorded reason (not a permanent red)"
echo "$out" | grep -q "disappeared_unexplained" \
  && ok "a vanished HIGH is itself a finding" || bad "disappeared HIGH not flagged"

# A disappeared finding whose file changed is explained, not flagged.
printf 'server/api/s/[shortId]/verify.get.ts\n' > /tmp/ap-changed.txt
out="$($C $FIX/ratchet/findings.jsonl --baseline $FIX/ratchet/baseline.json \
        --changed-files /tmp/ap-changed.txt --run-id run-2026-07-25 --now "$NOW" 2>&1)"
echo "$out" | grep -q "disappeared_unexplained" \
  && bad "changed-files evidence did not explain the disappearance" \
  || ok "a code change explains a disappearance"

# A justification recorded for a DIFFERENT severity must not license this one.
# Otherwise one reason logged in March covers every later downgrade, which is
# exactly the ladder the historical finding walked down (MEDIUM -> LOW -> INFO).
tmp_stale=$(mktemp /tmp/ap-stale-XXXX.jsonl)
python3 - "$tmp_stale" <<'EOF'
import json, sys
rows = [json.loads(l) for l in open('tests/fixtures/attack-paths/ratchet/findings.jsonl') if l.strip()]
for r in rows:
    if r['fingerprint'] == 'bbbbbbbbbbbb':
        r['severity_history'][0]['severity'] = 'MEDIUM'   # stale: not the current LOW
with open(sys.argv[1], 'w') as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")
EOF
out="$($C "$tmp_stale" --baseline $FIX/ratchet/baseline.json \
        --run-id run-2026-07-25 --now "$NOW" 2>&1)"
echo "$out" | grep -q "app:auth:0002" \
  && ok "a justification recorded for another severity does not license this one" \
  || bad "stale severity justification accepted — R4 ladder regression"
rm -f "$tmp_stale"

# --- 4. lifecycle gates -----------------------------------------------------
out="$($C $FIX/lifecycle/findings.jsonl --now "$NOW" --out /tmp/ap-life.jsonl 2>&1)"
rc=$?
[ "$rc" -eq 1 ] && ok "lifecycle exits 1" || bad "lifecycle exit=$rc (want 1)"
echo "$out" | grep -q "\[L1\]" && ok "L1 fires on the 132-day-old CONFIRMED HIGH" \
  || bad "L1 age gate did not fire"
echo "$out" | grep -q "\[L2\]" && ok "L2 fires on acceptance with no owner/expiry" \
  || bad "L2 did not fire"
echo "$out" | grep -q "\[L3\]" && ok "L3 fires on verified-with-no-test" \
  || bad "L3 did not fire"
grep -q "app:auth:0002" /tmp/ap-life.jsonl \
  && bad "L1 flagged a finding with a valid owned, unexpired acceptance" \
  || ok "an owned, unexpired acceptance is respected"

# --- 4b. R1-F4/F5: the compounded ratchet bypass -----------------------------
# Fingerprints are sha1(file:line:cwe:category), so adding an import above the
# handler un-matches the finding from its baseline entry. Combined with
# file-granular --changed-files evidence, round 1 proved a CONFIRMED MEDIUM->LOW
# downgrade with no reason exiting 0 and printing "governance gates clean" — the
# exact failure this gate exists to prevent, via a different mechanical path.
tmp_drift=$(mktemp /tmp/ap-drift-XXXX.jsonl)
tmp_ch=$(mktemp /tmp/ap-ch-XXXX.txt)
python3 - "$tmp_drift" <<'EOF'
import json, sys
rows = [json.loads(l) for l in open('tests/fixtures/attack-paths/ratchet/findings.jsonl') if l.strip()]
r = [x for x in rows if x['fingerprint'] == 'aaaaaaaaaaaa'][0]
del r['fingerprint']          # sub-agent emitted none; Phase 7 recomputes
r['line'] = 41                # an import was added above the handler
with open(sys.argv[1], 'w') as f:
    f.write(json.dumps(r) + "\n")
EOF
printf 'server/api/decks/[id]/build-output.get.ts\nserver/api/assets/proxy.get.ts\nserver/api/s/[shortId]/verify.get.ts\n' > "$tmp_ch"
out="$($C "$tmp_drift" --baseline $FIX/ratchet/baseline.json --changed-files "$tmp_ch" \
        --run-id run-2026-07-25 --now "$NOW" 2>&1)"; rc=$?
{ [ "$rc" -eq 1 ] && echo "$out" | grep -q "Unjustified severity downgrade"; } \
  && ok "R4 survives line drift (baseline matched by (file,cwe) window)" \
  || bad "line drift still blinds the ratchet (rc=$rc)"

# File-granular disappearance evidence must be visible, not silently trusted.
echo "$out" | grep -q "explained only at file granularity" \
  && ok "file-granular disappearance evidence is surfaced, not assumed" \
  || bad "bare-path --changed-files silently explains a vanished HIGH"

# With a line RANGE that does not cover the finding, it is not explained at all.
printf 'server/api/s/[shortId]/verify.get.ts:900-910\n' > "$tmp_ch"
out="$($C $FIX/ratchet/findings.jsonl --baseline $FIX/ratchet/baseline.json \
        --changed-files "$tmp_ch" --run-id run-2026-07-25 --now "$NOW" 2>&1)"
echo "$out" | grep -q "disappeared_unexplained" \
  && ok "a line range away from the finding does not explain it" \
  || bad "out-of-range change accepted as an explanation"
rm -f "$tmp_drift" "$tmp_ch"

# --- 4c. R3-F2: baseline slots go to the BEST match, not the first one ------
# First-come-first-served let a weaker nearby decoy consume the baseline entry,
# leaving the true continuation with base=None — silently exempt from R4, the one
# gate it most needed.
tmp_b=$(mktemp /tmp/ap-b-XXXX.json); tmp_f=$(mktemp /tmp/ap-f-XXXX.jsonl)
python3 - "$tmp_b" "$tmp_f" <<'EOF'
import json, sys
base = {"schema_version":2,"audit_id":"b","skill_version":"2.4.0","git_head":"x",
 "created_at":"2026-03-15T00:00:00Z","repo_topology":{},"partition_manifest":[],
 "surface":[],"keystone_files":[],"config":{},"scanner_versions":{},
 "methodology_coverage":{},"ignored":[],
 "findings_carryover":[{"fingerprint":"ffffffffffff",
   "title":"Unscoped collection returns other users decks","severity":"HIGH",
   "confidence":"CONFIRMED","file":"r.ts","line":100,"cwe":"CWE-1220",
   "category":"collection_scope","first_seen_at":"2026-03-15T00:00:00Z"}]}
json.dump(base, open(sys.argv[1],'w'))
def mk(i,line,title):
    return {"id":f"a:collection_scope:{i:04d}","severity":"LOW","confidence":"CONFIRMED",
      "category":"collection_scope","partition":"a","file":"r.ts","line":line,
      "cwe":"CWE-1220","owasp_ids":["A01:2025"],"title":title,"description":"d",
      "sources":[{"kind":"grep"}],"preconditions":[],"postconditions":["knows:any_x_id"]}
rows=[mk(1,110,"Totally different problem about decks collection"),   # decoy FIRST
      mk(2,101,"Unscoped collection returns other users decks")]      # true continuation
with open(sys.argv[2],'w') as f:
    for r in rows: f.write(json.dumps(r)+"\n")
EOF
out="$($C "$tmp_f" --baseline "$tmp_b" --run-id r --now "$NOW" 2>&1)"; rc=$?
{ [ "$rc" -eq 1 ] && echo "$out" | grep -q "a:collection_scope:0002"; } \
  && ok "the near-exact match wins the baseline slot, not the earlier decoy" \
  || bad "baseline assignment is order-dependent (rc=$rc)"
# Scope the check to the R4 line: the decoy legitimately appears in the persona
# reachability listing, which says nothing about baseline assignment.
echo "$out" | grep "Unjustified severity downgrade" | grep -q "0001" \
  && bad "the decoy consumed the baseline entry" \
  || ok "the decoy did not consume the baseline entry"
rm -f "$tmp_b" "$tmp_f"

# --- 5. negative control ----------------------------------------------------
$C $FIX/clean/findings.jsonl --now "$NOW" --quiet
[ $? -eq 0 ] && ok "clean fixture exits 0 (gate is not a permanent red)" \
  || bad "clean fixture failed — gate fires on everything"

# --- 6. governance findings validate against the schema ---------------------
if python3 "$LIB/validate-findings.py" \
     --schema "$LIB/finding-schema.json" --cwe-map "$LIB/cwe-map.json" \
     /tmp/ap-gov.jsonl --quiet 2>/dev/null; then
  ok "governance findings validate against finding-schema"
else
  bad "governance findings FAILED schema validation"
fi
if python3 "$LIB/validate-findings.py" \
     --schema "$LIB/finding-schema.json" --cwe-map "$LIB/cwe-map.json" \
     /tmp/ap-chain.jsonl --quiet 2>/dev/null; then
  ok "rewritten findings validate against finding-schema"
else
  bad "rewritten findings FAILED schema validation"
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "=== PASS ==="
  exit 0
fi
echo "=== FAIL — $fails assertion(s) ===" >&2
exit 1
