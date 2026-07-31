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
#              Plus a LOW third leg -> CRITICAL: the UNCAPPED rung, asserted
#              explicitly so §7.4's ±1 context cap can never leak into R3.
#
# v2.6 escalation matrix (epic §3.4) — R3 is gated on evidence, not on a cap:
#   unreachable  a CONTRIBUTING member marked structurally_unreachable WITH a
#                cite suppresses the chain, and says so out loud.
#   uncited      the same claim with NO cite does NOT suppress. The field must
#                not become a free pass — that is how `confidence: CONFIRMED`
#                became a 9.6%-true label worth +1 rung.
#   flagged      gated_by_runtime_flag does NOT suppress. A flag an admin can
#                toggle in a deployed environment is live, not theoretical.
#   bystander    a member OUTSIDE the contributing slice cannot veto a chain it
#                is not load-bearing in.
#   annex        a heuristic row on the same file:line as a judgement finding is
#                annexed: no severity, absent from the capability graph. An
#                ORPHAN heuristic row still surfaces (the recall preservation).
#   contract     the prose in steps/phase-07-synthesis.md and the behaviour of
#                compose-attack-paths.py agree — asserted, not read. v2.5 shipped
#                "±1 rung regardless of how many triggers fire" next to a
#                composer that set CRITICAL, for a whole release, undetected.
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

# UNCAPPED (v2.6): §7.4 caps CONTEXT-SIGNAL adjustment at ±1 rung; R3 chain
# composition is a different mechanism and is not capped. The founding case was
# a MEDIUM whose mitigation was discharged by a HIGH in the same document —
# cap R3 at one rung and it becomes HIGH, the rating that let it rot 96 days.
echo "$out" | grep -q "app:secret_sprawl:0004: LOW -> CRITICAL" \
  && ok "R3 is uncapped: a contributing LOW goes straight to CRITICAL (3 rungs)" \
  || bad "LOW -> CRITICAL did not fire — the §7.4 ±1 cap has leaked into R3"

# PRECISION: the bystander LOW must survive untouched.
if python3 - <<'EOF'
import json
rows = {r['id']: r for r in (json.loads(l) for l in open('/tmp/ap-chain.jsonl') if l.strip())}
assert rows['app:crypto:0003']['severity'] == 'LOW', \
    "bystander finding was escalated — backward slice is not working"
assert rows['app:idor:0002']['severity_asserted'] == 'MEDIUM'
assert rows['app:idor:0002']['severity_computed'] == 'CRITICAL'
assert rows['app:idor:0002']['severity_history'][-1]['reason_kind'] == 'chain_escalation'
# v2.6: every finding computed CRITICAL names the composition rule that made it
# so. An unexplained CRITICAL is what made the calibrated run hard to triage —
# one cluster arrived with 13 of 15 CRITICAL, eight of them asserted LOW/INFO.
for fid in ('app:idor:0002', 'app:secret_sprawl:0004', 'app:collection_scope:0001'):
    r = rows[fid]
    assert r['severity_computed'] == 'CRITICAL', fid
    assert r.get('escalation_rules'), f"{fid} computed CRITICAL with no escalation_rules"
    assert 'R3' in r['escalation_rules'], fid
assert 'escalation_suppressed_by' not in rows['app:idor:0002']
EOF
then ok "bystander not escalated; severity_asserted/computed/history stamped"
else bad "precision or rewrite-stamping regression"
fi

# 3, not 2: v2.6 adds the LOW third leg that proves R3 is uncapped.
python3 -c "
import json,sys
s=json.load(open('/tmp/ap-chain.json'))
sys.exit(0 if s['blocking'] and s['escalations']==3 and not s['suppressed_escalations'] else 1)" \
  && ok "json-summary reports blocking + escalation count, no suppressions" \
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

# --- 4d. v2.6 escalation matrix: R3 is gated on EVIDENCE, not on a cap -------
# The defect: a finding asserted LOW and computed CRITICAL on a genuine chain,
# for a dev-mode path whose isDemoCapableEnv allowlists {local, sandbox} with a
# fail-closed `unknown` default. The analyst who rated it LOW already knew that;
# the information had no channel to reach the composer. deployment_reachability
# is that channel — and it only counts when it is cited.

# (a0) two-route: a cited blocker on ONE route must not veto a SECOND live route.
# contributing_slice() returns the UNION of all routes to a jewel, so membership
# alone is the wrong suppression test — it would silence a live CRITICAL on the
# strength of an unrelated finding's unreachability, which is the precise
# failure this gate exists to prevent. Suppression is decided by re-composition.
out="$($C $FIX/two-route/findings.jsonl --profile "$PROFILE" --now "$NOW" 2>&1)"
grep -q "CRITICAL app:idor:0002" <<<"$out" \
  && ok "two-route: the live route still escalates despite a blocked sibling route" \
  || bad "two-route: a blocked route suppressed a second, reachable route"
grep -q "R3 SUPPRESSED" <<<"$out" \
  && bad "two-route: suppressed a chain that is still reachable without the blocker" \
  || ok "two-route: no suppression while an unblocked path to the jewel remains"
grep -qE "^\s+HIGH\s+app:auth:0001" <<<"$out" \
  && ok "two-route: the unreachable member does not ride the live route's escalation" \
  || bad "two-route: escalated a member whose own route is dead"

# (a) unreachable: a CONTRIBUTING member, structurally_unreachable WITH a cite.
out="$($C $FIX/unreachable/findings.jsonl --profile "$PROFILE" --now "$NOW" \
        --rewrite /tmp/ap-unreach.jsonl --json-summary /tmp/ap-unreach.json 2>&1)"
echo "$out" | grep -q "CROWN JEWELS REACHED" \
  && ok "unreachable: the chain still composes (suppression is not blindness)" \
  || bad "unreachable: chain no longer composes at all"
echo "$out" | grep -q -- "-> CRITICAL" \
  && bad "unreachable: R3 escalated a chain with a cited unreachable member" \
  || ok "unreachable: cited structurally_unreachable suppresses the R3 CRITICAL"
echo "$out" | grep -q "SUPPRESSED ESCALATIONS" \
  && ok "unreachable: the suppression is REPORTED, not silent" \
  || bad "unreachable: suppression was silent — the E1 failure shape"
# R1 must be untouched: suppression declines the CRITICAL rung, it does not
# remove the finding or disable the other rules.
echo "$out" | grep -q "\[R1\] app:idor:0002: MEDIUM -> HIGH" \
  && ok "unreachable: R1 still applies under a suppressed R3" \
  || bad "unreachable: suppression wrongly disabled R1"
if python3 - <<'EOF'
import json
rows = {r['id']: r for r in (json.loads(l) for l in open('/tmp/ap-unreach.jsonl') if l.strip())}
s = json.load(open('/tmp/ap-unreach.json'))
assert rows['app:idor:0002']['severity_computed'] == 'HIGH'
assert rows['app:idor:0002']['escalation_suppressed_by'] == 'app:auth:0001'
assert rows['app:secret_sprawl:0004']['severity_computed'] == 'LOW'
ids = {e['id'] for e in s['suppressed_escalations']}
assert ids == {'app:auth:0001', 'app:idor:0002', 'app:secret_sprawl:0004'}, ids
e = [x for x in s['suppressed_escalations'] if x['id'] == 'app:idor:0002'][0]
assert e['would_have_been'] == 'CRITICAL' and e['blocked_by'] == 'app:auth:0001'
assert 'isDemoCapableEnv' in e['evidence'], "the blocking cite is not carried"
EOF
then ok "unreachable: escalation_suppressed_by + cite reach the finding and the summary"
else bad "unreachable: suppression provenance not recorded"
fi

# (b) uncited: the SAME claim with no cite must NOT suppress.
out="$($C $FIX/uncited/findings.jsonl --profile "$PROFILE" --now "$NOW" \
        --json-summary /tmp/ap-uncited.json 2>&1)"
echo "$out" | grep -q "app:secret_sprawl:0004: LOW -> CRITICAL" \
  && ok "uncited: an uncited structurally_unreachable does NOT suppress" \
  || bad "uncited: the field became a free pass — no cite required"
echo "$out" | grep -q "NO cite" \
  && ok "uncited: the ignored claim is reported, not swallowed" \
  || bad "uncited: an uncited reachability claim was ignored SILENTLY"
python3 -c "
import json,sys
s=json.load(open('/tmp/ap-uncited.json'))
sys.exit(0 if not s['suppressed_escalations']
         and s['uncited_unreachable_claims']==['app:auth:0001'] else 1)" \
  && ok "uncited: summary records the claim and suppresses nothing" \
  || bad "uncited: summary wrong"

# A whitespace-only cite is not a cite. Same free-pass hole, one space wide.
tmp_ws=$(mktemp /tmp/ap-ws-XXXX.jsonl)
python3 - "$tmp_ws" <<'EOF'
import json, sys
rows = [json.loads(l) for l in
        open('tests/fixtures/attack-paths/uncited/findings.jsonl') if l.strip()]
rows[0]['deployment_reachability']['evidence'] = "   "
with open(sys.argv[1], 'w') as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")
EOF
out="$($C "$tmp_ws" --profile "$PROFILE" --now "$NOW" 2>&1)"
echo "$out" | grep -q "app:secret_sprawl:0004: LOW -> CRITICAL" \
  && ok "uncited: a whitespace-only cite is not a cite" \
  || bad "uncited: whitespace passed as evidence"
rm -f "$tmp_ws"

# (c) flagged: a runtime flag is LIVE, not theoretical.
out="$($C $FIX/flagged/findings.jsonl --profile "$PROFILE" --now "$NOW" \
        --json-summary /tmp/ap-flagged.json 2>&1)"
echo "$out" | grep -q "app:secret_sprawl:0004: LOW -> CRITICAL" \
  && ok "flagged: gated_by_runtime_flag does NOT suppress" \
  || bad "flagged: a runtime flag suppressed an escalation — only build/deploy-time counts"
python3 -c "
import json,sys
s=json.load(open('/tmp/ap-flagged.json'))
sys.exit(0 if not s['suppressed_escalations'] else 1)" \
  && ok "flagged: nothing suppressed" || bad "flagged: summary records a suppression"

# (d) bystander: outside the contributing slice, so it may not veto.
out="$($C $FIX/bystander/findings.jsonl --profile "$PROFILE" --now "$NOW" \
        --json-summary /tmp/ap-bystander.json 2>&1)"
echo "$out" | grep -q "app:secret_sprawl:0004: LOW -> CRITICAL" \
  && ok "bystander: a non-contributing member cannot suppress the chain" \
  || bad "bystander: a bystander vetoed a chain it is not load-bearing in"
echo "$out" | grep -q "not escalated — reachable but not contributing: app:crypto:0003" \
  && ok "bystander: still correctly excluded from the slice itself" \
  || bad "bystander: backward slice regression"
python3 -c "
import json,sys
s=json.load(open('/tmp/ap-bystander.json'))
sys.exit(0 if not s['suppressed_escalations'] else 1)" \
  && ok "bystander: nothing suppressed" || bad "bystander: summary records a suppression"

# --- 4e. Wave 2b: the annex ---------------------------------------------------
# Of the 17 TRUE mechanical findings in the calibrated run, 15 were restatements
# of a deep-dive finding on the same line, and the rules surfaced no unique
# CRITICAL. But they enumerated a credential-exfil class's nine legs at exact
# line granularity, which no agent did. So: re-cast, don't delete.
out="$($C $FIX/annex/findings.jsonl --profile "$PROFILE" --now "$NOW" \
        --rewrite /tmp/ap-annex.jsonl --json-summary /tmp/ap-annex.json 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "annex exits 0 (the annexed jewel tag mints nothing)" \
  || bad "annex exit=$rc (want 0)"
echo "$out" | grep -q "CROWN JEWELS REACHED" \
  && bad "annex: an annexed row's capability tag still reached a crown jewel" \
  || ok "annex: the annexed row is absent from the capability graph"
echo "$out" | grep -q "1 annexed row(s) excluded from the capability graph" \
  && ok "annex: the exclusion is stated, not silent" \
  || bad "annex: exclusion not reported"
echo "$out" | grep -q "ORPHAN ANNEXES" \
  && ok "annex: the orphan heuristic row still surfaces (recall preserved)" \
  || bad "annex: ORPHAN ANNEXES block missing — recall regression"
echo "$out" | grep -q "capability minted ONLY by heuristic_inventory rows: knows:any_report_id" \
  && ok "annex: capability provenance names the heuristic that minted the tag" \
  || bad "annex: heuristic-minted capability is still anonymous (story 1.3)"
if python3 - <<'EOF'
import json
rows = {r['id']: r for r in (json.loads(l) for l in open('/tmp/ap-annex.jsonl') if l.strip())}
s = json.load(open('/tmp/ap-annex.json'))
a = rows['egress:R2:0002']
assert a['severity_computed'] == a['severity_asserted'] == 'HIGH', "annexed row was re-rated"
assert 'escalation_rules' not in a, "an annexed row carries a composition rule"
assert s['annexed_rows'] == ['egress:R2:0002'], s['annexed_rows']
assert s['orphan_annexes'] == ['collections:C1:0003'], s['orphan_annexes']
prov = s['heuristic_minted_capabilities']
assert 'knows:any_report_id' in prov
assert prov['knows:any_report_id']['rule_families'] == ['validate-collection-scoping:C1']
# The annexed row left the graph, so its jewel tag is not even in provenance.
assert 'reads:any_deck_content' not in prov
EOF
then ok "annex: annexed row carries no computed severity; summary splits annex/orphan"
else bad "annex: rewrite or summary regression"
fi

# POSITIVE CONTROL: strip annexed_to and the same row DOES escalate the slice.
# Without this the fixture proves only that the row is inert, not that the
# exclusion is what made it inert.
tmp_an=$(mktemp /tmp/ap-an-XXXX.jsonl)
python3 - "$tmp_an" <<'EOF'
import json, sys
rows = [json.loads(l) for l in
        open('tests/fixtures/attack-paths/annex/findings.jsonl') if l.strip()]
for r in rows:
    r.pop('annexed_to', None)
with open(sys.argv[1], 'w') as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")
EOF
out="$($C "$tmp_an" --profile "$PROFILE" --now "$NOW" 2>&1)"; rc=$?
{ [ "$rc" -eq 1 ] && echo "$out" | grep -q "CROWN JEWELS REACHED"; } \
  && ok "annex positive control: un-annexed, the SAME row reaches a jewel" \
  || bad "annex positive control: the fixture proves nothing (rc=$rc)"
rm -f "$tmp_an"

# --- 4f. the prose and the code agree — asserted, not read -------------------
# v2.5 shipped "±1 rung regardless of how many triggers fire" in §7.4 next to a
# composer that set CRITICAL outright, and nothing detected it for a release.
SYN="skills/security-audit/steps/phase-07-synthesis.md"
$C --print-contract > /tmp/ap-contract-code.txt 2>/dev/null
awk '/^```severity-contract$/{f=1;next} /^```$/{f=0} f' "$SYN" > /tmp/ap-contract-md.txt
[ -s /tmp/ap-contract-md.txt ] \
  && ok "phase-07-synthesis.md carries a severity-contract block" \
  || bad "no severity-contract block in $SYN — prose/code agreement is unasserted"
if diff -u /tmp/ap-contract-md.txt /tmp/ap-contract-code.txt >/tmp/ap-contract.diff 2>&1; then
  ok "the §7.15 contract block and --print-contract agree byte-for-byte"
else
  bad "prose/code severity contract DISAGREE:"; cat /tmp/ap-contract.diff >&2
fi
# And the contract's own claims are what the fixtures above just demonstrated.
grep -q "^r3_escalation_capped = false$" /tmp/ap-contract-code.txt \
  && ok "contract declares R3 uncapped — matched by the LOW -> CRITICAL fixture" \
  || bad "contract claims R3 is capped while the chain fixture escalates 3 rungs"
grep -q "^promotable_evidence = external_scanner$" /tmp/ap-contract-code.txt \
  && ok "contract: only external_scanner earns the §7.4 +1 promotion" \
  || bad "PROMOTABLE_EVIDENCE is not {external_scanner}"
# §7.4's own table must name evidence_class, not the retired confidence rule.
grep -q '`evidence_class == "external_scanner"`.*+1' "$SYN" \
  && ok "§7.4's signal table keys the +1 on evidence_class" \
  || bad "§7.4 still promotes on something other than evidence_class"
grep -q '| `confidence == "CONFIRMED"` | \*\*+1\*\*' "$SYN" \
  && bad "§7.4 still grants +1 for confidence == CONFIRMED (story 1.1 not applied)" \
  || ok "§7.4 no longer promotes on confidence"
grep -q "scanners are mechanical ground truth" "$SYN" \
  && bad "§7.3 still asserts 'scanners are mechanical ground truth' unqualified" \
  || ok "§7.3's category error is gone"

# --- 4g. the methodology and Track D's template agree -----------------------
# Track D owns lib/report-template.md; §7.7 tells the emitter how to fill it.
# When the two drift, the emitter follows §7.7 and silently undoes the story
# the template was written for. These are the seams that actually drifted.
TPL="skills/security-audit/lib/report-template.md"

# (a) story 1.5: class-major / severity-minor. The retired v2.5 sentence must
# be gone — severity-major with class sub-bands still points the reading path
# at the worst pile first, which was the measured harm.
grep -q "grouped by severity (CRITICAL → INFO), within severity" "$SYN" \
  && bad "§7.7 still specifies v2.5 severity-major ordering — story 1.5 undone" \
  || ok "§7.7 no longer specifies severity-major findings ordering"
grep -q "CLASS-MAJOR, SEVERITY-MINOR" "$SYN" \
  && ok "§7.7a specifies class-major / severity-minor ordering" \
  || bad "§7.7a missing — the emitter has no ordering rule to follow"

# (b) the routing table must be exclusive and cover every template destination.
for dest in "What Is Sound" "Annex" "§ C" "§ B" "§ A"; do
  grep -q "$dest" "$SYN" \
    && ok "§7.7a routing names destination: $dest" \
    || bad "§7.7a routing has no destination for $dest"
done

# (c) every v2.6 placeholder Track D added is given semantics in §7.7. A
# placeholder the template prints and the methodology never defines is filled
# by guesswork, which is how {{annex_precision}} would have become a number
# nobody measured.
missing=""
for ph in n_ev_judgement n_ev_scanner n_ev_heuristic n_ev_governance \
          findings_index_rows judgement_critical_block judgement_info_block \
          scanner_critical_block scanner_info_block governance_block \
          refutation_rows unscoped_refutation_ids n_refutations \
          annex_lead_count annex_attached_count annex_orphan_count \
          annex_precision annex_orphan_list \
          sibling_sweeps_run n_high_plus sibling_sites_total \
          escalation_rules_note; do
  grep -q "{{$ph}}" "$TPL" || { missing="$missing $ph(not-in-template)"; continue; }
  grep -q "$ph" "$SYN" || missing="$missing $ph"
done
[ -z "$missing" ] \
  && ok "every v2.6 template placeholder has semantics in §7.7" \
  || bad "placeholders printed by the template but undefined in §7.7:$missing"

# (d) story 4.5 has not landed: the precision column must degrade to a stated
# "not yet measured", never vanish. Absence of data is not evidence of
# precision — an unlabelled band is what §7.7a exists to replace.
grep -q "not yet measured" "$SYN" \
  && ok "§7.7b specifies the 'not yet measured' precision fallback" \
  || bad "§7.7b missing — the precision column can silently vanish"
grep -q "rule_family_precision" skills/security-audit/manifest.yaml 2>/dev/null \
  && ok "manifest.yaml carries rule_family_precision (Track E landed)" \
  || ok "manifest.yaml has no rule_family_precision yet — fallback path is live"

# (e) story 3.3: the fix contradiction check, and the direction it fails in.
grep -q "FIX RECONCILIATION REQUIRED" "$SYN" \
  && ok "§7.4b specifies the fix contradiction block" \
  || bad "§7.4b missing — conflicting fixes still ship silently (story 3.3)"
grep -q "withholds the FIX, never the FINDING" "$SYN" \
  && ok "§7.4b withholds the fix, never the finding" \
  || bad "§7.4b could suppress a finding — a severity-suppression mechanism"

# (f) story 1.1's second door: cross-referencing must not upgrade a row's class.
grep -q "evidence_class\` DOES NOT MOVE" "$SYN" \
  && ok "§7.3 forbids evidence_class promotion on cross-reference" \
  || bad "§7.3 lets a second source upgrade evidence_class — story 1.1 undone"
grep -q "evidence_class\` does not move" \
     skills/security-audit/steps/phase-05-deepdives.md \
  && ok "the matching §5.6 guard is present (both halves of the rule)" \
  || bad "§5.6's evidence_class guard is missing"

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
# The v2.6 fields the composer WRITES must also validate: escalation_suppressed_by
# on a suppressed row, annexed_to / deployment_reachability carried through.
for f in /tmp/ap-unreach.jsonl /tmp/ap-annex.jsonl; do
  if python3 "$LIB/validate-findings.py" \
       --schema "$LIB/finding-schema.json" --cwe-map "$LIB/cwe-map.json" \
       "$f" --quiet 2>/dev/null; then
    ok "$(basename "$f") validates (v2.6 escalation_suppressed_by / annexed_to)"
  else
    bad "$(basename "$f") FAILED schema validation"
  fi
done

echo
if [ "$fails" -eq 0 ]; then
  echo "=== PASS ==="
  exit 0
fi
echo "=== FAIL — $fails assertion(s) ===" >&2
exit 1
