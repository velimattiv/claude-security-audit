#!/usr/bin/env bash
# tests/test-egress.sh — deterministic regression test for the Authorized-Egress
# reconciliation (scripts/validate-egress.py). CI-runnable, no Claude needed.
#
# Asserts:
#   1. The deck-bug fixture (control minted at the resolve layer, never consumed
#      on the byte-serving sinks) is CAUGHT: exit 1, >=1 CRITICAL, and rules
#      R5 (cross-layer), R4 (theatre), R3 (capability-only) all fire.
#   2. The omitted-sink fixture (agent failed to inventory two real candidates)
#      FAILS the coverage gate fail-closed: exit 1 with an "UNACCOUNTED" message.
#   3. Emitted findings validate against finding-schema.json.
#
# Exit 0 = all assertions pass.
set -u
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

V="python3 scripts/validate-egress.py"
FIX="tests/fixtures/egress"
fails=0
ok() { printf "  ok: %s\n" "$*"; }
bad() { printf "  FAIL: %s\n" "$*" >&2; fails=$((fails + 1)); }

echo "=== Authorized-Egress deterministic test ==="

# --- 1. deck-bug: caught AND precise (exact finding set, zero FPs) ----------
out="$($V $FIX/deck-bug/*.json --partition deck --out /tmp/egress-test.jsonl 2>&1)"
rc=$?
[ "$rc" -eq 1 ] && ok "deck-bug exits 1" || bad "deck-bug exit=$rc (want 1)"
total=$(grep -c . /tmp/egress-test.jsonl)
crit=$(grep -c '"severity": "CRITICAL"' /tmp/egress-test.jsonl)
inv=$(grep -c "Invoice" /tmp/egress-test.jsonl)
r1=$(grep -c "validate-egress.py:R1\b" /tmp/egress-test.jsonl)
[ "$total" -eq 7 ] && ok "deck-bug exact finding count (7)" || bad "deck-bug count=$total (want 7)"
[ "$crit" -eq 3 ]  && ok "deck-bug exactly 3 CRITICAL" || bad "deck-bug CRITICAL=$crit (want 3)"
# PRECISION: Invoice is correctly gated (role:billing + X-API-Key in middleware)
# — it MUST produce zero findings. This is the P0-3 false-positive regression.
[ "$inv" -eq 0 ]   && ok "deck-bug: zero FPs on correctly-gated Invoice" || bad "deck-bug: $inv FP(s) on Invoice"
# R1 (substring-consumption) was removed as unsound — it must never appear.
[ "$r1" -eq 0 ]    && ok "deck-bug: no unsound R1 findings" || bad "deck-bug: R1 reappeared ($r1)"
for rule in R5 R3; do
  echo "$out" | grep -q "validate-egress.py:$rule" \
    && ok "deck-bug fires $rule" || bad "deck-bug missing $rule"
done
grep -q "resolve-layer surface" /tmp/egress-test.jsonl \
  && ok "R5 traces gate to resolve layer" || bad "R5 missing resolve-layer trace"
grep -q "verification_probe" /tmp/egress-test.jsonl \
  && ok "findings carry verification_probe" || bad "no verification_probe"

# --- 1b. prose-gap: negation-aware ranker (P0-1 regression) -----------------
# The gap is described in natural language ("no verification check ..."), not the
# magic value "none". A negation-blind ranker emits nothing; ours must fire.
out="$($V $FIX/prose-gap/*.json --partition pg 2>&1)"; rc=$?
{ [ "$rc" -eq 1 ] && echo "$out" | grep -q "CRITICAL"; } \
  && ok "prose-gap caught (negation-aware ranker)" || bad "prose-gap MISSED (negation-blind regression)"

# --- 1c. theatre: R4 zero-reader credential (P0-3 — must be reader-based) ----
out="$($V $FIX/theatre/*.json --partition th --out /tmp/egress-th.jsonl 2>&1)"; rc=$?
thr4=$(grep -c "validate-egress.py:R4" /tmp/egress-th.jsonl)
thtot=$(grep -c . /tmp/egress-th.jsonl)
{ [ "$rc" -eq 1 ] && [ "$thr4" -eq 1 ] && [ "$thtot" -eq 1 ]; } \
  && ok "theatre: exactly 1 R4 (zero-reader credential), no other noise" \
  || bad "theatre: rc=$rc r4=$thr4 total=$thtot (want rc1, 1 R4, 1 total)"

# --- 1d. line-mask: coverage gate is line-scoped, not file-scoped (P0-2) -----
out="$($V $FIX/line-mask/*.json --partition lm 2>&1)"; rc=$?
{ [ "$rc" -eq 1 ] && echo "$out" | grep -q "UNACCOUNTED.*99"; } \
  && ok "line-mask: line-99 sink NOT masked by line-5 sink (line-scoped gate)" \
  || bad "line-mask: file-granular fail-open regression"

# --- 2. omitted-sink fails the coverage gate fail-closed --------------------
out="$($V $FIX/omitted-sink/*.json --partition deck 2>&1)"
rc=$?
[ "$rc" -eq 1 ] && ok "omitted-sink exits 1" || bad "omitted-sink exit=$rc (want 1)"
echo "$out" | grep -q "UNACCOUNTED" \
  && ok "omitted-sink trips coverage gate" || bad "omitted-sink coverage gate silent"
echo "$out" | grep -qi "coverage gate (fail-closed)" \
  && ok "omitted-sink reports fail-closed" || bad "omitted-sink no fail-closed message"

# --- 3. emitted findings validate against the schema ------------------------
if python3 scripts/validate-findings.py \
     --schema skills/security-audit/lib/finding-schema.json \
     --cwe-map skills/security-audit/lib/cwe-map.json \
     /tmp/egress-test.jsonl --quiet 2>/dev/null; then
  ok "emitted findings validate against finding-schema"
else
  bad "emitted findings FAILED schema validation"
fi

# --- 4. extractor recall over the synthetic source app ----------------------
# The adversarial review's sharpest point: the deck-bug fixture stubs the hard
# step (source -> inventory). This asserts the deterministic extractor actually
# SEES sinks of every modality in real source — if it can't see a sink, the
# fail-closed coverage gate can't demand it.
PY="${PYTHON:-python3}"
recall="$($PY - <<'EOF'
import importlib.util
spec = importlib.util.spec_from_file_location("ve", "scripts/validate-egress.py")
ve = importlib.util.module_from_spec(spec); spec.loader.exec_module(ve)
kinds = {c["kind"] for c in ve.extract_candidates("tests/fixtures/egress/source-app")}
need = {"file", "proxy", "graphql_field", "presigned_url", "sse", "db_entity", "credential"}
missing = need - kinds
print("MISSING:" + ",".join(sorted(missing)) if missing else "ALL")
EOF
)"
if [ "$recall" = "ALL" ]; then
  ok "extractor surfaces every modality in source-app"
else
  bad "extractor recall gap in source-app — $recall"
fi

# --- 5. metamorphic battery -------------------------------------------------
# Each mutant is a mechanical variant of the bug; each must still be caught.
echo "  -- metamorphic mutants --"
declare -A EXPECT=( [m1-gate-sibling]="R2" [m2-bypass-branch]="CRITICAL" \
                    [m3-resource-rename]="R3" [m4-sink-kind-swap]="CRITICAL" )
for m in m1-gate-sibling m2-bypass-branch m3-resource-rename m4-sink-kind-swap; do
  out="$($V $FIX/metamorphic/$m/*.json --partition mut 2>&1)"; rc=$?
  want="${EXPECT[$m]}"
  if [ "$rc" -eq 1 ] && echo "$out" | grep -q "$want"; then
    ok "$m caught (expects $want)"
  else
    bad "$m NOT caught (rc=$rc, want $want)"
  fi
done

echo
if [ "$fails" -eq 0 ]; then
  echo "=== PASS ==="
  exit 0
fi
echo "=== FAIL — $fails assertion(s) ===" >&2
exit 1
