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
#   4. v2.6 PRECISION — the specific false-positive shapes a calibrated run
#      measured (19.8% true over 81 HIGH+ R-rule findings) now stay silent, and
#      each silence is proved non-vacuous by re-running the SAME inventory with
#      the v2.6 typing fields stripped, which must still fire.
#   5. v2.6 RECALL FLOOR (EPIC §3.2) — every site the eight-engineer triage
#      returned REAL or ACCEPTED_RISK still produces a finding at its exact
#      (file, line). This is a hard release gate: a silent drop here is a recall
#      regression regardless of how good the precision number looks.
#
# Exit 0 = all assertions pass.
set -u
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

V="python3 scripts/validate-egress.py"
FIX="tests/fixtures/egress"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0
ok() { printf "  ok: %s\n" "$*"; }
bad() { printf "  FAIL: %s\n" "$*" >&2; fails=$((fails + 1)); }

# cnt <file> [pattern] -> matching line count, 0 when the file is absent/empty.
# `grep -c` exits 1 on zero matches, so `|| echo 0` would emit TWO lines and every
# numeric comparison downstream would blow up; `|| true` keeps grep's own "0".
cnt() {
  [ -s "$1" ] || { echo 0; return; }
  grep -c -- "${2:-.}" "$1" 2>/dev/null || true
}

# strip_v26 <fixture-dir> <out-dir>
# Copy a fixture with every v2.6 typing field removed, recursively. A precision
# fixture asserting "0 findings" proves nothing on its own — it could be empty,
# or malformed, or joined on a resource nobody serves. Running the SAME inventory
# minus `layer`/`destination`/`path_control`/`gate_rank_hint` reproduces the v2.5
# behaviour, so a fixture that stays silent both ways is a broken fixture, not a
# fixed rule.
strip_v26() {
  python3 - "$1" "$2" <<'PYEOF'
import json, pathlib, sys
src, dst = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
DROP = {"layer", "destination", "path_control", "gate_rank_hint",
        "carries_credential", "carries_credential_name"}
def scrub(o):
    if isinstance(o, dict):
        return {k: scrub(v) for k, v in o.items() if k not in DROP}
    if isinstance(o, list):
        return [scrub(v) for v in o]
    return o
dst.mkdir(parents=True, exist_ok=True)
for f in sorted(src.glob("*.json")):
    (dst / f.name).write_text(json.dumps(scrub(json.loads(f.read_text()))))
PYEOF
}

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
# Load the CANONICAL module, not the scripts/ shim: only skills/security-audit/
# is installed, so that is the file an audit actually executes.
spec = importlib.util.spec_from_file_location(
    "ve", "skills/security-audit/lib/validate-egress.py")
ve = importlib.util.module_from_spec(spec); spec.loader.exec_module(ve)
kinds = {c["kind"] for c in ve.extract_candidates("tests/fixtures/egress/source-app")}
# `local_fs` (v2.6 story 4.3) is in this set for the same reason as the rest: a
# modality the extractor cannot SEE is a modality the fail-closed coverage gate
# cannot demand, so R6 would have no input and the class would stay unfindable
# rather than merely unmodelled.
need = {"file", "proxy", "graphql_field", "presigned_url", "sse", "db_entity",
        "credential", "local_fs"}
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

# --- 6. v2.6 PRECISION — the measured false-positive shapes -----------------
# Each block asserts (a) the shape is now silent and (b) the identical inventory
# with the v2.6 typing stripped still fires, so the silence is the new field
# doing work rather than a dead fixture.
echo "  -- v2.6 precision (measured false positives) --"

# 6a. Story 2.4 — the egress join is typed by LAYER.
# `ExportCsvButton.vue:31`, a client-side <a download> click, was filed for not
# having a server gate. The gate lives in server/api/v1/reports/export.get.ts,
# which is where it belongs; a browser cannot enforce it and never could. Neither
# sink sets `layer` — the inference from the path is what is under test.
out="$($V $FIX/layer-split/*.json --partition rep --out $TMP/layer.jsonl 2>&1)"; rc=$?
n=$(cnt $TMP/layer.jsonl)
{ [ "$rc" -eq 0 ] && [ "$n" -eq 0 ]; } \
  && ok "2.4: browser click handler not compared to its server handler's gate" \
  || bad "2.4: ExportCsvButton FP still fires (rc=$rc, findings=$n)"
# EPIC §2.1 part 4 — suppression is the dangerous direction, so every sink v2.6
# removes from R2/R3/R5 must be NAMED in the run output, not merely absent.
echo "$out" | grep -q "SUPPRESSED SINKS.*1 in a layer with no caller" \
  && echo "$out" | grep -q "ExportCsvButton.vue:31) layer=browser" \
  && ok "2.4: the suppressed sink is named in the output, not silently dropped" \
  || bad "2.4: sinks are excluded from R2/R3/R5 silently"

# 6a-ii. Story 2.4 — the layer inference truth table, including the polyglot
# traps. `app/` is the browser dir in Nuxt 4 and SERVER code in Rails, Laravel,
# Flask and FastAPI, so a rule that reads `app/` as "browser" would exempt a
# Rails controller from every authorization rule — a silent recall hole far worse
# than the false positive it was fixing. Unrecognised paths must land on `http`,
# the bucket everything shared before v2.6, so a bad guess costs a false positive
# rather than a silent drop.
layers="$(python3 - <<'EOF'
import importlib.util
spec = importlib.util.spec_from_file_location(
    "ve", "skills/security-audit/lib/validate-egress.py")
ve = importlib.util.module_from_spec(spec); spec.loader.exec_module(ve)
cases = [
    # the two measured false positives
    ("app/components/ExportCsvButton.vue", None, "browser"),
    ("plugin/scripts/summarise.mjs",       None, "cli"),
    ("server/workers/nightly-rollup.ts",   None, "worker"),
    ("server/api/v1/reports/export.get.ts", None, "http"),
    # polyglot traps: app/ is NOT browser in these stacks
    ("app/controllers/decks_controller.rb", None, "http"),
    ("app/Http/Controllers/DeckController.php", None, "http"),
    ("app/main.py",                        None, "http"),
    ("app/jobs/rollup_job.rb",             None, "worker"),
    # framework routing conventions
    ("pages/api/export.ts",                None, "http"),
    ("app/api/export/route.ts",            None, "http"),
    ("pages/dashboard.vue",                None, "browser"),
    # partition fallback matches whole tokens, not substrings
    ("lib/util.ts",                        "guide", "http"),
    ("lib/util.ts",                        "cron-workers", "worker"),
    ("lib/util.ts",                        None, "http"),
]
bad = [(p, ve.infer_layer(None, p, part), want)
       for p, part, want in cases if ve.infer_layer(None, p, part) != want]
# An explicit `layer` always wins over every inference above.
if ve.infer_layer("worker", "app/components/X.vue") != "worker":
    bad.append(("explicit-override", "?", "worker"))
print("OK" if not bad else "BAD:" + repr(bad))
EOF
)"
[ "$layers" = "OK" ] && ok "2.4: layer inference truth table (incl. Rails/Laravel/Flask app/)" \
  || bad "2.4: layer inference — $layers"

# 6b. Story 2.5 — a non-network sink is not egress to an untrusted caller.
# A console.log to the invoking developer's own stdout, and a 0600 writeFileSync
# under the device's own state dir. Six of 49 sampled R-rule false positives were
# these two shapes. The cron-scheduler resolve-layer surface in the fixture is
# the second half of the same measured row: it set the floor across a layer
# boundary (story 2.4) for a CLI that has no caller at all.
out="$($V $FIX/local-sinks/*.json --partition rep --out $TMP/local.jsonl 2>&1)"; rc=$?
n=$(cnt $TMP/local.jsonl)
{ [ "$rc" -eq 0 ] && [ "$n" -eq 0 ]; } \
  && ok "2.5: own-stdout and own-home writes are not caller egress" \
  || bad "2.5: non-network sink FP still fires (rc=$rc, findings=$n)"
echo "$out" | grep -q "SUPPRESSED SINKS.*2 non-network" \
  && ok "2.5: both suppressed non-network sinks are named in the output" \
  || bad "2.5: non-network exclusions are silent"
strip_v26 "$FIX/local-sinks" "$TMP/local-untyped"
out="$($V $TMP/local-untyped/*.json --partition rep 2>&1)"; rc=$?
[ "$rc" -eq 1 ] \
  && ok "2.5: the same inventory untyped DOES fire (fixture is live)" \
  || bad "2.5: untyped fixture is silent too — the fixture proves nothing"

# 6c. Story 2.6 — a credential KIND alone may not set an unreachable floor.
# RLS GUCs inventoried as kind `capability` mapped to GATE_VERIFIED, a rank only
# `2fa|mfa|otp|verif|step-up` can reach, in an app with no step-up auth — so the
# CORRECTLY GATED branch was filed HIGH. The same fixture's SessionShare resource
# DOES have a rank-3 gate text, and its ungated branch must still be CRITICAL: a
# cap that silenced both would trade one failure mode for another.
out="$($V $FIX/kind-floor/*.json --partition cc --out $TMP/kind.jsonl 2>&1)"; rc=$?
cc=$(cnt $TMP/kind.jsonl CostCentre)
sh_crit=$(grep "SessionShare" $TMP/kind.jsonl | grep -c '"severity": "CRITICAL"' || true)
[ "$cc" -eq 0 ] \
  && ok "2.6: RLS-GUC kind does not set an unreachable floor (0 CostCentre rows)" \
  || bad "2.6: kind-derived floor still over-fires ($cc CostCentre rows)"
[ "$sh_crit" -ge 1 ] \
  && ok "2.6: a resource with an OBSERVED rank-3 gate keeps its floor (CRITICAL)" \
  || bad "2.6: the cap is blanket — it silenced a real rank-3 floor too"

# 6d. Story 2.7 — gate_rank_hint is the authority, the keyword ranker a fallback.
# The fixture's enforced_gate is verbatim from a row the calibrated run filed
# CRITICAL/CONFIRMED: a paragraph of genuine correct hardening containing none of
# the ranker's keywords. Unrecognised text ranks 0, and rank-0-under-a-rank-2-
# floor is CRITICAL — so the more precisely an analyst described a real control,
# the more likely it was filed CRITICAL.
out="$($V $FIX/rich-gate/*.json --partition dev --out $TMP/rich.jsonl 2>&1)"; rc=$?
n=$(cnt $TMP/rich.jsonl)
{ [ "$rc" -eq 0 ] && [ "$n" -eq 0 ]; } \
  && ok "2.7: a richly-described real gate is not filed CRITICAL" \
  || bad "2.7: rich-gate FP still fires (rc=$rc, findings=$n)"
echo "$out" | grep -q "gate_rank_hint: 1 applied" \
  && ok "2.7: the hint override is reported, never applied silently" \
  || bad "2.7: hint override not surfaced in the run summary"
strip_v26 "$FIX/rich-gate" "$TMP/rich-untyped"
out="$($V $TMP/rich-untyped/*.json --partition dev 2>&1)"; rc=$?
{ [ "$rc" -eq 1 ] && echo "$out" | grep -q "CRITICAL"; } \
  && ok "2.7: without the hint the same gate text IS filed CRITICAL (fixture live)" \
  || bad "2.7: untyped rich-gate fixture is silent — the fixture proves nothing"

# --- 7. v2.6 story 2.8 — three silent-corruption bugs shipped in v2.5.0 ------
echo "  -- v2.6 story 2.8 (silent corruption) --"

# 7a. `_norm` used lstrip("./"), a CHARACTER SET rather than a prefix. Asserted
# directly because it is imported into validate-collection-scoping.py at :102 —
# one bug in two validators.
norm="$(python3 - <<'EOF'
import importlib.util
spec = importlib.util.spec_from_file_location(
    "ve", "skills/security-audit/lib/validate-egress.py")
ve = importlib.util.module_from_spec(spec); spec.loader.exec_module(ve)
cases = [(".output/bundle.js", ".output/bundle.js"),
         (".claude-audit/x.json", ".claude-audit/x.json"),
         (".github/workflows/ci.yml", ".github/workflows/ci.yml"),
         ("./server/api/x.ts", "server/api/x.ts"),
         (".//server/api/x.ts", "/server/api/x.ts"),
         ("server\\api\\x.ts", "server/api/x.ts")]
bad = [(i, ve._norm(i), w) for i, w in cases if ve._norm(i) != w]
# The functional consequence: a mangled leading dot escapes the default ignore
# list, which is how build output re-entered the coverage gate.
if not ve.ignored(".output/nitro/chunk.mjs", []):
    bad.append(("ignored(.output/...)", False, True))
print("OK" if not bad else "BAD:" + repr(bad))
EOF
)"
[ "$norm" = "OK" ] && ok "2.8/3: _norm strips the ./ PREFIX, not the dot character" \
  || bad "2.8/3: _norm regression — $norm"

# 7b. Neither reconciler read an ignore file, so a calibrated run demanded
# inventory entries for an unrelated repository cloned under tmp/.
out="$($V $FIX/norm-ignore/sinks.json $FIX/norm-ignore/candidates.json \
        --ignore $FIX/norm-ignore/ignore.txt --partition ni 2>&1)"; rc=$?
{ [ "$rc" -eq 0 ] && echo "$out" | grep -q "candidates dropped by"; } \
  && ok "2.8/2: --ignore drops the out-of-scope tree (and reports how many)" \
  || bad "2.8/2: ignore file not honoured (rc=$rc)"
out="$($V $FIX/norm-ignore/sinks.json $FIX/norm-ignore/candidates.json \
        --ignore /nonexistent-ignore-file --partition ni 2>&1)"; rc=$?
{ [ "$rc" -eq 1 ] && echo "$out" | grep -q "UNACCOUNTED.*tmp/vendored-clone"; } \
  && ok "2.8/2: without the ignore file the same tree IS demanded (test is live)" \
  || bad "2.8/2: ignore-file assertion proves nothing (rc=$rc)"

# 7c. `s.get('reachable_via', ['<path>'])[0]` — .get(k, default) returns the
# default only on a MISSING key, so a present-but-empty reachable_via raised
# IndexError. That crashed §6.19 outright in the calibrated run: the flagship
# v2.4 control produced nothing at all. recall-floor's otel-headers-helper.sh
# sink carries `"reachable_via": []`.
out="$($V $FIX/recall-floor/*.json --partition plugin --out $TMP/recall.jsonl 2>&1)"; rc=$?
{ [ "$rc" -eq 1 ] && ! echo "$out" | grep -q "IndexError\|Traceback"; } \
  && ok "2.8/1: an empty reachable_via reconciles instead of crashing §6.19" \
  || bad "2.8/1: empty reachable_via still breaks the run"

# --- 8. v2.6 RECALL FLOOR (EPIC §3.2) — a HARD release gate -----------------
# Every site the eight-engineer triage returned REAL or ACCEPTED_RISK. Modelled
# by shape (an unauthenticated relay leg, an argv-controlled write, a node:http
# downgrade on a POST body, a refresh-grant curl to a caller-chosen host), since
# the original codebase is not available. A silent drop here blocks the release.
echo "  -- v2.6 recall floor (EPIC §3.2) --"
recall_missing=""
while IFS='|' read -r site rule; do
  [ -n "$site" ] || continue
  f="${site%:*}"; l="${site##*:}"
  if python3 - "$TMP/recall.jsonl" "$f" "$l" "$rule" <<'EOF'
import json, sys
path, f, l, rules = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4].split(",")
hit = any(r["file"] == f and r["line"] == l
          and r["sources"][0]["detail"].split(":")[-1] in rules
          for r in map(json.loads, open(path)))
sys.exit(0 if hit else 1)
EOF
  then :; else recall_missing="$recall_missing $site($rule)"; fi
done <<'SITES'
plugin/scripts/otel-headers-helper.sh:120|R2,R3
plugin/scripts/otel-headers-helper.sh:283|R2,R3
plugin/scripts/landed-check.mjs:54|R2,R3
plugin/scripts/project-check.mjs:90|R2
plugin/scripts/plugin-runtime.mjs:77|R2
plugin/scripts/otlp-forwarder.mjs:146|R5
plugin/scripts/otlp-forwarder.mjs:150|R5
plugin/scripts/otlp-forwarder.mjs:123|R5
plugin/scripts/otlp-capture-server.mjs:22|R5,R6
plugin/scripts/otlp-capture-server.mjs:23|R5,R6
plugin/scripts/backfill.mjs:469|R5
server/api/setup/enroll.post.ts:145|R2,R3
SITES
[ -z "$recall_missing" ] \
  && ok "recall floor: all 12 triage-confirmed sites still fire" \
  || bad "RECALL REGRESSION — silenced:$recall_missing"

# The CLI layer must stay in scope. Only `browser` is exempt from the
# authorization rules (nothing there has a second party to authorize); a plugin
# script that hands a credential to a host somebody else picked is a real
# deficit whichever process runs it.
cli_n=$(cnt $TMP/recall.jsonl "plugin/scripts/")
[ "$cli_n" -ge 10 ] \
  && ok "recall floor: layer typing did not exempt the cli layer ($cli_n rows)" \
  || bad "recall floor: cli-layer findings collapsed to $cli_n"

# --- 9. v2.6 story 4.3 — local-filesystem exfil ----------------------------
# A repo-steerable state dir made a hook write a live OAuth access token into an
# attacker's own working tree. No network call, so no v2.5 rule could see it; the
# calibrated run missed it entirely and the triagers rated it CRITICAL. The two
# sinks in the fixture are the same writeFileSync with the same 0600 mode and
# differ only in `path_control` — the discriminator is who controls the path.
echo "  -- v2.6 story 4.3 (local-filesystem exfil) --"
out="$($V $FIX/local-exfil/*.json --partition hook --out $TMP/exfil.jsonl 2>&1)"; rc=$?
r6c=$(grep '"severity": "CRITICAL"' $TMP/exfil.jsonl 2>/dev/null | grep -c "R6" || true)
benign=$(cnt $TMP/exfil.jsonl '"line": 31')
tot=$(cnt $TMP/exfil.jsonl)
{ [ "$rc" -eq 1 ] && [ "$r6c" -eq 1 ] && [ "$tot" -eq 1 ]; } \
  && ok "4.3: a credential landing in a repo-steerable path is CRITICAL" \
  || bad "4.3: repo-steerable credential write not caught (rc=$rc r6=$r6c total=$tot)"
[ "$benign" -eq 0 ] \
  && ok "4.3: the identical 0600 write to the device's own state dir stays silent" \
  || bad "4.3: benign own_config write flagged — the 2.5/4.3 discriminator is broken"
grep -q "CWE-538" $TMP/exfil.jsonl \
  && ok "4.3: filed as CWE-538 (externally-accessible file), not a bare CWE-862" \
  || bad "4.3: wrong CWE for the local-exfil class"

# The whole class turns on `path_control`, so an inventory that declares a
# filesystem sink and omits it must trip the fail-closed COVERAGE gate rather
# than have a severity guessed for it. Drop only that one field and re-run.
mkdir -p $TMP/exfil-nopc
python3 - "$FIX/local-exfil" "$TMP/exfil-nopc" <<'PYEOF'
import json, pathlib, sys
src, dst = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
def scrub(o):
    if isinstance(o, dict):
        return {k: scrub(v) for k, v in o.items() if k != "path_control"}
    if isinstance(o, list):
        return [scrub(v) for v in o]
    return o
for f in sorted(src.glob("*.json")):
    (dst / f.name).write_text(json.dumps(scrub(json.loads(f.read_text()))))
PYEOF
out="$($V $TMP/exfil-nopc/*.json --partition hook 2>&1)"; rc=$?
{ [ "$rc" -eq 1 ] && echo "$out" | grep -q "no path_control"; } \
  && ok "4.3: local_fs without path_control fails the coverage gate, not guessed" \
  || bad "4.3: a filesystem sink can omit the field the whole class turns on"

# --- 10. every new fixture's findings validate against finding-schema -------
for j in $TMP/recall.jsonl $TMP/exfil.jsonl $TMP/kind.jsonl; do
  [ -s "$j" ] || continue
  if python3 scripts/validate-findings.py \
       --schema skills/security-audit/lib/finding-schema.json \
       --cwe-map skills/security-audit/lib/cwe-map.json \
       "$j" --quiet 2>/dev/null; then
    ok "v2.6 findings validate against finding-schema ($(basename $j))"
  else
    bad "v2.6 findings FAILED schema validation ($(basename $j))"
  fi
done

echo
if [ "$fails" -eq 0 ]; then
  echo "=== PASS ==="
  exit 0
fi
echo "=== FAIL — $fails assertion(s) ===" >&2
exit 1
