#!/usr/bin/env bash
# tests/test-secret-redaction.sh — the v2.6.1 credential-containment invariant.
#
# Through v2.6.0 this skill wrote live credentials into the repository it was
# auditing: gitleaks' verbatim `region.snippet.text` rode the "copy scanner runs
# through verbatim" instruction in phase-07-synthesis.md §7.8.1 into
# `findings.sarif`, which §7.10 copies to a tracked `<output_dir>`. A token the
# audited project had correctly kept out of git was committed by the audit.
#
# Two enforcers now stand between a scanner and a deliverable, and prose in a
# step file is not one of them. This suite pins both.
#
# NOTE ON FIXTURES: every credential-shaped string here is synthesised at
# runtime, never committed. A test fixture carrying a token-shaped literal would
# make this repository's own secret scan permanently noisy — which is the exact
# triage failure (§4.4c) that let the original defect survive two detections.
#
# CI-runnable, no Claude needed.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$REPO_ROOT/skills/security-audit/lib"
REDACT="$LIB/redact-scanner-output.py"
GATE="$LIB/verify-deliverable.py"
DETECTORS="$LIB/secret-detectors.py"

fails=0
ok()  { echo "  ok: $1"; }
bad() { echo "  FAIL: $1"; fails=$((fails + 1)); }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Shape-valid, obviously synthetic. Split so this file itself contains no
# matchable literal.
TOKEN="ghp_""SyNtH3t1cT0k3nF0rT3stZz9QwErTyUiOp12"
AKID="AKIA""7QWERTYUIOPASDFG"
PEMHDR="-----BEGIN RSA ""PRIVATE KEY-----"

echo "== secret redaction (v2.6.1) =="

# ---------------------------------------------------------------------------
echo "-- enforcers exist and share one detector table --"
# ---------------------------------------------------------------------------
for f in "$REDACT" "$GATE" "$DETECTORS"; do
  [ -f "$f" ] && ok "present: ${f#$REPO_ROOT/}" || bad "MISSING: ${f#$REPO_ROOT/}"
done

# Both must resolve the SAME module OBJECT. An earlier version of this check
# counted occurrences of the string "secret-detectors.py" in each source file,
# which a comment satisfies -- it asserted nothing. Load both enforcers and
# compare the table they actually bound.
shared="$(python3 - "$REDACT" "$GATE" "$DETECTORS" <<'PY'
import importlib.util, os, sys
def load(path):
    name = "_probe_" + os.path.basename(path).replace("-", "_")[:-3]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
redact, gate, table = (load(a) for a in sys.argv[1:4])
same_file = (os.path.realpath(redact.SD.__file__)
             == os.path.realpath(gate.SD.__file__)
             == os.path.realpath(table.__file__))
same_table = redact.SD.DETECTOR_NAMES == gate.SD.DETECTOR_NAMES == table.DETECTOR_NAMES
same_fp = (redact.SD.fingerprint("probe", "ctx")
           == gate.SD.fingerprint("probe", "ctx")
           == table.fingerprint("probe", "ctx"))
print("SHARED" if (same_file and same_table and same_fp) else "SPLIT")
PY
)"
[ "$shared" = "SHARED" ] && ok "both enforcers bind the SAME detector module (path, table, fingerprint)" \
                          || bad "enforcers do not share the detector table"

# ---------------------------------------------------------------------------
echo "-- layer 1: structural strip of scanner output --"
# ---------------------------------------------------------------------------
# Under a realistic blackboard path, so the DEFAULT (guarded) code path is what
# the suite exercises. Fixtures in a bare temp dir would be refused by the
# write-scope guard, and passing --allow-any-path to work around that would
# leave the guard untested in the very suite that owns it.
SCAN="$WORK/.claude-audit/current/phase-04-scanners"
mkdir -p "$SCAN"

python3 - "$SCAN" "$TOKEN" "$PEMHDR" <<'PY'
import json, sys
scan, token, pemhdr = sys.argv[1], sys.argv[2], sys.argv[3]
key = pemhdr + "\nMIIEowIBAAKCAQEA7Zq9vXk2ZmNqRt\n-----END RSA PRIVATE KEY-----"
sarif = {
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "gitleaks", "version": "8.28.0",
                        "rules": [{"id": "github-pat"}]}},
    "invocations": [{"commandLine": "gitleaks detect --no-git",
                     "executionSuccessful": True}],
    "artifacts": [{"location": {"uri": "tmp/scratch/.env"},
                   "contents": {"text": "GITHUB_TOKEN=" + token + "\n"}}],
    "results": [
      {"ruleId": "github-pat", "level": "error",
       "message": {"text": "secret detected at line 1: " + token},
       "locations": [{"physicalLocation": {
          "artifactLocation": {"uri": "tmp/scratch/.env"},
          "region": {"startLine": 1, "startColumn": 14,
                     "snippet": {"text": token}},
          "contextRegion": {"startLine": 1,
                            "snippet": {"text": "GITHUB_TOKEN=" + token}}}}]},
      {"ruleId": "private-key", "level": "error",
       "message": {"text": "private key detected"},
       "locations": [{"physicalLocation": {
          "artifactLocation": {"uri": "tmp/slideshow/deploy.pem"},
          "region": {"startLine": 1, "snippet": {"text": key}}}}]}]}]}
open(scan + "/gitleaks.sarif", "w").write(json.dumps(sarif, indent=2))

# trufflehog: ONE finding is a single-line file that is also valid JSON. That
# shape bypassed the JSONL handler in development and must stay covered.
rec = {"DetectorName": "Github", "Verified": True, "Raw": token,
       "RawV2": token + ":x", "Redacted": token[:10] + "...",
       "ExtraData": {"account": "someone", "key": token},
       "SourceMetadata": {"Data": {"Filesystem": {"file": "tmp/scratch/.env",
                                                  "line": 1}}}}
open(scan + "/trufflehog.json", "w").write(json.dumps(rec) + "\n")
open(scan + "/trufflehog-multi.json", "w").write(
    json.dumps(rec) + "\n" + json.dumps(rec) + "\n")

# A scanner shape the skill has never seen must fail CLOSED, not pass through.
open(scan + "/unknown-tool.json", "w").write(
    json.dumps({"findings": [{"where": "a.py", "matched": token}]}, indent=2))

# manifest.yaml declares these two as REQUIRED outputs of Phase 4. They are LLM
# prose about the secrets that were found, and an extension list scoped to the
# JSON formats skipped both -- the fail-open R1 finding F1 caught.
open(scan + "/security-review-app.md", "w").write(
    "# Security review\n\nHardcoded token " + token + " at tmp/scratch/.env:1.\n")
open(scan + "/adversarial-app.md", "w").write(
    "The reviewer notes the credential " + token + " is still live.\n")
PY

before="$(grep -rc "SyNtH3t1cT0k3n" "$SCAN" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')"
[ "$before" -gt 0 ] && ok "fixtures carry the synthetic token ($before occurrences)" \
                     || bad "fixture generation produced no token occurrences"

python3 "$REDACT" "$SCAN" --quiet
rc=$?
[ "$rc" -eq 0 ] && ok "redactor exits 0" || bad "redactor exited $rc"

after="$(grep -rc "SyNtH3t1cT0k3n" "$SCAN" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')"
[ "$after" -eq 0 ] && ok "zero token occurrences remain across all scanner files" \
                   || bad "$after token occurrence(s) SURVIVED redaction"

grep -rq "MIIEowIBAAKCAQEA" "$SCAN" && bad "private key body survived redaction" \
                                    || ok "private key body removed"

# R1 finding F1: the markdown review artifacts must be covered too.
for md in security-review-app.md adversarial-app.md; do
  grep -q "SyNtH3t1cT0k3n" "$SCAN/$md" \
    && bad "$md passed through unredacted (manifest-declared Phase 4 output)" \
    || ok "$md scrubbed"
done

# Fail-closed on an unrecognised scanner format.
grep -q "SyNtH3t1cT0k3n" "$SCAN/unknown-tool.json" \
  && bad "unknown JSON shape passed through unredacted (fails OPEN)" \
  || ok "unknown scanner shape fails closed"

# ---------------------------------------------------------------------------
echo "-- layer 1: triage survives redaction --"
# ---------------------------------------------------------------------------
python3 - "$SCAN" <<'PY'
import json, sys
d = json.load(open(sys.argv[1] + "/gitleaks.sarif"))
r = d["runs"][0]["results"][0]
loc = r["locations"][0]["physicalLocation"]
checks = [
  ("ruleId preserved",        r.get("ruleId") == "github-pat"),
  ("level preserved",         r.get("level") == "error"),
  ("file preserved",          loc["artifactLocation"]["uri"] == "tmp/scratch/.env"),
  ("line preserved",          loc["region"]["startLine"] == 1),
  ("column preserved",        loc["region"]["startColumn"] == 14),
  ("snippet still an ArtifactContent (SARIF stays valid)",
                              isinstance(loc["region"].get("snippet"), dict)
                              and "text" in loc["region"]["snippet"]),
  ("secret_fingerprint added", bool(r.get("properties", {}).get("secret_fingerprint"))),
  ("redacted flag set",        r.get("properties", {}).get("redacted") == "true"),
]
for name, passed in checks:
    print(("  ok: " if passed else "  FAIL: ") + name)
sys.exit(0 if all(p for _n, p in checks) else 1)
PY
[ $? -eq 0 ] || fails=$((fails + 1))

th_fp="$(python3 -c "
import json,sys
print(json.load(open('$SCAN/trufflehog.json')).get('SecretFingerprint',''))" 2>/dev/null)"
[ -n "$th_fp" ] && ok "trufflehog single-record file got a SecretFingerprint" \
                || bad "trufflehog single-record file was not handled"

# ---------------------------------------------------------------------------
echo "-- layer 1: idempotency (the gate deadlocks without it) --"
# ---------------------------------------------------------------------------
python3 "$REDACT" "$SCAN" --check --quiet
[ $? -eq 0 ] && ok "--check passes an already-redacted tree" \
             || bad "--check re-flags its own markers; the write gate can never pass"

sum1="$(cat "$SCAN"/*.sarif "$SCAN"/*.json | md5sum)"
python3 "$REDACT" "$SCAN" --quiet >/dev/null
sum2="$(cat "$SCAN"/*.sarif "$SCAN"/*.json | md5sum)"
[ "$sum1" = "$sum2" ] && ok "second redaction pass is byte-identical" \
                      || bad "redactor is not idempotent"

# ...and it must still fail closed on a genuinely dirty file.
python3 - "$WORK" "$TOKEN" <<'PY'
import json, sys
json.dump({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gitleaks"}},
  "results": [{"ruleId": "x", "locations": [{"physicalLocation": {
     "region": {"snippet": {"text": sys.argv[2]}}}}]}]}]},
  open(sys.argv[1] + "/dirty.sarif", "w"))
PY
python3 "$REDACT" "$WORK/dirty.sarif" --check --quiet 2>/dev/null
[ $? -eq 1 ] && ok "--check exits 1 on unredacted material" \
             || bad "--check did not fail closed on a dirty file"

# ---------------------------------------------------------------------------
echo "-- layer 1: self-leak detection and write-scope guard (R2) --"
# ---------------------------------------------------------------------------
SL="$WORK/selfleak"; mkdir -p "$SL"
python3 - "$SL" <<'PYSL'
import json, sys
json.dump({"version": "2.1.0", "runs": [{
  "tool": {"driver": {"name": "gitleaks"}},
  "results": [
    {"ruleId": "r1", "locations": [{"physicalLocation": {"artifactLocation": {
        "uri": ".claude-audit/history/2026/findings.sarif"}}}]},
    {"ruleId": "r2", "locations": [{"physicalLocation": {"artifactLocation": {
        "uri": "./docs/security-audit-output/findings.sarif"}}}]},
    {"ruleId": "r3", "locations": [{"physicalLocation": {"artifactLocation": {
        "uri": "src/app.py"}}}]}]}]}, open(sys.argv[1] + "/g.sarif", "w"))
PYSL
cand="$(python3 "$REDACT" "$SL" --check --output-dir docs/security-audit-output \
        2>/dev/null | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: print(''); raise SystemExit
print(','.join(sorted(c['file'] for c in d.get('self_leak_candidates', []))))")"

case "$cand" in
  *".claude-audit/history/2026/findings.sarif"*)
    ok "self-leak detection sees .claude-audit/ paths (leading dot preserved)" ;;
  *) bad "self-leak detection missed .claude-audit/ (lstrip ate the leading dot)" ;;
esac
case "$cand" in
  *"docs/security-audit-output/findings.sarif"*)
    ok "self-leak detection sees <output_dir> paths through a ./ prefix" ;;
  *) bad "self-leak detection missed a ./-prefixed <output_dir> path" ;;
esac
case "$cand" in
  *"src/app.py"*) bad "self-leak detection false-positived on user source" ;;
  *) ok "user source is not a self-leak candidate" ;;
esac

# The scrubber rewrites in place. Pointing it at source files is destructive,
# and during the v2.6.0 cleanup a remediation pass did exactly that to localhost
# dev connection strings in a project's source copies.
SRC="$WORK/srcguard"; mkdir -p "$SRC"
printf '{"db":"postgres://u:devpassword123xyz@localhost/app"}\n' > "$SRC/config.json"
python3 "$REDACT" "$SRC" --quiet >/dev/null 2>&1
[ $? -eq 2 ] && ok "redact mode refuses paths outside .claude-audit/ and <output_dir>" \
             || bad "redact mode rewrote a file outside the audit-owned directories"
grep -q "devpassword123xyz" "$SRC/config.json" \
  && ok "the refused source file was left byte-identical" \
  || bad "the source file was modified despite the scope guard"
python3 "$REDACT" "$SRC" --check --quiet >/dev/null 2>&1
[ $? -eq 1 ] && ok "--check is read-only and still scans outside the guard" \
             || bad "--check did not scan an out-of-scope path"

# ---------------------------------------------------------------------------
echo "-- layer 2: deliverable write gate --"
# ---------------------------------------------------------------------------
REPORT="$WORK/security-audit-report.md"
cat > "$REPORT" <<REPORTEOF
# Security Audit Report

> #### SEC-001: Hardcoded token in deploy script
> - **Location:** scripts/deploy.sh:12
> - **Description:** The script embeds $TOKEN directly in the curl call.

> #### SEC-002: Example config uses placeholders
> - **Description:** \`.env.example\` has api_key: "your-api-key-here" and
>   aws_key: "$AKID" was found in scripts/bootstrap.sh:4.
REPORTEOF

python3 "$GATE" --check --quiet "$REPORT" 2>/dev/null
[ $? -eq 1 ] && ok "--check exits 1 on analyst prose carrying a value" \
             || bad "gate missed a credential pasted into report prose"

python3 "$GATE" --redact --json-report "$WORK/gate.json" --quiet "$REPORT" 2>/dev/null
rc=$?
[ "$rc" -eq 3 ] && ok "--redact exits 3 (obliges the §7.10a CRITICAL self-finding)" \
                || bad "--redact exited $rc, expected 3"

grep -q "SyNtH3t1cT0k3n" "$REPORT" && bad "token survived the write gate" \
                                   || ok "token scrubbed from the report"
grep -q "$AKID" "$REPORT" && bad "AWS key id survived the write gate" \
                          || ok "AWS key id scrubbed from the report"
grep -q "your-api-key-here" "$REPORT" \
  && ok "placeholder left intact (no false positive on .env.example prose)" \
  || bad "gate scrubbed a documentation placeholder"

python3 "$GATE" --check --quiet "$REPORT" 2>/dev/null
[ $? -eq 0 ] && ok "gate passes after its own redaction (idempotent)" \
             || bad "gate re-flags its own markers"

# R1 finding F2: a PEM spans lines. A line-oriented scan redacted the
# -----BEGIN----- header and copied every base64 body line through untouched.
PEMREPORT="$WORK/pem-report.md"
{
  echo "# Report"
  echo "> - **Description:** the deploy key at deploy.pem:1 is:"
  echo "$PEMHDR"
  echo "MIIEowIBAAKCAQEA7Zq9vXk2ZmNqRtYuIoPaSdFgHjKlZxCvBnMqWeRtYuIoPaSd"
  echo "FgHjKlZxCvBnMqWeRtYuIoPaSdFgHjKlZxCvBnMqWeRtYuIoPaSdFgHjKlZxCvBn"
  echo "-----END RSA PRIVATE KEY-----"
} > "$PEMREPORT"
python3 "$GATE" --redact --quiet "$PEMREPORT" 2>/dev/null
grep -q "MIIEowIBAAKCAQEA" "$PEMREPORT" \
  && bad "PEM body survived the gate (multi-line detector defeated)" \
  || ok "whole PEM block redacted, not just the header"
grep -q "BEGIN RSA PRIVATE KEY" "$PEMREPORT" \
  && bad "PEM header survived the gate" || ok "PEM header redacted"

# The JSON report feeds §7.10a and must never carry the value it found.
if [ -f "$WORK/gate.json" ]; then
  grep -q "SyNtH3t1cT0k3n" "$WORK/gate.json" \
    && bad "gate's own JSON report leaked the secret" \
    || ok "gate report carries detector+fingerprint only, never the value"
  python3 -c "
import json,sys
d=json.load(open('$WORK/gate.json'))
sys.exit(0 if d.get('total_occurrences',0) > 0 and d.get('detectors') else 1)" \
    && ok "gate report records detectors and occurrence count" \
    || bad "gate report is missing detector/occurrence data"
else
  bad "--json-report wrote no file"
fi

# ---------------------------------------------------------------------------
echo "-- detector table: positives and placeholder negatives --"
# ---------------------------------------------------------------------------
python3 - "$DETECTORS" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("sd", sys.argv[1])
sd = importlib.util.module_from_spec(spec); spec.loader.exec_module(sd)

must_fire = [
    ("github_pat",               'tok = "ghp_' + 'A1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvWxYz' + '"'),
    ("aws_access_key_id",        'AKIA' + '7QWERTYUIOPASDFG'),
    ("private_key_header",       '-----BEGIN EC ' + 'PRIVATE KEY-----'),
    ("private_key",              '-----BEGIN RSA ' + 'PRIVATE KEY-----\\nMIIBOgIBAAJBAK\\n-----END RSA PRIVATE KEY-----'),
    ("jwt",                      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N'),
    ("azure_client_secret",      'client_secret="Q~8fLmZ2vKp9xR4tW7yB1nH6jD3sG5aE0cU"'),
    ("basic_auth_url",           'postgres://u:S3cretP4ssw0rdXy@db.host/app'),
    ("generic_secret_assignment",'password = "Tr0ub4dor&3xKq9zLm"'),
]
must_not_fire = [
    'api_key: "your-api-key-here"',
    'token = "<YOUR_TOKEN_HERE>"',
    'secret = "${VAULT_SECRET}"',
    'password = "xxxxxxxxxxxxxxxxxxxx"',
    'api_key = "changeme-please-now"',
    'see the ghp_ prefix convention in docs/security.md',
    'password = "[REDACTED:github_pat:0123456789abcdef:len40]"',
]
bad = 0
for name, text in must_fire:
    fired = [h[0] for h in sd.scan(text)]
    if name in fired:
        print("  ok: fires on %s" % name)
    else:
        print("  FAIL: %s did not fire (got %s)" % (name, fired or "nothing")); bad += 1
for text in must_not_fire:
    fired = [h[0] for h in sd.scan(text)]
    if fired:
        print("  FAIL: false positive %s on %r" % (fired, text[:48])); bad += 1
    else:
        print("  ok: silent on %r" % text[:48])

# Fingerprints must be stable (Phase 7 dedupe / Phase 8 carry-forward) and
# must not be the value in disguise.
v = "ghp_" + "A1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvWxYz"
if sd.fingerprint(v, "c") == sd.fingerprint(v, "c"):
    print("  ok: fingerprint stable for the same (value, context)")
else:
    print("  FAIL: fingerprint unstable"); bad += 1
if sd.fingerprint(v, "a") != sd.fingerprint(v, "b"):
    print("  ok: fingerprint is context-salted")
else:
    print("  FAIL: fingerprint ignores context salt"); bad += 1
if v not in sd.marker("github_pat", v, "c"):
    print("  ok: marker contains no part of the value")
else:
    print("  FAIL: marker leaks the value"); bad += 1
sys.exit(1 if bad else 0)
PY
[ $? -eq 0 ] || fails=$((fails + 1))

# ---------------------------------------------------------------------------
echo "-- step files actually invoke the enforcers (control-with-no-enforcer) --"
# ---------------------------------------------------------------------------
STEPS="$REPO_ROOT/skills/security-audit/steps"
grep -q "redact-scanner-output.py" "$STEPS/phase-04-scanners.md" \
  && ok "phase-04 invokes the ingest redactor" \
  || bad "phase-04 does not invoke redact-scanner-output.py"
grep -q "verify-deliverable.py" "$STEPS/phase-07-synthesis.md" \
  && ok "phase-07 invokes the write gate" \
  || bad "phase-07 does not invoke verify-deliverable.py"
grep -q "verify-deliverable.py" "$STEPS/phase-08-baseline.md" \
  && ok "phase-08 invokes the write gate" \
  || bad "phase-08 does not invoke verify-deliverable.py"
grep -q "7.10a" "$STEPS/phase-07-synthesis.md" \
  && ok "phase-07 defines the fired-gate self-finding (§7.10a)" \
  || bad "phase-07 has no §7.10a"
grep -q "skill_self_leak" "$STEPS/phase-04-scanners.md" \
  && ok "phase-04 defines the prior-artifact escalation (§4.4c)" \
  || bad "phase-04 has no prior-artifact escalation rule"

# R1 finding F5: the RC=3 obligation must be mechanical, not narrative.
grep -q "phase-07-gate-fired.marker" "$STEPS/phase-07-synthesis.md" \
  && ok "phase-07 enforces the fired-gate obligation with a marker" \
  || bad "phase-07 leaves the GATE_RC=3 obligation to prose only"

# R1 finding F6: every artifact a step file mandates must be in the contract.
MANIFEST="$REPO_ROOT/skills/security-audit/manifest.yaml"
for art in phase-04-redaction.json deliverable-gate.json baseline-gate.json; do
  grep -q "$art" "$MANIFEST" \
    && ok "manifest declares $art" \
    || bad "manifest does not declare $art (step files mandate it)"
done

# R1 finding F3: the gitignore recipe must not write jq errors into .gitignore.
grep -q "config.json 2>/dev/null || echo docs/security-audit-output" \
     "$REPO_ROOT/skills/security-audit/workflow.md" \
  && ok "3.5b resolves output_dir defensively" \
  || bad "3.5b jq call has no fallback; a missing config.json corrupts .gitignore"

echo
if [ "$fails" -eq 0 ]; then
  echo "PASS: secret redaction invariants hold."
  exit 0
fi
echo "FAIL: $fails secret-redaction check(s) failed."
exit 1
