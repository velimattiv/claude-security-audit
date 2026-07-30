#!/usr/bin/env bash
# tests/test-evidence-discipline.sh — the v2.6 Wave-3 obligations, enforced.
#
# Every check here started life as methodology prose in a step file. The
# calibrated run that motivated v2.6 found that the audit's own headline defect
# class, across five of five themes, was "control-versus-prose gaps" — a control
# exists in a comment, a policy table or a design doc, and is not enforced on the
# path that matters. An obligation that lives only in a step file is that same
# defect, committed by the tool that exists to detect it. So each obligation gets
# a mechanical enforcer, and this suite pins the enforcer.
#
# CI-runnable, no Claude needed.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="$REPO_ROOT/skills/security-audit/lib/finding-schema.json"
VALIDATOR="$REPO_ROOT/skills/security-audit/lib/validate-findings.py"
FIXTURE="$REPO_ROOT/tests/fixtures/evidence-discipline/findings.jsonl"

fails=0
ok()   { echo "  ok: $1"; }
bad()  { echo "  FAIL: $1"; fails=$((fails + 1)); }

echo "== evidence discipline (v2.6 Wave 3) =="

out="$(python3 "$VALIDATOR" --schema "$SCHEMA" --require-evidence-discipline \
        "$FIXTURE" 2>&1)"
rc=$?

# The flag must FAIL this fixture — it is a catalogue of the five omissions.
if [ "$rc" -eq 0 ]; then
  bad "--require-evidence-discipline passed a fixture built to violate it"
else
  ok "--require-evidence-discipline fails closed on violations"
fi

expect_hit() {  # <line-marker> <human description>
  if grep -q "line $1:" <<<"$out"; then ok "$2"; else bad "$2 (no error on line $1)"; fi
}
expect_clean() {
  if grep -q "line $1:" <<<"$out"; then bad "$2 (unexpected error on line $1)"; else ok "$2"; fi
}

# A HIGH+ finding with no sibling sweep at all. Of 34 defects the triage found
# and the audit missed, the majority were the 2nd/3rd/4th site of a defect the
# audit correctly found once.
expect_hit 1 "HIGH+ without sibling_sites is refused"

# An empty list is a CLAIM ("this is the only site"). Without the pattern that
# was run, it is an omission wearing a claim's clothes.
expect_hit 2 "empty sibling_sites with no sibling_pattern is refused"

# The well-formed row: empty list, backed by the pattern. This is the shape we
# want analysts to emit, and it must not be punished.
expect_clean 3 "empty sibling_sites WITH a pattern is accepted"

# A refutation may only be scoped to what was examined. The worst single defect
# in the calibrated run was a refutation true of one module, generalised to a
# system property, which buried a live HIGH.
expect_hit 4 "attacked:refuted without refutation_scope is refused"

# Fix text is what gets executed. Six findings on one defect had the FINDING
# right on all six and the FIX wrong on five.
expect_hit 5 "suggested_fix without fix_confidence is refused"

# Fail-open by design: this field suppresses an R3 escalation, so an uncited
# claim must not be able to. Otherwise it becomes the next self-asserted
# CONFIRMED.
expect_hit 6 "uncited structurally_unreachable is refused"

# Annexed rows are enumeration legs folded into a parent finding, not findings.
# The parent carries the obligations.
expect_clean 7 "an annexed row is exempt (its parent carries the obligations)"

# The flag is opt-in: without it, the same fixture must validate cleanly, so
# existing callers are unaffected.
if python3 "$VALIDATOR" --schema "$SCHEMA" "$FIXTURE" >/dev/null 2>&1; then
  ok "without the flag the same rows validate (opt-in, no silent breakage)"
else
  bad "the fixture fails plain schema validation — it should only fail the discipline checks"
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "=== PASS ==="
  exit 0
fi
echo "=== FAIL — $fails assertion(s) ==="
exit 1
