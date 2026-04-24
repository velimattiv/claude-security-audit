# E2E Assertion Suite — Self-Dogfood, 2026-04-24T20:45:00Z

**Purpose.** Prove the v2.0.1 E2E assertion suite (`tests/e2e/assertions.py`) behaves correctly against real audit artifacts, without requiring a full `claude -p "/security-audit"` invocation (which only the user can trigger from their authenticated host).

**Target artifacts.** The partial dogfood in `/tmp/audit-targets/juice-shop/.claude-audit/current/` from the original M4/M5 runs:
- `phase-05-auth-juice-shop.jsonl` — 40 findings (cat-01 auth)
- `phase-05-injection-juice-shop.jsonl` — 40 findings (cat-08 injection)
- `phase-06-config.json`, `phase-06-*.jsonl`, `phase-06-stride/juice-shop.md`
- `findings.sarif` — 235 results, 6 runs
- `phase-07-report.md` — 185 KB report
- `docs/security-audit-baseline.json` — 54 KB pruned

**What this is NOT.** A full run of the skill. Categories cat-02 (IDOR), cat-03 (token_scope), cat-04 (MITM), cat-05 (crypto), cat-06 (secret_sprawl), cat-07 (deployment), cat-09 (LLM) were never executed in the original dogfood. The assertion suite correctly flags this by refusing to pass.

## Invocation

```bash
python3 tests/e2e/assertions.py \
  --artifact-dir /tmp/audit-targets/juice-shop \
  --repo-root . \
  --fixture tests/e2e/expected-findings.json \
  --require-jsonschema-backend
```

## Result

```
=== E2E assertion suite (juice-shop@v19.2.1) ===
[1/5] Phase-done markers...
[2/5] SARIF structure...
[3/5] Report section headers (tolerant)...
[4/5] Phase-05 JSONL schema + CWE-in-map (gated-aware)...
[5/5] Fixture expectations...

=== FAIL — 4 issue(s) ===
  MISSING marker: .claude-audit/current/phase-05.done
  2 of 12 fixture expectations not matched:
    - e2e-11: IDOR on basket — /api/Basket/:id returns without ownership check
    - e2e-12: MD5 used for password hashing
```

Exit code: 1.

## Interpretation

**All 4 failures are correct behavior.** None represent bugs in the suite:

| Failure | Why it's correct |
|---|---|
| `phase-05.done` missing | M4/M5 dogfood only ran 2 of 9 categories; the umbrella marker is emitted by the orchestrator only when every category (or gated equivalent) completes. Partial run = missing marker. |
| e2e-11 IDOR basket | `cat-02-idor-bola.md` never ran in the partial dogfood; no JSONL to match. |
| e2e-12 MD5 passwords | `cat-05-crypto.md` never ran in the partial dogfood; no JSONL to match. |

**10 of 12 fixture expectations matched** — exactly the subset covered by the categories that did run (cat-01 auth, cat-08 injection). The v2 schema additions (`alternate_cwes`, `alternate_categories`) let three previously-failing expectations match against pre-v2.0.1 artifacts that used older CWE codes:
- **e2e-01** (RSA key) now matches cat-01 output (`category: "auth"`) via `alternate_categories: ["auth", "config"]`.
- **e2e-02** (alg:none) matches cat-01's `CWE-287` via `alternate_cwes: ["CWE-287", "CWE-327"]`.
- **e2e-03** (kekse cookie) matches cat-01's `category: "auth"` via `alternate_categories`.

## What this validates about the suite

1. **Structural checks work.** Phase-done markers, SARIF structure (including the new `security-severity` property check), report section headers (tolerant of `## Findings` vs `## CRITICAL` format drift), and per-JSONL schema + CWE-in-map all execute without false passes or false fails.
2. **Gated categories work.** Empty/absent JSONL for `token_scope`, `mitm`, `deployment`, `llm` does not trigger a failure. The suite cross-references `gated_categories` correctly.
3. **jsonschema backend gate works.** `--require-jsonschema-backend` flag hard-fails if the library is missing; in this run the library was present and the check was silent (as designed).
4. **Path normalization works.** Findings with absolute paths (e.g., `/tmp/audit-targets/juice-shop/lib/insecurity.ts`) match fixture patterns after the `normalize_path` helper strips the `/juice-shop/` prefix.
5. **Fixture-drift tolerance works.** The v2 schema's `alternate_cwes` + `alternate_categories` let fixtures accept pre-v2.0.1 artifacts without regenerating the dogfood.

## What this does NOT validate

- **No real `claude -p "/security-audit"` invocation.** The script's step 4 (the claude call) was not exercised in this session — that requires the user's host auth. First real run will likely surface friction (flag verification, permissions prompt, sub-agent retries).
- **Baseline emission path (Phase 8).** The partial dogfood didn't run Phase 8; `phase-08.done` is optional per the assertion, so its absence isn't flagged — but neither has it been validated against a schema-compliant baseline.
- **SARIF from a full run.** The 235-result SARIF we're asserting against is from the partial dogfood's synthesis sub-agent; a full 9-category run's SARIF will be 2-3× larger and may surface size / schema edge cases.

## Next action

User runs `scripts/run-e2e-test.sh` on their host (with Claude Max auth). The first real run's output lands as a new writeup: `docs/test-runs/e2e-full-run-<ISO-ts>.md`.
