# E2E Test Suite

Local-only end-to-end test that runs the full `/security-audit` skill
against a pinned vulnerable-by-design target and asserts against a
fixture of known vulnerabilities. As of schema **v3** the suite also
emits a **precision/recall scorecard** (it no longer only measures
coverage — it now penalises false positives on labeled-safe decoys).

Three targets are wired (one fixture each):

| `--target` | Fixture | Stack | Adds |
|---|---|---|---|
| `juice-shop` (default) | `expected-findings.json` | JS/TS (Express) | the original 12-fixture coverage gate + decoys |
| `dvwa` | `dvwa-fixture.json` | PHP + MariaDB | SQLi/XSS/cmd-inj/LFI/upload; graded `impossible.php` decoys |
| `crapi` | `crapi-fixture.json` | Java/Spring + Python/Django + Go + TS | `token_scope` (JWT/JWK), `deployment`, partial `mitm`, BOLA, mass-assignment, SSRF |

## Quick start

```bash
# From the skill's repo root
scripts/run-e2e-test.sh                      # Juice Shop (default)
scripts/run-e2e-test.sh --target dvwa        # DVWA (PHP)
scripts/run-e2e-test.sh --target crapi       # OWASP crAPI (polyglot)

# Opt-in scorecard floors (default floors are 0.0 = no-op):
scripts/run-e2e-test.sh --min-recall 0.9 --min-precision 0.8
```

> **Live runs need Claude auth.** `run-e2e-test.sh` invokes the host's
> already-authenticated `claude` CLI (API key, claude.ai OAuth, or
> Claude Max). A fresh CI runner has none of these — see "Why
> local-only" below. The harness logic + fixtures in this directory are
> validated offline ( `python3 tests/e2e/assertions.py --help`,
> `ast.parse`, `jq empty <fixture>`); only the full
> clone→audit→assert loop needs live auth.

Runs in ≈30-60 minutes wall time on a medium host; cost is your Claude
Code usage (Max subscription or pay-per-token, whichever your local
`claude` is authenticated against).

## What it does

1. Verifies `claude --version` is present and readable.
2. Clones Juice Shop at the pinned tag (`config.env → TARGET_TAG`) to
   `/tmp/e2e-target/`.
3. Copies this skill into the target's `.claude/skills/security-audit/`
   so Claude Code's project-local skill discovery finds it.
4. Runs `claude -p "/security-audit" --dangerously-skip-permissions` in
   the target directory.
5. Runs `assertions.py` against the resulting `.claude-audit/` artifacts.

## What the assertions check

**Structural (5 categories):**
- every `phase-NN.done` marker exists (0 through 7)
- `findings.sarif` is valid SARIF 2.1.0 with `.runs[].tool.driver.name`
  and `.runs[].results[]`
- The report has required section headers (`# Security Audit Report`,
  `## Executive Summary`, `## Findings`, surface/route section,
  `## Methodology Coverage`)
- every non-empty `phase-05-*.jsonl` validates against
  `finding-schema.json` + every CWE is present in `cwe-map.json`
  (via `scripts/validate-findings.py --cwe-map`)
- `jq '[inputs] | length > 0'` equivalent — no empty-file passes

**Capability (12 fixtures):**
- 12 specific known-bug expectations. Each entry in
  `expected-findings.json` must be matched by at least one finding in
  `phase-05-*.jsonl` or `phase-06-config.json` by `(file_pattern, cwe,
  category)`.
- Categories with ≥1 fixture: `auth` (3), `injection` (5),
  `secret_sprawl` (2), `idor` (1), `crypto` (1).
- Gated categories (noted in `gated_categories`): `token_scope`,
  `mitm`, `deployment`, `llm`, **`agentic`**. No fixture; Juice Shop
  v19.2.1 has no ground truth for these. An absent
  `phase-05-<gated>-*.jsonl` is a **legitimate skip, not a failure**
  (see "Gated vs always-on categories" below). DVWA and crAPI supply
  the missing language/category coverage.

**Precision/recall scorecard (schema v3):**
- After the coverage gate, `assertions.py` scores every finding against
  the fixture's positive expectations **and** its
  `negative_expectations[]` decoys, then writes `scorecard.json` +
  `scorecard.md` (next to the run artifacts; the manual default is the
  fixture's directory).
- **The scorecard is additive.** With the default floors
  (`--min-precision 0.0`, `--min-recall 0.0`) it never changes the
  exit code — the existing coverage gate and all structural checks are
  unchanged. Use `--no-scorecard` to skip it entirely.

## Fixture schema v3 — `negative_expectations[]` (decoys)

v3 adds a sibling array to `expectations[]`. Each decoy is a **safe
location that MUST NOT produce a finding**; a finding that lands on one
(matching its forbidden tuple, at or above its severity floor) is
counted as a **false positive**.

```jsonc
"negative_expectations": [
  {
    "id": "neg-01",                       // required, unique
    "description": "...",                 // human note
    "file_pattern": "Dockerfile",         // required; same glob rules as expectations
    "alternate_file_patterns": ["..."],   // optional
    "forbidden_cwe": "CWE-89",            // forbid by CWE (single)…
    "forbidden_cwes": ["CWE-250", "..."], // …or several
    "forbidden_category": "deployment",   // and/or forbid by category…
    "forbidden_categories": ["..."],      // …or several
    "min_severity": "HIGH",               // optional; default MEDIUM. Findings
                                          //   below this rank are ignored (an
                                          //   informational note on safe code
                                          //   is not an FP). Accepts
                                          //   LOW/MEDIUM/HIGH/CRITICAL or a
                                          //   numeric CVSS security-severity.
    "rationale": "..."                    // why this is a realistic decoy
  }
]
```

**Scoring (`score_findings` in `assertions.py`):**

- **TP** — a positive expectation matched by ≥1 finding.
- **FN** — a *hard* positive expectation (`must_match` ≠ `false`) with
  no match. Recall is computed over hard fixtures only; soft fixtures
  are orchestrator-depth-dependent and reported separately (they do not
  lower recall).
- **FP** — a finding that matches a decoy's forbidden tuple at ≥ its
  `min_severity`, **and is not itself a true positive**. TP precedes FP:
  a finding that legitimately satisfies a positive expectation is never
  counted against a decoy on the same file (lets a decoy and a positive
  share a file/CWE — e.g. `lib/insecurity.ts` has both the MD5 misuse
  *and* a correct bcrypt path).
- When both `forbidden_cwe(s)` and `forbidden_category(s)` are present,
  **either** match is an FP. SARIF-sourced findings carry no native
  category, so category-only decoys only catch JSONL findings; give a
  `forbidden_cwe` too if you need the SARIF export covered.
- Findings outside any labeled region (neither positive nor decoy) are
  **unscored** — precision is computed only over labeled territory, so
  legitimate extra finds are neither rewarded nor penalised.
- `precision = TP/(TP+FP)`, `recall = TP/(TP+FN)`,
  `F1 = 2PR/(P+R)`. A fixture with **no** decoys yields
  `precision = 1.0` (no FP denominator) — backward compatible.

**Seed decoys (real FP denominator on day one):** the Juice Shop fixture
ships three — the hardened v19.2.1 Dockerfile (distroless + `USER 65532`,
flagging it `deployment HIGH` is an FP), the Sequelize ORM model layer
(flagging it `CWE-89` is the ORM false-positive twin of the real raw-SQL
SQLi), and the bcrypt path in `lib/insecurity.ts`. DVWA's graded
`impossible.php` files and crAPI's BCrypt/ORM/JPA layers are the decoys
for those targets.

## Gated vs always-on categories

`gated_categories{}` documents categories that have **no ground truth in
this target** and whose absence is a *legitimate skip*:

- **`agentic`** is gated on `profile.mcp_agentic.detected`. Juice Shop,
  DVWA, and crAPI have no MCP server / agent / tool-definition surface,
  so the profiler sets `detected=false` and `cat-agentic` is gated off.
  **An absent `phase-05-agentic-*.jsonl` is a PASS, not a failure** —
  the suite never demands agentic findings on a target with no MCP
  surface.
- `token_scope`, `mitm`, `deployment`, `llm` are gated on Juice Shop
  (no ground truth); crAPI un-gates `token_scope`/`deployment`/`mitm`
  by providing fixtures for them.

`always_on_categories{}` documents the opposite: **`supply_chain`** runs
on *every* target and is **never** excused by gating. It lives in its
own key (not `gated_categories`) precisely so the empty-JSONL excuse does
not apply to it.

## Why local-only (no GitHub Actions yet)

`scripts/run-e2e-test.sh` uses the host's already-configured Claude
Code auth — API key, claude.ai OAuth, or Claude Max subscription. A
fresh CI runner has none of these.

Three options for a future GHA variant, none shipped today:

- **(a) Dedicated API key.** Separate from any Claude Max subscription.
  Provisioned and billed pay-per-token. Stored as a GHA secret
  (`ANTHROPIC_API_KEY_E2E`). Runs cost ≈$5-20 per invocation.
- **(b) OAuth credential delegation.** Unknown if supported by Claude
  Code; would require verification.
- **(c) Skip GHA entirely.** Local-only remains the canonical flow.

Current state: (c). `docs/ROADMAP.md` tracks the investigation as a
v2.1 candidate. The blocker is auth, not capability.

## Dry-run + keep modes

```bash
scripts/run-e2e-test.sh --dry-run     # skip claude call; validate existing artifacts
scripts/run-e2e-test.sh --keep        # preserve prior baseline for delta-mode testing
```

- `--dry-run`: validates an existing `.claude-audit/` without paying
  for Opus calls. Useful for iterating on the assertion script.
- `--keep`: skips the `rm -rf $TARGET_DIR` step so a prior baseline
  survives; the next `claude -p "/security-audit mode: delta"`
  exercises delta-mode invalidation.
- Without either flag, the script archives any existing
  `.claude-audit/baseline.json` under `.claude-audit/history/` with a
  timestamp before wiping — you can always recover prior state.

## Updating a fixture / pinning a target

**Where the pin lives.** Juice Shop pins via `config.env`
(`TARGET_TAG`) for back-compat. DVWA and crAPI pin **inside their
fixture JSON** — the `target_repo` + `target_ref` fields are the single
source of truth; `run-e2e-test.sh --target dvwa|crapi` reads them
directly. Current pins:

- `juice-shop` → `v19.2.1` (config.env)
- `dvwa` → `v1.10` (dvwa-fixture.json `target_ref`)
- `crapi` → `v1.1.6` (crapi-fixture.json `target_ref`)

When upstream releases a new version:

1. Update the pin (`config.env` for Juice Shop; `target_ref` in the
   fixture for DVWA/crAPI).
2. Run the E2E; it'll likely fail on file-path drift (routes/handlers
   rename between majors; crAPI's microservice paths are especially
   version-sensitive).
3. Update the fixture — adjust `file_pattern` +
   `alternate_file_patterns` per the new layout, and re-verify
   `negative_expectations[]` still point at the hardened twin.
4. Commit pin + fixture edit **atomically**. A mismatched pair makes
   the test flaky.

## Known gaps

Moved to `docs/KNOWN-GAPS.md` — single canonical list with
"mitigation available" lines per gap rather than a README afterthought.
The assertion suite is not a full regression harness; treat its PASS
as "structurally valid + 12 fixture hits" not "semantically correct."

## What this catches that the partial M4/M5 dogfoods don't

- **Full 11-category fan-out succeeded.** Every category either produced
  findings or was gated. No category silently returned zero because of
  a prompt bug.
- **Phase 7 synthesis produced valid SARIF + report.** The M4/M5
  dogfoods validated this on 2 of 11 categories' output — this does it
  on all 11.
- **Baseline emission works end-to-end.** M6 only dry-ran the
  invalidation math; E2E runs Phase 8.
- **Scanner bundle ran at the real fan-out scale.** Previous dogfoods
  spot-ran individual scanners; this runs them as Phase 4 orchestrates.
