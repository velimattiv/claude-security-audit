# E2E Test Suite

Local-only end-to-end test that runs the full `/security-audit` skill
against a pinned Juice Shop tag and asserts against a fixture of known
vulnerabilities.

## Quick start

```bash
# From the skill's repo root
scripts/run-e2e-test.sh
```

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
  `mitm`, `deployment`, `llm`. No fixture; Juice Shop v19.2.1 has no
  ground truth for these. Coverage supplemented in v2.1 via a DVWA +
  Go-target dogfood.

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

## Dry-run mode

```bash
scripts/run-e2e-test.sh --dry-run
```

Skips the `claude` invocation and runs assertions against the target
dir's existing `.claude-audit/` contents. Useful for:
- Iterating on the assertion script without paying for Opus calls.
- Validating a prior run's artifacts after the fact.

## Updating the fixture

When upstream Juice Shop releases a new version:

1. Pin `TARGET_TAG` in `config.env` to the new tag.
2. Run the E2E; it'll likely fail on file-path drift (routes rename
   between majors).
3. Update `expected-findings.json` — adjust `file_pattern` +
   `alternate_file_patterns` per the new layout.
4. Commit pin + fixture edit **atomically**. A mismatched pair makes
   the test flaky.

## False passes this can still produce

- **Schema validator lied.** The assertion re-runs the schema validator
  on every Phase 5 JSONL — if THAT validator has a bug, bad findings
  could pass.
- **A category fixture is satisfied by a wrong finding.** E.g., the
  (file, cwe, category) tuple happens to match another similar finding
  at the same location. Mitigated by the fixture list being
  hand-curated from Juice Shop's known-vuln set, not scanned.
- **Report contains the required section headers but no real content
  between them.** We check structure, not semantic completeness.
  Mitigated by the per-fixture match + schema-validator-must-pass.

These are known gaps; documented here so future contributors can
harden them without re-discovering.

## What this catches that the partial M4/M5 dogfoods don't

- **Full 9-category fan-out succeeded.** Every category either produced
  findings or was gated. No category silently returned zero because of
  a prompt bug.
- **Phase 7 synthesis produced valid SARIF + report.** The M4/M5
  dogfoods validated this on 2 of 9 categories' output — this does it
  on all 9.
- **Baseline emission works end-to-end.** M6 only dry-ran the
  invalidation math; E2E runs Phase 8.
- **Scanner bundle ran at the real fan-out scale.** Previous dogfoods
  spot-ran individual scanners; this runs them as Phase 4 orchestrates.
