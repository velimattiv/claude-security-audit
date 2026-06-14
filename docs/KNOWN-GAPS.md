# Known Gaps

Explicit list of v2.0.1 limitations. Each entry describes what's NOT enforced, so reviewers can decide what additional checks they need beyond what ships. Moved here from `tests/e2e/README.md` per Round-4 adversarial feedback — "documentation is acknowledgment, not mitigation."

## E2E assertion suite

### 1. Semantic correctness of findings
The suite validates *structural* conformance (schema, CWE-in-map, section headers) and *coverage* (fixture list matches). It does NOT verify that a finding's description is accurate — a sub-agent could emit "SQL injection" when the actual bug is XSS, as long as it satisfies (file, cwe, category).

**Mitigation available:** the fixture's `description` field is human-readable; a reviewer comparing fixture text to actual finding text would catch gross mismatches. Not automated. **v2.1 update:** fixture schema v3 adds `negative_expectations[]` decoys and a precision/recall/F1 scorecard (`tests/e2e/assertions.py` → `scorecard.json`/`.md`), giving the first automated false-positive signal — a different axis than semantic accuracy, but the suite is no longer coverage-only.

### 2. Report body content
`check_report_sections` verifies section headers are present. It does NOT check that the sections have non-trivial content. A report with `## Executive Summary` followed by an empty line then the next header would pass.

**Mitigation available:** add `--min-section-bytes` flag that grep's each section and asserts ≥N bytes between headers. Not implemented; would trade false-positives (legitimately short summaries) for false-negatives.

### 3. Single-run evidence
No non-determinism detection. A sub-agent that passes 3-of-5 runs (intermittent failure) is harder to catch with a one-shot E2E. Nightly runs would surface flakes; GHA not shipped in v2.0.1 (Max-auth blocker).

**Mitigation available:** `scripts/run-e2e-test.sh` could re-run and diff, but doubles cost. Deferred to v2.1 when GHA lands.

### 4. No regression catch on skill behavior changes
The assertion suite validates against Juice Shop v19.2.1 + the 12-entry fixture. Changes to `cat-*.md` instructions that alter sub-agent behavior will be caught only if they break a specific fixture — subtler shifts (e.g., severity calibration drift, CWE tagging drift) may pass.

**Mitigation available:** the `alternate_cwes` support in fixture v2 is partial mitigation. Full drift detection would require baselining sub-agent outputs across runs, not shipped.

### 5. Phase 6 `config.json` shape uncontracted
`collect_all_findings` tries two known layouts for `phase-06-config.json` (flat array OR `{"findings": [...]}`). Anything else is silently skipped — any fixture matching via Phase 6 config findings may silently miss.

**Mitigation available:** define a formal schema for `phase-06-config.json` and have Phase 6 sub-agent emit it. Tracked as a v2.1 candidate in `docs/ROADMAP.md`.

## Installer + scanner bundle

### 6. Scanner CVE DB freshness not enforced
`scripts/install-scanners.sh --check` warns on stale version pins, but the skill doesn't block audits against outdated scanner DBs. A 6-month-old trivy DB misses recent CVEs silently.

**Mitigation available:** `trivy` itself refreshes DB on each run by default; we explicitly pin `--skip-db-update` nowhere. OSV-scanner fetches online at run-time. So this gap is smaller than it sounds — but gitleaks rule updates land via binary updates.

### 7. No enforcement of the `--dangerously-skip-permissions` flag at runtime
`run-e2e-test.sh` preflight checks whether `claude --help` advertises the flag, but if the flag is silently gated behind an env var in a particular Claude Code version, the audit may stall mid-run waiting for interactive permission. The script warns but does not prevent.

**Mitigation available:** set `CLAUDE_CODE_DANGEROUSLY_SKIP_PERMISSIONS=1` in the script's env export. Not done because forcing that env var for a user who doesn't want skipped-permissions is invasive.

## Deferred to v2.1

Tracked in `docs/ROADMAP.md`:
- **GHA-hosted E2E** (Max-auth resolution) — still deferred.
- ~~**Second polyglot E2E target**~~ — **delivered in v2.1**: DVWA (PHP) +
  OWASP crAPI (Java/Go/Python) fixtures, `--target` selectable.
- **AST-based handler hashing** (replaces content hash) — still deferred.
- **Pre-commit recipe** (sub-second incremental checks) — still deferred.
- **ASVS L3 support** — still deferred.
- **Non-English codebase framework detection** — still deferred.

New v2.1 deferrals (see `docs/EPIC-v2.1-refresh.md` §4 + `docs/ROADMAP.md`):
- **Opengrep engine swap + rule-licensing posture** — held for owner sign-off
  (legal one-way door; the skill does not vendor Semgrep rule packs, which
  lowers urgency).
- **Live-container E2E for v2.1** — not run here (pre-existing Max-auth
  blocker). The static assertion suite + new scorecard logic are updated and
  internally consistent; a host run with Claude auth is still required to
  exercise the new categories end-to-end.
- **CWE↔OWASP-tag pair validator** — `validate-schemas.sh` checks the *shape*
  of `owasp_ids` and that CWEs exist in the map, but does NOT assert that a
  finding's `CWE-N / A##:2025` pairing matches `lib/owasp-web-top10.md`. Two
  Gate-C rounds each caught a hand-authored tag mismap (cat-07, then cat-06)
  that all validators passed green. A machine-readable CWE→A## map + a §
  asserting each pair would prevent recurrence. Deferred (needs the mapping
  encoded as data first).

## Reporting a new gap

If you find a scenario the suite silently passes but should fail, open an issue with `tests/e2e/` label + a minimal repro (a diff that should break something but doesn't). PRs that add tolerated drift to fixtures without a justification paragraph in the fixture's `rationale` are rejected.
