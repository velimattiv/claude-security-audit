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
- ~~**Opengrep engine swap + rule-licensing posture**~~ — **RESOLVED (v2.3):**
  project is free OSS forever → Semgrep invoke-only is unrestricted; **kept
  Semgrep** (fresher community rules), **declined Opengrep** (archived/frozen
  `opengrep-rules`). Added an `AUDIT_SAST_RULES` offline/BYO-rules override.
  See CHANGELOG [2.3.0].
- **Live-container E2E** — not run in-session (pre-existing Max-auth blocker).
  The static assertion suite + scorecard logic are updated and internally
  consistent; a host run with Claude auth is still required to exercise the
  categories end-to-end. **Cost anchor for a future live/GHA run** (from
  CyberGym-E2E, `research/08-cybergym-e2e.md`): budget ≈ **$10 / 90 min per
  target**, with diminishing returns after ~60 min (30→60 min yields most of
  the gain). [A4]
- ~~**CWE↔OWASP-tag pair validator**~~ — **delivered in v2.2**:
  `lib/cwe-owasp-map.json` (canonical map + documented `context_overrides`) +
  `validate-schemas.sh` [8/8] asserts each cat-file `CWE-N / A##:2025` pair
  matches canonical or a justified override. **Residual (low):** the map's
  `canonical` block and `lib/owasp-web-top10.md` Part-1 table are two
  hand-maintained copies kept in sync by convention; nothing yet diffs them —
  a future check could generate one from the other.

## Reporting a new gap

If you find a scenario the suite silently passes but should fail, open an issue with `tests/e2e/` label + a minimal repro (a diff that should break something but doesn't). PRs that add tolerated drift to fixtures without a justification paragraph in the fixture's `rationale` are rejected.

---

## v2.5 — collection scoping and severity arithmetic

These gates close specific, observed failures. They are not general solutions,
and the boundaries below are deliberate rather than aspirational.

### 12. Both reconciliations trust an agent-populated inventory
`validate-collection-scoping.py` and `validate-egress.py` reconcile an inventory
that a sub-agent wrote. Rule **C5** (a scoping claim with no caller-derived
predicate is rewritten to `unscoped`) and **C2b** (a handler with a
permission-shaped field and no filter, inventoried as un-decorated) re-check the
two claims most likely to be wrong, and the fail-closed coverage gates make an
*absent* entry loud. But an agent that mislabels an entity, or records a
plausible-looking predicate that is not actually applied on the query path, is
not caught mechanically. C5 verifies that a claimed predicate actually appears
within ±3 lines of the cited location, and C2b verifies a denied decoration
against the source — but an agent that cites a *real* predicate from an
unrelated code path, or mislabels the entity, still passes. **Mitigation
available:** the §6.20 adversarial pass must name the file:line of the scope it
claims to have found; a refutation with no line is not a refutation.

### 19. The partition-coverage escape hatch is a full bypass
`--allow-catch-all` permits a bare `**` glob alongside specific partitions. A
catch-all matches every file, so coverage is trivially "complete" and the gate
proves nothing. The flag prints a WARN saying exactly that and records
`catch_all_accepted` in the JSON report, but nothing stops an operator from
wiring it into CI and forgetting. It exists because a genuine single-partition
repo needs it; treat its presence in a config as a finding of its own.

### 20. Fingerprints are line-anchored
`sha1(file:line:cwe:category)` moves when code above the finding moves. v2.5 adds
a `(file, cwe)` line-window fallback (±25 lines) so R4 and L1 survive ordinary
edits, but a finding that moves further than that window — a large refactor, a
file split — still un-matches from its baseline entry. The consequences are a
reset `first_seen_at` and an R4 check that has nothing to compare against.
Changing the formula outright would invalidate every existing baseline, so the
window is the compromise. **Watch for it after a big refactor.**

The fallback carries its own residual risk, disclosed here rather than buried:
two DIFFERENT findings of the same CWE in the same file within 25 lines could in
principle bind to each other. A title-similarity floor (Jaccard ≥ 0.34) and a
one-baseline-entry-to-one-consumer rule guard against it, but a routes file with
several near-identical unscoped-collection findings — this release's own primary
output shape — is exactly where a similarity floor is weakest, because the titles
genuinely are near-identical. Assignment is two-pass and best-first (title
similarity desc, then line distance asc, one baseline entry to one consumer), so
a weaker nearby decoy can no longer take the slot the true continuation needed —
but a genuine tie between two near-identical findings is resolved arbitrarily.
Cross-check the R4 section of the report after a refactor that moves several
same-CWE findings at once.

### 22. `Model.find(variableFilter)` is not a candidate
The ODM anchor requires a `)` or `{` after `find(` — that is what separates
`User.find({})` from an in-memory `Roles.find(r => r.id === x)` on a capitalised
constant array, which is ubiquitous in real TypeScript and would otherwise fail
the coverage gate on every run. The cost is that `User.find(filter)` with a
variable filter is missed: a variable is indistinguishable from a predicate
callback without type information. Accepted deliberately — a gate that cries wolf
gets disabled, and a disabled gate catches nothing.

### 21. `--changed-files` line ranges are near-exact by design
Range matching pads by ±2 lines, not by the fingerprint window's ±25. That is
deliberate (a 25-line pad made ranges barely tighter than bare paths while being
sold as the precise option), but it means a genuine fix whose diff hunk lands
more than 2 lines from the reported line is NOT accepted as an explanation, and
the finding reports as `disappeared_unexplained`. That is the intended failure
direction: a false alarm you close by recording the reason, rather than a
vanished HIGH nobody notices.

### 13. Base scopes are the main false-positive mode
A `default_scope`, a tenant-injecting repository, a Prisma client extension, or
database row-level security **is** valid row scoping, and none of them appear in
the handler. C1 will over-flag when Phase 2 misses one. This is deliberate — the
failure direction is toward triage, not toward silence — but on a codebase that
scopes centrally, expect noise on the first run until the scopes are recorded as
`scope_evidence`. **Not automated:** there is no detector for "a scope exists
somewhere else".

### 14. Runtime-assembled queries are out of mechanical reach
A query built by string concatenation at request time, or dispatched through a
generic query-service abstraction, cannot be statically decided. These are
recorded as `coverage: caveat` and surfaced in the report. They are **not**
counted as scoped.

### 15. The composer can only compose what was tagged
`compose-attack-paths.py` chains `preconditions`/`postconditions`. A capability
nobody wrote down joins nothing, so a real chain between two untagged findings is
invisible to R1 and R3. **Mitigations available:** R2 fires on prose that names
another finding (no tags needed); `--require-capabilities` enforces tags on the
four access-control categories; the ORPHAN CAPABILITIES report makes a
half-composed chain visible. None of these makes chain analysis complete — they
make the gap loud. **A clean gate with a long orphan list is not a clean gate.**

### 16. Personas and crown jewels are derived, not verified
Phase 0 §0.14 derives them by rule from the profile. If it mis-classifies the
lowest self-provisionable role as privileged, R3 stops firing for the persona
that matters most. The composer falls back to capability *patterns* when the
lexicon is absent, but it cannot detect a lexicon that is present and wrong.
**Review the persona list in the report** — it is printed for that reason.

### 17. L1's threshold is policy, not physics
30 days is a default (`--max-age-days`). It is not derived from anything. The
claim is only that *a* threshold now exists and is enforced mechanically, which
is strictly more than the previous state, where a CONFIRMED finding aged 96 days
without any mechanism noticing.

### 18. R4 cannot distinguish a fixed finding from an unlooked-for one
A HIGH+ that disappears between runs is matched against `--changed-files`. If the
fix landed in a file the audit did not diff (a config change, an infrastructure
control, a dependency bump), the run reports `disappeared_unexplained` — a false
positive that must be closed by recording the reason. The inverse (a finding that
disappears because Phase 5 silently under-covered) is the failure this accepts
noise to catch.
