# Phase 7 — Synthesis & Report

## 🛑 MANDATORY EXECUTION RULES (READ FIRST)

📋 **This phase MUST produce, on disk, before advancing:**
- `.claude-audit/current/phase-07-report.md` (full structured human-readable report)
- `.claude-audit/current/findings.sarif` (SARIF 2.1.0 — see ⚠ below for per-result requirements)
- `.claude-audit/current/findings.cyclonedx.json` (SBOM, minimal skeleton if no scanner SBOM available)
- `.claude-audit/current/phase-07-findings-computed.jsonl` (§7.15 — findings with `severity_computed` applied; AUTHORITATIVE input to the report and SARIF)
- `.claude-audit/current/phase-07-governance.jsonl` (§7.15 — R4/L1-L3 governance findings; empty file if clean)
- `.claude-audit/current/phase-07-severity-gate.json` (§7.15 — gate summary incl. `blocking`, read by Phase 8)
- `.claude-audit/current/phase-07.done`

⚠ **EVERY `results[]` row in the synthetic `security-audit-skill` SARIF run MUST carry these properties:**
- `properties.security-severity`: CVSS-style numeric string. CRITICAL→`"9.0"`, HIGH→`"7.0"`, MEDIUM→`"5.0"`, LOW→`"3.0"`, INFO→`"1.0"`. Required for the GitHub Security tab.
- `properties.cwe`: the CWE id as a string (e.g. `"CWE-798"`). Required for fixture matching, baseline delta, and GitHub Security tab grouping. Look up the CWE in `lib/cwe-map.json`; if absent, use your best judgement and add an entry in a follow-up.
- `properties.category` (recommended): one of `auth`, `idor`, `token_scope`, `collection_scope`, `mitm`, `crypto`, `secret_sprawl`, `deployment`, `injection`, `llm`, `supply_chain`, `agentic`, `config`.

Per-scanner SARIF runs are copied through verbatim — do NOT rewrite
scanner results. Scanner CWE lives in `tags[]` / `rule.properties.tags` /
driver relationships per the scanner's own conventions (§7.8).

⛔ **DO NOT emit the human report without also emitting findings.sarif with CWE-per-result.** The report is the cover page; SARIF is the machine-readable deliverable. Producing only the report is a regression to v1 and breaks every downstream integration (delta mode, GitHub Security tab upload, CI gating on CRITICAL counts, fixture-based E2E validation).

---

**Goal.** Collect every finding from Phases 1-6, deduplicate, cross-
reference sources, assign final severity, identify skill-unique findings,
and emit three consumable artifacts: a human Markdown report, a
consolidated SARIF 2.1.0 document, and a CycloneDX SBOM.

**Inputs.**
- `phase-04-scanners/*.slim.json` (all scanner output)
- `phase-04-scanners/security-review-*.md`
- `phase-04-scanners/adversarial-*.md`
- `phase-05-*.jsonl` (all deep-dive category findings)
- `phase-06-config.json`, `phase-06-asvs.jsonl`, etc.
- `phase-06-egress.jsonl` (Authorized-Egress reconciliation findings, §6.19)
- `phase-06-collections.jsonl` (collection-scoping reconciliation findings, §6.20)
- `phase-02-sinks.json`, `phase-02-credentials.json` (egress inventories, for the report's coverage counts)
- `phase-02-collections.json` (collection inventory, for the report's row-scope counts)
- `phase-00-profile.json`, `partitions.json`, `phase-02-surface.json`

**Outputs.**
- `.claude-audit/current/phase-07-report.md` — the full, structured report.
- `.claude-audit/current/findings.sarif` — SARIF 2.1.0 consolidated.
- `.claude-audit/current/findings.cyclonedx.json` — SBOM (from trivy
  output if present; otherwise produced by syft if installed).
- Deliverable copies under the resolved `<output_dir>` (default
  `docs/security-audit-output/`, see [../lib/output-routing.md](../lib/output-routing.md)):
  `<output_dir>/security-audit-report.md`, `<output_dir>/findings.sarif`,
  `<output_dir>/findings.cyclonedx.json`. Copy AFTER the blackboard files
  above exist (blackboard-first).
- `.claude-audit/current/phase-07.done`

**Execution.** Single orchestrator pass. No sub-agent fan-out (synthesis
must see the whole picture).

---

## 7.1 — Collect

Load every JSONL / JSON artifact into in-memory lists:
- `findings[]` — all Phase 5 + Phase 6 JSONL lines + scanner-derived
  findings (from slim SARIF, with the scanner tool name in `sources[0].detail`).
  **Include `phase-06-egress.jsonl`** — the Authorized-Egress reconciliation
  findings (cross-layer / missing-enforcer class). These carry
  `sources[].detail = "validate-egress.py:R<n>"` and often a `verification_probe`;
  preserve the probe through dedup so it reaches the SARIF (`properties`) and the
  report. They are deterministic (`scanner` source) ⇒ CONFIRMED per §7.3.
- `asvs_results[]` — Phase 6 ASVS rows.
- `stride_tables{}` — per-partition Markdown blobs.
- `surfaces[]` — Phase 2.
- `profile`, `partitions` — discovery / partition data.

## 7.2 — Deduplicate

Deduplication key: `(file, line, category, fingerprint)` where
`fingerprint` is the first 12 chars of
`sha1(handler_file:line:cwe:category)`.

**Why keyed on CWE + category, not title** (v2.0.1 correction): the
sub-agent's finding `title` can drift between runs — a re-run that
rephrases "Hard-coded JWT secret" to "Hard-coded RSA private key in
lib/insecurity.ts" produces a different sha1 and the baseline's
carryover misses it. Keying on the CWE + category class makes
fingerprints stable across title drift while keeping file+line
specificity. Two findings at the same file:line with the same CWE are
semantically the same finding regardless of wording.

Two findings with the same key:
- Merge — keep the one with the longest description (most detailed),
  union their `sources[]`, set `confidence` according to §7.3.
- Keep the higher severity.
- Union their `owasp_ids[]`.

**Stability guarantee.** A finding's fingerprint is reproducible given
`(handler_file, line, cwe, category)`. Baseline carryover (Phase 8) and
delta-mode invalidation (M6) both use this fingerprint. If the sub-
agent emits a `fingerprint` field on the JSONL row, Phase 7 uses it
verbatim; otherwise Phase 7 computes it. Either way the canonical
formula is the one above.

## 7.3 — Cross-reference confidence

After dedup:
- **CONFIRMED** — `sources[].length >= 2` OR a single source of type
  `scanner` (scanners are mechanical ground truth).
- **LIKELY** — single `grep` source with a specific, unambiguous
  pattern name.
- **POSSIBLE** — single `grep` source with a generic pattern, or
  single `manual` source from `/security-review`.

The Phase 5 sub-agents already assign an initial `confidence`. Phase 7
may promote (LIKELY → CONFIRMED when another source appears) but never
demote.

## 7.4 — Severity rubric (final)

Severity was assigned per finding; Phase 7 may adjust by exactly one
rung based on context signals. **Cap at ±1 rung total regardless of
how many triggers fire** — the promotion is a calibration adjustment,
not a stacking modifier.

**Rule:**

1. Compute the signed signal:

   | Signal | Contribution |
   |---|---|
   | `trust_zone == "public"` | **+1** (promotion) |
   | `confidence == "CONFIRMED"` | **+1** (promotion) |
   | `data_ops ∩ {write, delete, exec} ≠ ∅` | **+1** (promotion) |
   | `trust_zone == "dev"` | **−1** (demotion) |

   | `RETURNS_OTHER_PRINCIPALS_ROWS` on the surface (v2.5) | **+1, and VETOES any demotion** |

2. Sum the signals. If net > 0, promote by exactly one rung. If net
   < 0, demote by one rung. If net == 0, no change. **Regardless of
   magnitude, the adjustment is at most one rung in either direction.**

   **`RETURNS_OTHER_PRINCIPALS_ROWS` dominates the zone weight** (v2.5): when
   set, the net can never be negative, so a dev-zone label cannot demote a
   finding on an endpoint that returns other principals' rows. Data breadth
   outranks a declared trust zone — an "internal" endpoint returning every
   tenant's rows outranks a "public" endpoint returning one. The ±1 cap still
   holds; this only removes the demotion, it does not stack a second rung.

3. Bounds: never exceed CRITICAL at the high end; never fall below
   INFO at the low end.

**Examples:**
- MEDIUM finding, CONFIRMED, public, write → net = +3 → promote one
  rung → HIGH. (Not CRITICAL — cap holds.)
- HIGH finding, grep-only, internal zone, read-only → net = 0 → stays
  HIGH.
- LOW finding, CONFIRMED, dev zone → net = 0 → stays LOW.
- MEDIUM finding, CONFIRMED, internal, read → net = +1 → promote →
  HIGH.
- LOW finding, grep-only, dev zone, read → net = −1 → demote → INFO.

Rationale: the severity **is already set** by the rubric on the
finding itself; this rule is a calibration adjustment based on
*context*. Context is corroborating evidence, not cumulative
severity. One context positive nudges the severity up by one rung;
more positives don't nudge further (they'd be double-counting the
same underlying signal). The symmetric dev-zone demotion captures
the inverse — test fixtures rarely warrant the same severity as
production code with the same finding body.

## 7.5 — Unique-to-skill identification

Compute the set of findings whose `sources[]` contains NO entry of type
`scanner` AND NO entry with `detail == "security-review"` AND NO entry
with `detail == "adversarial-review"`. These are the skill's
**unique value** — findings that generic scanners and the built-in
reviews missed. Call them out explicitly in the report.

## 7.6 — Methodology coverage matrix

Build a table for the report:

| Methodology | Coverage | Findings tagged |
|---|---|---|
| ASVS 5.0 L2 | X% (pass / fail / n.a.) | N |
| OWASP Top 10:2025 (web) | K/10 categories fired (A01..A10) | N |
| API Top 10 (2023) | per-category counts | N |
| LLM Top 10 (2025) | per-category counts (or N/A) | N |
| OWASP Agentic Applications (2026) | K/10 ASI categories fired (or N/A) | N |
| LINDDUN | 7-category counts (or N/A) | N |
| STRIDE | partitions covered | Markdown tables |
| CWE | unique CWEs seen | N |
| CWE Top 25 (2025) | hits / 25 (highest-ranked: #R) | N |
| Authorized-Egress (§6.19) | sinks reconciled / coverage-gate status | N |
| Collection scoping (§6.20) | collections reconciled by row_scope / coverage-gate status | N |
| Severity gate (§7.15) | escalations applied; governance failures outstanding | N |

- **OWASP Top 10:2025 (web)** row reads `phase-06-web-top10.jsonl` (§6.16);
  count categories whose `count > 0`. **Agentic (2026)** row reads
  `phase-06-agentic-top10.jsonl` (§6.17); show `N/A` when that file is
  zero bytes (gate did not fire).
- **CWE Top 25 (2025)** row is computed by §7.13 below.

## 7.13 — CWE Top 25 (2025) prioritization enrichment

**Additive, after §7.4 severity is final. Pure lookup, no fan-out.** Uses
the ranked list in `lib/owasp-web-top10.md` (Part 2) — MITRE CWE Top 25
(2025), published 2025-12-15.

For each finding whose `properties.cwe` matches an in-map `CWE-NNN` row in
that list:
1. Stamp `properties.cwe_top25_2025_rank` = the row's rank (1–25) on the
   finding's SARIF result (and carry it on the in-memory finding).
2. Treat Top-25 membership as a **reporting-priority** signal, surfaced in
   the Executive Summary ("CWE Top 25 (2025) hits: <n>, top-ranked #<r>")
   and as a tiebreaker when ordering findings of equal severity (lower
   rank = list first).

**Severity-cap interaction (MANDATORY — do NOT break §7.4):**
- This enrichment may **raise priority by at most one rung** and **never
  lowers** severity.
- The ±1-rung cap in §7.4 is the single authority. If §7.4 already applied
  a +1 promotion to a finding, Top-25 membership adds **zero** further
  rungs — it becomes a pure reporting highlight only (no second bump).
- Concretely: the total context-driven promotion for any finding is **≤ +1
  rung** counting §7.4 and §7.13 together. Top-25 never stacks on top of an
  existing §7.4 promotion, and never demotes.

The seven memory-safety entries in the Part 2 list (rendered as `#NNN`,
not `CWE-NNN`) are not in `lib/cwe-map.json`, so they never match a finding
— correct for a web/polyglot audit.

## 7.14 — grype EPSS / CISA-KEV join

**Additive prioritization, after §7.4. Never lowers severity.** Scanner
side already documented in `lib/scanner-bundle.md` (grype EPSS/KEV).

If `phase-04-scanners/grype.json` exists, read it and join onto matching
findings by CVE / GHSA id:
- EPSS probability: `.matches[].vulnerability.epss[0].epss`
- CISA-KEV flag: `.matches[].vulnerability.knownExploited` (boolean)

Match grype entries to findings by vulnerability id (CVE-/GHSA-) — these
appear in dependency/SCA findings' `id`, `title`, or `sources[].detail`,
and in scanner-run SARIF `ruleId`. For each matched finding:
1. Stamp `properties.epss` (numeric string, e.g. `"0.142"`) and
   `properties.kev` (`"true"`/`"false"`) on its SARIF result.
2. If **EPSS ≥ 0.10 OR KEV == true**, add it to an **"Exploit-likely"**
   callout surfaced in the Executive Summary and at the top of the
   Remediation Roadmap.

**Severity-cap interaction:** EPSS/KEV is prioritization-only and
**additive** — it may raise reporting priority but **never lowers**
severity, and like §7.13 it does not stack a second rung on top of any
§7.4 promotion (the ±1-rung cap is authoritative). KEV/high-EPSS findings
that are still only MEDIUM by the rubric stay MEDIUM but are flagged
"Exploit-likely" so triage sees them first.

If `grype.json` is absent, skip silently (grype is optional) and note
"EPSS/KEV: grype not run" in the report's coverage section.

## 7.15 — Severity gate (v2.5) — MANDATORY, runs BEFORE the report is written

**Severity stops being asserted here and starts being computed.**

Everything above rates findings *in isolation*. That is the step that failed: a
CONFIRMED finding whose own description read *"…if the deck UUID is known.
Combined with H1, an attacker can identify published decks and access output
directly"* was filed MEDIUM — while `H1`, a **HIGH in the same document**,
supplied exactly the capability the mitigation assumed nobody had. It went
unremediated for 96 days, was downgraded to LOW at the next baseline, and its
sibling endpoint was affirmatively described as "well-defended (INFO)".

Chain **detection** was not the failure. The chain was written down, in prose, by
a human. Chain **arithmetic** was. This section is the arithmetic.

### Step 1 — run the gate

```bash
SKILL_DIR=$(cat .claude-audit/.skill-dir)
[ -n "$SKILL_DIR" ] || { echo "ERROR: SKILL_DIR not resolved"; exit 1; }
python3 "$SKILL_DIR/lib/compose-attack-paths.py" \
  .claude-audit/current/phase-05-*.jsonl \
  .claude-audit/current/phase-06-*.jsonl \
  --profile   .claude-audit/current/phase-00-profile.json \
  --baseline  .claude-audit/baseline.json \
  --run-id    "$(jq -r .audit_id .claude-audit/current/phase-00-profile.json)" \
  --max-age-days 30 \
  --out          .claude-audit/current/phase-07-governance.jsonl \
  --rewrite      .claude-audit/current/phase-07-findings-computed.jsonl \
  --json-summary .claude-audit/current/phase-07-severity-gate.json
```

(`--baseline` is omitted on a first run — R4 and the lifecycle gates need a prior
baseline to compare against. Pass `--changed-files` with
`git diff --name-only <baseline.git_head> HEAD` when a baseline exists, so a
finding that disappeared because its file changed is explained rather than
flagged.)

### Step 2 — apply, then converge

Two distinct classes of exit-1, handled differently:

**(a) Escalations (R1/R2/R3) are auto-applicable.** Replace your in-memory
finding set with `phase-07-findings-computed.jsonl` — it carries
`severity_computed` (authoritative), `severity_asserted` (the analyst's
opinion, retained for provenance), an appended `severity_history` entry, and
`escalation_rules`. **Re-run the gate against the rewritten file.** It must now
exit 0 on the escalation count. If it does not, you did not apply the rewrite.

**(b) Governance failures (R4, L1-L3) are NOT auto-applicable.** They require a
human decision — a fix, an owned acceptance, a recorded reason, or a linked
commit. They must **not** silently disappear:

- The report is still written, but it is **stamped `AUDIT GATE: FAILED` at the
  top of the Executive Summary**, listing each unresolved governance failure.
- **Phase 8 does NOT write a baseline** while governance failures stand (see
  §8.1). This is the load-bearing part: without it, a run that silently
  downgrades a finding would persist that downgrade as the new baseline, and the
  next run would have nothing to ratchet against. **You cannot launder a
  downgrade by re-running.**
- The skill's exit status is non-zero so CI fails.

### The rules, and the failure each one is for

| Rule | Check | Observed failure it exists for |
|---|---|---|
| **R1** | A finding's `precondition` is supplied by another finding's `postcondition` in this same report ⇒ its severity floor is the supplier's. Applied to a fixpoint, so multi-hop chains propagate. | "Only exploitable if the UUID is known" — while a HIGH in the same report handed out the UUIDs. |
| **R2** | Prose matching `combined with\|chained\|together with\|in combination\|…` that names another finding ⇒ severity ≥ that finding's. | Five lines of regex that **alone** would have escalated M6 in March. Fires even with zero capability tags. |
| **R3** | Any path from an **unprivileged** persona reaching a **crown jewel** ⇒ CRITICAL — for the findings that actually *contribute* (backward slice), not every finding that happens to be reachable. | A genuinely-MEDIUM cookie-scope bug is CRITICAL once you notice the persona holding it is external. No analyst makes that call by eye across 60+ findings. |
| **R4** | Severity may not decrease across runs without a `severity_history` entry naming what changed (`fix_commit` / `compensating_control` / `disproven_exploitability` / `rescoped`). A HIGH+ that *disappears* must be matched to a code change or it is itself a finding. | CONFIRMED MEDIUM → LOW → "well-defended (INFO)", while still exploitable. |
| **L1** | A CONFIRMED HIGH/CRITICAL older than 30 days with no `lifecycle.fix_commit` and no unexpired acceptance ⇒ fail. | The 96-day hole. Detection was never the bottleneck; triage-to-fix was. |
| **L2** | HIGH+ cannot be `accepted` without a named owner **and** a live expiry. | "The team says it is fine." |
| **L3** | `verified` requires `verified_by_test`. `fixed` without one is reported. | The fix shipped with no denial test, and a sibling test mocked the very gate it should have pinned — so "fixed" was never mechanically proven, and the class recurred on a different endpoint. |

### Read the ORPHAN CAPABILITIES section

The gate prints preconditions no finding or persona supplies, and postconditions
that feed nothing. That list is the drift alarm: a chain that should have
composed and did not, usually because two sub-agents named the same capability
differently. Reconcile the vocabulary against
[`../lib/capability-lexicon.md`](../lib/capability-lexicon.md) and re-run — do
not ignore it. **An empty orphan list is evidence the arithmetic actually ran;
a long one means the gate is quietly inert.**

### Honest scope

The composer can only compose what was tagged, and a capability nobody wrote
down joins nothing. R2 is the backstop for untagged chains named in prose, and
the orphan list is the backstop for the backstop — but neither makes this
complete. What v2.5 changes is that the failure is now **loud** rather than
silent, and that a tagged chain can no longer be out-voted by instinct.

## 7.7 — Emit `phase-07-report.md`

Use the template in `lib/report-template.md`. Sections in order:

1. **Header** — project name, audit id, skill version, generated-at,
   scope, duration.
2. **Executive Summary** — total findings, by severity, by category,
   by confidence. Top 3 risks (one line each). Plus: **CWE Top 25 (2025)
   hits** (§7.13) and the **"Exploit-likely" callout** (EPSS ≥ 0.10 OR
   KEV=true, §7.14) when either is non-empty.
3. **Partition Risk Ranking** — table from Phase 1 with finding counts
   appended per partition.
4. **Findings** — grouped by severity (CRITICAL → INFO), within severity
   grouped by category. Per finding: id, title, confidence, file:line,
   CWE, OWASP ids, description, attack scenario, suggested fix.
5. **Attack Surface Summary** — from Phase 2, counts by category,
   noteworthy surfaces listed.
5c. **Collection Scoping (row-level access control)** — from §6.20.
   Report: collections inventoried by `row_scope`; the fail-closed coverage-gate
   status; every C1/C2 finding WITH its `verification_probe`; the C4 tests that
   pin insecure behaviour; and the `public_resources` allowlist again in this
   context (it is the one place "we decided this is public" is auditable). State
   the caveat plainly: a clean reconciliation means every *known* list-query
   candidate was accounted for and scoped — not that no unscoped path exists.

5d. **Severity Gate (computed severity + lifecycle)** — from §7.15.
   Report: escalations applied with the rule that fired and the from→to rungs;
   per-persona reachability and any crown jewels reached; unresolved governance
   failures (R4/L1-L3) as a **blocking** list; and the ORPHAN CAPABILITIES list
   with a one-line note on what it means. If any governance failure stands, the
   Executive Summary opens with `AUDIT GATE: FAILED` and Phase 8 is skipped.

5b. **Authorized-Egress (cross-layer access control)** — from §6.19.
   Report: sensitive-resource count (default-deny) + the `public_resources`
   allowlist for human review; egress sinks inventoried + candidates dismissed;
   the fail-closed **coverage gate** status; the cross-layer / missing-enforcer
   findings WITH their `verification_probe` (the request that should fail). Close
   with the honest caveat: a clean reconciliation is high-signal, **not** a proof
   of absence; list any `coverage: caveat` modalities (e.g. CDN-edge) explicitly.
6. **Methodology Coverage** — the §7.6 matrix (add the Authorized-Egress row).
7. **STRIDE Tables** — per-partition, inline from phase-06-stride/*.md.
8. **ASVS Checklist** — summary then per-category breakdown.
9. **Route Inventory** — first 50 rows (truncated with count).
10. **Unique-to-Skill Findings** — §7.5.
11. **Audit Coverage** — per-phase status (completed / degraded /
    skipped) with notes.
12. **Remediation Roadmap** — grouped by effort (trivial / small /
    medium / large) for quick triage.

## 7.8 — Emit `findings.sarif`

Single SARIF 2.1.0 document with `runs[]` = one run per scanner + one
synthetic run named `security-audit-skill` for the grep/manual findings.

Required per SARIF 2.1.0:
- `$schema`: `https://json.schemastore.org/sarif-2.1.0.json`
- `version`: `2.1.0`
- `runs[]`: each with `tool.driver.name`, `tool.driver.rules[]`,
  `results[]`.

Every `results[]` item in the synthetic `security-audit-skill` run:
- `ruleId`: finding's id
- `level`: SARIF maps from our severity — CRITICAL/HIGH → `error`,
  MEDIUM → `warning`, LOW/INFO → `note`
- `message.text`: title + description
- `locations[0].physicalLocation.artifactLocation.uri`: `file`
- `locations[0].physicalLocation.region.startLine`: `line`
- `partialFingerprints.primary`: the dedup fingerprint
- `properties.security-severity`: CVSS-compatible numeric (CRITICAL=9.0,
  HIGH=7.0, MEDIUM=5.0, LOW=3.0, INFO=1.0) — consumed by GitHub Security
  tab.
- `properties.cwe`: the CWE id as a string (e.g. `"CWE-798"`). Required
  for fixture matching, baseline carryover, and GitHub Security tab
  grouping. Look up in `lib/cwe-map.json`.
- `properties.category`: one of the 13 category slugs (`auth`, `idor`, `token_scope`, `collection_scope`, `mitm`, `crypto`, `secret_sprawl`, `deployment`, `injection`, `llm`, `supply_chain`, `agentic`, `config`). Recommended.
- `properties.cwe_top25_2025_rank` (optional): integer 1–25 when the
  finding's CWE is in the 2025 CWE Top 25 (§7.13).
- `properties.epss` / `properties.kev` (optional): EPSS probability and
  CISA-KEV flag joined from grype (§7.14). Additive prioritization signals
  only — they never change `level` or `properties.security-severity`.
- `properties.verification_probe` (optional): for Authorized-Egress (§6.19) and
  collection-scoping (§6.20) findings, the JSON `{request, expected, actual}` —
  the executable proof (the request that should fail). Carry it through verbatim
  so a triager can run it.
- `properties.severity_asserted` / `properties.severity_computed` (v2.5): when
  they differ, the SARIF `level` and `security-severity` follow **computed**.
  Emit both so a reader can see that the rating was raised by path arithmetic
  rather than by opinion, and `properties.escalation_rules` naming which rule
  fired.
- `properties.first_seen_at` (v2.5): carried from the baseline. This is what
  makes an ageing HIGH visible in the GitHub Security tab rather than looking
  identical to one found this morning.

**Scanner-run results.** Per-scanner SARIF runs (semgrep, trivy, etc.)
emit CWE in scanner-specific locations — `tags[]`, `rule.properties.tags`,
or driver `relationships`. The skill copies those runs through
*verbatim* — do NOT rewrite scanner results to add `properties.cwe`
where they already encode CWE elsewhere. The per-result-CWE mandate
applies to the synthetic skill run only; scanner-run CWE is consumed by
the assertion suite via the same multi-source extraction logic that
`tests/e2e/assertions.py:_sarif_result_to_finding` uses (it inspects
`ruleId`, `properties.cwe`, `properties.cwes`, and `tags`).

Validate with `jq -e .runs .` before write.

## 7.9 — Emit `findings.cyclonedx.json`

If trivy produced `phase-04-scanners/sbom.cyclonedx.json`, copy and
annotate with findings (`vulnerabilities[]` list pointing to
`findings.sarif` entries).

If no SBOM is available, emit a minimal CycloneDX skeleton with the
detected languages / frameworks from Phase 0 and note "SBOM
incomplete — install trivy or syft for full coverage".

## 7.10 — Save user-facing deliverables

Resolve `<output_dir>` per [../lib/output-routing.md](../lib/output-routing.md)
(already resolved + persisted in `.claude-audit/config.json` during preflight;
read it from there, default `docs/security-audit-output/`). Then, AFTER the
blackboard files exist:

```bash
OUT=$(jq -r '.output_dir // "docs/security-audit-output"' .claude-audit/config.json 2>/dev/null || echo docs/security-audit-output)
mkdir -p "$OUT"
cp .claude-audit/current/phase-07-report.md      "$OUT/security-audit-report.md"
cp .claude-audit/current/findings.sarif          "$OUT/findings.sarif"
cp .claude-audit/current/findings.cyclonedx.json "$OUT/findings.cyclonedx.json"
```

Echo `$OUT/security-audit-report.md` to the user. (The pruned baseline is
copied to `$OUT/` by Phase 8.)

## 7.11 — Report summary to user

> Security audit complete.
>
> - **Total findings:** <N> (<C> CRITICAL, <H> HIGH, <M> MEDIUM, <L> LOW, <I> INFO)
> - **Partitions audited:** <N> at full depth, <K> inventory-only
> - **Confidence mix:** <X> CONFIRMED, <Y> LIKELY, <Z> POSSIBLE
> - **Unique-to-skill findings:** <U>
> - **Report:** `<output_dir>/security-audit-report.md`
> - **SARIF:** `<output_dir>/findings.sarif` (also in
>   `.claude-audit/current/findings.sarif`; upload to GitHub Security tab via
>   `gh security-advisory` or CI integration)
>
> **Next steps:**
> 1. "fix finding <id>" — fix a specific finding
> 2. "fix all CRITICAL and HIGH findings" — batch remediation
> 3. "create a GitHub issue for this report" — file triage ticket
>
> Re-run `/security-audit mode: delta` after fixes to verify remediation
> in sub-minute runtime.

## 7.12 — Edge cases

- **Empty findings.** Emit the report anyway with "Clean — no findings"
  sections. Do not skip the run.
- **Oversized report.** If `phase-07-report.md` exceeds 1MB, move the
  findings list to `phase-07-findings.md` and reference from the main
  report. Keep executive summary + top risks in the main file.
- **SARIF validation failure.** Log the JSON error, keep the raw output,
  write a `.json` version instead of `.sarif`; note in the report.

---

## Verify before exit (MANDATORY)

Before declaring this phase complete and proceeding, run:

```bash
test -f .claude-audit/current/findings.sarif # (plus phase-07-report.md, findings.cyclonedx.json) \
  && test -f .claude-audit/current/phase-07.done \
  && echo "phase-07 verified" \
  || { echo "phase-07 INCOMPLETE — re-write artifact + .done marker before proceeding" >&2; exit 1; }
```

Do not advance to the next phase until this check prints "phase-07 verified". Producing only a downstream artifact (e.g. the final report) without the per-phase artifact + marker is an INVALID run.
