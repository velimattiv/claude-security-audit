# Phase 7 — Synthesis & Report

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
- `phase-00-profile.json`, `partitions.json`, `phase-02-surface.json`

**Outputs.**
- `.claude-audit/current/phase-07-report.md` — the full, structured report.
- `.claude-audit/current/findings.sarif` — SARIF 2.1.0 consolidated.
- `.claude-audit/current/findings.cyclonedx.json` — SBOM (from trivy
  output if present; otherwise produced by syft if installed).
- The report is ALSO copied to:
  - `_bmad-output/implementation-artifacts/security-audit-report.md`
    if `_bmad-output/` exists in the project,
  - else `docs/security-audit-report.md`.
- `.claude-audit/current/phase-07.done`

**Execution.** Single orchestrator pass. No sub-agent fan-out (synthesis
must see the whole picture).

---

## 7.1 — Collect

Load every JSONL / JSON artifact into in-memory lists:
- `findings[]` — all Phase 5 + Phase 6 JSONL lines + scanner-derived
  findings (from slim SARIF, with the scanner tool name in `sources[0].detail`).
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

2. Sum the signals. If net > 0, promote by exactly one rung. If net
   < 0, demote by one rung. If net == 0, no change. **Regardless of
   magnitude, the adjustment is at most one rung in either direction.**

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
| API Top 10 (2023) | per-category counts | N |
| LLM Top 10 (2025) | per-category counts (or N/A) | N |
| LINDDUN | 7-category counts (or N/A) | N |
| STRIDE | partitions covered | Markdown tables |
| CWE | unique CWEs seen | N |

## 7.7 — Emit `phase-07-report.md`

Use the template in `lib/report-template.md`. Sections in order:

1. **Header** — project name, audit id, skill version, generated-at,
   scope, duration.
2. **Executive Summary** — total findings, by severity, by category,
   by confidence. Top 3 risks (one line each).
3. **Partition Risk Ranking** — table from Phase 1 with finding counts
   appended per partition.
4. **Findings** — grouped by severity (CRITICAL → INFO), within severity
   grouped by category. Per finding: id, title, confidence, file:line,
   CWE, OWASP ids, description, attack scenario, suggested fix.
5. **Attack Surface Summary** — from Phase 2, counts by category,
   noteworthy surfaces listed.
6. **Methodology Coverage** — the §7.6 matrix.
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

Every `results[]` item:
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

Validate with `jq -e .runs .` before write.

## 7.9 — Emit `findings.cyclonedx.json`

If trivy produced `phase-04-scanners/sbom.cyclonedx.json`, copy and
annotate with findings (`vulnerabilities[]` list pointing to
`findings.sarif` entries).

If no SBOM is available, emit a minimal CycloneDX skeleton with the
detected languages / frameworks from Phase 0 and note "SBOM
incomplete — install trivy or syft for full coverage".

## 7.10 — Save user-facing report

Check for `_bmad-output/` directory in the project root. If present:
- Write to `_bmad-output/implementation-artifacts/security-audit-report.md`.

Else:
- Write to `docs/security-audit-report.md`.

Echo the path to the user.

## 7.11 — Report summary to user

> Security audit complete.
>
> - **Total findings:** <N> (<C> CRITICAL, <H> HIGH, <M> MEDIUM, <L> LOW, <I> INFO)
> - **Partitions audited:** <N> at full depth, <K> inventory-only
> - **Confidence mix:** <X> CONFIRMED, <Y> LIKELY, <Z> POSSIBLE
> - **Unique-to-skill findings:** <U>
> - **Report:** `<report_path>`
> - **SARIF:** `.claude-audit/current/findings.sarif` (upload to GitHub
>   Security tab via `gh security-advisory` or CI integration)
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
