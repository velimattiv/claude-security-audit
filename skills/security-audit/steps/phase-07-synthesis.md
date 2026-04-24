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
`fingerprint` is the first 12 chars of `sha1(title + file + line)`.

Two findings with the same key:
- Merge — keep the first, union their `sources[]`, set `confidence`
  according to §7.3.
- Keep the higher severity.
- Union their `owasp_ids[]`.

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

Severity was assigned per finding, but Phase 7 may adjust based on
context signals:

- **Surface trust zone** — a finding on a `public` partition surface
  rises one severity level if not already CRITICAL. A finding on a `dev`
  surface drops one level.
- **Confirmation** — CONFIRMED findings rise one level if borderline.
- **Surface `data_ops`** — findings on write/delete/exec surfaces rise
  one level.

Do not let promotions exceed CRITICAL.

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
