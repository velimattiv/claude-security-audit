# Security Audit Report — Template

Used by `steps/phase-07-synthesis.md §7.7` to emit
`phase-07-report.md`. Token-aware: fill only populated sections, omit
empty ones. Keep the executive summary to one page.

---

```markdown
# Security Audit Report

**Project:** {{project_name}}
**Audit ID:** {{audit_id}}
**Skill version:** {{skill_version}}
**Generated:** {{generated_at}}
**Scope:** {{mode}} — {{scope_hint_or_full}}
**Total runtime:** {{duration_minutes}} minutes

## Executive Summary

{{audit_gate_banner}}

<!-- v2.5: when the Phase-7 §7.15 gate reports unresolved governance failures
     (R4 ratchet / L1-L3 lifecycle), this banner MUST be the first thing in the
     summary, verbatim:

       > ## ⛔ AUDIT GATE: FAILED
       > <n> unresolved governance failure(s). No baseline was written for this
       > run — an unexplained downgrade cannot persist itself as the new truth.
       > <bulleted list of the failures with rule ids>

     When the gate is clean, replace this placeholder with the empty string.
     Do NOT soften or omit the banner: a report that reads as a clean bill while
     a CONFIRMED HIGH ages past its threshold is the exact artifact that made a
     92-day exposure look like normal operation. -->

- **Total findings:** {{n_total}}
  — CRITICAL {{n_critical}} · HIGH {{n_high}} · MEDIUM {{n_medium}} · LOW {{n_low}} · INFO {{n_info}}
- **Confidence mix:** CONFIRMED {{n_confirmed}} · LIKELY {{n_likely}} · POSSIBLE {{n_possible}}
- **Partitions audited:** {{n_partitions_full}} at full depth + {{n_partitions_inventory}} inventory-only
- **Attack surface:** {{n_surfaces}} entry points across {{n_categories}} categories
- **Unique-to-skill findings:** {{n_unique}} (not flagged by any scanner or built-in review)
- **CWE Top 25 (2025) hits:** {{cwe_top25_hits}} (highest-ranked #{{cwe_top25_top_rank}})
- **Exploit-likely (EPSS ≥ 0.10 or CISA-KEV):** {{exploit_likely_count}}
- **Severity escalated by attack-path arithmetic:** {{gate_escalations}} (§7.15 — computed, not asserted)
- **Unscoped collections (rows not bound to the caller):** {{collection_unscoped}} (§6.20)
- **Oldest unremediated CONFIRMED HIGH+:** {{gate_oldest_days}} days

### Top Risks

1. {{top_risk_1}}
2. {{top_risk_2}}
3. {{top_risk_3}}

### Methodology Coverage

| Methodology | Coverage | Findings |
|---|---|---|
| OWASP ASVS 5.0 L2 | {{asvs_pct}}% | {{asvs_count}} |
| OWASP Top 10:2025 (web) | {{web_top10_cat_count}}/10 categories fired | {{web_top10_total}} |
| OWASP API Top 10 (2023) | {{api_cat_count}}/10 categories fired | {{api_total}} |
| OWASP LLM Top 10 (2025) | {{llm_status}} | {{llm_count}} |
| OWASP Agentic Apps (2026) | {{agentic_status}} | {{agentic_count}} |
| LINDDUN (privacy) | {{linddun_status}} | {{linddun_count}} |
| STRIDE | {{stride_partition_count}} partitions covered | see Appendix C |
| Authorized-Egress (cross-layer) | {{egress_status}} | {{egress_count}} |
| CWE tags | {{unique_cwe_count}} unique CWE IDs | — |
| MITRE CWE Top 25 (2025) | {{cwe_top25_hits}}/25 hit (top #{{cwe_top25_top_rank}}) | {{cwe_top25_count}} |

---

## Partition Risk Ranking

| # | Partition | Kind | LOC | Risk | Depth | Findings |
|---|-----------|------|-----|------|-------|----------|
{{per_partition_rows}}

---

## Findings

### CRITICAL

{{critical_findings_block}}

### HIGH

{{high_findings_block}}

### MEDIUM

{{medium_findings_block}}

### LOW

{{low_findings_block}}

### INFO

{{info_findings_block}}

(Per-finding block format:)

> #### {{id}}: {{title}}
> - **Severity:** {{severity}} · **Confidence:** {{confidence}}
> - **Category:** {{category}} · **Partition:** {{partition}}
> - **Location:** {{file}}:{{line}}
> - **CWE:** [{{cwe}}](https://cwe.mitre.org/data/definitions/{{cwe_number}}.html){{cwe_top25_badge}}
> - **OWASP:** {{owasp_ids_joined}}
> - **Exploit signal:** {{epss_kev_badge}} (omit line if neither EPSS nor KEV present)
> - **Sources:** {{sources_joined}}
> - **Description:** {{description}}
> - **Attack scenario:** {{attack_scenario}}
> - **Verification probe:** {{verification_probe}} (the request that should fail — run it to confirm; omit line if absent)
> - **Suggested fix:** {{suggested_fix}}
> - **Effort:** {{remediation_effort}}

---

## Attack Surface Summary

| Category | Count | Notable surfaces |
|---|---|---|
{{surface_category_rows}}

---

## Authorized-Egress (cross-layer access control)

Result of the Phase 6 §6.19 reconciliation — does every path that emits a
sensitive resource's bytes enforce that resource's strongest intended gate?

- **Sensitive resources:** {{egress_sensitive_count}} (default-deny;
  {{egress_public_count}} on the public allowlist — review: {{egress_public_list}})
- **Egress sinks inventoried:** {{egress_sink_count}} · **candidates dismissed:** {{egress_dismissed_count}}
- **Coverage gate:** {{egress_coverage_status}} (fail-closed — a silently-omitted sink fails the run)
- **Cross-layer / missing-enforcer findings:** {{egress_finding_count}}

{{egress_findings_block}}

> **Scope & honesty.** A clean reconciliation means every *known* egress
> candidate (per `lib/egress-detection.md`) was accounted for and gated — it is
> high-signal but **NOT a proof of absence**. CDN-edge egress with no code path,
> and any modality outside the catalogue, are out of mechanical reach and listed
> here as caveats, never silently dropped: {{egress_caveats}}

---

## Collection Scoping (row-level access control)

Result of the Phase 6 §6.20 reconciliation — for every endpoint that returns a
list, are the rows constrained to the caller? A gate being *present* does not
answer this question; that is the whole point of the section.

- **Collections inventoried:** {{collection_count}} · **candidates dismissed:** {{collection_dismissed_count}}
- **By row scope:** caller_bound {{collection_caller_bound}} · visibility_filtered {{collection_visibility_filtered}} · public_allowlisted {{collection_public}} · role_restricted {{collection_role_restricted}} · **unscoped {{collection_unscoped}}** · unknown {{collection_unknown}}
- **Coverage gate:** {{collection_coverage_status}} (fail-closed — a silently-omitted list query fails the run)
- **Findings:** C1 unscoped {{collection_c1}} · C2 decoration {{collection_c2}} · C3 coverage {{collection_c3}} · C4 test-pinned {{collection_c4}} · C5 unevidenced claim {{collection_c5}}
- **Public-resource allowlist (review this):** {{collection_public_list}}

{{collection_findings_block}}

> **Scope & honesty.** A clean reconciliation means every *known* list-query
> candidate was accounted for and scoped — high-signal, **not** a proof of
> absence. A scope applied by an un-modelled mechanism (a base scope, a
> tenant-injecting repository, database row-level security) is missed in the
> conservative direction — the §6.20 adversarial pass exists to retire those.
> Runtime-assembled queries are recorded as caveats, never as silent passes:
> {{collection_caveats}}

---

## Severity Gate (computed severity + finding lifecycle)

Result of the Phase 7 §7.15 gate. Severity here is **computed over composed
attack paths**, not asserted per finding — `severity_asserted` is retained only
as the analyst's opinion.

- **Findings carrying capability tags:** {{gate_tagged}} / {{gate_total}}
- **Escalations applied:** {{gate_escalations}} — {{gate_escalation_list}}
- **Personas evaluated:** {{gate_personas}}
- **Crown jewels reached from an unprivileged persona:** {{gate_jewels}}
- **Governance failures (R4 ratchet, L1–L3 lifecycle):** {{gate_blocking}}
- **Oldest unremediated CONFIRMED HIGH+:** {{gate_oldest_days}} days ({{gate_oldest_id}})

{{gate_governance_block}}

**Orphan capabilities** (vocabulary drift — a chain that should have composed and
did not): {{gate_orphans}}

> **Scope & honesty.** The composer can only compose what was tagged. R2 (prose
> naming another finding) backstops untagged chains; the orphan list backstops
> R2. None of this makes chain analysis complete — it makes the gaps loud, and it
> stops a tagged chain from being out-voted by instinct.

---

## Route Inventory (first 50)

| # | Method | Path | Auth | Roles | Partition | Handler |
|---|--------|------|------|-------|-----------|---------|
{{first_50_routes}}

(Full inventory in `.claude-audit/current/phase-02-surface.json`.)

---

## Audit Coverage

| Phase | Status | Notes |
|---|---|---|
| Phase 0 Discovery | completed | {{phase0_notes}} |
| Phase 1 Partition | completed | {{phase1_notes}} |
| Phase 2 Surface Inventory | completed | {{phase2_notes}} |
| Phase 3 Keystone Index | completed | {{phase3_notes}} |
| Phase 4 Scanners | {{phase4_status}} | {{phase4_notes}} |
| Phase 5 Deep Dives | {{phase5_status}} | {{phase5_notes}} |
| Phase 6 Config + Methodology | {{phase6_status}} | {{phase6_notes}} |

---

## Unique-to-Skill Findings

The following findings were identified only through the systematic
inventory-based audit and were NOT flagged by `/security-review`, the
adversarial review, or the scanner bundle. These represent the skill's
specific value-add.

{{unique_findings_list}}

---

## Remediation Roadmap

Grouped by estimated effort (from each finding's `remediation_effort`).

### Exploit-likely (fix first — EPSS ≥ 0.10 or CISA-KEV)

{{exploit_likely_list}}

### Trivial (≤1 hour)

{{trivial_list}}

### Small (≤1 day)

{{small_list}}

### Medium (≤1 week)

{{medium_list}}

### Large (≥1 week)

{{large_list}}

---

## Appendix A — ASVS Checklist

{{asvs_full_table}}

## Appendix B — STRIDE Tables

{{stride_tables_inline}}

## Appendix C — Scanner Provenance

| Scanner | Version | Status | Findings | Notes |
|---|---|---|---|---|
{{scanner_rows}}

## Appendix D — Dependencies (SBOM summary)

- `findings.cyclonedx.json` at `.claude-audit/current/` — CycloneDX 1.5
  SBOM, VEX-ready.
- Top 10 direct dependencies with known CVEs:

{{top_vulnerable_deps}}

---

*Generated by `/security-audit` v{{skill_version}}. Full machine-readable
artifacts are in `.claude-audit/current/`. Re-run `/security-audit mode:
delta` after fixes to verify remediation.*
```
