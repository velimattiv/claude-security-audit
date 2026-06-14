# Methodology & Standards Refresh — `/security-audit` v2.0.6

> Research angle: which security standards/editions the skill's Phase 6 methodology spine and Phase 7 reporting should adopt, upgrade, or skip. Primary-source-verified editions and dates as of **2026-06-14**. Prior research baseline: 2026-04-24; window of interest from ~2026-01.

## TL;DR

- **OWASP Top 10:2025 (web) is FINAL** — announced Nov 2025 at Global AppSec DC, final text released Jan 2026. The skill has **NO web-Top-10 mapping at all**. This is the single biggest gap. **P0: add a web-Top-10 mapping layer.** The 2025 edition is materially different: new **A03 Software Supply Chain Failures** and **A10 Mishandling of Exceptional Conditions**, **SSRF folded into A01**, Security Misconfiguration up to **A02**.
- **MITRE CWE Top 25 (2025) published 2025-12-15** (XSS #1, SQLi #2, CSRF #3, Missing Authorization #4). The skill already tags every finding with a CWE but has **no Top-25 prioritization layer**. **P0: add a cheap, zero-fan-out CWE-Top-25 enrichment** — it piggybacks on the CWE tag the skill already emits.
- **OWASP API Security Top 10 remains at 2023** — no newer edition. Skill is **current; no change**. (Confirmed against the OWASP API Security project page.)
- **OWASP ASVS is at 5.0.0 (May 2025)**; 5.0.1 is only *planned*, not released. Skill says "ASVS 5.0 L2" — **current; no version change needed.** (Watch for 5.0.1 patch.)
- **OWASP LLM Top 10 2025 (v2.0, published 2024-11-18) is still current.** New in-window: **OWASP Top 10 for Agentic Applications 2026** (GenAI Security Project, 2025-12-09) — a *complementary* list, not a replacement. **P1: add a conditional agentic-AI lens** when tool-calling agents are detected.
- **NIST SP 800-218 is v1.1 (Feb 2022); SP 800-218A (Generative-AI SSDF Community Profile) is FINAL (July 2024).** Skill's SSDF meta-check should cite the right version and **add 218A assertions when LLM usage is detected. P1.**
- **PCI DSS 4.0.1 future-dated requirements (incl. 6.4.3 / 11.6.1 client-side script & skimming) became mandatory 2025-03-31.** A **PCI-relevant tagging mode (opt-in) is worth offering** for payment-handling repos. **P2.**
- **EU CRA**: SBOM + vuln-handling obligations phase in (incident reporting 2026-09-11; full incl. machine-readable SBOM 2027-12-11). The skill already emits CycloneDX; a **CRA/SBOM-provenance note in Phase 7 is low-cost. P2.**

---

## Standard-by-standard status

| Standard | Current edition + date (primary source) | Skill's current version | Gap | Recommend |
|---|---|---|---|---|
| **OWASP Top 10 (web)** | **2025** — list final; announced Nov 2025 Global AppSec DC, final text Jan 2026 ([owasp.org/Top10/2025](https://owasp.org/Top10/2025/)) | **Not mapped at all** (verified gap) | No web-Top-10 layer; the most widely-recognized AppSec taxonomy is absent from reports | **ADD (P0)** |
| **OWASP API Security Top 10** | **2023** — still latest; no 2024/2025 edition ([owasp.org/API-Security](https://owasp.org/www-project-api-security/)) | API Top 10 **2023** (Phase 6 §6.10) | None — already current | **SKIP** (no change) |
| **OWASP ASVS** | **5.0.0** — May 2025 (Global AppSec EU Barcelona); 5.0.1 *planned* only ([github.com/OWASP/ASVS/releases](https://github.com/OWASP/ASVS/releases)) | **ASVS 5.0 L2** (lib/asvs-l2.md, 17 cats) | None — current; numbering stable | **SKIP** (watch 5.0.1) |
| **OWASP LLM Top 10** | **2025 / v2.0** — published 2024-11-18, LLM01:2025–LLM10:2025 ([genai.owasp.org/llm-top-10](https://genai.owasp.org/llm-top-10/)) | **LLM Top 10 2025** (Phase 6 §6.11) | None for LLM; but **no agentic-AI coverage** | **SKIP for LLM; ADD agentic lens (P1)** |
| **OWASP Top 10 for Agentic Applications** | **2026** — published 2025-12-09 by OWASP GenAI Security Project; complementary to LLM Top 10 ([genai.owasp.org](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)) | **Not mapped** | Tool-calling/autonomous-agent risks (memory poisoning, tool misuse, excessive agency) not first-class | **ADD conditional (P1)** |
| **MITRE CWE Top 25** | **2025** — published **2025-12-15** (window: 2024-06-01→2025-06-01, 39,080 CVEs); MITRE w/ CISA+HSSEDI ([cwe.mitre.org/top25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)) | **Not prioritized** (per-finding CWE tag exists; no Top-25 layer) | No "is this a Top-25 weakness" prioritization signal | **ADD (P0)** — cheap enrichment |
| **NIST SSDF (SP 800-218)** | **v1.1 — Feb 2022** ([csrc.nist.gov/pubs/sp/800/218/final](https://csrc.nist.gov/pubs/sp/800/218/final)) | SSDF as repo meta-check (cite version) | Should assert version explicitly | **UPGRADE wording (P2)** |
| **NIST SP 800-218A (GenAI SSDF Profile)** | **FINAL — July 2024** ([csrc.nist.gov/pubs/sp/800/218/a/final](https://csrc.nist.gov/pubs/sp/800/218/a/final)) | **Not referenced** | No AI-model-development secure-SDLC assertions | **ADD conditional (P1)** |
| **PCI DSS** | **4.0.1** — future-dated reqs mandatory **2025-03-31**; 6.4.3 & 11.6.1 client-side script/skimming ([blog.pcisecuritystandards.org](https://blog.pcisecuritystandards.org/new-information-supplement-payment-page-security-and-preventing-e-skimming)) | **Not mapped** | No payment-page / e-skimming / client-side-script tagging | **ADD opt-in mode (P2)** |
| **EU Cyber Resilience Act (CRA)** | In force; incident reporting **2026-09-11**, full incl. SBOM **2027-12-11** ([eur-lex / Mend.io guide](https://www.mend.io/blog/eu-cyber-resilience-act-compliance-guide/)) | CycloneDX SBOM emitted (Phase 7 §7.9) | No provenance/SBOM-completeness assertion vs CRA | **ADD note (P2)** |

---

## What changed since 2026-01 (dated, cited)

- **2026-01 — OWASP Top 10:2025 final text released.** *(Confirmed.)* The 2025 list was announced at OWASP Global AppSec DC (Nov 2025) and finalized Jan 2026. Authoritative category list ([owasp.org/Top10/2025](https://owasp.org/Top10/2025/)):
  - A01 Broken Access Control (now **absorbs SSRF**)
  - A02 **Security Misconfiguration** (↑ from #5 in 2021)
  - A03 **Software Supply Chain Failures** *(new — expands 2021 "Vulnerable & Outdated Components" to dependencies, build systems, distribution infra; 5 CWEs but highest avg exploit/impact)*
  - A04 Cryptographic Failures
  - A05 Injection (↓ from #3)
  - A06 Insecure Design
  - A07 Authentication Failures *(renamed from "Identification and Authentication Failures")*
  - A08 Software or Data Integrity Failures
  - A09 Security Logging and **Alerting** Failures *(renamed; "Monitoring"→"Alerting")*
  - A10 **Mishandling of Exceptional Conditions** *(new — 24 CWEs; improper error handling, logical errors, failing open)*
- **2025-12-15 — MITRE CWE Top 25 (2025) published.** *(Confirmed.)* XSS #1, SQLi #2, CSRF #3, Missing Authorization #4 (↑5), OOB-Write #5. New entries: CWE-120/121/122 (buffer overflows), CWE-284 (Improper Access Control), CWE-639 (Auth bypass via user-controlled key), CWE-770 (resource allocation w/o limits) ([cwe.mitre.org/top25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)).
- **2025-12-09 — OWASP Top 10 for Agentic Applications 2026 published.** *(Confirmed.)* OWASP GenAI Security Project; complementary to (not replacing) the LLM Top 10 2025 ([genai.owasp.org](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)).
- **Unchanged in-window (confirmed):** OWASP API Security Top 10 still 2023; ASVS still 5.0.0 (5.0.1 not yet shipped); OWASP LLM Top 10 still 2025/v2.0; NIST SP 800-218 still v1.1; SP 800-218A still the July-2024 final.
- **Speculative / watch (not confirmed):** ASVS **5.0.1** patch release expected but no date — do not bump the skill's "5.0" label until it ships. A future "OWASP API Security Top 10 2025/26" has **not** been published as of this writing.

---

## Mapping to the skill (Phase 6 spine + Phase 7 report)

### 1. OWASP Top 10:2025 (web) — ADD a new mapping spine (P0)
- **Phase 6:** add §6.16 "OWASP Top 10:2025 mechanical mapping" producing `phase-06-web-top10.jsonl` — one row per A01–A10 category with counts + pointers into underlying findings. This is a **roll-up from existing findings' CWEs**, not new analysis, so it needs **no sub-agent fan-out** (mirror the §6.10 API-Top-10 pattern exactly). Drive the mapping off a small `lib/web-top10-2025-map.json` (CWE → A0x). Note the SSRF→A01 fold and supply-chain (A03) draws from scanner SBOM/dependency findings + cat-06.
- **Phase 7:** add a "OWASP Top 10:2025" row to the §7.6 Methodology Coverage matrix; surface per-category counts in the Executive Summary. Optionally add `properties.owasp_web` to SARIF synthetic-run results.
- **Caveat:** keep web-Top-10 and API-Top-10 *both* — they overlap but serve different audiences; do not collapse.

### 2. MITRE CWE Top 25 (2025) — ADD a prioritization layer (P0)
- **Phase 6/7:** ship `lib/cwe-top25-2025.json` (ordered list of the 25 CWE IDs + rank). During Phase 7 dedup/enrich, for any finding whose `properties.cwe` is in the set, stamp `properties.cwe_top25_rank` (1–25) and a boolean `cwe_top25: true`. **Interaction with the existing per-finding CWE tag:** purely additive — the CWE tag stays the canonical key; Top-25 is a derived flag. Zero extra LLM cost (pure lookup).
- **Phase 7 reporting:** add a "CWE Top 25 (2025) hits" line to the Executive Summary and a tiebreaker in the §7.4 severity calibration (consider Top-25 membership as a *reporting* highlight, **not** a severity bump — keep the ±1-rung cap intact to avoid double-counting). Add a "CWE Top 25 coverage" row to §7.6.

### 3. Agentic Applications 2026 — ADD conditional lens (P1)
- **Phase 6 §6.11:** when `profile.llm_usage.detected == true` **AND** tool-calling / autonomous-agent patterns are present (agent frameworks, tool registries, multi-step planners), additionally emit `phase-06-agentic-top10.jsonl` mapping cat-09 findings to the 2026 agentic categories (memory poisoning, tool misuse, excessive agency, etc.). Gate it like the LLM spine (write zero-byte file when not applicable, so the gate signal is preserved).
- **Phase 7:** add an "Agentic AI (2026)" row to §7.6 when non-empty.

### 4. NIST SSDF 800-218 v1.1 + 800-218A — UPGRADE wording + ADD AI profile (P1/P2)
- **Repo meta-check:** assert presence of (a) a documented vuln-disclosure/SECURITY.md (PO/RV), (b) dependency-pinning + SBOM generation in CI (PS/PW), (c) signed releases/provenance (PS.2), (d) automated SAST/secret-scanning in CI (PW.7/PW.8). Cite **SP 800-218 v1.1 (Feb 2022)** explicitly.
- **When LLM usage detected:** add **SP 800-218A** assertions — training-data provenance, model-artifact integrity, model-supply-chain documentation. Report as a meta-check section, not per-finding.

### 5. PCI DSS 4.0.1 — ADD opt-in tagging mode (P2)
- **Trigger:** opt-in arg `pci: true` *or* auto-detect payment indicators (Stripe/Braintree/Adyen SDKs, `card`/`pan`/`cvv` handling, checkout pages).
- **Phase 6:** new conditional check set — **6.4.3** (payment-page scripts authorized + integrity-checked + inventoried; look for SRI `integrity=`, CSP `script-src`, script inventory), **11.6.1** (tamper/change-detection on payment-page + security headers), **6.3.x** (vuln management / patching cadence from CI). Tag findings `owasp_ids`-style with `pci_dss: ["6.4.3","11.6.1"]`.
- **Phase 7:** add a "PCI DSS 4.0.1 (payment-page security)" subsection only when the mode is active.

### 6. EU CRA / SBOM provenance — ADD a Phase 7 note (P2)
- The skill already emits CycloneDX (§7.9). Add an assertion: SBOM present + machine-readable + covers ≥ top-level deps (CRA Art. minimum). If SBOM is the "incomplete skeleton" fallback, emit an INFO finding "SBOM incomplete — CRA Art. 13/Annex I machine-readable SBOM obligation (effective 2027-12-11) not yet satisfiable." Pure reporting; no new analysis phase.

---

## Prioritized recommendations

| Pri | Rec | Effort | Rationale |
|---|---|---|---|
| **P0** | Add **OWASP Top 10:2025 (web)** mapping spine (`lib/web-top10-2025-map.json`, Phase 6 §6.16 roll-up, Phase 7 §7.6 row) | **M** | Most-recognized AppSec taxonomy is entirely absent — verified gap. 2025 is final and materially restructured (A03 supply-chain, A10 exceptions, SSRF→A01). Roll-up from existing CWE tags = no fan-out. |
| **P0** | Add **CWE Top 25 (2025)** prioritization flag (`lib/cwe-top25-2025.json`, derived `cwe_top25` + rank in Phase 7) | **S** | Pure lookup on the CWE tag the skill *already* emits. Highest ROI: near-zero cost, big triage value, no severity-model disruption. |
| **P1** | Add **Agentic Applications 2026** conditional lens gated on tool-calling agent detection | **M** | New in-window (2025-12-09); LLM-tool-using repos are common and the LLM Top 10 alone misses excessive-agency / tool-misuse / memory-poisoning. Mirror the existing conditional LLM gate. |
| **P1** | Add **SP 800-218A** AI-SSDF assertions when LLM detected; fix SSDF citation to **v1.1 (Feb 2022)** | **S** | 218A is final (Jul 2024) and directly relevant to the skill's own LLM-detection path; cheap meta-check additions. |
| **P2** | Offer **PCI DSS 4.0.1** opt-in/auto mode (6.4.3, 11.6.1, 6.3.x) | **M** | Future-dated reqs mandatory since 2025-03-31; high value for payment repos but irrelevant to most — must be opt-in to avoid noise. |
| **P2** | Add **CRA/SBOM-completeness** note in Phase 7 (leverage existing CycloneDX) | **S** | Obligations phase in 2026-09→2027-12; cheap to surface given SBOM already emitted; raises provenance awareness. |
| **P2** | Tighten **SSDF repo meta-check** wording (PO/PS/PW/RV assertions, signed releases, SBOM-in-CI) | **S** | Makes the existing meta-check concrete and version-anchored. |
| — | **SKIP**: API Top 10 (already 2023), ASVS (already 5.0.0), LLM Top 10 (already 2025) | — | All current; no edition change. Re-check ASVS 5.0.1 next cycle. |

**Sequencing note:** P0s share infrastructure (both are CWE→category lookups driven by JSON map files + a Phase 7 enrichment pass) — implement them together as one "standards-map refresh" change. P1/P2 conditional lenses reuse the existing zero-byte-gate pattern from §6.11/§6.12.

---

## Sources

- [OWASP Top 10:2025 — category list & status](https://owasp.org/Top10/2025/) — authoritative A01–A10 2025 names (final edition).
- [OWASP Top 10:2025 — Introduction](https://owasp.org/Top10/2025/0x00_2025-Introduction/) — A03 Supply Chain & A10 Exceptional Conditions detail, SSRF→A01 consolidation.
- [GitLab: 2025 OWASP Top 10 — what's changed (2026-01-07)](https://about.gitlab.com/blog/2025-owasp-top-10-whats-changed-and-why-it-matters/) — corroborates Nov-2025 announce / Jan-2026 final timeline.
- [OWASP API Security project](https://owasp.org/www-project-api-security/) + [2023 edition header](https://owasp.org/API-Security/editions/2023/en/0x00-header/) — confirms 2023 is still latest API edition + API1–API10 names.
- [OWASP/ASVS GitHub Releases](https://github.com/OWASP/ASVS/releases) + [ASVS 5.0 RC1 blog](https://owasp.org/blog/2025/04/09/asvs-rc1-review) — ASVS 5.0.0 (May 2025) latest; 5.0.1 planned.
- [OWASP GenAI — LLM Top 10 archive](https://genai.owasp.org/llm-top-10/) — LLM Top 10 2025 / v2.0 (published 2024-11-18) current.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — published 2025-12-09; complementary to LLM Top 10.
- [MITRE CWE Top 25 (2025)](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html) — 2025 ranked list; published 2025-12-15; MITRE/CISA/HSSEDI.
- [BleepingComputer: MITRE 2025 Top 25](https://www.bleepingcomputer.com/news/security/mitre-shares-2025s-top-25-most-dangerous-software-weaknesses/) — analysis window (2024-06-01→2025-06-01, 39,080 CVEs) + new entries.
- [NIST SP 800-218 (final)](https://csrc.nist.gov/pubs/sp/800/218/final) — SSDF v1.1, Feb 2022.
- [NIST SP 800-218A (final)](https://csrc.nist.gov/pubs/sp/800/218/a/final) — GenAI/dual-use SSDF Community Profile, final July 2024.
- [PCI SSC blog — payment-page security / e-skimming](https://blog.pcisecuritystandards.org/new-information-supplement-payment-page-security-and-preventing-e-skimming) — 6.4.3 / 11.6.1 intent.
- [Sikich — preparing for PCI DSS 4.0.1 6.4.3 & 11.6.1](https://www.sikich.com/insight/preparing-for-pci-dss-v4-0-1-requirements-6-4-3-and-11-6-1/) — requirement detail + applicability (SAQ A-EP / D).
- [Feroot — PCI DSS 4.0.1 has arrived](https://www.feroot.com/blog/pci-4-0-1-has-arrived/) — 2025-03-31 mandatory-enforcement date.
- [Mend.io — EU CRA 2026 compliance guide](https://www.mend.io/blog/eu-cyber-resilience-act-compliance-guide/) + [Anchore — EU CRA SBOM](https://anchore.com/sbom/eu-cra/) — CRA timeline (2026-09-11 / 2027-12-11) + machine-readable SBOM obligation.
