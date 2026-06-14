# 04 — Scanner / Tooling Landscape Refresh

> Research angle: scanner/tooling landscape for the `/security-audit` Phase-4 bundle.
> Skill version at time of writing: **v2.0.6**. Last tooling research: **2026-04-24**. This refresh: **2026-06-14**.
> Constraints every recommendation is judged against: **SARIF output** (native or easy converter), **single-binary preferred**, **free / no paid API**, **Linux + macOS**.
> Verification: version numbers/dates confirmed against GitHub Releases API (`gh api .../releases/latest`), official changelogs, advisory DBs, and spec sites. Claims are marked **[C]** confirmed (primary source) or **[S]** speculative/secondary.

## TL;DR

- **One security-mandatory upgrade: trivy 0.70.0 → 0.71.0.** The pinned 0.70.0 is in the affected range (`<0.71.0`) of **GHSA-q3fv-x8vg-qqm4** (Helm-chart tar-bomb OOM, MEDIUM, patched only in 0.71.0). This is a **P0**. [C]
- **Three stale-but-safe pins:** osv-scanner 2.3.5 → **2.3.8**, trufflehog 3.95.2 → **3.95.5**, and the trufflehog flag `--only-verified` is now soft-deprecated → use `--results verified`. gitleaks (8.30.1) and hadolint (2.14.0) are already current. [C]
- **The Semgrep→Opengrep story is real and decision-relevant.** Opengrep (LGPL-2.1 engine, **single binary**, SARIF 2.1.0, latest **v1.22.0**) is now a viable swap-in. The load-bearing issue is **rule redistribution**: Semgrep relicensed its community rules (Dec 2024) under a no-redistribution / no-SaaS license, so the skill should **not bundle `p/...` registry packs regardless of engine**. Recommend **vendoring `opengrep-rules` (LGPL-2.1 + Commons Clause)** and adding Opengrep as the default engine, keeping Semgrep `--config` compatibility for BYO-entitlement users. **P1.** [C]
- **Two genuinely new, well-fitting OSS entrants:** **Kingfisher** (Rust single-binary secrets scanner with live validation + blast-radius/revocation — the closest OSS tool to the NHI/machine-identity trend; native SARIF; Apache-2.0) and **OpenSSF Scorecard** (supply-chain posture; fills a gap nothing in the bundle covers; native SARIF). **GuardDog** adds malicious-package detection (a category CVE scanners structurally cannot cover). [C]
- **Reachability beyond govulncheck is still a gap for JS/TS/Python in OSS.** No free, single-binary, SARIF reachability tool covers them. **OSV-Scanner `--call-analysis`** is the only OSS/SARIF option (Go solid, Rust experimental, Java JAR-level). OWASP dep-scan covers Java/JS/TS/Python/PHP but is heavy and has **no native SARIF**. Semgrep/Socket/Endor cover JS/Python but are SaaS/paid. [C]
- **Prioritization:** **EPSS v4 (v2025.03.14)** is current; **grype** natively attaches EPSS + KEV + a composite risk score and is fully OSS — the cheapest path to EPSS-aware ranking. **Trivy will not implement EPSS** (out of scope, per maintainers). Carry EPSS in SARIF as custom `properties.epss*` while keeping `properties.security-severity` for CVSS. [C]
- **VEX:** Trivy is the broadest free VEX *consumer* (OpenVEX + CSAF + CycloneDX, plus VEX Hub). **OpenVEX** is the format to standardize on (lightest), though its spec has been a stable draft v0.2.0 since 2023. [C]
- **SBOM currency:** CycloneDX spec head is **1.7.1** (2026-06-02), but **trivy still emits 1.6** — which is **compliant and current-enough** (EU CRA / BSI TR-03183-2 require CDX ≥1.6 or SPDX ≥3.0.1). No action needed; track trivy adding 1.7. [C]

---

## What changed since 2026-01

Dated, cited; **[C]** = confirmed against a primary source, **[S]** = speculative/secondary.

- **2026-03 — Trivy supply-chain compromise (CRITICAL).** GHSA-69fq-xp46-6x23 / CVE-2026-33634: malicious **v0.69.4–0.69.6** binaries + force-pushed `trivy-action`/`setup-trivy` tags (published 2026-03-21). v0.69.3 is safe; the skill's 0.70.0 postdates it and is clean — but anyone who pulled trivy during 2026-03-19→23 should verify checksums. **[C]**
- **2026-03-14 — EPSS v4** (version string `v2025.03.14`) is the current model; began publishing 2025-03-17, replacing v3. No v5 exists as of this writing. **[C]** (Model-internals narrative — malware/EDR telemetry features — is **[S]**, vendor blogs only.)
- **2026-03-21 — gitleaks 8.30.1** (current pin == latest; nothing newer). **[C]**
- **2026-04-22 — govulncheck v1.3.0.** Note the "latest" trap: GitHub `releases/latest` returns a stale v1.1.4; v1.2/v1.3 are tag-only. Resolve via `go install ...@latest` / pkg.go.dev, **not** the GitHub releases endpoint. **[C]**
- **2026-04-24 — Nosey Parker archived/retired** → successor is **Titus** (praetorian-inc/titus). Not in the bundle, but relevant if anyone reached for Nosey Parker. **[C]**
- **2026-05-08 — osv-scanner 2.3.8** (skill pins 2.3.5 — **3 releases behind**). 2.3.6/2.3.8 add output-injection hardening (sanitize `\r`/`\n` to block GHA workflow-command injection). **Do not pin v2.3.7 — the tag exists but ships no release artifacts.** **[C]**
- **2026-05-16 — zizmor v1.25.2**, and the canonical repo moved to **`zizmorcore/zizmor`** (`woodruffw/zizmor` 301-redirects — confirmed live). Breaking in v1.25.0: stricter expression handling (rejects unknown functions/arities); deprecated `--collect=*-only` → `--collect=workflows|actions`. The skill's installer references the old repo path. **[C]**
- **2026-05-19 — Opengrep v1.22.0** (roughly weekly cadence; LGPL-2.1 engine; single binary via Nuitka; SARIF 2.1.0; Semgrep-rule-format compatible). Consortium-governed (10+ AppSec vendors), stated intent to move to a foundation (not yet executed **[S]**). **[C]**
- **2026-06-01 — trivy 0.71.0**, the patched release for **GHSA-q3fv-x8vg-qqm4** (Helm-chart tar-bomb OOM, affected `<0.71.0`). 0.71.0 also bumps emitted **CycloneDX SBOM 1.6 → 1.7** (PR #10715) — regression-test if a downstream consumer can't parse 1.7. `trivy config` is **NOT** deprecated/renamed (still present, alias `conf`). **[C]**
- **2026-06-02 — trufflehog 3.95.5** (skill pins 3.95.2). `--only-verified` now hidden/soft-deprecated → `--results verified` (old flag still works). New detectors (GitLab OAuth, AWS AppSync, SpectralOps, Box). TruffleHog still has **no native SARIF** (issue #578 closed unimplemented) — the skill's JSONL→SARIF post-processing remains required. License is **AGPL-3.0** (copyleft — note for any embedding/redistribution). **[C]**
- **2026-06-11 — semgrep OSS 1.166.0** (skill's research baseline was ~1.161). Changes since: token-redaction in `ci` error messages, CI no longer transmits SCM tokens to the platform, `SEMGREP_APP_TOKEN` no longer persisted to `settings.yml` (security fix), faster JSON rule parsing. No breaking `--config auto` behavior change. **[C]**
- **2025-10-21 / 2026-06-02 — CycloneDX 1.7 / 1.7.1** released (spec head). **SPDX 3.0.1** (Dec 2024) is the current SPDX spec. **[C]**
- **Still current / no change worth a bump:** hadolint 2.14.0 (2025-09-22; project quiet ~9mo but latest), checkov **Apache-2.0** confirmed unchanged (the "Palo Alto Networks" copyright is acquisition attribution, not relicensing). **[C]**

---

## Per-tool status table

| Tool | Current version (date) | Change / CVE / deprecation since 2026-04 | Pin status | Verdict |
|---|---|---|---|---|
| **semgrep** (OSS CLI) | 1.166.0 (2026-06-11) [C] | Security hardening (token redaction, no SCM-token transmit). Rules registry licensing unchanged (still restrictive). | baseline ~1.161 stale-ish | **Keep, but see Opengrep** — engine fine; reconsider rule sourcing |
| **osv-scanner** | 2.3.8 (2026-05-08) [C] | Output-injection hardening. v2.3.7 has no artifacts (skip). | **2.3.5 — 3 behind** | **Upgrade → 2.3.8** |
| **gitleaks** | 8.30.1 (2026-03-21) [C] | None newer. | **current** | **Keep** |
| **trufflehog** | 3.95.5 (2026-06-02) [C] | `--only-verified` → `--results verified` (soft-deprecated). New detectors. No native SARIF. AGPL-3.0. | **3.95.2 — mild** | **Upgrade → 3.95.5 + migrate flag** |
| **trivy** | 0.71.0 (2026-06-01) [C] | **GHSA-q3fv-x8vg-qqm4 affects `<0.71.0` (pin is vulnerable).** SBOM CDX 1.6→1.7. `config` not deprecated. | **0.70.0 — VULNERABLE** | **UPGRADE → 0.71.0 (P0)** |
| **hadolint** | 2.14.0 (2025-09-22) [C] | None. Project quiet. GPL-3.0. | **current** | **Keep** (watch for staleness) |
| **brakeman** (cond.) | 8.0.5 (2026-06-12) [C] | Breaking in 8.0.0 (pre-Apr): removed `--skip-libs`/`--index-libs`; min Ruby 3.2. Gem/GitHub tag drift (pin via RubyGems). | unpinned | **Keep — flag non-OSS license** (Brakeman Public Use License = non-commercial; commercial needs Black Duck) |
| **checkov** (cond.) | 3.3.1 (2026-06-11) [C] | No breaking/graph/framework change. CVE-2025-2180 fixed long ago (3.2.415). **Still Apache-2.0.** | unpinned | **Keep** |
| **kube-linter** (cond.) | 0.8.3 (2026-03-10) [C] | Additive only; no breaking. Apache-2.0, Go single binary. | unpinned | **Keep** |
| **govulncheck** (cond.) | v1.3.0 (2026-04-22) [C] | "latest" endpoint stale (v1.1.4) — resolve via Go tooling. SARIF/openvex/json exit 0 → parse output, not exit code. | unpinned | **Keep — fix version-resolution note** |
| **psalm** (cond.) | 6.16.1 (2026-03-19) [C] | **Actively maintained** (abandonment narrative is stale; 7.0 in beta). SARIF via `--report=*.sarif`, **not** `--output-format`. MIT. | unpinned | **Keep — fix SARIF invocation note** |
| **zizmor** (cond.) | v1.25.2 (2026-05-16) [C] | **Repo moved → `zizmorcore/zizmor`.** Breaking expr handling (v1.25.0); `--collect` flag change. MIT, Rust single binary. | unpinned | **Keep — update repo path + flags** |
| **grype** (optional) | v0.114.0 (2026-06-05) [C] | Now bundles **EPSS + KEV + composite risk** (DB schema v6 on OSV). Apache-2.0, Go single binary. | optional | **Promote** (best free EPSS path) |

---

## New candidates

| Tool | Role | SARIF? | License | Single-binary / free | Recommend |
|---|---|---|---|---|---|
| **Opengrep** v1.22.0 [C] | SAST engine (Semgrep fork) | native (2.1.0) | LGPL-2.1 (engine); rules LGPL-2.1+Commons Clause | yes (Nuitka) / yes | **YES (P1)** — single binary, redistributable rules, sidesteps Semgrep rules license |
| **Kingfisher** v1.102.0 [C] | Secrets + **live validation** + blast-radius/revocation | native | Apache-2.0 | yes (Rust) / yes | **YES (P1)** — best NHI/machine-identity-aligned OSS fit; complements gitleaks/trufflehog |
| **OpenSSF Scorecard** v5.5.0 (2026-04-23) [C] | Supply-chain **posture** (branch protection, token perms, pinned deps, dangerous workflows, signed releases) | native | Apache-2.0 | yes (Go) / yes | **YES (P2)** — fills an uncovered category; caveat: remote-first, needs GitHub token |
| **GuardDog** v2.10.0 stable (v3.0.0a1 alpha) [C] | **Malicious-package** detection (typosquat, install-script abuse) | native | Apache-2.0 | no (Python ≥3.10) / yes | **YES (P2)** — unique vs CVE scanners; Python runtime is the only knock |
| **OWASP dep-scan** v6.2.0 [C] | SCA + **reachability** (Java/JS/TS/Py/PHP) + CSAF/VEX | **no** (Jinja template only) | MIT | no (Python) / yes | **CONDITIONAL** — only multi-lang OSS reachability, but heavy (32–64GB on big repos) + JSON→SARIF transform needed |
| **KICS** v2.1.20 (2026-03-03) [C] | IaC misconfig (24+ platforms, 2400+ queries) | native | Apache-2.0 | yes (Go) / yes | **CONDITIONAL** — overlaps trivy+checkov; add only for Pulumi/Crossplane/OpenAPI/Knative/Serverless |
| **syft** v1.45.1 / **cdxgen** v12.5.1 [C] | SBOM generators (not findings) | n/a | Apache-2.0 | syft yes / cdxgen no | **NO** — only as backends (syft→grype; cdxgen→dep-scan) |
| **CodeQL CLI** 2.24.0 [C] | SAST | native | proprietary (OSS-codebase-only free) | yes / restricted | **NO (stay excluded)** — free CLI only for OSI OSS on GitHub.com; private/commercial needs paid GHAS |
| **Bearer** v2.0.2 [C] | SAST (privacy/data-flow) | native | Elastic License v2 | yes (Go) / yes\* | **OPTIONAL** — ELv2 forbids hosted-service resale; viable secondary if skill isn't resold as SaaS |
| **Snyk Code / SonarQube CE** [C] | SAST | yes / import-only | proprietary / LGPL-3 | no (SaaS / server) | **NO** — Snyk = metered SaaS, no OSS tier; Sonar = server, no native SARIF export of own findings |
| **terrascan** [C] | IaC | no | Apache-2.0 | yes / yes | **NO — archived 2025-11-20 (Tenable EOL)** |
| **bomber** [C] | SBOM vuln scan | no | MPL-2.0 | yes / yes\* | **NO** — no SARIF, ~21mo stale, OSS-Index account; redundant vs trivy/grype/osv |
| **OWASP Dependency-Check** v12.2.2 [C] | SCA | native | Apache-2.0 | no (JVM) / yes\* | **NO** — JVM dep + NVD API-key friction; SCA already covered |
| **ggshield / detect-secrets** [C] | Secrets | ggshield: n/d; detect-secrets: no | MIT / Apache-2.0 | partial | **NO** — ggshield needs GitGuardian API (paid); detect-secrets stale (2024), no validation |

\* OSS tool, but a recommended data source is account-gated.

---

## Mapping to the skill (Phase-4 bundle slots)

| Bundle slot | Current | Recommended change |
|---|---|---|
| **SAST (required)** | semgrep + `p/...` registry packs | **Switch default engine to Opengrep; vendor `opengrep-rules`; stop bundling `p/...` packs** (Semgrep Rules License forbids redistribution). Keep semgrep `--config` path for BYO-entitlement users. Files: `scripts/install-scanners.sh` (add `OPENGREP_VER`, install logic), `lib/scanner-bundle.md` (semgrep section), `steps/phase-04-scanners.md` (invocation), `README.md`/`NOTICE.md` (licensing & attribution). |
| **SCA (required)** | osv-scanner 2.3.5 | **Bump to 2.3.8.** Optionally document `osv-scanner fix` guided remediation (npm/Maven; still "experimental"). File: `install-scanners.sh` (`OSV_VER`). |
| **Secrets (required)** | gitleaks + trufflehog | **trufflehog 3.95.2→3.95.5 + migrate `--only-verified`→`--results verified`.** **Add Kingfisher** as a third secrets scanner (native SARIF, validation, NHI blast-radius). Files: `install-scanners.sh`, `lib/scanner-bundle.md`, `steps/phase-04-scanners.md`, `steps/deepdive/cat-06-secret-sprawl.md`. |
| **IaC/vuln/SBOM/secret (required)** | trivy 0.70.0 | **Bump to 0.71.0 (security).** Regression-test CycloneDX 1.6→1.7 SBOM output. File: `install-scanners.sh` (`TRIVY_VER`); note SBOM version in `lib/sarif-postprocess.md`/SBOM docs. |
| **Dockerfile (required)** | hadolint 2.14.0 | No change (current). |
| **Rails / TF / k8s / Go / PHP / GHA (conditional)** | brakeman, checkov, kube-linter, govulncheck, psalm, zizmor | **zizmor:** update repo path to `zizmorcore/zizmor` + `--collect` flag. **govulncheck:** fix version-resolution note (use Go tooling, not GH `releases/latest`). **psalm:** fix SARIF invocation (`--report=*.sarif`). **brakeman:** add non-OSS license caveat. Files: `install-scanners.sh`, `lib/scanner-bundle.md`. |
| **Prioritization (EPSS) — optional** | grype (optional, EPSS) | **Promote grype** from "optional/Dockerfile-gated" to a first-class prioritization step: grype now natively carries **EPSS + KEV + composite risk**. Carry into SARIF as `properties.epss`, `properties.epssPercentile`, `properties.kev`; keep `properties.security-severity` for CVSS. Files: `steps/phase-04-scanners.md`, `lib/sarif-postprocess.md`. |
| **VEX suppression — new** | (none) | Document **trivy `--vex`** (OpenVEX/CSAF/CycloneDX + VEX Hub) to suppress non-exploitable findings; standardize authored VEX on **OpenVEX**. File: `steps/phase-06-config.md` or a new lib note. |
| **Supply-chain posture — new slot** | (none) | **Add OpenSSF Scorecard** (native SARIF) + **GuardDog** (malicious-package, native SARIF) as a new conditional "supply-chain posture" sub-step. Files: `steps/phase-04-scanners.md`, `lib/scanner-bundle.md`, `steps/deepdive/cat-07-deployment.md`. |
| **Reachability (beyond Go) — gap** | govulncheck (Go only) | **Document the gap.** Optionally enable **OSV-Scanner `--call-analysis`** (Go/Rust/Java-JAR) and offer **OWASP dep-scan** behind a flag for JS/TS/Python/Java (heavy, no native SARIF). Note JS/Python OSS reachability does not exist as a single binary. File: `docs/KNOWN-GAPS.md`, `lib/scanner-bundle.md`. |
| **CodeQL** | excluded by default | No change — exclusion remains correct (free CLI is OSS-codebase-only). |

---

## Prioritized recommendations

Effort: **S** ≈ a pin/flag/doc edit, **M** ≈ new installer + invocation + post-processing, **L** ≈ engine swap + licensing/docs rework.

### P0 — do now
- **[P0 · S] Bump trivy 0.70.0 → 0.71.0.** The pin is in the affected range of GHSA-q3fv-x8vg-qqm4 (tar-bomb OOM, patched only in 0.71.0). The skill runs `trivy config` / misconfig scanning, which is exactly the vulnerable path. Edit `TRIVY_VER` in `install-scanners.sh`. Regression-test the CycloneDX 1.6→1.7 SBOM change downstream. **[C]**

### P1 — this refresh
- **[P1 · S] Bump osv-scanner 2.3.5 → 2.3.8** (avoid 2.3.7 — no artifacts) and **trufflehog 3.95.2 → 3.95.5** (+ migrate `--only-verified` → `--results verified`). Both safe additive bumps with CI-hardening fixes. **[C]**
- **[P1 · S] Fix stale tool references** that will silently break installs/invocations: zizmor repo → `zizmorcore/zizmor` and `--collect` flag; govulncheck version-resolution note (use Go tooling); psalm SARIF invocation (`--report=*.sarif`); brakeman non-OSS-license caveat. **[C]**
- **[P1 · L] Adopt Opengrep as the default SAST engine and stop bundling Semgrep `p/...` packs.** Rationale: (1) the skill *redistributes* rule packs, which the **Semgrep Rules License v1.0** forbids — this is a latent licensing exposure today regardless of Opengrep; (2) Opengrep is a single binary (no Python), LGPL-2.1, SARIF 2.1.0, rule-format compatible; (3) `opengrep-rules` (LGPL-2.1 + Commons Clause) is redistributable-with-care for a free skill. Keep semgrep `--config` compatibility for users with their own registry entitlement. **Flag to the user:** Commons Clause is non-OSI and its "value derives substantially from the Software" clause is fuzzy — if the skill is ever part of a paid offering, get legal sign-off. This is the one item warranting an explicit decision before implementation. **[C]**
- **[P1 · M] Promote grype to a first-class prioritization step + EPSS in SARIF.** grype now natively emits EPSS + KEV + composite risk (fully OSS). Add `properties.epss*`/`properties.kev` to findings while preserving `properties.security-severity`. Cheapest possible EPSS adoption — no new dependency type, grype is already optional in the bundle. **[C]**

### P2 — opportunistic / next cycle
- **[P2 · M] Add Kingfisher** as a third secrets scanner (native SARIF, live validation, NHI blast-radius/revocation). Best OSS answer to the machine-identity/NHI trend; complements rather than replaces gitleaks/trufflehog. **[C]**
- **[P2 · M] Add a "supply-chain posture" sub-step: OpenSSF Scorecard + GuardDog.** Scorecard covers repo posture (no bundle overlap); GuardDog covers malicious packages (a category CVE scanners can't). Both native SARIF. Caveats: Scorecard is remote-first/needs a token; GuardDog needs Python. **[C]**
- **[P2 · S] Document VEX consumption** via `trivy --vex` (OpenVEX/CSAF/CycloneDX + VEX Hub) and recommend OpenVEX as the authoring format. Low effort, meaningful noise reduction. **[C]**
- **[P2 · S] Document the reachability gap** in `KNOWN-GAPS.md` and optionally wire **OSV-Scanner `--call-analysis`** (Go/Rust/Java-JAR) + flag-gated **OWASP dep-scan** for JS/TS/Python/Java. Set expectations: no OSS single-binary JS/Python reachability exists in mid-2026. **[C]**
- **[P2 · S] No SBOM action needed.** trivy's CycloneDX 1.6 (→1.7 in 0.71.0) is CRA/BSI-compliant; spec head 1.7.1 is not required. Just track it. **[C]**

---

## Sources

URL → what it supports. All version/date claims below verified via `gh api .../releases/latest` unless noted; spec/license claims via the listed sites.

**Core bundle versions & CVEs**
- `gh api repos/aquasecurity/trivy/releases/latest` → **trivy v0.71.0, 2026-06-01** (confirmed in-session)
- `gh api repos/aquasecurity/trivy/security-advisories` (GHSA-q3fv-x8vg-qqm4) → **vulnerable `<0.71.0`**, MEDIUM, Helm tar-bomb OOM (confirmed in-session); GHSA-69fq-xp46-6x23 / CVE-2026-33634 → 2026-03 supply-chain compromise
- `gh api repos/google/osv-scanner/releases/latest` → **osv-scanner v2.3.8, 2026-05-08** (confirmed in-session); v2.3.7 tag has no artifacts
- `gh api repos/trufflesecurity/trufflehog/releases/latest` → **trufflehog v3.95.5, 2026-06-02** (confirmed in-session); AGPL-3.0; SARIF issue #578 closed unimplemented
- `gh api repos/gitleaks/gitleaks/releases/latest` → **gitleaks v8.30.1, 2026-03-21** (confirmed in-session; == pin)
- `gh api repos/hadolint/hadolint/releases/latest` → **hadolint v2.14.0, 2025-09-22** (confirmed in-session; == pin); GPL-3.0

**Conditional tools**
- `gh api repos/presidentbeef/brakeman/releases/latest` → **brakeman v8.0.5, 2026-06-12**; license = Brakeman Public Use License (non-commercial)
- `gh api repos/bridgecrewio/checkov/releases/latest` → **checkov 3.3.1, 2026-06-11**; Apache-2.0 unchanged
- `gh api repos/stackrox/kube-linter/releases/latest` → kube-linter v0.8.3, 2026-03-10
- pkg.go.dev/golang.org/x/vuln → **govulncheck v1.3.0, 2026-04-22**; GH `releases/latest` returns stale v1.1.4
- `gh api repos/vimeo/psalm/releases/latest` → **psalm 6.16.1, 2026-03-19** (actively maintained; 7.0 beta); SARIF via `--report=*.sarif`
- `gh api repos/zizmorcore/zizmor/releases/latest` → **zizmor v1.25.2, 2026-05-16**; `gh api repos/woodruffw/zizmor` → redirects to `zizmorcore/zizmor` (confirmed in-session)

**Semgrep / Opengrep**
- `gh api repos/opengrep/opengrep/releases/latest` → **Opengrep v1.22.0, 2026-05-19** (confirmed in-session)
- `gh api repos/semgrep/semgrep/releases/latest` → **semgrep OSS v1.166.0, 2026-06-11** (confirmed in-session)
- github.com/opengrep/opengrep → LGPL-2.1 engine, `--sarif-output`, single binary (Nuitka), Semgrep-rule compatible
- github.com/opengrep/opengrep-rules → fork of semgrep-rules at Dec-2024 state, LGPL-2.1 + Commons Clause
- semgrep.dev/legal/rules-license/ → Semgrep Rules License v1.0: no redistribution, no SaaS
- semgrep.dev/blog/2024/important-updates-to-semgrep-oss/ → Dec 13 2024 rules relicense; engine stays LGPL-2.1
- codeql.github.com/.../codeql-cli-2.24.0/ + github.com/github/codeql-cli-binaries/blob/main/LICENSE.md → CodeQL CLI 2.24.0; OSS-codebase-only free restriction
- github.com/Bearer/bearer/blob/main/LICENSE.txt → Bearer ELv2 (SaaS-resale prohibited)

**New candidates**
- `gh api repos/mongodb/kingfisher/releases/latest` → **Kingfisher v1.102.0, 2026-05-29**; Apache-2.0, Rust, native SARIF, live validation
- mongodb.com/.../introducing-kingfisher-real-time-secret-detection-validation → validation + blast-radius/revocation
- `gh api repos/ossf/scorecard/releases/latest` → **Scorecard v5.5.0, 2026-04-23**; Apache-2.0; native SARIF (`--format sarif`)
- `gh api repos/DataDog/guarddog/releases/latest` → v3.0.0a1 alpha (2026-05-26); pypi.org/project/guarddog → **v2.10.0 stable, 2026-05-07**; Apache-2.0, native SARIF, 6 ecosystems
- `gh api repos/anchore/grype/releases/latest` → **grype v0.114.0, 2026-06-05**; Apache-2.0, native SARIF
- anchore.com/blog (grype DB schema v6) → grype bundles EPSS + KEV + composite risk
- github.com/owasp-dep-scan/dep-scan + depscan.readthedocs.io/reachability-analysis → dep-scan v6.2.0, reachability Java/JS/TS/Py/PHP, **no native SARIF**, heavy RAM
- github.com/Checkmarx/kics (`gh api`) → KICS v2.1.20, 2026-03-03; Apache-2.0, native SARIF, Go
- github.com/tenable/terrascan → **archived 2025-11-20**; docs.tenable.com EOS PDF → Tenable EOL
- github.com/praetorian-inc/noseyparker → archived 2026-04-24 → Titus successor
- github.com/devops-kung-fu/bomber → v0.5.1 (2024-09-23), no SARIF, OSS-Index account
- github.com/dependency-check/DependencyCheck → v12.2.2 (2026-05-03), JVM, NVD API-key friction

**Reachability / EPSS / VEX / SBOM**
- first.org/epss/data_stats → **EPSS v4 (v2025.03.14)**, publishing since 2025-03-17 (current; no v5)
- github.com/aquasecurity/trivy/discussions/4543 → Trivy will NOT implement EPSS natively (out of scope)
- trivy.dev/docs (VEX) + aquasec.com/blog/introducing-vex-hub → Trivy consumes OpenVEX/CSAF/CycloneDX VEX + VEX Hub
- github.com/openvex/spec (+ tags) → OpenVEX spec v0.2.0, draft, last revised 2023-07-18; vexctl + go-vex tooling
- api.github.com/repos/CycloneDX/specification/releases → CDX 1.6 (2024-04-09), 1.7 (2025-10-21), 1.7.1 (2026-06-02)
- cyclonedx.org/news/cyclonedx-v1.6-released + .../ecma-international-standard → 1.6 features (CBOM, CDXA), Ecma-424 ratified 2024-06-26
- spdx.github.io/spdx-spec/v3.0.1/ + Linux Foundation press → SPDX 3.0 (2024), 3.0.1 (Dec 2024) current
- deepwiki.com/aquasecurity/trivy/6.1-cyclonedx-format + trivy discussion #7174 → Trivy emits CycloneDX 1.6 (pre-0.71.0); EU CRA / BSI TR-03183-2 require CDX ≥1.6 or SPDX ≥3.0.1

**Items flagged not-verifiable (not guessed):** EPSS v4 model-internals (FIRST primary article 404'd → secondary only); OSV-Scanner native EPSS attachment (no doc found → treat as not-native); grype OSS VEX-suppression parity with Trivy (unverified); whether trivy emits CDX 1.7 by default vs. on-flag (feature-add confirmed, default mechanics not); Opengrep foundation-governance move (stated intent, not executed).
