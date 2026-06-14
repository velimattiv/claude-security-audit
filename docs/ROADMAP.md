# v2.1 Roadmap Candidates

Forward-looking candidates for the next minor release. Items delivered
in v2.0.1 have been removed from this list. Ordered by severity of the
underlying problem (highest impact first).

---

# Research round — 2026-06-14

Synthesized, deduplicated backlog from seven parallel research agents
(reports in [`research/`](research/)). This is the "since-last-research"
refresh; the last round (2026-04-24) is the basis for `V2-SCOPE.md`.

**Scope of this round was research only — nothing below is implemented yet.**
Bracketed `[NN]` tags cite the source report in `research/`.

> **Verify-before-ship caveat.** Several 2026 CVE IDs in the source reports
> are flagged "verify on NVD," and report 01 self-flagged `CVE-2026-23993`
> as fabricated. Confirm every CVE identifier against NVD before encoding it
> into a pattern, fixture, or doc. Bug *classes* are well-sourced; individual
> IDs are not all confirmed.

## 🔴 Fix-now (security issue in our own tooling)

- **Bump `TRIVY_VER` 0.70.0 → 0.71.0** in `scripts/install-scanners.sh:37`.
  Our pin is in the vulnerable range of **GHSA-q3fv-x8vg-qqm4** (Helm-chart
  tar-bomb OOM, patched in 0.71.0) and we run `trivy config` — the affected
  path. Effort **S**. Verified against our code. Regression-test the
  CycloneDX 1.6→1.7 SBOM output change while doing it. [04]

## P0 — highest impact

| Item | Touches | Effort | Src |
|---|---|---|---|
| **New deep-dive `cat-10` Supply Chain & CI/CD Integrity** — static lifecycle-hook scan (npm pre/postinstall, Python `setup.py`/`.pth`, gem `extconf.rb`, cargo `build.rs`, Go), dependency-confusion / lockfile-integrity, CI script-injection. Regex-first MVP catches every 2026 campaign (Shai-Hulud 2.0, TrapDoor, trivy-action compromise). | Phase 5 (new cat) + `manifest.yaml` + Phase 0 gate | M | [02] |
| **New deep-dive `cat-11` MCP / Agentic** with its **own** Phase-0 gate (separate from cat-09's LLM gate — MCP servers/agents are a distinct surface the LLM gate would wrongly skip): MCP tool-scope breadth, prompt-injection-via-tool-output, confused-deputy/token-passthrough. | Phase 5 (new cat) + Phase 0 detection | M–L | [03] |
| **Deserialization false-safety corrections** in cat-08: PyYAML `FullLoader` is NOT safe; `torch.load(weights_only=True)` was bypassable pre-2.10. Both currently trusted by most tooling. | cat-08 (+ cat-09 model files) | S | [01][03] |
| **Framework fail-open auth heuristic** in cat-01: flag positive-allowlist ("protect these paths") auth matchers — the Next.js `x-middleware-subrequest` / Clerk / Spring matcher-evasion class. | cat-01 | M | [01] |
| **OWASP Top 10:2025 (web) mapping** — final Jan 2026; new A03 Supply-Chain, A10 Exceptional-Conditions, SSRF folded into A01. The skill maps the web Top 10 *nowhere* today. CWE→category lookup, no fan-out. | Phase 6 spine + Phase 7 report | M | [05] |
| **CWE Top 25 (2025) prioritization layer** — published 2025-12-15; additive enrichment on the existing per-finding CWE tag (keep the ±1-rung severity cap). | Phase 6/7 | S | [05] |
| **Precision/recall scorecard** — add `negative_expectations[]` decoys to the fixture schema (v3) + TP/FP/FN/precision/recall/F1 scorer in `assertions.py`; emit `scorecard.json`/`.md`; gate on floors. Closes KNOWN-GAPS #1 ("we measure coverage, not false-positive rate"). | `tests/e2e/` | M | [07] |
| **Lambda Function URL `AuthType = NONE`** detection in cat-07 — now *actively exploited* (HazyBeacon C2). Trivial regex, high signal. | cat-07 | S | [06] |

## P1

**Scanner hygiene** [04]:
- Bump `osv-scanner` 2.3.5→2.3.8, `trufflehog` 3.95.2→3.95.5 (+ migrate
  `--only-verified` → `--results verified`). Effort S.
- Fix stale tool references that will silently break: `zizmor` repo moved to
  `zizmorcore/zizmor` (+ flag change); `govulncheck` "latest" install
  endpoint; `psalm` SARIF flag (`--report=*.sarif`); `brakeman` license is
  non-OSS (non-commercial) — note it. Effort S.
- Promote **grype** to a first-class EPSS/KEV prioritization step; carry EPSS
  in SARIF `properties.epss*`. Effort M.

**Detection depth** [01]:
- JWT header-trust + missing `iss`/`aud` + exact `redirect_uri` (cat-01/03). S–M.
- SSRF validation-method upgrade + metadata-denylist completeness, incl.
  IPv4-mapped-IPv6 (cat-08). S.
- SAML signature-wrapping sub-section (cat-01). S.
- DOMPurify-class prototype-pollution→XSS gadget signals. S.

**Cloud / IaC / NHI** [06]:
- Kyverno CEL **SSRF CVE-2026-4789** (CVSS 9.8, verified on NVD) +
  admission-webhook misconfig (cat-07). M.
- **Native-sidecar `securityContext` parsing** — k8s 1.33 GA'd
  `initContainers[].restartPolicy: Always`; container-only greps now
  silently miss privileged sidecars (correctness fix, cat-07). M.
- OIDC workload-identity trust misconfig (wildcard/missing `sub`) + IMDSv1
  detection (cat-07). M.
- MCP-config secret sweep in cat-06 (GitGuardian: 24,008 secrets in MCP
  config files). S.

**Methodology** [03][05]:
- Conditional **OWASP Agentic Applications 2026** lens (`ASI01:2026…ASI10:2026`),
  gated on tool-calling detection. M.
- NIST **SP 800-218A** (GenAI SSDF profile) assertions; fix the SSDF citation
  to v1.1 (Feb 2022). S.
- Add `supply_chain` + `agentic` category enums; add **CWE-1426** to
  `lib/cwe-map.json` (currently missing). S.

**Benchmark targets** [07]:
- Add **DVWA** (PHP) as the second E2E target — cheapest already-planned win;
  its "impossible" level gives free false-positive decoys. Closes the
  ROADMAP "second polyglot target" item. S.
- Add **OWASP crAPI** as the third — one repo covers `token_scope` +
  `deployment` + partial `mitm` and adds Java/Go/Python. M.

## P2

- PCI DSS 4.0.1 opt-in tagging mode (6.4.3 / 11.6.1 client-side & e-skimming);
  EU CRA / SBOM-completeness note leveraging existing CycloneDX. [05]
- RAG / memory-poisoning + LLM-output→code-interpreter-sink detections (cat-11). [03]
- Dogfood: enumerate this repo's own Claude Code skill / agent / MCP surfaces
  (`.mcp.json`, `.claude/settings*.json` scopes, sub-agent prompt
  interpolation) as cat-11 self-audit targets. [03]
- Polyglot precision micro-benchmark from **CVEfixes** (CC-BY-4.0, multi-lang);
  optional **OWASP Benchmark** (Java v1.2 + Python v0.1) calibration run; mine
  **CyberSecEval** Insecure-Code-Detector rule corpus (~189 patterns / 50 CWEs
  / 8 langs) for ready-made detections. [07]
- Terraform/IaC breadth to CIS v6/v7. [06]
- "Funky Chunks" request-smuggling + web cache poisoning/deception — note most
  of this is **NOT statically detectable** (CDN cache-key composition, proxy
  chains); flag-location-and-defer only. [01]

## ⚠️ Needs a user decision before implementing

- **Opengrep migration + rule-licensing.** The Semgrep Rules License (Dec 2024)
  forbids redistributing the `p/...` rule packs the skill currently bundles —
  a latent licensing exposure *today*, independent of engine choice. Opengrep
  (v1.22, LGPL-2.1, SARIF, Semgrep-rule-compatible) is the OSS path, but
  Commons Clause / non-OSI concerns apply if the skill ever becomes part of a
  paid offering. Decide engine + rule-distribution posture. [04]
- **Prototype pollution placement** — new Phase-5 category vs. a sub-area of
  cat-08 (injection). [01]
- **Fan-out width.** Adding cat-10 + cat-11 takes Phase-5 categories 9 → 11
  while the concurrency cap is 8. Confirm scheduling/cap implications (more
  waves, or raise cap). [02][03]

## Negative findings (do NOT chase)

- No 2026 Terraform AWS-provider default-drift — provider 6.0 (2025-06-18)
  flipped no security defaults. [06]
- OWASP **LLM Top 10 is still 2025** (no newer edition) — keep `LLMxx:2025`
  tags. API Top 10 still **2023**; ASVS still **5.0.0** (5.0.1 only planned). [03][05]
- Offensive agentic cyber gyms (Cybench, NYU CTF Bench, CyberGym,
  AutoPenBench) are the **wrong instrument** for a defensive static auditor.
  Only **CyberSecEval's** Insecure-Code-Detector rule corpus is reusable. [07]

---


## ✅ Delivered in v2.0.1

The following were on the v2.0.0 roadmap and have landed:
- Local E2E test (`scripts/run-e2e-test.sh` + `tests/e2e/`) with pinned
  Juice Shop @ v19.2.1 + 12-fixture capability gate.

- Phase 2 handler-file vs registration-file tracking.
- Fingerprint-off-CWE for baseline stability.
- OSV-scanner lockfile-dependence warning (now in `--check` + CHANGELOG).
- Missing-CWE entries (208, 215, 598, 1004) backfilled.
- Container-isolated scanner execution (scripts/Dockerfile.audit +
  run-audit-in-container.sh).
- Installer checksum verification + stale-version warning.
- JSON-schema enforcement on every sub-agent (scripts/validate-findings.py).

## E2E coverage (net-new v2.1 candidates)

### GHA-hosted E2E run

**Problem.** Local-only E2E requires a developer on their host. Can't
block a PR's CI on an E2E that only runs locally.

**Blockers.** (1) Claude Max auth is OAuth-based; fresh CI runners have
no claude.ai session. (2) Pay-per-token API key for CI means a dedicated
key, separately billed. (3) Headless OAuth-for-CI via Claude Code is
not documented / verified.

**Fix.** Either: (a) provision a dedicated API key + wire
`ANTHROPIC_API_KEY_E2E` as a GHA secret, or (b) verify Claude Code
supports OAuth for headless use. Decide + implement.

### Second E2E target — polyglot coverage

**Problem.** Juice Shop is JS/TS/Express only. The current fixture list
doesn't exercise `deployment` (v19.2.1's Dockerfile is hardened),
`mitm`, or `token_scope` categories — no ground truth in this target.

**Fix.** Add a second E2E fixture against DVWA (PHP) or a small Go repo
with known TLS / secret / deployment misconfigs. One fixture per target
in `tests/e2e/<target>-fixture.json`. The current script accepts a
`--target` flag to select which fixture to use.

## Correctness refinements

### AST-based handler hashing (supersedes content hashing)

**Problem.** Content hashing in `lib/handler-hash.md` over-invalidates:
whitespace-only formatting changes are stable, but any reordering
of independent statements is treated as a semantic change.

**Fix.** Replace `sha1(normalized_body)` with a lexer-derived token
stream hash (tokens only; no whitespace, no comments, no string
literal content). Requires per-language lexer (tree-sitter or
handler-rolled).

**Impact.** Reduces spurious delta-mode re-audits on refactor-heavy
PRs. Locked as v2.1 per Q10 at bootstrap.

## Install / install-path ergonomics

### Pre-commit hook recipe

**Problem.** `/security-audit mode: delta` is slow enough that it
doesn't fit a typical pre-commit budget, but stripped-down checks
(secrets, hardcoded keys, direct grep hits) could run in <5 sec.

**Fix.** Ship a `docs/ci-examples/pre-commit/` recipe that runs a
subset: semgrep on staged files + gitleaks staged + Phase 2 surface
re-enumeration for changed routes only. No Phase 5 / Phase 6.

### Installer progress UI

**Problem.** Trufflehog and trivy install via vendor install.sh scripts
that print their own progress bars; users see confusing interleaved
output.

**Fix.** Wrap install calls with `--quiet` where possible and emit
per-scanner `[installing trufflehog...]` / `[OK]` lines at the skill
installer level.

## Coverage / analysis

### Windows / WSL native support

**Problem.** Several scanners (osv-scanner, gitleaks) have native
Windows binaries; trivy and hadolint do. Semgrep does not. Full
native Windows is infeasible; full WSL support is already viable.

**Fix.** Document WSL-only officially; attempt a smaller Windows
binary bundle (semgrep-less) for audits that skip SAST.

### CodeQL integration (OSI-license auto-detection)

**Problem.** CodeQL is excluded by default because the CLI is
license-restricted to OSI-approved OSS. Eligible users currently have
to enable it manually.

**Fix.** Phase 0 heuristically detects OSI-approved licenses (parse
`LICENSE` / `LICENSE.md` / `package.json.license`). If matched, offer
(but don't auto-enable) CodeQL in the Phase 4 bundle.

### Non-English codebase support

**Problem.** Framework detection regex assumes English identifiers.
Known limitation documented in `lib/framework-detection.md`.

**Fix.** Expand detection to include common non-English naming patterns
for the top 5 languages where non-English codebases are significant
(Chinese, Japanese, Russian).

## Performance

### Pruned-baseline gzip for huge monorepos

**Problem.** 53KB pruned baseline for a 103K-LOC monolith; linear
scaling suggests ~500KB for a 1M-LOC 8-partition monorepo. Diffable,
but larger than necessary.

**Fix.** gzip the pruned baseline (`docs/security-audit-baseline.json.gz`)
if size exceeds 200KB. Check-in impact is small.

### Phase 2 + Phase 3 fusion for single-partition repos

**Problem.** Single-partition repos pay two sub-agent spawn costs for
Phase 2 + Phase 3 when the data flows sequentially.

**Fix.** Detect single-partition case in workflow §5 and run Phase 2
and Phase 3 as a single sub-agent.

## Methodology / tagging

### ASVS L3 support

**Problem.** Currently targets L2 only. Some regulated industries need
L3 coverage (finance, healthcare).

**Fix.** Add an optional `--asvs-level L3` flag; ship a sub-agent
prompt per V* L3 sub-item.

### Full LINDDUN expansion

**Problem.** Dogfood produced minimal LINDDUN coverage (4 entity
family rows). Full LINDDUN is 7 threats × per-PII-data-flow.

**Fix.** Expand `steps/phase-06-config.md §6.12` into a per-threat
sub-agent fan-out gated on PII column density.

## Documentation / UX

### Interactive "fix this finding" workflow

**Problem.** The report says "ask me to fix finding <id>", but the
flow from report → Claude Code chat → code diff isn't documented.

**Fix.** Add a "Fix flow" section to README and wire an explicit
`--fix <id>` sub-command.

### GitHub Issue creation from report

**Problem.** V1 had `gh issue create` from report; v2 mentions it in
Phase 7 but the actual invocation is manual.

**Fix.** Add a dedicated `/security-audit mode: issue` that spawns
the gh call with the correct body format.
