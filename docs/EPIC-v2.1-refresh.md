# EPIC — v2.1 Security-Audit Capability Refresh

Status: **COMPLETE** (autonomous build, 2026-06-14) — all waves landed on
`epic/v2.1-security-refresh`; Opengrep deferred to v2.2 per §4. See CHANGELOG
[2.1.0] for the shipped set.
Owner: Tech Lead (autonomous).
Source of truth for scope: `docs/research/` (7 reports) → `docs/ROADMAP.md`
("Research round — 2026-06-14") → this epic.

---

## 1. Context & provenance

The v2.0.x skill is architecturally sound but its *content* (categories,
pattern catalogs, methodology versions, tool pins) aged ~7 weeks since the
2026-04-24 research that produced `docs/V2-SCOPE.md`. A 2026-06-14 research
round (7 parallel agents, reports in `docs/research/`) surfaced new exploit
classes, two missing categories, stale tool pins (one a live CVE in our own
bundle), methodology gaps, and a measurement gap. This epic delivers that
backlog as **v2.1**, plus two owner directives received during planning:
**de-BMAD** the output routing and **unify + prompt for the output dir**.

## 2. Goal & definition of done

A merged-ready **v2.1 release branch + PR** (`epic/v2.1-security-refresh` →
`main`) in which:

- All P0 + most P1 backlog items are implemented as real, specific detection
  content (not stubs), wired into the manifest/schema/contract.
- Output routing is unified + configurable + prompted; **zero** `_bmad-output/`
  references remain.
- `VERSION` = `2.1.0`; `manifest.yaml skill_version` aligned; CHANGELOG,
  README, V2-SCOPE, KNOWN-GAPS, ROADMAP updated.
- **All static validators pass** (`validate-findings.py`, `validate-patterns.py`,
  `validate-schemas.sh`, `validate-install-pins.sh`, install-snippet drift lint).
- The three methodology gates (§5) are completed: plan gap review, per-feature
  modularisation/refactor review, and **2× adversarial review** before PR.
- Known un-run gate (live-container E2E — pre-existing Max-auth blocker per
  KNOWN-GAPS) is documented in the PR; the **static** E2E assertion suite is
  updated and internally consistent.

## 3. Global Safeguards (invariants that MUST NOT break)

Threaded into every story's acceptance criteria. Sourced from `manifest.yaml`:

1. Every phase writes its `.done` marker **after** its artifacts exist.
2. A run that produces only the human report without `.claude-audit/current/*`
   is INVALID (blackboard-first).
3. Every SARIF result carries `properties.cwe` **and** `properties.security-severity`.
4. No consolidated `phase-05-*.json` (per-category-per-partition JSONL only).
5. Phase 5 fan-out must not collapse to a serial single pass.
6. E2E fixture coverage must not regress (every existing fixture still matches).
7. CWE on every finding (fallback `CWE-1007`); every referenced CWE exists in
   `lib/cwe-map.json`.

## 4. Decisions

**Resolved autonomously (technical, reversible):**
- **Prototype pollution** → sub-area of `cat-08` (injection), not a new
  category. Keeps fan-out width down.
- **Fan-out width** → categories grow 9 → 11; concurrency cap stays **8**;
  excess queues into a second scheduling wave (documented in `phase-05`).
- **Output dir default** → `docs/security-audit-output/` (tracked). Blackboard
  (`.claude-audit/`) stays as gitignored working state — it is the contract
  everything keys off; relocating it is high-risk and out of scope.
- **NHI secrets** → cross-cutting additions to `cat-06`/`cat-07`, not a 10th
  category (per report 06's own recommendation).

**Opengrep migration + rule-licensing posture — RESOLVED (2026-06-14, in v2.3).**
The owner confirmed the project stays **free OSS forever**, so the Semgrep Rules
License (which only restricts commercial / SaaS / competing-product use) does
not bind this invoke-only, non-redistributing tool — the skill fetches `p/...`
packs at runtime and never bundles them. **Decision: keep Semgrep** (its
continuously-maintained community packs) and **decline Opengrep** — its only
free ruleset (`opengrep-rules`) is archived/frozen at Dec-2024, a rule-freshness
downgrade for a licensing benefit we don't need. Shipped an `AUDIT_SAST_RULES`
offline/BYO-rules override instead. See CHANGELOG [2.3.0].

## 5. Methodology & gates

Standard BMAD-style epic → stories, built in dependency-ordered waves on the
epic branch, with three explicit gates (matching the owner's instruction):

- **Gate A — Plan gap/enhancement review** (before build). Architecture-review
  lens over *this plan*; fold findings in. (Task #2)
- **Gate B — Per-feature modularisation/refactor review.** Each wave ends with
  a modularisation pass (dedupe pattern catalogs, shared gate/scheduler logic,
  schema/SARIF-postprocess reuse, single source of truth for output routing);
  plus a consolidated pass before Gate C. (Task #11)
- **Gate C — 2× adversarial review before PR.** `/vault-adversarial-review`
  twice over the full branch; fix all warranted findings each round. (Task #13)

Per-story spec shape (lightweight SPDD REASONS Canvas): each story below
carries **Files**, **Acceptance**, and inherits the **Safeguards** in §3.

## 6. Themes & stories

Bracketed `[NN]` = source report in `docs/research/`. Effort S/M/L.

### Theme 0 — Scanner hygiene & fix-now (Wave 0) [04]
- **S0.1 (S)** Bump `TRIVY_VER` 0.70.0 → 0.71.0 (GHSA-q3fv-x8vg-qqm4; we run
  `trivy config`). Files: `scripts/install-scanners.sh`, `lib/scanner-bundle.md`.
  Acceptance: pin updated; `validate-install-pins.sh` green; CycloneDX output
  version change noted in CHANGELOG.
- **S0.2 (S)** Bump `OSV_VER`→2.3.8, `TRUFFLEHOG_VER`→3.95.5; migrate
  `--only-verified` → `--results verified`. Files: installer + scanner-bundle +
  `phase-04-scanners.md`. Acceptance: pins + invocation updated, checksums
  re-pinned.
- **S0.3 (S)** Fix stale tool references: `zizmor` repo → `zizmorcore/zizmor`
  (+ flag), `govulncheck` install endpoint, `psalm` SARIF flag (`--report`),
  `brakeman` non-OSS license note. Files: `scanner-bundle.md`, installer.

### Theme 7 — Output routing + de-BMAD (Wave 1a) [owner directive]
- **S7.1 (M)** New `lib/output-routing.md` defining resolution order:
  `output:` arg → persisted `.claude-audit/config.json` `output_dir` →
  interactive prompt (default `docs/security-audit-output/`) → non-interactive
  fallback to default (no prompt; log choice). Persist chosen dir for
  delta/report-only modes.
- **S7.2 (M)** Remove ALL `_bmad-output/` auto-detect: `SKILL.md`,
  `manifest.yaml final_outputs`, `workflow.md`, `phase-07-synthesis.md`,
  `phase-08-baseline.md`, `lib/delta-mode.md`, `README.md`, `docs/V2-SCOPE.md`.
  Acceptance: `grep -ri bmad skills/ docs/ README.md` returns zero functional
  references (a single historical note in CHANGELOG is allowed).
- **S7.3 (M)** Route deliverables (report, `findings.sarif`,
  `findings.cyclonedx.json`, pruned baseline) into `<output_dir>/`. Update
  `.gitignore`, `manifest.yaml`, schemas referencing paths.
- **S7.4 (S)** Add `output:` to the canonical arg grammar in `SKILL.md`
  description + `workflow.md`; document interactive vs CI behavior.
- **S7.5 (S)** Update `tests/e2e/assertions.py` + fixtures + `docs/ci-examples/`
  to the resolved output dir. Acceptance: assertion suite logic references the
  new path; Safeguard #6 preserved.

### Theme 1 — Foundations: taxonomy/schema/gates (Wave 1b) [02][03][05]
- **S1.1 (S)** Add `supply_chain`, `agentic` category enums to
  `lib/finding-schema.json`, `validate-findings.py`, `manifest.yaml`, SARIF
  `properties.category` doc in `SKILL.md`.
- **S1.2 (S)** Add `CWE-1426` (+ any referenced-but-missing CWEs from the new
  categories) to `lib/cwe-map.json`; update `NOTICE.md` (MITRE CWE attribution
  already present).
- **S1.3 (M)** Phase-0 detection gates: `profile.supply_chain.*` signals and
  `profile.mcp_agentic.detected` (separate from `llm_usage`). Files:
  `lib/profile-schema.json`, `steps/phase-00-discovery.md`.
- **S1.4 (S)** Document fan-out 9→11 with cap-8 queueing in
  `steps/phase-05-deepdives.md` + `manifest.yaml` (categories list).

### Theme 2 — New categories + deser/proto-pollution (Wave 2) [01][02][03]
- **S2.1 (M)** `steps/deepdive/cat-10-supply-chain.md` — lifecycle-hook scan
  (npm pre/postinstall, Python `setup.py`/`.pth`, gem `extconf.rb`, cargo
  `build.rs`, Go), dependency-confusion/lockfile-integrity, CI script-injection
  (`${{ github.event.* }}` → run), action-pinning. Gate: always (cheap regex
  pass). Manifest entry id `supply_chain`.
- **S2.2 (M-L)** `steps/deepdive/cat-11-mcp-agentic.md` — MCP server/tool-scope
  breadth, prompt-injection-via-tool-output/description, confused-deputy /
  token pass-through, `.mcp.json`/agent-config scopes. Gate:
  `profile.mcp_agentic.detected`. Manifest entry id `agentic`.
- **S2.3 (S)** `cat-08` deserialization false-safety corrections (PyYAML
  `FullLoader`; `torch.load(weights_only=True)` pre-2.10) + `cat-09` model-file
  deser (pickle/`from_pretrained` from untrusted hubs).
- **S2.4 (M)** `cat-08` prototype-pollution sub-area (sources/sinks, DOMPurify
  gadget class).

### Theme 3 — Detection-depth upgrades (Wave 3) [01][06]
- **S3.1 (M)** `cat-01` framework fail-open auth heuristic (positive-allowlist
  matcher-evasion: Next.js/Clerk/Spring) + SAML signature-wrapping subsection.
- **S3.2 (S-M)** `cat-01`/`cat-03` JWT header-trust + missing `iss`/`aud` +
  exact `redirect_uri`.
- **S3.3 (S)** `cat-08` SSRF validation-method upgrade + metadata-denylist
  completeness (incl. IPv4-mapped-IPv6).
- **S3.4 (M)** `cat-07` cloud: Lambda Function URL `AuthType=NONE` (actively
  exploited), Kyverno CEL SSRF (CVE-2026-4789, NVD-verified), native-sidecar
  `securityContext` parsing (k8s 1.33 GA correctness fix), OIDC
  workload-identity trust + IMDSv1.
- **S3.5 (S)** `cat-06` MCP-config secret sweep.

### Theme 4 — Methodology spine refresh (Wave 4) [03][05]
- **S4.1 (M)** OWASP **Top 10:2025 (web)** mapping layer (CWE→category lookup,
  no fan-out) + Phase-7 coverage matrix row. Files: `phase-06-config.md`,
  `phase-07-synthesis.md`, `report-template.md`, new `lib/owasp-web-top10.md`.
- **S4.2 (S)** **CWE Top 25 (2025)** additive enrichment on existing CWE tag
  (±1-rung severity cap preserved). Files: `cwe-map.json` (flag), synthesis.
- **S4.3 (M)** OWASP **Agentic Applications 2026** (`ASI01:2026…ASI10:2026`)
  conditional lens gated on tool-calling detection. Files: `phase-06-config.md`,
  new `lib/owasp-agentic-2026.md`, tag vocab.
- **S4.4 (S)** NIST **SP 800-218A** AI-SSDF assertions + fix SSDF citation to
  v1.1 (Feb 2022). Files: `phase-06-config.md`.

### Theme 5 — Measurement/benchmark harness (Wave 5) [07]
- **S5.1 (M)** Fixture schema **v3** with `negative_expectations[]` decoys +
  TP/FP/FN/precision/recall/F1 scorer in `tests/e2e/assertions.py`; emit
  `scorecard.json`/`.md`; gate on precision/recall **floors**. Closes
  KNOWN-GAPS #1.
- **S5.2 (S)** Seed decoys from Juice Shop hardened Dockerfile + safe handlers
  (real FP denominator).
- **S5.3 (S)** Add **DVWA** (PHP) fixture (`tests/e2e/dvwa-fixture.json`,
  `--target dvwa`). Closes ROADMAP "second polyglot target".
- **S5.4 (M)** Add **OWASP crAPI** fixture (token_scope/deployment/mitm +
  Java/Go/Python).

### Deferred to v2.2 (documented, not built)
Opengrep engine swap + rule-licensing posture; grype EPSS/KEV promotion (P1 —
include only if time permits as it touches Phase-4 ordering); PCI DSS 4.0.1
mode; CRA/SBOM note; CVEfixes micro-benchmark; CyberSecEval ICD rule mining.

## 7. Wave sequencing & dependency graph

```
Wave 0 (S0.*)  ─┐  scanner hygiene (isolated: installer + scanner-bundle)
Wave 1a (S7.*) ─┤  output routing + de-BMAD   ── shared files, do FIRST
Wave 1b (S1.*) ─┘  taxonomy/schema/gates       ── shared files, do FIRST
        │
        ├─ Wave 2 (S2.*)  new categories + deser/PP   ┐
        ├─ Wave 3 (S3.*)  detection-depth per-cat     ├ parallelizable
        ├─ Wave 4 (S4.*)  methodology spine           │  (mostly disjoint
        └─ Wave 5 (S5.*)  benchmark harness           ┘   files)
        │
   Gate B (modularisation/refactor)
        │
   Integration (VERSION/CHANGELOG/docs/validators)
        │
   Gate C (2× adversarial review)
        │
   Push + PR
```

Waves 0/1 land on the epic branch first (shared-file changes, kept internally
consistent). Waves 2–5 touch mostly disjoint files (own cat step files / own
lib docs / tests). Where a worktree fan-out is used, agents edit only their own
new/owned files and **never** shared wiring (`manifest.yaml`, `*-schema.json`,
`cwe-map.json`, `CHANGELOG`, `VERSION`, `phase-05/06/07`); the Tech Lead wires
shared files centrally to avoid merge collisions.

## 8. Branch & integration strategy

- Epic branch `epic/v2.1-security-refresh` off current `main`.
- Direct commits to `main` are blocked by a repo hook — correct; the PR is the
  only path. Per-wave commits on the epic branch with descriptive messages.
- The Tech Lead runs all validators before Gate C and before PR.
- PR is **opened, not merged** (owner reviews on return).

## 9. Risk register

| Risk | Mitigation |
|---|---|
| Live-container E2E can't run here (Max-auth blocker) | Keep static assertion suite consistent; document as the one un-run gate in the PR (pre-existing KNOWN-GAP). |
| Shared-file merge collisions across waves | Foundations land first; fan-out agents never touch shared wiring. |
| Unverified 2026 CVE IDs in research | Encode bug *classes* + grep signals; cite a CVE only when NVD-verified; mark others "verify". |
| Fan-out width 11 > cap 8 changes scheduling | Documented 2-wave queueing in phase-05; no cap change. |
| Output-routing change breaks delta/report-only path discovery | Persist chosen dir in `.claude-audit/config.json`; delta/report-only read it. |
| Scope creep (26+ stories) | P0+P1 are the bar; P2 explicitly deferred and logged. |

## 10. Out of scope (unchanged from v2)

DAST/runtime, CSPM (needs creds), runtime container security, manual
business-logic flaws, pentest replacement. Opengrep swap (deferred, §4).

---

## 11. Gate A — review outcomes & plan amendments (2026-06-14)

Two parallel reviewers (architecture/sequencing + completeness/coverage) ran
over this plan. Findings below are **authoritative** and override §6 where they
conflict. The coverage matrix confirmed all Fix-now + P0 + P1 items are
covered; these are the corrections.

### 11.1 BLOCKING — fix before build

- **B1 — `owasp_ids` regex rejects new vocab.** `lib/finding-schema.json` pattern
  `^(ASVS-V\d+\.\d+(\.\d+)?|API\d+:\d{4}|LLM\d+:\d{4})$` rejects `A03:2025`
  (web Top 10, S4.1) and `ASI01:2026` (agentic, S4.3) → every such finding
  fails `validate-findings.py`. **NEW story S1.5 (Wave 1b):** extend pattern to
  also accept `A\d+:\d{4}` and `ASI\d+:\d{4}`; add a `validate-schemas.sh`
  check that the tag vocab in `lib/owasp-web-top10.md` / `lib/owasp-agentic-2026.md`
  matches the regex. Must land in Wave 1b, before S4.1/S4.3.
- **B2 — category enum is the real gate.** S1.1 must edit the `category` **enum
  in `lib/finding-schema.json`** (validated via `Draft202012Validator`), adding
  `supply_chain` + `agentic`. `validate-findings.py` needs no enum edit.
- **B3 — SARIF/CycloneDX stay in the blackboard (corrects S7.3).** Do NOT write
  `findings.sarif`/`findings.cyclonedx.json` *only* to `<output_dir>/`. Phase 7
  writes them to `.claude-audit/current/` first (blackboard-first, Safeguard
  #2), then **copies** all deliverables to `<output_dir>/` as the final step.
  CI sample + GitHub upload path updated to the default
  `docs/security-audit-output/findings.sarif` (was `.claude-audit/current/...`).
- **B4 — pruned baseline discovery (corrects S7.3 + delta-mode).** Pruned
  baseline is a deliverable in `<output_dir>/security-audit-baseline.json`, but
  `lib/delta-mode.md` reads `docs/security-audit-baseline.json` unconditionally.
  Update delta/report-only resolution to: `output:` arg → `.claude-audit/config.json`
  → default `docs/security-audit-output/security-audit-baseline.json` → **legacy
  fallback** `docs/security-audit-baseline.json`. Because the default dir is
  tracked, fresh-clone delta works without the arg; non-default dirs in CI must
  pass `output:`.
- **B5 — manifest contract for new categories.** S1.4 must add cat-10
  (`supply_chain`, gate always) and cat-11 (`agentic`, gate
  `profile.mcp_agentic.detected`) to `manifest.yaml` `phase-05` categories AND
  the E2E `gated_categories` so an absent `phase-05-agentic-*.jsonl` on Juice
  Shop is a legitimate skip (Safeguard #6). Confirm Phase-7 `phase-05-*.jsonl`
  glob ingests the new files (it does).

### 11.2 Scope changes

- **Grype EPSS/KEV un-deferred → NEW story S0.4 (Wave 0).** Both reviewers: it's
  a cheap P1 (grype already optional in the bundle; additive SARIF
  `properties.epss`/`properties.kev`; no new dependency type). Build it in v2.1.
- **SCA fixed-version threshold map → NEW story S2.5 (Wave 2).** Report 01's
  third P0 ("most 2026 CVEs are dependency version-pins — the broadest, most
  reliable detector") was dropped from the synthesis. Add `lib/known-vuln-versions.md`
  (curated, version-pinned, CVE-verify caveat) consumed by cat-10 (supply chain)
  and cat-11 (LangChain 68664/68665, MCP Inspector 49596, mcp-remote 6514).
- **De-BMAD file list (corrects S7.2).** Add `docs/TROUBLESHOOTING.md` and
  `AGENTS.md` (both carry BMAD routing/setup notes). `phase-08-baseline.md` and
  `lib/delta-mode.md` carry no BMAD string but DO need the B4 baseline-path
  edits. **Carve-outs** (legitimate attribution, do not strip): `NOTICE.md`,
  `vendored/adversarial-review/`, and the historical `CHANGELOG.md` entry.
  Acceptance grep must include repo root and exclude carve-outs:
  `grep -rIl -i bmad . --exclude-dir=.git --exclude-dir=vendored
  --exclude-dir=_agent-memory --exclude=NOTICE.md --exclude=CHANGELOG.md`
  → only carve-outs remain.

### 11.3 Tighten under-specified stories

- **S2.2 (cat-11)** explicit sub-check coverage (each an acceptance line):
  (1) MCP server defs (`.mcp.json`, server registration) + tool-scope breadth;
  (2) prompt-injection via tool **description/result** into the agent context;
  (3) command/arg/path injection in MCP tool handlers; (4) confused-deputy /
  OAuth token pass-through (post-2025-11-25 spec: no passthrough); (5) unsafe
  STDIO/transport config; (6) excessive agency / unscoped tool grants;
  (7) model-file deser already in S2.3 — cross-link, don't duplicate.
- **S3.4** split into per-item acceptance: (a) Lambda Function URL
  `AuthType=NONE`; (b) Kyverno CEL SSRF (CVE-2026-4789) **+ generic
  admission-webhook misconfig** (the other half of the P1); (c) native-sidecar
  `securityContext` parsing; (d) OIDC workload-identity trust breadth + IMDSv1.
- **S2.1 (cat-10)** name the high-signal CI sinks explicitly:
  `pull_request_target` + untrusted head checkout; `${{ github.event.*.body }}`
  / `github.event.issue.title` script-injection; the Shai-Hulud
  self-hosted-runner-registration pattern; plus **provenance positive signals**
  (npm trusted-publishing/OIDC, sigstore) and a long-lived publish-token flag.

### 11.4 Wiring + enhancements folded in

- S7.1 non-blocking prompt detection is explicit: prompt only if `[ -t 0 ]`
  AND not `$CI` AND not `--dangerously-skip-permissions` /
  `$CLAUDE_CODE_DANGEROUSLY_SKIP_PERMISSIONS`; otherwise default + log.
- `.gitignore` for consumers (documented in `lib/output-routing.md` + README):
  track `security-audit-report.md` + `security-audit-baseline.json`; optionally
  ignore `<output_dir>/*.sarif` + `*.cyclonedx.json` (large machine state).
- S5.x adds `gated_categories` fixture entries for `supply_chain` (none — always
  on) and `agentic` (gated) so Safeguard #6 holds on Juice Shop.
- Delta-in-CI note: `.claude-audit/config.json` is gitignored working state and
  is gone on a fresh clone; CI with a non-default output dir must pass `output:`.

### 11.5 Confirmed sound (no change)

Opengrep deferral (legal one-way door; §4 redistribution correction stands);
negative-findings respected (no Terraform default-drift, LLM tags stay `:2025`,
no offensive cyber-gym scoring). CyberSecEval ICD rule-mining stays v2.2.
