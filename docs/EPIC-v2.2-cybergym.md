# EPIC — v2.2: CyberGym-E2E-derived quality hardening

Status: **IN PROGRESS** (autonomous build, 2026-06-14).
Source: a fresh read of **CyberGym-E2E** (arXiv 2606.04460v1, Shi et al., UC
Berkeley) — see `docs/research/08-cybergym-e2e.md` — plus the systemic
finding deferred from the v2.1 Gate-C adversarial rounds.

## 1. Why this exists

v2.1 added breadth (categories, methodology, output routing). CyberGym-E2E
benchmarks the *same harnesses we run on* (Claude Code et al.) on real-repo
vulnerability work and reports **why agents succeed or fail** at it — directly
applicable to our Phase-5 deep-dive sub-agents, which do the same navigate-the-
repo-and-find-the-bug task minus the exploit. v2.2 turns those lessons into
concrete quality improvements, and closes two measurement gaps v2.1 left open.

The paper does NOT score static auditors (it's exploit/patch lifecycle), so we
take **method and failure-analysis**, not the benchmark itself.

## 2. Definition of done

A merged-ready **v2.2** branch + PR in which: the four applicable CyberGym-E2E
lessons are implemented; the CWE↔OWASP pair validator closes the v2.1 Gate-C
systemic gap; VERSION=2.2.0 with CHANGELOG/docs updated; all static validators
green; the three methodology gates (plan review, modularisation, 2× adversarial)
are completed. The live-container E2E remains the one un-run gate (pre-existing
Claude-auth blocker).

## 3. Global Safeguards (unchanged from v2.1)

The artifact-contract invariants in `skills/security-audit/manifest.yaml` still
hold; every change must preserve them. New code must keep the scorecard
**additive / default-no-op** (no regression of existing exit codes), and keep
`assertions.py` stdlib-only + import-clean.

## 4. Themes & stories

### Theme A — CyberGym-E2E lessons

- **A1 — Sub-agent prompt hardening.** CyberGym-E2E's failure taxonomy:
  (i) *context-flooding → premature abandonment* (full-file loaders burned
  2000+ tokens/file and quit after 2–3 hypotheses; targeted grep + task-tracking
  was the fix and is why Claude Code beat OpenHands), and (ii) *incomplete
  data-flow tracing*. Apply to `templates/subagent-prompt.md` (mandate
  grep/ripgrep-to-the-surface-row, read only handler ±N lines, never whole
  files unless small) and to the taint-dependent categories (`cat-02`,
  `cat-08`): require an explicit source→sink trace and emit
  `confidence: POSSIBLE` when the trace can't be completed. Effort S–M.
  Files: `templates/subagent-prompt.md`, `cat-02-idor-bola.md`,
  `cat-08-injection-ssrf.md`.

- **A2 — Patched-commit-as-decoy precision micro-benchmark.** CyberGym-E2E's
  construction insight: the **pre-patch** code at a fix site is a labeled
  true-positive for a known CWE, and the **post-patch** code is a labeled
  true-negative — i.e. exactly our v3 `negative_expectations[]` decoy. Ship the
  *mechanism* + a **small seeded** micro-benchmark in the v3 fixture format +
  an expansion doc (how to mint pairs from CVEfixes / OSS-Fuzz fix commits).
  Not a 920-task corpus — a method + seed. Effort M. Files: `tests/e2e/`.
  NOTE: CyberGym-E2E's own corpus is C/C++ memory-safety (off our web/app-sec
  axis) — borrow the *method*, seed with web-framework CVE fix pairs.

- **A3 — Semantic-correctness scorecard check.** CyberGym-E2E's S3↔S4 gap
  (19.2% vs 7.6% for Opus) shows "found A bug here" ≠ "found THE bug" is a
  large, real error class. Our scorecard matches on (file, cwe, category) only
  — blind to mechanism. Add an OPTIONAL `expected_mechanism` /
  `mechanism_keywords` to the fixture and a check in `assertions.py` that a
  matched finding's `title`/`description` actually describes the expected
  mechanism; report a `semantic_match` rate in the scorecard. Turns
  KNOWN-GAPS #1 from "not automated" to "partially automated". Keep additive.
  Effort M. Files: `tests/e2e/assertions.py`, fixtures, `tests/e2e/README.md`.

- **A4 — Budget calibration note.** CyberGym-E2E: ~$10 / 90-min per task,
  diminishing returns after 60 min. Record as guidance for any future
  live/GHA E2E (not a code change). Effort S. Files: `tests/e2e/README.md` /
  `docs/KNOWN-GAPS.md`.

### Theme B — v2.1 Gate-C systemic deferral

- **B1 — CWE↔OWASP pair validator.** Both v2.1 adversarial rounds caught a
  hand-authored `CWE-N / A##:2025` mismap that every validator passed green.
  Encode the canonical CWE→web-Top-10:2025 mapping as data (derive from
  `lib/owasp-web-top10.md` into a machine-readable `lib/cwe-owasp-map.json`)
  and add a `validate-schemas.sh` section asserting each `CWE-N / A##:2025`
  pairing in the cat files matches. Effort M. Files: new
  `lib/cwe-owasp-map.json`, `scripts/validate-schemas.sh`.

### Theme C — research + integration

- **C1 — Research note + ROADMAP.** `docs/research/08-cybergym-e2e.md`
  (the read + applicable lessons) + v2.2 ROADMAP entries.
- **C2 — Integration.** VERSION→2.2.0, manifest `skill_version`, `config.env`,
  README/INSTALL pins, CHANGELOG `[2.2.0]`, KNOWN-GAPS updates; validators green.

### Explicitly out of scope (v2.2)

- Adopting CyberGym-E2E as a scored benchmark (it's exploit/patch, not static
  detection). Opver patch-with-functional-tests auto-fix flow (future).
  Opengrep engine swap (resolved in v2.3 — kept Semgrep; see CHANGELOG). A
  full CVEfixes corpus (A2 ships the method + a seed, not 100s of tasks).

## 5. Sequencing

Branch `epic/v2.2-cybergym` off main (post-v2.1). A1 / (A2+A3) / B1 touch
disjoint files (cat+template / tests / lib+validator) → parallelizable. C1 +
A4 + integration done centrally. A2 and A3 share `tests/e2e/` → one track.
Gates: plan review (now) → modularisation → 2× adversarial → PR.

## 5.5 Gate-A review amendments (authoritative; override §4 on conflict)

- **A2 re-scoped — the decoy *mechanism* already shipped in v2.1** (#19: v3
  `negative_expectations[]`, `score_findings`, `write_scorecard`, SARIF→title
  carry, DVWA/crAPI fixtures). v2.2 A2 is therefore **a method doc only** — the
  "patched-commit-as-decoy" recipe in `tests/e2e/README.md` for minting more
  TP(pre-patch)/TN(post-patch) fixture pairs from CVE fix commits, plus 1–2
  demonstrative decoy entries framed explicitly as vuln-vs-fixed. No new
  scorer/mechanism code. CHANGELOG must say "v2.1 shipped the scorer; v2.2 adds
  the semantic check + the decoy-pair method."
- **A3 stays the only substantive scorecard code.** New `expected_mechanism` /
  `mechanism_keywords[]` (with optional `alternate` synonym sets) fixture field
  + a `semantic_match` rate in the scorecard. **Report-only by default**
  (floor 0.0, opt-in `--semantic-floor`, wired into `run-e2e-test.sh`); guard
  empty-denominator → 1.0 exactly like `_metrics`. SARIF findings carry `title`
  by scoring time, so the data exists.
- **B1 must NOT false-fail on deliberate context roll-ups.** cat-10 tags
  `CWE-94 / A03:2025` and `CWE-798 / A03:2025` (supply-chain context; canonical
  = A05 / A07), and `CWE-250 / A02:2025` uses a CWE absent from the canonical
  web-Top-10 table. Design: `lib/cwe-owasp-map.json` carries the canonical 1:1
  `{CWE: A##}` map **plus an explicit `context_overrides` block** listing
  per-cat allowed non-canonical pairs (each with a one-line justification). The
  validator passes a `CWE-N / A##:2025` pair iff it matches canonical OR is in
  `context_overrides`; a CWE absent from the canonical table → **warn, not
  fail**. This still catches NEW unintended mismaps (absent from both) while
  forcing every deliberate exception to be documented.
- **B1 naming/wiring:** name it `cwe-owasp-map.json` (NOT `*-schema.json`) so
  `validate-schemas.sh §2` ignores it; §1 still jq-parses it. No `$schema`
  needed.
- **A1 wording:** reconcile with `cat-02-idor-bola.md` ("Read the handler
  file") and the template scope rules — say "read the handler ±N lines," not
  "the file." Prompt-only; no RETURN-SHAPE / contract change.

## 6. Risks

| Risk | Mitigation |
|---|---|
| Semantic check too strict → false E2E failures | Make it report-only by default (a rate, not a hard gate) with an opt-in floor. |
| Decoy seed mislabeled (a "fixed" commit still vulnerable) | Cite the fix commit; mark seed entries `verify on NVD`; keep the seed tiny + reviewed. |
| CWE→A## map drift vs owasp-web-top10.md | Single JSON map is the SoT; validator reads it; note to update both together. |
| Sub-agent prompt change alters fan-out behavior | Prompt-only guidance; preserves the contract; covered by adversarial review. |
| Scope creep | A2 = method + seed only; full corpus stays future. |
