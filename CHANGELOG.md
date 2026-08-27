# Changelog

All notable changes to this project. Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing queued.

## [2.6.1] — 2026-08-28

**The audit stops writing credentials into the repository it audits.**

A v2.6.0 full-mode run committed a live GitHub token — plus an Azure AD client
secret, a second one from a different `.env`, and an RSA private key — into the
audited project's git history. None of that material was ever in version
control before the audit: it lived in gitignored scratch paths, exactly where it
belonged. `git log --all -S<token>` returned the audit's own SARIF files and
nothing else. **The skill read the credentials from outside version control and
wrote them inside it.**

### The chain

Four links, each behaving exactly as specified:

1. `phase-04-scanners.md` runs `gitleaks detect --no-git`. The flag makes
   gitleaks ignore `.gitignore` — correctly; uncommitted secrets are the ones
   worth finding. Its SARIF carries the match verbatim in
   `region.snippet.text`. `trufflehog --results=verified` carries it in `Raw` /
   `RawV2` / `Redacted`, and `verified` means the scanner authenticated the
   credential against the live provider.
2. `phase-07-synthesis.md §7.8.1` assembles `findings.sarif` as one run per
   scanner plus one synthetic run, instructing that scanner runs be "copied
   through *verbatim* — do NOT rewrite". The instruction was written about CWE
   metadata. It moved snippets.
3. `§7.10` copies that document to `<output_dir>`.
4. `lib/output-routing.md` defaults `<output_dir>` to
   `docs/security-audit-output/` and calls it "tracked".

Two details about how it *stayed*, which shaped the fix more than the chain did:

- **`workflow.md §1` gitignored `.claude-audit/` and never `<output_dir>`.** The
  protection sat on the scratch directory and was absent from the one whose
  entire purpose is to be committed.
- **The skill had no concept that its own output was secret-bearing.** A later
  run's gitleaks flagged its predecessor's `findings.sarif`; the hits were
  triaged away as prior-artifact noise, because a security report is *expected*
  to look full of secrets. The dismissal confirmed itself. It happened twice,
  and a human's `git rm --cached` + `.gitignore` fix in between removed the file
  from `HEAD` while leaving the blob and the live token reachable in history.

### Added

- **`lib/secret-detectors.py`** — the single detector table both enforcers
  import by absolute path from the directory they ship in. Two copies would
  drift, and the day they drift the gate stops matching the redactor: a control
  whose enforcer no longer covers it, which is the defect class this skill
  exists to detect.
- **`lib/redact-scanner-output.py`** — Layer 1, the structural strip, invoked at
  the new **`phase-04-scanners.md §4.4b`** immediately after the scanners write
  and before §4.5 normalization, §4.6 slimming, or any sub-agent read.

  It removes SARIF `snippet` / `contents` / `insertedContent` from **every**
  scanner run unconditionally — not by matching credential patterns. That is a
  whitelist: the field is gone, so nothing in it survives regardless of format
  or of whether this skill has heard of the credential type. It is free because
  no consumer reads those fields — `lib/sarif-postprocess.md` discards them when
  slimming, Phases 5-7 read the slim form, and
  `tests/e2e/assertions.py:_sarif_result_to_finding` keys on `ruleId`,
  `properties.cwe`, `properties.cwes` and `tags`.

  Findings keep rule, level, file, line and column, and gain
  `properties.secret_fingerprint` — stable across runs, so Phase 7 still dedupes
  and Phase 8 still carries secret findings forward now that the value is gone.
- **`lib/verify-deliverable.py`** — Layer 2, a fail-closed gate at
  `phase-07-synthesis.md §7.10` and `phase-08-baseline.md §8.4`, before every
  `cp` into `<output_dir>`. It gates the **blackboard** copies and the `cp`
  follows, so no raw value is left behind in `.claude-audit/current/` to be
  archived into `history/<ts>/`.
- **`phase-07-synthesis.md §7.10a`** — what to do when the gate fires. It scrubs
  and writes rather than aborting (a user 45 minutes into an audit will find
  whatever flag silences an abort, and that flag becomes the hole), then obliges
  Phase 7 to emit a CRITICAL finding naming **this skill** as defective. A
  firing gate means Layer 1 did not hold; it is a bug report, not a finding
  about the audited code.
- **`phase-04-scanners.md §4.4c`** — secret-scanner hits under `<output_dir>/`,
  `.claude-audit/`, or legacy `docs/security-audit-*` paths are **not** noise.
  They escalate to CRITICAL / CWE-538 with `skill_self_leak: "true"` and a
  `suggested_fix` that says rotate first, purge history second — and states
  explicitly that untracking is not purging.
- **`workflow.md §3.5b`** — gitignore hygiene for `<output_dir>`, applying the
  `*.sarif` / `*.cyclonedx.json` recipe that `lib/output-routing.md` had only
  ever suggested. Defence in depth; the report and pruned baseline stay tracked
  by design so `mode: delta` keeps working on a fresh clone.
- **`lib/secret-redaction.md`** — the layering contract, including what the
  fingerprint is *not*: it is domain-separated and rule-salted so a generic
  rainbow table is useless, and it is not resistant to a targeted guess against
  a known-weak secret. That is acceptable, and why, is written down.
- **`tests/test-secret-redaction.sh`** (45 assertions, wired into CI) — both
  layers, idempotency in both directions, triage-field survival, placeholder
  negatives, and the control-with-no-enforcer check that the step files actually
  invoke the enforcers. Every credential-shaped string is synthesised at runtime;
  committing a token-shaped fixture would make this repo's own secret scan
  permanently noisy, which is the exact triage failure §4.4c exists to stop.
- **`finding-schema.json`** — optional `skill_self_leak` (`"true"` / `"false"`).

### Changed

- `lib/sarif-postprocess.md` — the "raw SARIF is **kept on disk**" note now says
  *raw means un-slimmed, not un-redacted*, and warns against reading the slim
  step as a security control. Its incidental discarding of `snippet` is what
  made the leak look impossible; the consolidated SARIF never passes through it.
- `steps/deepdive/cat-06-secret-sprawl.md` — a hard reporting rule: never write
  the value, not in `description`, `attack_scenario`, `suggested_fix`,
  `verification_probe`, a fenced block "for context", or hand-masked. Cite
  `file:line` and the fingerprint. Analyst prose is the one path into a
  deliverable that a structural strip cannot cover.
- `lib/report-template.md` — the same rule at the per-finding block.
- `lib/output-routing.md` — the `.gitignore` recipe is applied rather than
  suggested, with a warning against reading it as the credential control: it
  covers two globs and does nothing for `security-audit-report.md`.

### Caught in adversarial review, before release

Two fail-open paths in the first cut of this fix, both found by reviewing the
*inventory* the enforcers run over rather than the mechanism:

- **The redactor skipped the markdown review artifacts.** Its extension list was
  `.sarif` / `.json` / `.jsonl`, while `manifest.yaml` declares
  `phase-04-scanners/security-review-*.md` and `adversarial-*.md` as required
  Phase 4 outputs. Those are LLM prose *about* the secrets that were found, they
  are read by Phases 5 to 7, and every one of them walked past the redactor. The
  mechanism had 45 passing assertions; nothing checked that it ran over
  everything the phase actually writes.
- **A multi-line PEM survived the deliverable gate.** The gate scanned line by
  line and the `private_key` detector matched only the `-----BEGIN-----` header,
  so the header was redacted and every base64 body line was copied through. The
  gate now scans whole documents and the detector matches the whole block, with
  a separate `private_key_header` for a truncated paste.

Also fixed before release: `workflow.md §3.5b` resolved `output_dir` without
jq's error fallback, so a missing `config.json` wrote jq's error message into
`.gitignore` as an ignore pattern and Layer 3 silently never applied;
`GATE_RC == 3` obliged the §7.10a self-finding in prose only, and now writes
`phase-07-gate-fired.marker` that blocks phase completion until the finding
exists; the three new gate artifacts were mandated by step files but absent from
`manifest.yaml`; and `redact-scanner-output.py --output-dir` now computes
`self_leak_candidates[]` so §4.4c is an artifact rather than a judgement call
that has already been made wrongly twice.

`scripts/validate-install-pins.sh` now also checks the `# → X.Y.Z` verification
comments in the install docs, not only `--branch v` lines. It found
`docs/INSTALL.md` still showing 2.5.0.

A second review round found one more fail-open and added a guard:

- **Self-leak detection could not see the blackboard.** `_self_leak_candidates`
  normalised paths with `lstrip("./")`, and `str.lstrip` takes a *set of
  characters*, so it ate the leading dot of `.claude-audit/…` and turned it into
  `claude-audit/…`, matching no prefix. Every self-leak inside the blackboard and
  its rotated history was invisible to §4.4c, which is the one place the rule
  most needed to fire.
- **The redactor will no longer rewrite files outside the audit's own
  directories.** In redact mode it refuses anything not under `.claude-audit/`
  or the resolved `<output_dir>` unless `--allow-any-path` is passed; `--check`
  stays read-only and unguarded. This is not hypothetical: during the v2.6.0
  cleanup a remediation pass aimed at audit outputs also rewrote *source* copies
  of a project, replacing localhost dev connection strings that trufflehog had
  reported as `Raw` values. They were not credentials and it had to be restored
  from git. An in-place scrubber pointed at the wrong directory is a destructive
  tool, and "I passed the right path last time" is not a control.
- **§4.4c now requires stating the matched length before claiming a leak.** A
  short match is often a prefix a document quotes deliberately. On the incident
  that motivated this release, an 11-character prefix in a planning note was
  reported as the full token, turning a tidy-up into a rotation emergency. Write
  what the length supports.

### Note for existing users

If you ran v2.6.0 or earlier against a repo containing secrets in gitignored
paths, check `<output_dir>/findings.sarif` and your history for them.
**Rotate first** — the credential is live until rotated and everything else is
irrelevant until it is done — **then** purge with `git filter-repo` or BFG,
force-push, and have collaborators re-clone. `git rm --cached` plus a
`.gitignore` line is not a fix: it removes the file from `HEAD` and leaves the
blob reachable.

A v2.6.1 run will now flag such artifacts as CRITICAL rather than dismissing
them as noise.

## [2.6.0] — 2026-07-31

**Calibrated severity.** The first release measured against ground truth. Eight
security engineers triaged all 263 HIGH-or-above findings from a v2.5.0
full-mode run against the real code — 255 verdicts — and recorded 34 defects the
audit missed. An adversarial reviewer then attacked the remediation plan built
from the triage. See `docs/EPIC-v2.6-calibrated-severity.md`.

The headline result: **the audit's own confidence marker was anti-correlated
with truth.** Findings labelled `CONFIRMED` were **9.6%** true; findings carrying
no label at all were **92.1%** true. The cause was structural — the adversarial
confirmation pass existed only in Phase 6, so it could only ever label the two
*least* precise rule families, and the most precise family could never be
labelled at all. The marker recorded *which phase emitted a row*, not how much to
trust it. A reader following the report's own advice to "read the confidence
bands" was sent to the 9.6% pile first and the 92.1% pile last.

Two numbers frame the rest. The category deep-dive agents ran at **96.6%** true
(98.9% excluding unresolvable duplicate cycles), with four categories at 100% —
that part of the pipeline works and is untouched here. The two mechanical rule
families were **19.8%** and **1.4%** true, together 60% of all HIGH+ findings and
15% of the true ones.

> Denominators: 255 is *verdicts*, not the 263 HIGH+ findings — 8 were never
> triaged — so these are precision-over-triaged. 51 unresolvable duplicate cycles
> count as not-true, making every rate a lower bound.

### The invariant this release restores

v2.5's design bet — over-flag, then retire via the adversarial pass — is sound
only while a false positive is **locally** expensive. By v2.5 it was not:
`validate-collection-scoping.py` minted `reads:any_*_pii` capability tags from an
entity name and a profile column list with **no check that the collection was
actually unscoped**, producing **47%** of every capability tag in the composition
graph; the composer then escalated contributing findings straight to CRITICAL.
**53 of 73** HIGH+ C-rule findings ended CRITICAL while **72 of 73** were false —
and the escalation reached their *neighbours*, including true findings.

`docs/KNOWN-GAPS.md` #23 had predicted the precise defect and dismissed it:
*"the failure direction is a false positive — which a human closes — not a silent
pass."* That reasoning was correct when written and expired silently when the
composer landed. Nobody re-checked it.

> **A low-evidence finding must not be able to raise the severity of anything —
> itself or its neighbours.** And: a "the failure direction is safe" argument is
> scoped to the consumers that existed when it was written. Adding a downstream
> consumer of a finding obliges you to re-check every such argument against it.

### Added

- **Typed evidence** (`lib/finding-schema.json`). `confidence` conflated three
  orthogonal things; they are now separate fields:
  - `evidence_class` (**required**) ∈ `external_scanner` | `heuristic_inventory`
    | `agent_judgement` | `governance`. **Only `external_scanner` earns the §7.4
    +1 severity promotion.** Unset falls back to `agent_judgement`, never to a
    promotable class — the fail-safe direction is toward *not* promoting.
  - `attacked` ∈ `not_attempted` | `confirmed` | `partial` | `refuted`, replacing
    the run-level `verification_status` that appeared **nowhere** in the skill.
  - `fix_confidence` ∈ `verified` | `inferred` | `untested`.
  - `sibling_sites[]` + `sibling_pattern`, `refutation_scope`,
    `deployment_reachability`, `rule_family`, `annexed_to`,
    `escalation_suppressed_by`.
- **New source kind `heuristic`.** Both reconcilers previously declared
  `sources[].kind = "scanner"`, which is what tripped §7.3's *"scanners are
  mechanical ground truth"* rule and handed the 1.4%- and 19.8%-true families a
  CONFIRMED label plus a severity rung. The rule is now structurally unable to
  match them — fixed at the type level rather than in prose.
- **Evidence-aware escalation** (`lib/compose-attack-paths.py`, story 1.4). R3
  chain escalation stays **uncapped** — capping it would kill v2.5's founding
  case, where a MEDIUM had to be able to reach CRITICAL in one step — but is now
  suppressed when a **load-bearing** member of the contributing slice declares
  `deployment_reachability: structurally_unreachable` **with a cited line**.
  `gated_by_runtime_flag` does **not** suppress: a flag an admin can toggle in a
  deployed environment is live, not theoretical. Uncited claims do not suppress
  and are printed. Every suppression is reported in a `SUPPRESSED ESCALATIONS`
  block — suppression is now the dangerous direction, so it is made loud.
- **Mechanical findings become an annex** (Wave 2b). Of the 17 true mechanical
  findings, **15 were restatements of a deep-dive finding on the same line**, and
  the families surfaced **no unique CRITICAL** — but they *did* enumerate one
  credential-exfil class's **nine distinct legs at exact line granularity**,
  which no agent did. So rows now attach to the judgement finding they restate as
  a fix-surface annex, carry no severity of their own, and are excluded from the
  capability graph. **Orphan annexes** — no judgement twin — still surface as an
  explicitly low-confidence lead list, capped out of the headline band; on a
  codebase with no deep-dive coverage of an area, the mechanical rule is the only
  thing that sees it.
- **Sibling sweep** (story 3.1). Every HIGH+ finding must derive its defect's
  shape as a pattern, run it repo-wide, and report the full site list — or state
  that the cited site is the only one. `sibling_sites: []` is a **claim** and
  must carry the `sibling_pattern` that backs it. The majority of the 34 missed
  defects were the second, third and fourth site of a defect found once: 10
  `postgres()` call sites filed as "all four", **25 RLS bypass clauses across 10
  migrations filed as one policy**, 10 mutable action tags filed as 4, 7
  plain-HTTP downgrades filed as 1. Each is a one-line grep.
- **Refutation discipline** (story 3.2). `refutation_scope` is required, and a
  "What is sound" row backed by a single module may not make a system-level
  assertion. Where a finding alleges *credential X reaches sink Y*, a refutation
  from reading X's producer requires a **caller enumeration of the accessor**
  first. In the calibrated run exactly that shape — true of one module,
  generalised to a system property — buried a live HIGH in which two call sites
  handed a GitHub App signing key to a function that set `Authorization: Bearer`.
  **A wrong refutation is more dangerous than a false positive:** the false
  positive costs a triager minutes and self-corrects; the wrong refutation stops
  them reading the code and nothing downstream reopens it.
- **Fix-contradiction check** (story 3.3, §7.4b). Two findings on one defect
  whose `suggested_fix` texts disagree are flagged rather than both shipped.
  Never resolved by majority, severity or recency — in the measured case the
  correct fix was **1 of 6** and the only one citing driver source, so every one
  of those heuristics picks the wrong text. This withholds the **fix**, never the
  **finding**: findings still ship at full computed severity with the fix line
  replaced by a `WITHHELD` notice.
- **`--require-evidence-discipline`** (`lib/validate-findings.py`) — the Wave-3
  obligations enforced mechanically rather than as methodology prose, plus
  `tests/test-evidence-discipline.sh` and a CI step. The calibrated run found the
  audit's headline defect class, across five of five themes, was
  *control-versus-prose gaps*; an obligation living only in a step file is that
  same defect, committed by the tool built to detect it.
- **`scripts/calibration-report.py`** — joins a run's findings to a triage
  verdict file and emits measured true-positive rates by `rule_family`,
  `evidence_class` and `attacked`. Handles duplicate resolution, unresolvable
  cycles, and untriaged rows (excluded from the denominator, reported as
  coverage, so a run cannot improve its number by triaging less). Makes the next
  calibration a command rather than eight engineers.
- **Standing calibration control** (`manifest.yaml`). Per-family measured
  precision, seeded from this triage. A family measured below 0.50 on n≥30 is
  **barred from the headline band**; unmeasured families are admitted but marked
  PROVISIONAL and can never report `pass`; a family with no entry at all is
  barred hardest. Gating uses the with-cycles lower bound — gating on the
  flattering number is the failure this release exists to fix.
- **Availability/integrity lens** (`steps/deepdive/lens-availability-integrity.md`)
  — attack paths with no confidentiality component. The calibrated run missed a
  HIGH where uncapped provisioning displaces every real row from a downstream
  fixed-size scan, causing an estate-wide silent attribution stop.
- **Local-filesystem exfil** as an egress modality. A repo-steerable state
  directory made a hook write a live access token into an attacker's working
  tree; with no network call, no egress rule could see it.
- **New rule C6** — the cited predicate is not at the cited line — split out from
  C5, which keeps the access-control claim. Different claims with different
  follow-ups: 9 of 14 sampled C-rule false positives fired on the miscitation
  branch against handlers whose predicate was genuinely present two frames up the
  call stack.

### Fixed

- **`_strip_literals()` was not template-aware** (`lib/validate-collection-scoping.py`).
  A backtick sat in the same delimiter set as `'` and `"`, so the entire body of a
  tagged template — including its `${…}` interpolations — was blanked, and
  `predicate_binds_caller()` derived both its token list and its `components`
  from the blanked text. Fatal on any drizzle/Kysely codebase, where the caller
  predicate lives inside a tagged template by construction. **72 of 73** HIGH+
  C-rule findings were false because of it. Compounding it, `_CALLER_TOKENS` had
  no entry for the Postgres RLS-GUC idiom — and a GUC name is a single-quoted
  literal, precisely what the stripper correctly discards for
  `eq(decks.scope, 'session')`. Neither fix alone is sufficient; both landed,
  pinned by a seven-case truth table where three cases must flip to `True` **and
  three must stay `False`**.
- **Cross-layer egress joins.** `floor` was computed per `serves_resource` — a
  free-text string an inventory agent wrote — so everything sharing the string
  was compared regardless of layer, process or trust boundary. A Vue click
  handler was compared against a cron worker's HMAC gate. Joins are now typed by
  layer.
- **Kind-derived gate floors no real gate text could reach.** `_KIND_RANK` mapped
  `capability`/`verification` to `GATE_VERIFIED`, a rank only the keywords
  `2fa|mfa|otp|verif|step-up|…` reach — so request-scoped RLS GUCs gave every
  resource they touch floor 3 in an app with no step-up auth, and the
  **correctly gated** branch was filed HIGH. Now capped unless a rank-3 gate is
  actually observed, with an explicit `gate_rank_hint` overriding the keyword
  ranker. The old behaviour meant *the more precisely an analyst described a real
  control, the more likely it was to rank 0 and be filed CRITICAL*.
- **Three silent-corruption bugs, all shipped in v2.5.0:** an `IndexError` on a
  sink whose `reachable_via` was present-but-empty (`.get(k, default)[0]` only
  defaults on a *missing* key) that **crashed §6.19 entirely**; neither
  reconciler reading an ignore file, so a run scanned an unrelated cloned repo;
  and `_norm` using `str(p).lstrip("./")` — a **character set**, not a prefix, so
  `.output/` became `output/`. The last two together produced **64 phantom
  coverage failures that masked 7 real credential gaps and 129 real collection
  gaps**. These were fail-closed gates failing in the *noisy* direction, which is
  the specific way a fail-closed gate stops being trusted.
- **The L1 age gate was keyed on the same broken label** — `confidence ==
  "CONFIRMED"` — so the gate that exists to stop a real finding rotting for 96
  days fired on the 9.6%-true population and skipped the 92.1%-true one. Re-keyed
  on `evidence_class`. *(Found while implementing; not in the calibration
  analysis.)*
- **`chain_severity` was computed before suppression**, so a suppressed chain
  still advertised CRITICAL in the per-persona summary while nothing underneath
  it was escalated.
- **Refutations were forced to declare capabilities.** `--require-capabilities`
  demands non-empty `postconditions` for access-control categories, which for a
  refutation meant tagging it with the capability the *disproven* defect would
  have granted — feeding a refuted capability into the composition graph to
  satisfy other findings' preconditions. Refuted rows are now exempt.
- **Duplicate ids survived Phase 7.** 1361 rows carried 1256 distinct ids; seven
  `config` ids appeared six times each with three distinct payloads. Dedup keyed
  on `(file, line, category, fingerprint)` while only 420 of 1361 rows carried a
  fingerprint at all. Nine surplus rows sat inside the HIGH+ population, so every
  headline count in the report was overstated. Id-first dedup plus a uniqueness
  assertion before SARIF.
- **SARIF carried no finding `id`** — only `ruleId` as `<category>/<CWE>`, which
  is neither unique nor joinable. This is why 255 triage verdicts could not be
  mechanically rejoined and the calibration had to be rebuilt from the JSONL.
  `properties.id` is now required, alongside `rule_family`, `evidence_class`,
  `attacked` and `sibling_sites`.
- **`lib/asvs-l2.md` was headed "OWASP ASVS 5.0 Level 2" while enumerating
  4.0.3's category set.** Retitled rather than rewritten, because every ASVS id
  the skill emits is a 4.0.3 id and 5.0.0 renumbered every chapter — rewriting
  the file alone would have produced a mixed-edition tag set, worse than either
  edition applied consistently. Five other files asserting 5.0 were corrected to
  match. A fabricated `V2.11` entry was removed.
- **LINDDUN could not be expressed.** The `category` enum had no member and the
  `owasp_ids` pattern excluded `LINDDUN-*`, while §6.12 instructs the artifact to
  carry them — so LINDDUN findings were smuggled through `config`.

### Changed

- **The report's reading path is now class-major, severity-minor.** v2.5 told
  readers *"the 182 CONFIRMED + deep-dive findings are the trustworthy spine"* —
  half that spine was 9.6% true and the other half 92.1%, and merging them hid a
  factor of ten. No band may mix `evidence_class` values. Severity-major *with*
  class sub-bands is explicitly not sufficient: it satisfies the letter while
  still pointing the reading path at the worst pile first.
- **§6.19/§6.20 emit `attacked`, not a confidence.** Both must now scope their
  refutations; §6.20 additionally requires the `file:line` of the predicate it
  claims to have found — a refutation with no line is not a refutation.
- **A subsystem-wide remediation must enumerate its members.** The calibrated run
  advised adding a clamp across a path glob where **11 of 16 handlers had nothing
  to clamp** — the pivotal table has no such column, so the change would either
  no-op or deny every legitimate caller. "Add X across `path/**`" is a claim
  about every member and now needs the same evidence bar as a finding.
- **Design records outrank inference.** Where a decision record ratifies an
  asymmetry, an inference that the asymmetry *is* the finding requires an
  explicit rebuttal of the record. In the calibrated run this theme's
  remediation would have added a call that cannot fire, against the design record.

## [2.5.0] — 2026-07-25

**Sufficiency & severity arithmetic.** A live v2.4.0 run (all six scanners, no
degraded mode) returned a clean bill for an endpoint disclosing every user's
private data to any authenticated caller. Two methodology gaps let that happen,
and a third defect meant v2.4's flagship control could not run at all from a real
install. See `docs/EPIC-v2.5-sufficiency-severity.md`.

### Added

- **Collection-scoping reconciliation** (`lib/validate-collection-scoping.py`) —
  the answer to *gate presence ≠ gate sufficiency*. Rules C1–C5 over a new
  Phase-2 inventory (`phase-02-collections.json`, `lib/collection-schema.json`)
  with a fail-closed coverage gate:
  - **C1** unscoped collection of a sensitive entity (CWE-1220). A `WHERE` clause
    being present proves nothing — `scope = 'user'` constrains *which* rows, not
    *whose*. `role_restricted` counts as unscoped unless the role is admin-tier.
  - **C2** authorization by decoration — a per-row permission computed and
    attached instead of applied (CWE-863). Write-permission decoration on a
    collection never read-filtered is a finding by construction.
  - **C3** `coverage: incomplete|caveat` surfaced as an open question, not a pass.
  - **C4** a sibling **test** asserting another principal's row is *present*
    rather than absent/404 — high-signal because it was written deliberately.
  - **C5** a `caller_bound` claim is checked against the source at the cited
    `file:line` — a predicate that is not there, or one that names no
    session/user/tenant/org value, is rewritten to `unscoped`. Together with
    **C2b** (a denied decoration the handler plainly performs) this closes the
    two inventory claims most likely to be wrong. It is **not** a general proof
    that an agent-written inventory is honest; see `docs/KNOWN-GAPS.md` #12.
- **Deep-dive category 12, `collection_scope`** (`steps/deepdive/cat-12-collection-scoping.md`)
  — BOLA at the **list** level (API1:2023 + API3:2023, A01:2025). Deliberately a
  separate category, not a cat-02 subsection: see Fixed below for why cat-02
  could never have caught it.
- **Attack-path severity gate** (`lib/compose-attack-paths.py`, Phase 7 §7.15) —
  severity becomes a **computed** function. `severity_asserted` is retained only
  as the analyst's opinion.
  - **R1** a finding's precondition supplied by another finding's postcondition
    is an *undischarged* mitigation; severity floor = the supplier's. Fixpoint,
    so multi-hop chains propagate.
  - **R2** prose matching `combined with|chained|together with|…` that names
    another finding binds severity ≥ that finding's. Fires with **zero**
    capability tags — five lines of regex that alone would have caught the
    historical case.
  - **R3** any path from an *unprivileged* persona to a crown jewel is CRITICAL,
    applied via a **backward slice** so bystanders are not escalated.
  - **R4** severity may not decrease across runs without a `severity_history`
    entry naming what changed; a HIGH+ that disappears unexplained is itself a
    finding.
  - **L1–L3** lifecycle: a CONFIRMED HIGH+ open past `--max-age-days` (default
    30) with no fix and no owned, unexpired acceptance **fails the run**;
    acceptance requires owner + live expiry; `verified` requires a regression
    test id.
  - **ORPHAN CAPABILITIES** report — preconditions nothing supplies and
    postconditions nothing consumes. The drift alarm that tells you the gate is
    quietly inert rather than genuinely clean.
- **Capability lexicon** (`lib/capability-lexicon.md`, Phase 0 §0.14) — one
  vocabulary (`<verb>:<scope>_<object>`), project-derived personas and crown
  jewels, and the containment rule (`any` subsumes narrower scopes).
- **Partition coverage gate** (`lib/validate-partition-coverage.py`, Phase 1
  §1.6b) — every non-ignored source file must map to a partition. Unmatched files
  **fail Phase 1** instead of vanishing into a catch-all. Also reports catch-all
  partitions and the **deep-dive cut line**, so a budget decision is visible
  rather than silent.
- **Evidence-based partition promotion** (Phase 2 §2.13) — a partition holding an
  unscoped collection or a high-risk surface flag is promoted into the deep-dive
  budget regardless of its a-priori rank, uncapped by `top_n`.
- **Surface flags** `RETURNS_OTHER_PRINCIPALS_ROWS` and `PERMISSION_DECORATION`
  (§2.7). The first dominates the trust-zone weight in §7.4 and vetoes any
  dev-zone demotion: data breadth outranks a declared zone label.
- **Finding-schema fields**: `preconditions`, `postconditions`,
  `severity_asserted`, `severity_computed`, `escalation_rules`,
  `severity_history[]`, `first_seen_at`, `lifecycle{state,owner,expiry,rationale,fix_commit,verified_by_test}`,
  `display_id`, `aliases`. Baseline schema carries the same forward.
- **`validate-findings.py --require-capabilities`** — enforces
  `preconditions` + non-empty `postconditions` on `auth`, `idor`, `token_scope`,
  `collection_scope`. Without tags the severity arithmetic silently has nothing
  to compose.
- **Tests**: `tests/test-collection-scoping.sh`, `tests/test-attack-paths.sh` and
  fixtures under `tests/fixtures/{collection-scoping,attack-paths,partition-coverage}/`
  — including a faithful reproduction of the handler that passed the v2.4 audit.
  Each gate has a negative control; a gate that fires on everything gets
  disabled, and a disabled gate catches nothing. Both wired into CI.

### Fixed

- **`$SKILL_DIR/scripts/validate-egress.py` never existed in an install.**
  Installation copies only `skills/security-audit/`; the repo-root `scripts/`
  directory is not part of it. v2.4's flagship deterministic control was
  unreachable at audit time — a control with no enforcer, which is the exact bug
  class it was written to detect. All audit-time validators now live in
  `skills/security-audit/lib/`; `scripts/` keeps thin shims so existing
  invocations, CI, and docs keep working. **New CI step** asserts every
  `$SKILL_DIR/<path>` referenced in the skill resolves inside the shipped
  directory.
- **`validate-findings.py` existed as two byte-divergent copies**, only one of
  which shipped. Consolidated to one implementation behind a shim.
- **cat-02's candidate filter made its own list-endpoint invariant
  unreachable.** It requires a path/query param matching
  `^(id|[a-z]+Id|[a-z]+_id)$`; a collection route has no id param, so invariant
  #2 ("list endpoints filter the result set by the authenticated scope") and the
  "Search / list endpoints" detection pattern could never fire in practice. The
  scope boundary is now stated explicitly and cross-referenced to cat-12.
- **`validate-patterns.py` misread JSON/JSONC key-value lines as regexes**
  (a `["a", "b"]` value looks like a character class). Added JSON-key and
  comment-line recognition to the code heuristic.
- **Egress sink inventory admitted only byte-emitting sinks**, so a JSON list of
  other principals' identifiers never entered `phase-02-sinks.json` and §6.19
  never evaluated it. `kind` now includes `json_collection`, `json_metadata`,
  and `identifier_list`.

### Changed

- **Phase 8 refuses to write a baseline** while the §7.15 gate reports unresolved
  governance failures. This is what makes the ratchet a ratchet: without it, a
  run carrying an unexplained downgrade would persist that downgrade as the new
  baseline and the next run would have nothing to compare against. **You cannot
  launder a downgrade by re-running the audit.**
- **Phase 8 carries `first_seen_at`, `severity_history[]` and `lifecycle`
  forward, never resetting them.** Resetting `first_seen_at` silently zeroes a
  finding's age and disables the L1 gate.
- Phase 5 fan-out is now **12 categories** (10 always-on). Phase 7 report gains
  a Collection Scoping section, a Severity Gate section, and an
  `AUDIT GATE: FAILED` banner that must open the Executive Summary when
  governance failures stand.
- Dependency pins refreshed (Dependabot): `actions/checkout` 6.0.3→7.0.1,
  `actions/setup-python` 6.2.0→7.0.0, `github/codeql-action/{init,analyze}`
  4.36.2→4.37.3, `debian:bookworm-slim` digest `67b30a6`→`96e378d`.

### Adversarial review (two rounds, external executor)

Both rounds ran through GitHub Copilot CLI rather than self-review, because
author-blindness is the structural failure mode for a diff this size. **Round 2
found that three of round 1's fixes had introduced new defects** — the strongest
argument for the two-round rule being mandatory rather than advisory:

- The R1 fix for C5 (read the source instead of trusting the claimed predicate)
  scored a ±3-line window, which absorbed the `const session = await
  requireRole(...)` line sitting two lines above the query — **reintroducing the
  exact motivating bug**, verified passing clean at exit 0. Now scored on the
  cited statement, extended FORWARD only: the gate is always above the query.
- The R1 catch-all fix shipped a four-string spelling allowlist. `*/**` matches
  every file below any top-level directory and evaded it entirely. Now
  behavioural (probe globs + a ≥95%-of-tree check).
- The R1 token-exact caller matching (fixing the `"me."`-in-`scheme.name`
  substring fail-open) scored `authUserId`, `currentUserId`, `viewerId` and
  `callerId` as NOT caller-bound, flagging correctly-scoped handlers. Now
  camelCase-aware.
- The Mongoose anchor added in R1 matched `Roles.find(r => r.id === x)` on any
  capitalised constant array — a false-positive storm that trains operators to
  dismiss the gate. Now requires a `(` `)` or `{` tail.
- The baseline drift fallback could bind two unrelated same-CWE findings within
  25 lines; added a title-similarity floor and one-entry-one-consumer.
- `--changed-files` ranges reused the ±25 fingerprint tolerance, making the
  "precise" option barely tighter than a bare path. Now ±2, with a visible note
  when the match relied on padding.

**Round 3** was a targeted verification pass on round 2's fixes, and found two
more HIGH regressions plus three MEDIUMs — while confirming two round-2 fixes
CLEAN. The pattern is why the two-round rule is a floor, not a ceiling:

- The forward-only statement window stopped at the cited line whenever its own
  brackets balanced, so `const rows = await db.select().from(decks)` never read
  the `.where(...)` on the next line and flagged a **correctly scoped** handler.
  Now continues across a method chain, still forward-only.
- Baseline drift assignment was first-come-first-served by findings order: a
  weaker nearby decoy could consume the entry the true continuation needed,
  leaving it with no baseline match and therefore silently exempt from R4. Now
  two-pass, best-first.
- The ≥95%-of-tree catch-all backstop fired on any backend-heavy monorepo
  (`backend: src/**` owning 96/100 files), a permanent red that trains operators
  to pass `--allow-catch-all` reflexively. Now requires dominance **and** an
  unanchored glob.
- camelCase splitting made bare generic words match `callerName`,
  `sessionType`, `callerPhoneNumber`. Generic words now need an adjacent
  identity token.
- The C2b handler boundary missed `export function`, `exports.handler =` and
  arrow-const handlers — the most common Express/Lambda shapes.
- The `.incomplete` sidecar was never cleared, so one failing run marked the
  artifact incomplete forever.

**Round 4** found that round 3 had done it again — 1 HIGH + 2 MEDIUM, all
outside the suite's coverage at the time:

- The new arrow-const handler boundary used `^\s*`, so an *indented* local
  helper (`const formatDate = (d) => ...`) counted as the start of the next
  handler and truncated C2b's search before the real `.filter(`, flagging a
  correctly-filtered collection. Now column-0 only.
- Requiring an adjacent identity token for generic caller words fixed
  `callerName` but broke `row.author === principal`, `row.subject === jwt` and
  four more — a narrow false positive traded for a much wider false negative.
  Now resolved at identifier granularity: a bare generic word standing alone IS
  the caller; as a camelCase fragment it depends on what it modifies.
- `_statement_at`'s comma continuation absorbed a second declarator
  (`, unused = session.user.id`), leaking a caller token from unrelated code —
  the same leak the forward-only rule exists to prevent, arriving from below.

**Round 5** found one more HIGH and one MEDIUM, both side effects of round 4's
mechanism rather than its reasoning:

- The identifier-component split discards quote characters along with all other
  punctuation, so `eq(decks.scope, 'session')` produced a standalone component
  `session` indistinguishable from a real identifier and scored as caller-bound.
  That is the founding `scope = 'user'` bug wearing a different literal, and it
  would have laundered an unscoped PII-bearing collection past C1. String
  literals are now blanked before analysis.
- The Python `def` alternative kept the `^\s*` that round 4 removed from every
  JS alternative for exactly this reason, so an indented local helper truncated
  C2b's window. Now column 0, with an indented `def` counting only when it takes
  `self`/`cls` — the signal that distinguishes a class-based-view handler from a
  local helper.

**Rounds 6 and 7** each returned HIGH=0 with two MEDIUMs — at the bar both
times, and fixed rather than shipped at the ceiling. Round 6: the literal regex
had no escape handling and paired a prose apostrophe with an unrelated quote;
the indented-`def` boundary required `self`, missing `@staticmethod` handlers.
Round 7: comment stripping blanked to end of *string* rather than end of *line*,
erasing the `.where()` two lines below in a fluent chain; and a bare `@\w+`
decorator boundary matched `@property` / `@Input()` inside the current handler.
Every one of these is the **false-positive** direction — a correctly-scoped
collection reported as unscoped, which a human closes — never a silent pass.

**Round 8** re-verified round 7's fixes: **CONVERGED at HIGH=0, MEDIUM=0.**

The trajectory across eight rounds (6H/4M → 4H/5M → 2H/3M → 1H/2M → 1H/1M →
0H/2M → 0H/2M → 0H/0M) is itself the argument for the two-round minimum being a
floor: **six** of the eight rounds found a defect introduced by the previous
round's fix, and every HIGH after round 1 was a regression rather than an
original miss.

One round-1 finding was **refuted with evidence** rather than fixed: the claimed
`_ID_TOKEN` ReDoS is linear (0.0 / 0.1 / 1.2 ms at 400 / 4k / 40k chars) because
the separator class is disjoint from the alphanumeric class, so there is no
ambiguity to backtrack on.

Every fix from every round is pinned by a regression test. Suite totals: 21
(egress) + 35 (collection scoping + partition coverage) + 25 (severity gate) =
**81 deterministic assertions**, all wired into CI.

### Honest scope

A clean C1–C5 run means every *known* list-query candidate was accounted for and
scoped — **not** that no unscoped path exists. A scope applied by an un-modelled
mechanism (base scope, tenant-injecting repository, database RLS) is missed in
the conservative direction and retired by the §6.20 adversarial pass. The
composer can only compose what was tagged; R2 backstops untagged chains named in
prose and the orphan list backstops R2. Both reconciliations operate on an
agent-populated inventory: C5 and the coverage gates make a dishonest or absent
inventory **loud**, not impossible.

## [2.4.0] — 2026-06-19

**Authorized-Egress detection** — catch the control-with-no-enforcer /
confused-deputy / capability-URL class that survived multiple prior audits + two
adversarial reviews (RCA: a 2FA `__sv_` cookie minted at a resolver but never
consumed on the byte-serving content endpoints). Design was itself adversarially
reviewed before build; see `docs/EPIC-v2.4-authorized-egress.md`.

### Added
- **Deterministic reconciliation** (`scripts/validate-egress.py`) — the robust
  core. Rules R2–R5 over a path-sensitive inventory: R2 gate-asymmetry across
  sinks, R3 capability-only/ungated byte path, R4 credential minted with
  **zero readers** (theatre), **R5 cross-layer gate-location** (the rule that
  catches the deck bug — gate lives on a resolve surface, not the byte sink). Gate
  ranking is **negation-aware** (an absent control described in prose ranks as no
  gate — conservative, over-flags rather than misses). Default-deny sensitivity.
  Emits finding-schema JSONL with a `verification_probe` (the curl that should
  fail — RCA §11).
- **Fail-closed coverage gate** — a deterministic per-framework extractor
  (`lib/egress-detection.md`) enumerates candidate egress sinks; the run FAILS if
  the agent inventory neither classifies nor explicitly dismisses any candidate.
  A silently-omitted sink breaks the run instead of passing quietly.
- **Two Phase-2 inventories** — `phase-02-sinks.json` (egress sinks, path-
  sensitive `guarded_paths[]`) + `phase-02-credentials.json` (mint/consume
  ledger), with `lib/sink-schema.json` + `lib/credential-ledger-schema.json`.
- **Phase 6 §6.19** — runs the reconciliation, then an *adversarial confirmation*
  fan-out ("construct the unauthenticated request that returns the bytes, or
  prove it impossible") that writes the executable probe.
- **Tests** — `tests/test-egress.sh` (CI): deck-bug caught, coverage gate fails-
  closed, extractor recall across modalities (file/proxy/graphql/sse/presigned/
  db), and a **metamorphic battery** (gate-moved, conditional-bypass, resource-
  rename, sink-kind-swap) each still caught. Synthetic source app +
  inventory mutants under `tests/fixtures/egress/`.

### Changed
- Phase 0 detects share/capability `access_mechanisms` + a default-deny
  `public_resources` allowlist; entities carry a canonical `id` join key.
- Surface rows gain `serves_resource` / `intended_gate` / `emits_bytes` /
  `guarded_paths` (path-sensitive, per-branch authz).
- `cat-01/02/03` add cross-layer-enforcement + "consistency-with-a-sibling is
  not proof" + capability-URL invariants; `finding-schema.json` adds optional
  `verification_probe`; report + synthesis surface the Authorized-Egress section.
- **Delta mode**: the egress inventories + §6.19 always regenerate **globally**
  and are never carried from baseline (a cross-layer gap is not a delta);
  resource-id rename invalidates egress findings.

### Hardened in pre-merge adversarial review (2× gate)
A second adversarial pass over the **built code** found and fixed three P0 bugs a
design review can't see: a **negation-blind ranker** (prose-described gaps scored
0 findings → now negation-aware), a **file-granular coverage gate** that was
fail-open (→ now line-scoped), and **substring-based credential consumption** that
false-positived on middleware-enforced gates (→ R1 removed, R4 is now zero-reader
theatre). Tests upgraded from substring-presence to exact-finding-set + zero-FP
assertions, with regression fixtures `prose-gap/`, `line-mask/`, `theatre/`. See
`docs/EPIC-v2.4-authorized-egress.md §4b`.

### Honest scope
Not a soundness proof. Reliably catches the named class and raises recall across
the egress family; a clean reconciliation means every *known* egress candidate
was accounted for and gated — **not** that no unauthorized path exists. Detection
depends on the agent recording each branch's gate; ambiguous/negated gates are
treated conservatively as ungated (over-flag, not miss). CDN-edge egress with no
code path, and modalities outside `lib/egress-detection.md`, are surfaced as
report caveats, never silently. `CWE-441` added to the CWE map.

## [2.3.0] — 2026-06-14

SAST-engine licensing decision resolved + an offline-rules escape hatch.

### Decided
- **Keep Semgrep; decline Opengrep.** With the project committed to staying
  **free OSS forever**, the Semgrep Rules License (commercial/SaaS/competing-use
  only) does not bind this **invoke-only, non-redistributing** tool — it fetches
  `p/...` community packs at runtime and never bundles them. Opengrep's only
  free ruleset (`opengrep-rules`) is archived/frozen at Dec-2024, so switching
  would downgrade rule freshness for a licensing benefit we don't need. The
  "latent redistribution exposure" framing from earlier research was inaccurate.
  Resolution recorded in `docs/EPIC-v2.1-refresh.md §4`, `docs/ROADMAP.md`
  ("Resolved decision"), `docs/KNOWN-GAPS.md`.

### Added
- **`AUDIT_SAST_RULES` offline / air-gapped override.** Point it at a local
  rules directory (a checkout of `semgrep-rules`, `opengrep-rules`, or your own)
  and the SAST pass scans `--config "$AUDIT_SAST_RULES"` instead of fetching
  registry packs — fully offline, no telemetry. Honored on the host path
  (`lib/scanner-bundle.md`, `steps/phase-04-scanners.md`) and by
  `scripts/run-audit-in-container.sh`, which bind-mounts the dir read-only.

## [2.2.0] — 2026-06-14

Quality hardening from a read of **CyberGym-E2E** (arXiv 2606.04460v1,
`docs/research/08-cybergym-e2e.md`; plan `docs/EPIC-v2.2-cybergym.md`), plus the
systemic validator deferred from the v2.1 Gate-C adversarial rounds.

### Added
- **Sub-agent repo-navigation discipline** (`templates/subagent-prompt.md`):
  grep/ripgrep-first, read the handler ±~40 lines (not whole files),
  move-on-after-2–3-failed-hypotheses → `confidence: POSSIBLE`. Backed by
  CyberGym-E2E's context-flooding failure mode (full-file loaders abandon
  early; targeted strategy wins).
- **Explicit source→sink taint-trace** guidance in `cat-02` + `cat-08`, with
  confidence calibrated to trace completeness (CyberGym-E2E's #1 failure =
  incomplete data-flow tracing).
- **Semantic-correctness scorecard check** (`tests/e2e/assertions.py`): optional
  `mechanism_keywords` fixture field + a `semantic_match` rate (scorecard
  v3.1) + opt-in `--semantic-floor` (default report-only). Addresses
  CyberGym-E2E's S3↔S4 "found A bug ≠ found THE bug" gap and partially
  automates KNOWN-GAPS #1. Additive — existing scorecard/exit codes unchanged.
- **Patched-commit-as-decoy method** doc (`tests/e2e/README.md`): recipe to
  mint TP(pre-patch)/TN(post-patch) precision-fixture pairs from CVE fix
  commits (the decoy mechanism itself shipped in v2.1).
- **CWE↔OWASP pair validator** (`lib/cwe-owasp-map.json` +
  `validate-schemas.sh` [8/8]): asserts each cat-file `CWE-N / A##:2025` pair
  matches the canonical map or a documented `context_override`; genuine
  mismaps fail CI. Closes the v2.1 Gate-C systemic gap (both rounds caught a
  hand-authored mismap that passed green).
- Live/GHA E2E **cost anchor** (KNOWN-GAPS): ≈ $10 / 90 min per target,
  diminishing returns after ~60 min.

### Changed
- `cat-01` handler-read wording aligned to "± ~40 lines, not the whole file"
  for consistency with the new navigation discipline.

### Note
CyberGym-E2E is an exploit/patch-lifecycle benchmark, **not** a static-auditor
scorer — v2.2 takes its method + failure-analysis, not the benchmark. This
corrects `docs/research/07`'s over-dismissal of the CyberGym line.

## [2.1.0] — 2026-06-14

Capability refresh from the 2026-06-14 research round (7 parallel reports in
`docs/research/`, synthesized backlog in `docs/ROADMAP.md`, plan in
`docs/EPIC-v2.1-refresh.md`). **Verify every cited 2026 CVE against NVD before
relying on it** — the detection encodes bug *classes*; specific IDs are
curated starting points (`docs/research/README.md`).

### Added
- **Two new deep-dive categories** (Phase 5 now fans out 11, concurrency cap 8):
  - `cat-10` Supply Chain & CI/CD Integrity — lifecycle hooks, dependency
    confusion, lockfile integrity, GitHub Actions script-injection /
    `pull_request_target` / unpinned actions / self-hosted-runner abuse,
    provenance posture. Always-on.
  - `cat-11` MCP / Agentic — MCP tool-scope, indirect prompt-injection via
    tool output, handler injection, confused-deputy / token pass-through,
    excessive agency. Gated on a NEW Phase-0 `mcp_agentic` detector (separate
    from the LLM gate). Tags `ASI01:2026`…`ASI10:2026`.
- **Detection depth** on existing categories: framework fail-open auth /
  matcher-evasion + SAML signature-wrapping + JWT header-trust (cat-01);
  exact `redirect_uri` + scope-at-use (cat-03); deserialization false-safety
  (PyYAML `FullLoader`, `torch.load` `weights_only`) + prototype pollution +
  SSRF metadata-denylist completeness (cat-08); model-file deserialization
  (cat-09); Lambda `AuthType=NONE` + Kyverno CEL SSRF + native-sidecar
  `securityContext` (k8s 1.33) + OIDC trust + IMDSv1 (cat-07); MCP-config
  secret sweep (cat-06).
- **Methodology spine**: OWASP Top 10:2025 (web) mapping, MITRE CWE Top 25
  (2025) prioritization enrichment (±1-rung cap preserved), OWASP Agentic
  Apps 2026 lens, NIST SP 800-218A (GenAI SSDF). New `lib/owasp-web-top10.md`
  + `lib/owasp-agentic-2026.md`.
- **grype promoted** to first-class EPSS + CISA-KEV prioritization
  (`properties.epss` / `properties.kev`, "Exploit-likely" callout; additive,
  never lowers severity).
- **Measurement harness**: fixture schema v3 with `negative_expectations[]`
  decoys + a precision/recall/F1 **scorecard** (`scorecard.json`/`.md`) with
  opt-in `--min-precision` / `--min-recall` floors — closes the
  coverage-only measurement gap (KNOWN-GAPS #1). New E2E targets **DVWA**
  (PHP) and **OWASP crAPI** (Java/Go/Python) via `--target`.
- `lib/known-vuln-versions.md`: curated SCA version-threshold reference.
- 13 CWEs added to the map (incl. CWE-1426 GenAI-output, CWE-1427
  prompt-injection, CWE-1321 prototype-pollution, supply-chain set). The
  `owasp_ids` schema now accepts `A##:YYYY` and `ASI##:YYYY`.

### Changed
- **Output routing unified + configurable.** All deliverables now land in a
  single output dir (default `docs/security-audit-output/`): the report,
  `findings.sarif`, `findings.cyclonedx.json`, and the pruned baseline. The
  skill asks where on first run (honors an `output:` arg + a persisted
  choice; the non-interactive default never blocks). See
  `lib/output-routing.md`.
- **Scanner pins**: trivy 0.70.0 → **0.71.0** (security — GHSA-q3fv-x8vg-qqm4,
  Helm-chart tar-bomb OOM in the `trivy config` path), osv-scanner
  2.3.5 → 2.3.8, trufflehog 3.95.2 → 3.95.5 (`--only-verified` →
  `--results=verified`). Stale refs fixed: psalm SARIF via `--report=*.sarif`,
  zizmor repo `zizmorcore/zizmor`.

### Removed
- **BMAD coupling.** The `_bmad-output/` auto-detect output routing is
  removed entirely (replaced by the configurable output dir). The vendored
  adversarial-review attribution (MIT, from bmad-method) is retained in
  `NOTICE.md` / `README.md` as required.

## [2.0.6] — 2026-04-25

### Fixed — DinD probe misclassifies SELinux confinement on Fedora/RHEL/CentOS

`tests/e2e/test-path-b-build.sh` line 78's bind-mount probe used
`-v $PROBE_DIR:/probe:ro` without the SELinux `,z` shared-label flag.
On SELinux-enforcing hosts (Fedora, RHEL, CentOS Stream — every
distro the wrapper is designed to work on with rootless podman) the
probe failed not because bind mounts were blocked but because the
default SELinux `container_t` ↔ `unlabeled_t` denial fired. The test
exited `PASS-WITH-LIMITATIONS` and the user concluded their setup
was unsupported — when in fact the actual wrapper would have worked
fine (the wrapper itself uses `:ro,Z` / `:rw,Z` correctly, lines 179-180
of `run-audit-in-container.sh`).

Fix: add `,z` (lowercase — shared label, appropriate for ephemeral
tmpdirs) to the probe. The flag is silently ignored on non-SELinux
systems, so the probe works correctly on Linux distros without
SELinux too. Caught by a downstream user running v2.0.5's smoke
test on Fedora.

This was a one-line bug with high visibility — every Fedora / RHEL
contributor running the smoke test would hit it and get a misleading
result, blocking the very Path B validation the test was meant to
provide.

## [2.0.5] — 2026-04-25

### Fixed — Phase 4 / Path B integration gap (the skill never used the wrapper)

v2.0.2's "in-skill mandate" + v2.0.3's Path B Containerfile fix both
shipped without ever validating that the skill's Phase 4 actually
USES the wrapper. Phase 4 just probed `command -v <scanner>` against
host `PATH`. A user who built the Path B container but didn't install
host scanners would invoke `/security-audit` and Phase 4 would find
zero scanners, log degraded-mode warnings, and never call the wrapper
— making Path B effectively a half-implemented feature.

This release closes the gap.

#### Phase 4 precedence chain

`steps/phase-04-scanners.md` rewritten with a 3-step precedence per
scanner:

1. **Path A (host PATH binary)** — preferred when present and
   `$AUDIT_FORCE_PATH_B != 1`.
2. **Path B (container wrapper)** — used when (1) is unavailable OR
   forced via `$AUDIT_FORCE_PATH_B=1`. Wrapper resolved via
   `$AUDIT_SKILL_REPO/scripts/run-audit-in-container.sh`, with
   fallbacks at `~/Code/`, `~/projects/`, and the cwd's `./scripts/`.
3. **Skip with warning** — append `{tool, reason}` to
   `phase-04-scanners/skipped.json`; never fail the phase.

`summary.json` records the chosen invocation method per scanner
(`invocation: "path_a" | "path_b" | "skipped"`) so future delta-mode
runs can detect path switches.

#### Wrapper hardening

`scripts/run-audit-in-container.sh`:

- New `$AUDIT_CONTAINER_RUNTIME` env override. Forces `podman` or
  `docker` regardless of detection order — for environments where
  rootless podman is misconfigured (e.g. `XDG_RUNTIME_DIR` pointing
  at a world-writable `/tmp` inside a nested container) but docker
  works.
- `--load` flag now passed to docker builds. The modern docker buildx
  default driver caches build output rather than loading it into the
  local daemon; without `--load`, `docker run` then fails with
  "Unable to find image ... locally". podman doesn't need this.
- `--build` alone (no subcommand) now exits after the build instead
  of falling through to default `preflight` (which needs bind mounts
  and fails in CI/DinD when the user just wanted to validate the
  build).
- Default image tag bumped from `:2.0.1` to `:latest` so the local
  image floats with rebuilds.

#### Path B regression gate, expanded

`tests/e2e/test-path-b-build.sh` now has 4 stages instead of 3:
build → DinD probe → preflight → end-to-end gitleaks scan against
the repo. The DinD probe lets the test exit `PASS-WITH-LIMITATIONS`
in nested-docker environments where bind mounts are blocked, instead
of producing a misleading FAIL. On real hosts (Fedora/Podman, Ubuntu/
Docker), all four stages run.

#### `scripts/run-e2e-test.sh --path-b` flag

New flag that:
1. Builds the Path B container.
2. Sets `AUDIT_SKILL_REPO=$REPO_ROOT` so Phase 4 finds the wrapper.
3. Sets `AUDIT_FORCE_PATH_B=1` so Phase 4 uses the wrapper for every
   scanner regardless of host PATH state — testing the recommended
   path even on a host that happens to have scanners installed.

#### What's NOT validated by this release

- Full `--path-b` E2E run against juice-shop. Requires a non-DinD
  host. Smoke test (`test-path-b-build.sh`) validates the wrapper
  end-to-end on bare metal; the deep audit run is the user's next
  step on Fedora.
- Hadolint output redirection — the wrapper's hadolint scan case
  (line 109) doesn't `> /target/.claude-audit/.../hadolint.sarif`.
  Out of scope for v2.0.5; tracked for v2.0.6.

## [2.0.4] — 2026-04-25

### Fixed — silent hadolint install failure on case-mismatched checksum file

`scripts/install-scanners.sh:fetch_checksum_from_release()` did a
case-sensitive `awk` match against the asset filename inside the
vendor's `.sha256` file. Hadolint publishes its release asset as
`hadolint-Linux-x86_64` (capital L, in the URL) but the body of the
accompanying `hadolint-Linux-x86_64.sha256` file lists the filename
as `hadolint-linux-x86_64` (lowercase). The match failed; the script
returned an empty hash; `download_verified` aborted with
`cannot fetch checksum for hadolint-Linux-x86_64`; the user was
left with 5 of 6 scanners installed and no clear pointer to the
case-mismatch root cause.

The fix adds a fallback case-insensitive comparison using POSIX
`awk`'s `tolower()`. The exact-case match is still tried first
(unchanged behaviour for vendors who get this right); only on a
miss does the lowercased fallback run. Any future vendor with the
same case-quirk gets handled transparently.

Caught in production by a downstream user running v2.0.3's
`install-scanners.sh` on Fedora — same dogfood loop that caught
the v2.0.3 PEP 668 issue.

## [2.0.3] — 2026-04-25

### Fixed — Path B Containerfile build (release-blocker for the recommended scanner-isolation path)

`scripts/Dockerfile.audit` line 75 used `pip3 install --user
jsonschema==4.22.0`, which fails on the Debian 12 (bookworm) base
image with `error: externally-managed-environment` (PEP 668). The
fix adds `--break-system-packages` to that line, matching the
fallback chain `install-scanners.sh` already uses for semgrep
(lines 252-258 of that script). We're in a container — there's no
system Python to protect.

This bug shipped in v2.0.2 because the v2.0.2 E2E only validated
the host-install path (Path A inside the test environment). Path B
(`scripts/run-audit-in-container.sh --build`) was never built in
the E2E loop, so the regression went undetected. Caught by a real
user trying the recommended path on Fedora/Podman.

### Added — Path B regression gate

New `tests/e2e/test-path-b-build.sh` smoke test that:
1. Detects the container runtime (Podman preferred, Docker fallback).
2. Runs `scripts/run-audit-in-container.sh --build` end-to-end.
3. Runs preflight inside the built image and asserts ≥5 of 6
   scanners report `[OK]`.

Cheap (~3-5 min on first build, ~30s on rebuild with layer cache),
so it can run alongside the deep audit E2E without doubling wall
time. This is the regression gate that should have existed in
v2.0.2 — without it, any Dockerfile breakage ships silently.

### Changed — install docs reframe

`README.md` and `docs/INSTALL.md` reframe scanner installation:

- **Recommended pattern: isolated full container** (everything
  inside — `git`, `claude`, the skill, the scanner bundle, the
  audit target). Use `cw`, Codespaces, dev containers, or plain
  Docker — whichever isolation primitive you have. Path A install
  inside the disposable container is the right model: scanners
  belong there, host pollution is a non-concern.
- **Acceptable: Path B** (scanners-only-in-container, Claude on
  host). Reasonable for one-off audits where Claude Code is already
  installed on the host.
- **Strongly discouraged: Path A on your daily-driver host.** Six
  security tools with auto-updating rule databases on your laptop
  is invasive state for a tool that may run once a week.

The previous framing led at least one downstream system Claude to
default to host install when Podman was available and would have
been better served by container isolation.

## [2.0.2] — 2026-04-25

### Changed — reliability patch, no new capability

This is a patch release. **No new capability, no new artifacts, no
public-API changes.** (The E2E harness's invocation shape *does*
change — `--append-system-prompt` is gone — see the Honest Scope Note
below.) The patch moves the v2.0.1 artifact contract from external
runtime injection (the `--append-system-prompt` mandate in
`scripts/run-e2e-test.sh`) into the skill itself, so `/security-audit`
is self-mandating for every invocation shape — `claude -p`, interactive
chat, or external harness.

**Why this is a patch, not a minor.** The skill already *claims* to
produce machine-readable artifacts (per SKILL.md, per workflow.md's
MANDATORY ARTIFACT CONTRACT, per every phase's "Verify before exit"
block). It just failed to honor those claims reliably without the
external mandate. v2.0.2 makes the skill self-honor its existing
contract — by definition a bug fix.

#### What moved in-skill

- **`SKILL.md` description field** now carries the imperative artifact
  contract (the `MANDATORY ARTIFACT CONTRACT` text that was previously
  only in the `--append-system-prompt` injection). The description is
  loaded into model context on every skill invocation, so the mandate
  travels with the skill regardless of how the user invokes it.

- **Every `steps/phase-NN.md`** now leads with a
  `## 🛑 MANDATORY EXECUTION RULES (READ FIRST)` block (BMAD-shaped —
  emphatic, emoji-flagged, listing required outputs + sub-agent fan-out
  + DO-NOT anti-patterns). Pattern borrowed from the
  `bmad-create-architecture` skill in the BMAD installation.

- **Phase 5 §5.2 rewrite** — the fan-out procedure is now an explicit
  Agent-tool invocation procedure with the exact tool-call shape, not
  descriptive prose. Single-shot orchestrator mode can no longer
  interpret "Phase 5 fans out to sub-agents" as "cover all 9 categories
  in one head-space" — the missed-bug anti-pattern from E2E runs 2-3 is
  now called out explicitly.

- **Phase 6 §6.9, §6.12, §6.13 rewrite** — ASVS, LINDDUN, and STRIDE
  methodology fan-outs similarly made literal.

- **`skills/security-audit/manifest.yaml`** — new structured machine-
  readable version of the per-phase contract (schema-versioned). The
  prose files remain authoritative for orchestrator behavior; the
  manifest is authoritative for downstream tooling (E2E assertion
  suite, future CI checks, delta-mode preflight).

#### What moved out of the E2E harness

- **`scripts/run-e2e-test.sh` drops `--append-system-prompt`.** The
  E2E run now validates that the in-skill mandate is sufficient. If a
  future regression re-breaks report-only output, the E2E fails and
  the fix belongs in-skill, not as external scaffolding. A comment
  in the script records this principle.

#### Delivery note

v2.0.1's E2E PASS (documented in
`docs/test-runs/e2e-full-run-2026-04-24T232300Z.md`) relied on the
external `--append-system-prompt` mandate. **v2.0.2 produces a clean
PASS on the same Juice Shop @ v19.2.1 fixture *without* the mandate**
— validated 2026-04-25 in
`docs/test-runs/e2e-full-run-v2.0.2-2026-04-25T0250Z.md`. Highlights:

- **12/12 fixtures matched** (vs 8/12 in v2.0.1) — the four soft
  misses (alg:none, 2FA trust, zip-slip, LFI) are all caught now,
  thanks to Phase 5 fan-out actually fanning out.
- **474 findings** (vs 25 in v2.0.1, 19× depth) across **60 unique
  CWEs** (vs 21).
- **Phase 5 emitted 64 per-(category × partition) JSONLs** + matching
  `.done` markers, vs v2.0.1's single consolidated `phase-05-tokens.json`.
- **17 ASVS L2 sub-agents** ran (V1-V17), each writing per-category
  intermediates concatenated into the canonical `phase-06-asvs.jsonl`.
- 51m 41s wall time — slower than v2.0.1's 7m, but trading minimum-
  viable for genuinely deep per-(cat, part) analysis.

#### Honest scope note

This patch removes the external `--append-system-prompt` mandate from
`scripts/run-e2e-test.sh`. That is a behavioural change to the E2E
harness even though there is no public API change. Any local user
copying `run-e2e-test.sh`'s mandate text for their own GHA harness
should know that the in-skill MANDATORY blocks are now the only place
the contract lives — there is no second source of truth to fall back
on.

Round 4 of adversarial review — additional fixes integrated into the
[2.0.1] entry below:
- `cwe-map.json` gains a `$schema` declaration for consistency with
  other lib/*.json files.
- `validate-findings.py` load_cwe_map hard-fails on missing /empty
  `mappings` instead of silently passing every CWE.
- `tests/fixtures/surface-minimal.json` contradictory row replaced
  with a consistent `NO_AUTH_WRITE` surface (auth_required=false).
- `.github/dependabot.yml` adds a `docker` ecosystem watcher so the
  Dockerfile.audit base-image digest pin doesn't decay.
- `run-audit-in-container.sh scan <tool>` now passes extra args
  through to the inner scanner command (e.g., `--config p/python`).
- Phase 0 §0.5 documents the multi-framework conflict rule: emit one
  entry per detected framework, don't silently pick one.
- Phase 1 §Axis-6 documents proactive partition pre-splitting at
  125K LOC instead of reactive-only needs_recursion.
- `.github/PULL_REQUEST_TEMPLATE.md` + `.github/ISSUE_TEMPLATE/*.md`
  make contribution expectations visible at submission time.
- Severity rule rationale in `phase-07-synthesis.md §7.4` rewritten
  to be internally consistent — no more contradictory framings.
- `workflow.md §5` adds an honest caveat: orchestrator-side
  re-validation is defense-in-depth, not cryptographic enforcement.
- `workflow.md §5` explicitly documents the file-lock convention
  (disjoint per-(cat,partition) paths; concurrency cap enforces
  non-overlap).
- `docs/test-runs/README.md` annotates superseded content (M5
  fingerprint formula + M6 surface.file lookup) so readers know
  which writeups reflect v2.0.1 state.
- `validate-patterns.py` gains a `--verbose` flag for debugging
  false negatives.
- `CODEOWNERS` notes the single-maintainer risk explicitly.
- README dropped the unmeasured "~500 MB image size" claim.

## [2.0.1] — 2026-04-24

### Changed
Correctness fixes from two rounds of adversarial review. Because the
project is pre-release (no external users), breaking schema changes
were applied cleanly without backwards-compatibility aliases.

Tier 0 (correctness):
- **Phase 2 surface rows** now record `handler_file` and
  `registration_file` as distinct required fields. `handler_hash` is
  computed against the handler body file. Delta-mode invalidation keys
  off either file being in `git diff --name-only`. The v2.0.0 `file`
  alias has been dropped cleanly (pre-release; no users to migrate).
- **Baseline fingerprint** switched from `sha1(file:line:title)` to
  `sha1(handler_file:line:cwe:category)`. Stable across title drift.
  Finding schema documents the formula; sub-agents may emit the
  `fingerprint` field directly.
- **Severity promotion capped at ±1 rung**. Any strengthening signal
  (CONFIRMED, public zone, write data-op) contributes +1; the dev zone
  contributes −1; net positive promotes one rung, net negative demotes
  one, net zero is unchanged. Capped regardless of signal count.
- **`top_n` invocation arg wired through** to `phase-01-partition.md`.
  Previously advertised, not implemented.
- **90-day staleness check now enforced** in `mode: delta` preflight
  (was prose-only in v2.0.0).
- **Severity promotion** symmetric: `dev` trust zone demotes by 1
  rung.

### Added
Tier 1 evidence + validation:
- **Polyglot dogfood runs** against Go (gosec, 20 MITM findings) and
  PHP (DVWA, 40 injection findings). All Go + PHP grep patterns from
  cat-04/cat-08 now have execution evidence.
- **`scripts/validate-findings.py`** — JSONL schema validator that
  every Phase 5 / Phase 6 sub-agent MUST run before returning.
- **`scripts/verify-unique-findings.py`** — independent recount of the
  "unique-to-skill" claim; run it against the final SARIF + Phase 5
  JSONL to reconcile with the synthesis sub-agent's self-report.

Tier 2 docs:
- **`docs/ANTI-PATTERNS.md`** — the consolidated catalog the deepdive
  category files reference.
- **`CHANGELOG.md`** (this file).
- **`SECURITY.md`** — how to report vulnerabilities in *this skill*.
- **`CONTRIBUTING.md`** — branch convention, commit signing, test
  expectations.
- **Missing CWE entries** added to `lib/cwe-map.json`: CWE-208, 215,
  598, 1004.
- **Category-name aliases** documented in `workflow.md §0` (e.g.,
  `secrets → secret_sprawl`, `transport → mitm`).
- **Container-isolated execution** option — ship `scripts/Dockerfile.audit`
  and `scripts/run-audit-in-container.sh` so scanners can run in an
  ephemeral container, not on the host. README documents both paths.

Tier 3 installer hardening:
- **Checksum verification** for every downloaded binary; the installer
  refuses to install mismatched tarballs.
- **Trufflehog `curl | sh` replaced** with a direct release-tarball
  download + checksum verify (matches gitleaks pattern).
- **Permission-fail path** fixed: installer falls back to
  `$HOME/.local/bin` if `$PREFIX` isn't writable, consistently across
  all `install_*` functions.
- **Stale-version warning** via the `--check` path: each tool's pinned
  version is compared against the vendor's latest release tag.

Tier 4 automated testing + CI:
- **`scripts/validate-schemas.sh`** — sanity-checks every JSON
  schema parses, every cat-*.md referenced CWE exists in the map,
  every installer shell script passes `bash -n`.
- **`scripts/validate-findings.py`** accepts `--cwe-map` for a
  semantic check (every finding's `cwe` must exist in the map, not
  just match the `CWE-\d+` regex).
- **`.github/workflows/ci.yml`** — runs the validation suite on push +
  PR; catches schema drift / broken references before merge. Runs a
  regex-compile check on cat-*.md patterns as a polyglot regression
  guard.
- **`tests/fixtures/`** — minimal findings JSONL used by the validator
  tests.
- **`.github/CODEOWNERS`** — routes all PR reviews to @velimattiv.

Round 2 of adversarial review — additional fixes:
- Surface schema `file` alias dropped (pre-release cleanup).
- Severity rule rewritten: ±1 rung cap, any signal counts.
- `run-audit-in-container.sh` renamed semantically: the wrapper
  isolates the SCANNER phase, not the full audit. README and script
  comments now say so explicitly.
- `validate-findings.py` gained `--cwe-map` for semantic CWE
  validation (closes the "CWE-99999 passes" hole).
- CI adds a regex-compile check for cat-*.md grep patterns (catches
  pattern drift without a full sub-agent run).
- `Dockerfile.audit` restructured: single USER toggle (root → audit
  at the end), not the v2.0.1-initial three-toggle muddle.
- `check_stale_versions` in installer reads `GITHUB_TOKEN` env var
  to avoid the 60-req/hr unauthenticated rate limit when set.
- 1M-context claim toned down in `docs/test-runs/1m-context-check-*.md`
  from "verified" to "self-report evidence" with an honest caveat.
- ROADMAP.md updated — v2.0.1-delivered items removed from the
  candidate list.
- `docs/ANTI-PATTERNS.md` reworked as a pure index (one-line summary +
  link to the canonical cat-*.md). No duplicated pattern content.
- `validate-schemas.sh` documents its markdown-link-check limitation
  (catches `[text](path)` only; reference-style links unchecked).

### Fixed
- Broken references in `cat-*.md` to `docs/ANTI-PATTERNS.md` now
  resolve to a file that actually exists.
- Category-name mismatch between user-facing examples
  (`categories: "secrets"`) and internal enum (`secret_sprawl`);
  aliases resolve both.

## [2.0.0] — 2026-04-24

### Added
Initial v2 release. Complete polyglot security-audit skill.

- **9-phase workflow** (Phase 0 Discovery → Phase 8 Baseline).
- **171 attack surfaces** enumerated on OWASP Juice Shop dogfood;
  polyglot coverage for 15+ languages via framework-detection +
  surface-detection catalogs.
- **6 required scanners** orchestrated (semgrep, osv-scanner, gitleaks,
  trufflehog, trivy, hadolint) + 6 conditional (brakeman, checkov,
  kube-linter, grype, govulncheck, psalm, zizmor).
- **9 deep-dive categories** with language-specific grep catalogs.
- **5 modes**: full, delta, scoped, focused, report.
- **SARIF 2.1.0 emitter** + CycloneDX SBOM skeleton.
- **Baseline persistence** for delta-mode sub-minute PR reviews.
- **OWASP methodology tagging**: ASVS L2, API Top 10 (2023), LLM Top
  10 (2025), LINDDUN, STRIDE.

### Deferred to v2.1
See `docs/ROADMAP.md` for 12+ candidate improvements (AST handler
hashing, ASVS L3 support, non-English framework detection, pre-commit
recipe, pruned-baseline compression, Phase 2+3 fusion for single-
partition repos).

## [1.0.0] — 2025-xx-xx

Initial single-file `/security-audit` skill for Node/Nuxt. Replaced
in-place by 2.0.0.
