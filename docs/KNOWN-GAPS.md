# Known Gaps

Explicit list of limitations. Each entry describes what's NOT enforced, so reviewers can decide what additional checks they need beyond what ships. Moved here from `tests/e2e/README.md` per Round-4 adversarial feedback — "documentation is acknowledgment, not mitigation."

> **Read [#24](#24-a-the-failure-direction-is-safe-argument-expires-silently) first.**
> It is the most transferable thing in this file: it explains how entry #23 in
> this same document was correct when written in v2.3, became false in v2.5
> without a word of it changing, and cost 72 false HIGH+ findings before anyone
> noticed. Every other entry here is a claim with the same expiry risk.

## E2E assertion suite

### 1. Semantic correctness of findings
The suite validates *structural* conformance (schema, CWE-in-map, section headers) and *coverage* (fixture list matches). It does NOT verify that a finding's description is accurate — a sub-agent could emit "SQL injection" when the actual bug is XSS, as long as it satisfies (file, cwe, category).

**Mitigation available:** the fixture's `description` field is human-readable; a reviewer comparing fixture text to actual finding text would catch gross mismatches. Not automated. **v2.1 update:** fixture schema v3 adds `negative_expectations[]` decoys and a precision/recall/F1 scorecard (`tests/e2e/assertions.py` → `scorecard.json`/`.md`), giving the first automated false-positive signal — a different axis than semantic accuracy, but the suite is no longer coverage-only.

### 2. Report body content
`check_report_sections` verifies section headers are present. It does NOT check that the sections have non-trivial content. A report with `## Executive Summary` followed by an empty line then the next header would pass.

**Mitigation available:** add `--min-section-bytes` flag that grep's each section and asserts ≥N bytes between headers. Not implemented; would trade false-positives (legitimately short summaries) for false-negatives.

### 3. Single-run evidence
No non-determinism detection. A sub-agent that passes 3-of-5 runs (intermittent failure) is harder to catch with a one-shot E2E. Nightly runs would surface flakes; GHA not shipped in v2.0.1 (Max-auth blocker).

**Mitigation available:** `scripts/run-e2e-test.sh` could re-run and diff, but doubles cost. Deferred to v2.1 when GHA lands.

### 4. No regression catch on skill behavior changes
The assertion suite validates against Juice Shop v19.2.1 + the 12-entry fixture. Changes to `cat-*.md` instructions that alter sub-agent behavior will be caught only if they break a specific fixture — subtler shifts (e.g., severity calibration drift, CWE tagging drift) may pass.

**Mitigation available:** the `alternate_cwes` support in fixture v2 is partial mitigation. Full drift detection would require baselining sub-agent outputs across runs, not shipped.

### 5. Phase 6 `config.json` shape uncontracted
`collect_all_findings` tries two known layouts for `phase-06-config.json` (flat array OR `{"findings": [...]}`). Anything else is silently skipped — any fixture matching via Phase 6 config findings may silently miss.

**Mitigation available:** define a formal schema for `phase-06-config.json` and have Phase 6 sub-agent emit it. Tracked as a v2.1 candidate in `docs/ROADMAP.md`.

## Installer + scanner bundle

### 6. Scanner CVE DB freshness not enforced
`scripts/install-scanners.sh --check` warns on stale version pins, but the skill doesn't block audits against outdated scanner DBs. A 6-month-old trivy DB misses recent CVEs silently.

**Mitigation available:** `trivy` itself refreshes DB on each run by default; we explicitly pin `--skip-db-update` nowhere. OSV-scanner fetches online at run-time. So this gap is smaller than it sounds — but gitleaks rule updates land via binary updates.

### 7. No enforcement of the `--dangerously-skip-permissions` flag at runtime
`run-e2e-test.sh` preflight checks whether `claude --help` advertises the flag, but if the flag is silently gated behind an env var in a particular Claude Code version, the audit may stall mid-run waiting for interactive permission. The script warns but does not prevent.

**Mitigation available:** set `CLAUDE_CODE_DANGEROUSLY_SKIP_PERMISSIONS=1` in the script's env export. Not done because forcing that env var for a user who doesn't want skipped-permissions is invasive.

## Deferred to v2.1

Tracked in `docs/ROADMAP.md`:
- **GHA-hosted E2E** (Max-auth resolution) — still deferred.
- ~~**Second polyglot E2E target**~~ — **delivered in v2.1**: DVWA (PHP) +
  OWASP crAPI (Java/Go/Python) fixtures, `--target` selectable.
- **AST-based handler hashing** (replaces content hash) — still deferred.
- **Pre-commit recipe** (sub-second incremental checks) — still deferred.
- **ASVS L3 support** — still deferred.
- **Non-English codebase framework detection** — still deferred.

New v2.1 deferrals (see `docs/EPIC-v2.1-refresh.md` §4 + `docs/ROADMAP.md`):
- ~~**Opengrep engine swap + rule-licensing posture**~~ — **RESOLVED (v2.3):**
  project is free OSS forever → Semgrep invoke-only is unrestricted; **kept
  Semgrep** (fresher community rules), **declined Opengrep** (archived/frozen
  `opengrep-rules`). Added an `AUDIT_SAST_RULES` offline/BYO-rules override.
  See CHANGELOG [2.3.0].
- **Live-container E2E** — not run in-session (pre-existing Max-auth blocker).
  The static assertion suite + scorecard logic are updated and internally
  consistent; a host run with Claude auth is still required to exercise the
  categories end-to-end. **Cost anchor for a future live/GHA run** (from
  CyberGym-E2E, `research/08-cybergym-e2e.md`): budget ≈ **$10 / 90 min per
  target**, with diminishing returns after ~60 min (30→60 min yields most of
  the gain). [A4]
- ~~**CWE↔OWASP-tag pair validator**~~ — **delivered in v2.2**:
  `lib/cwe-owasp-map.json` (canonical map + documented `context_overrides`) +
  `validate-schemas.sh` [8/8] asserts each cat-file `CWE-N / A##:2025` pair
  matches canonical or a justified override. **Residual (low):** the map's
  `canonical` block and `lib/owasp-web-top10.md` Part-1 table are two
  hand-maintained copies kept in sync by convention; nothing yet diffs them —
  a future check could generate one from the other.

## Reporting a new gap

If you find a scenario the suite silently passes but should fail, open an issue with `tests/e2e/` label + a minimal repro (a diff that should break something but doesn't). PRs that add tolerated drift to fixtures without a justification paragraph in the fixture's `rationale` are rejected.

---

## v2.5 — collection scoping and severity arithmetic

These gates close specific, observed failures. They are not general solutions,
and the boundaries below are deliberate rather than aspirational.

### 12. Both reconciliations trust an agent-populated inventory
`validate-collection-scoping.py` and `validate-egress.py` reconcile an inventory
that a sub-agent wrote. Rule **C5** (a scoping claim with no caller-derived
predicate is rewritten to `unscoped`) and **C2b** (a handler with a
permission-shaped field and no filter, inventoried as un-decorated) re-check the
two claims most likely to be wrong, and the fail-closed coverage gates make an
*absent* entry loud. But an agent that mislabels an entity, or records a
plausible-looking predicate that is not actually applied on the query path, is
not caught mechanically. C5 verifies that a claimed predicate actually appears
within ±3 lines of the cited location, and C2b verifies a denied decoration
against the source — but an agent that cites a *real* predicate from an
unrelated code path, or mislabels the entity, still passes. **Mitigation
available:** the §6.20 adversarial pass must name the file:line of the scope it
claims to have found; a refutation with no line is not a refutation.

**v2.6 update — what changed and, more importantly, what did not.**

*Changed.* The calibrated run showed the blast radius of one bad inventory row
was far larger than this entry implied, because both reconcilers joined on
untyped data:

- `validate-egress.py` computed a per-resource gate `floor` by joining on
  `serves_resource` — **a free-text string an inventory agent wrote**. Everything
  sharing that string was compared to everything else regardless of layer,
  process or trust boundary: 115 of 306 raw rows compared an HTTP RBAC gate to a
  cron HMAC gate on surfaces that serve no bytes. v2.6 **types the join** (a
  `layer` field; `floor` computed per `(resource, layer)`), so a browser
  component, a CLI script, a cron worker and an HTTP handler stop enforcing each
  other's gates.
- `_KIND_RANK` mapped the inventory *kind* `capability`/`verification` to
  `GATE_VERIFIED` (rank 3), reachable in text only via `2fa|mfa|otp|step-up`
  keywords. A request-scoped RLS GUC inventoried as `capability` therefore gave
  every resource it touched an unreachable floor, and the **correctly gated**
  branch was filed HIGH. v2.6 **caps a kind-derived floor at `GATE_AUTHZ`**
  unless real gate text at rank 3 is observed for that resource.

Both are blast-radius reductions: a wrong inventory row now poisons a smaller
neighbourhood.

*Not changed — and this is the honest part.* **Neither reconciler verifies the
inventory.** Typing a join key does not make the values in it true. An agent that
mislabels an entity, records a plausible predicate from an unrelated code path,
assigns the wrong `layer`, or sets a `gate_rank_hint` it did not earn still
passes every mechanical check, because there is nothing to check it against
except more agent output. The fail-closed coverage gates make an *absent* entry
loud; nothing makes a *wrong* entry loud. That is a verification problem, not a
typing problem, and v2.6 does not solve it.

The practical consequence: read the inventory-derived findings as *leads keyed to
a line*, not as conclusions. The v2.6 annex model (Wave 2b) encodes exactly that
reading — mechanical rows attach to a judgement finding as a fix-surface annex
rather than being filed as independent findings.

### 19. The partition-coverage escape hatch is a full bypass
`--allow-catch-all` permits a bare `**` glob alongside specific partitions. A
catch-all matches every file, so coverage is trivially "complete" and the gate
proves nothing. The flag prints a WARN saying exactly that and records
`catch_all_accepted` in the JSON report, but nothing stops an operator from
wiring it into CI and forgetting. It exists because a genuine single-partition
repo needs it; treat its presence in a config as a finding of its own.

### 20. Fingerprints are line-anchored
`sha1(file:line:cwe:category)` moves when code above the finding moves. v2.5 adds
a `(file, cwe)` line-window fallback (±25 lines) so R4 and L1 survive ordinary
edits, but a finding that moves further than that window — a large refactor, a
file split — still un-matches from its baseline entry. The consequences are a
reset `first_seen_at` and an R4 check that has nothing to compare against.
Changing the formula outright would invalidate every existing baseline, so the
window is the compromise. **Watch for it after a big refactor.**

The fallback carries its own residual risk, disclosed here rather than buried:
two DIFFERENT findings of the same CWE in the same file within 25 lines could in
principle bind to each other. A title-similarity floor (Jaccard ≥ 0.34) and a
one-baseline-entry-to-one-consumer rule guard against it, but a routes file with
several near-identical unscoped-collection findings — this release's own primary
output shape — is exactly where a similarity floor is weakest, because the titles
genuinely are near-identical. Assignment is two-pass and best-first (title
similarity desc, then line distance asc, one baseline entry to one consumer), so
a weaker nearby decoy can no longer take the slot the true continuation needed —
but a genuine tie between two near-identical findings is resolved arbitrarily.
Cross-check the R4 section of the report after a refactor that moves several
same-CWE findings at once.

### 22. `Model.find(variableFilter)` is not a candidate
The ODM anchor requires a `)` or `{` after `find(` — that is what separates
`User.find({})` from an in-memory `Roles.find(r => r.id === x)` on a capitalised
constant array, which is ubiquitous in real TypeScript and would otherwise fail
the coverage gate on every run. The cost is that `User.find(filter)` with a
variable filter is missed: a variable is indistinguishable from a predicate
callback without type information. Accepted deliberately — a gate that cries wolf
gets disabled, and a disabled gate catches nothing.

### 21. `--changed-files` line ranges are near-exact by design
Range matching pads by ±2 lines, not by the fingerprint window's ±25. That is
deliberate (a 25-line pad made ranges barely tighter than bare paths while being
sold as the precise option), but it means a genuine fix whose diff hunk lands
more than 2 lines from the reported line is NOT accepted as an explanation, and
the finding reports as `disappeared_unexplained`. That is the intended failure
direction: a false alarm you close by recording the reason, rather than a
vanished HIGH nobody notices.

### 13. Base scopes are the main false-positive mode
A `default_scope`, a tenant-injecting repository, a Prisma client extension, or
database row-level security **is** valid row scoping, and none of them appear in
the handler. C1 will over-flag when Phase 2 misses one. This is deliberate — the
failure direction is toward triage, not toward silence — but on a codebase that
scopes centrally, expect noise on the first run until the scopes are recorded as
`scope_evidence`. **Not automated:** there is no detector for "a scope exists
somewhere else".

### 14. Runtime-assembled queries are out of mechanical reach
A query built by string concatenation at request time, or dispatched through a
generic query-service abstraction, cannot be statically decided. These are
recorded as `coverage: caveat` and surfaced in the report. They are **not**
counted as scoped.

### 15. The composer can only compose what was tagged
`compose-attack-paths.py` chains `preconditions`/`postconditions`. A capability
nobody wrote down joins nothing, so a real chain between two untagged findings is
invisible to R1 and R3. **Mitigations available:** R2 fires on prose that names
another finding (no tags needed); `--require-capabilities` enforces tags on the
four access-control categories; the ORPHAN CAPABILITIES report makes a
half-composed chain visible. None of these makes chain analysis complete — they
make the gap loud. **A clean gate with a long orphan list is not a clean gate.**

### 16. Personas and crown jewels are derived, not verified
Phase 0 §0.14 derives them by rule from the profile. If it mis-classifies the
lowest self-provisionable role as privileged, R3 stops firing for the persona
that matters most. The composer falls back to capability *patterns* when the
lexicon is absent, but it cannot detect a lexicon that is present and wrong.
**Review the persona list in the report** — it is printed for that reason.

### 17. L1's threshold is policy, not physics
30 days is a default (`--max-age-days`). It is not derived from anything. The
claim is only that *a* threshold now exists and is enforced mechanically, which
is strictly more than the previous state, where a CONFIRMED finding aged 96 days
without any mechanism noticing.

### 18. R4 cannot distinguish a fixed finding from an unlooked-for one
A HIGH+ that disappears between runs is matched against `--changed-files`. If the
fix landed in a file the audit did not diff (a config change, an infrastructure
control, a dependency bump), the run reports `disappeared_unexplained` — a false
positive that must be closed by recording the reason. The inverse (a finding that
disappears because Phase 5 silently under-covered) is the failure this accepts
noise to catch.

### 23. Literal stripping is a scanner, not a parser
`predicate_binds_caller` blanks string literals and line comments before scoring,
because a quoted value can never bind the caller and treating one as an
identifier laundered an unscoped collection past C1. The scanner handles
backslash escapes and treats an *unterminated* quote as an ordinary apostrophe
rather than pairing it with the next unrelated quote. It is still not a language
parser: a `//` inside a string that was itself opened by an unterminated quote
can still be blanked.

**This entry was wrong from v2.5 until v2.6, and the way it was wrong is the
lesson in #24.** As written in v2.3 it named the tagged-template blind spot
exactly — *"a nested template-literal interpolation carrying the only caller
reference (`` sql`... ${session.user.id} ...` ``) can be blanked"* — and then
dismissed it: *"the failure direction is a **false positive** — which a human
closes — not a silent pass."*

That argument was **true when written** and **false by v2.5**, and nobody
re-checked it. Three things changed underneath it:

1. A failed C5 rewrites `scope = "unscoped"`, so C1 fires on the same row. Every
   false C5 cost **two** HIGH+ findings, not one.
2. v2.5 gave findings the ability to mint capability tags. 47% of all capability
   tags in the composition graph (531 of 1120) came from the C-rules, synthesised
   from the entity name with no check that the collection was actually unscoped.
3. `compose-attack-paths.py` escalates every contributing finding in an
   unprivileged→crown-jewel chain straight to CRITICAL. So a false positive
   stopped being a local triage cost and became a severity-inflation engine that
   escalated its **neighbours, including true findings**.

Measured cost: **72 of 73** HIGH+ C-rule findings were false, and **53 of 73**
ended CRITICAL. On a drizzle or Kysely codebase the caller predicate lives inside
a tagged template by construction, so this was not an edge case on that target —
it was the common path.

**v2.6 fixes the mechanism**, not just the symptom: `_strip_literals` is
template-aware (Wave 2 story 2.1), capability minting is gated on a *verified*
unscoped determination (story 1.3), and the C-rule family is barred from the
headline band by the standing calibration control in `manifest.yaml` until it is
re-measured (story 4.5). What remains true, and is why this entry still exists:
the scanner is still not a parser, and record the predicate as `scope_evidence`
on a plain line if a template literal is the only place your scoping lives.

---

## v2.6 — calibrated severity

The first release with a measured number for anything. Eight security engineers
triaged all 255 HIGH-or-above findings of a v2.5.0 full-mode run against the real
code. The entries below are what that measurement showed we do **not** know, plus
the one lesson that generalises past this tool entirely.

### 24. A "the failure direction is safe" argument expires silently

**This is the load-bearing entry in this file.**

Entry [#23](#23-literal-stripping-is-a-scanner-not-a-parser) predicted the
tagged-template blind spot precisely, in v2.3, and dismissed it with a sound
argument:

> *"The failure direction is a **false positive** — a correctly-scoped collection
> reported as unscoped, which a human closes — not a silent pass."*

That was **true when written**. In v2.3 the only consumer of a finding was a
human reading a list, and for that consumer a false positive really is cheap and
self-correcting. In v2.5 two new consumers landed — capability minting and
uncapped chain composition — and neither of them is a human who closes things. A
false positive became a tag that escalated its *neighbours*, including true
findings, straight to CRITICAL. The sentence did not change. Nothing flagged it.
The cost was **72 false HIGH+ findings, 53 of them CRITICAL**, and a report whose
top of list displaced real work.

**The generalised rule, adopted as a standing rule by this epic:**

> A "the failure direction is safe" argument is **scoped to the consumers that
> existed when it was written**. It is not a property of the defect; it is a
> property of the defect *plus the current downstream graph*. Adding a consumer
> silently invalidates every such argument in the codebase, and nothing in a
> normal review catches it, because the invalidating change is nowhere near the
> text it invalidates.

Two obligations follow, and they are cheap:

1. **When you write one, name the consumers.** "Safe because the only consumer is
   a human triager" is auditable. "The failure direction is safe" is not. An
   argument that does not name its consumers cannot be re-checked, so it will
   not be.
2. **When you add a consumer of findings** — a severity computation, a tag, a
   graph edge, a gate, an export, an auto-fix — grep this file and the source
   comments for accepted-risk arguments and re-check each against the new
   consumer. `grep -rin "false positive\|failure direction\|which a human"` is
   the whole procedure.

v2.6 adds the corresponding invariant in code: **a low-evidence finding must not
be able to raise the severity of anything — itself or its neighbours** (Wave 1).
That closes this specific instance. It does not close the class, because the
class is about arguments, not code, and the next consumer has not been written
yet.

*(The same shape appears in `docs/research/05-methodology-standards.md`, which
checked the skill's `ASVS 5.0` version **label** against the world, found it
current, and concluded "no version change needed" — without checking that the
body under the label was ASVS 5.0. It was 4.0.3. A check that verifies one half
of a claim is not a check; see story 4.2 and `lib/asvs-l2.md`.)*

### 25. The 96.6% deep-dive precision is one run on one codebase

The measured rates in `manifest.yaml` `calibration:` come from a **single**
target: a Nuxt 4 + h3/Nitro + drizzle TypeScript monolith, ~235K LOC, 1089 files,
8 partitions. Nothing here establishes any of those rates on a polyglot repo, a
Java monolith, a Go service mesh, or a codebase whose framework the deep-dive
prompts were not written against. The deep-dive agents may be substantially worse
where the framework idioms are unfamiliar, and there is no evidence either way.
Treat the numbers as *"this is what we measured, once"*, never as a specification.

### 26. The standing calibration control catches gross regressions, not drift

`manifest.yaml` `calibration:` bars a rule family from the headline severity band
when its last measured true-positive rate is below `headline_band_min_precision`
(0.50) over at least `min_sample_size` (30) verdicts. Three honest limits:

- **The sample floor is low.** At n=30 the 95% interval on a rate near 0.5 is
  roughly ±18 points. This control notices a family collapsing to 20% or 1%. It
  will not notice a family sliding from 85% to 70%.
- **It is only as fresh as the last triage.** `last_calibrated` is a date, and
  nothing forces it forward. A family's recorded rate can describe a rule that
  has since been rewritten.
  `calibration-report.py --check-manifest` detects drift **only when someone runs
  a new triage** — it cannot manufacture verdicts.
- **Unmeasured families still reach the headline band.** By deliberate choice:
  barring unmeasured families would bar every new rule on the day it ships, which
  is how a control gets switched off. They are marked PROVISIONAL and must carry
  a visible unmeasured-precision marker, so the state is loud rather than absent
  — but "loud" is not "gated", and a genuinely bad new rule can still reach a
  reader before its first measurement. `External scanner` and
  `Governance (composer)` are in exactly this state today: no independent verdict
  population exists for either.

### 27. The C-rule concept has still never been tested

The 1.4% figure recorded for `validate-collection-scoping.py` measures
`_strip_literals`, not C1/C5. The predicate scorer was blind to tagged templates,
which is where the caller predicate lives by construction on a drizzle or Kysely
codebase, so the rule never got to evaluate its own idea. v2.6 fixes the
mechanism. **Whether C1/C5 are good rules is an open question**, and the next
calibration is the first honest measurement of them. Do not read the recorded
1.4% as a verdict on the concept, and do not read a v2.6 re-run's lower finding
count as evidence the concept works — a re-run measures change, not truth.

### 28. The sibling sweep is grep-shaped

v2.6 requires every HIGH+ finding to state its sibling sites or to state
explicitly that the cited site is the only one. The sweep derives the defect's
shape as a grep/AST pattern and runs it repo-wide. That catches classes
expressible as a pattern — and in the calibrated run, most of the 34 missed
defects were exactly that (10 `postgres()` call sites where 4 were filed, 25 RLS
bypass clauses where 1 was filed). It does **not** catch a defect whose siblings
differ structurally: the same bug written three different ways, or a sibling
reachable only through a different framework idiom. That remains an
agent-diligence problem with no mechanical backstop.

### 29. No runtime verification, anywhere

Everything in this skill is static analysis over source plus an LLM's reading of
it. No finding is confirmed by executing anything: not a request, not a query,
not a container. `attacked: confirmed` means *an adversarial pass tried to argue
the finding away and failed* — it does **not** mean anyone reproduced the defect.
The v2.5 case that motivated the L1 age gate was ultimately settled by a live
`curl`, and nothing in the tool can perform that step.

### 30. The two new detection classes are a catalogue extension, not a solution

The calibrated run surfaced two defect classes the rule set could not express,
and v2.6 models them:

- **Local-filesystem exfil** — a repo-steerable state directory makes a hook
  write a live access token into the attacker's own working tree. No network
  call, so no egress rule could see it; `lib/egress-detection.md` modelled
  network modalities only.
- **Availability/integrity with no confidentiality component** — an uncapped
  provisioning call lets a caller mint enough empty rows to displace every real
  one from a downstream fixed-size scan, producing estate-wide silent data loss.
  Nothing in the rule set looked for one.

Both are now *modelled*. There is **no claim that either model is complete**. The
sink model still enumerates modalities we thought of; the availability class in
particular is a large space (exhaustion, ordering, quota, cache, scheduler) of
which one shape is now represented.
