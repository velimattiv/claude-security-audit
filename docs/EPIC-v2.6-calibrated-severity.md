# EPIC v2.6 — Calibrated Severity

**Status:** planned
**Trigger:** the first externally-calibrated run of this skill. `/security-audit`
v2.5.0, full mode, against a Nuxt 4 + h3/Nitro + drizzle platform (~235K LOC,
1089 files, 8 partitions, 675 surfaces, commit `5c42322`). **Eight security
engineers triaged all 263 HIGH-or-above findings against the real code** (255
verdicts), recorded 34 defects the audit missed, and an adversarial reviewer then
attacked the remediation plan built from the triage.

**One-line summary of the trigger:** the audit's own confidence marker is
anti-correlated with truth — findings labelled `CONFIRMED` are **9.6%** true,
findings carrying *no* label at all are **92.1%** true.

This is the first release where we have a measured number for anything. Every
figure below comes from that triage and was independently re-verified against
the shipped v2.5.0 tree before being written down.

---

## 1. What actually failed

### 1.1 The recall bias is correct and stays

The design doctrine (`SKILL.md:100-105`) — *"a scope applied by an un-modelled
mechanism is missed conservatively (over-flagging, then retired by the §6.20
adversarial pass)"* — is the right trade. A missed CRITICAL is unrecoverable; a
false positive costs triage time. **What failed is the retirement step, not the
over-flagging.** Nothing in v2.6 makes the tool quieter at the expense of recall.

### 1.2 Precision, measured

`true` := the triage returned REAL or ACCEPTED_RISK. 51 unresolvable duplicate
cycles are counted as *not* true, so every rate is a lower bound; the right-hand
column drops them.

**Read the denominator carefully.** It is **255 verdicts**, not the 263 HIGH+
findings — 8 were never triaged. So every rate below is *precision over triaged
findings*, not precision over all findings, and the two are not the same claim.
`scripts/calibration-report.py` models this correctly: untriaged rows are
excluded from the denominator and reported separately as coverage, so a future
run cannot quietly improve its number by triaging less.

| Rule family | n | true | rate | rate (excl. cycles) |
|---|---:|---:|---:|---:|
| Category deep-dive agent | 89 | 86 | **96.6%** | 98.9% |
| ASVS checklist | 6 | 4 | 66.7% | 100% |
| `config` (methodology) | 4 | 2 | 50.0% | 100% |
| LINDDUN | 2 | 1 | 50.0% | 100% |
| **R-rules** (`validate-egress.py`) | 81 | 16 | **19.8%** | 24.6% |
| **C-rules** (`validate-collection-scoping.py`) | 73 | 1 | **1.4%** | 2.2% |
| **Total** | **255** | **110** | **43.1%** | 53.9% |

Collapsed:

| | n | share of HIGH+ | precision | share of true findings |
|---|---:|---:|---:|---:|
| **Mechanical** (R + C) | 154 | 60% | **11.0%** | 15% |
| **Judgement** (deep-dive, ASVS, config, LINDDUN) | 101 | 40% | **92.1%** | 85% |

Six in ten HIGH+ findings came from the population that supplied one in seven of
the real ones. The deep-dive agents, by contrast, are an excellent detector —
four categories were 100% true at HIGH+ (`agentic` 18/18, `mitm` 16/16,
`deployment` 8/8, `injection` 6/6).

### 1.3 The invariant that broke

v2.5's bet — over-flag, retire later — is only sound while a false positive is
**locally** expensive. Three mechanisms took that apart simultaneously:

| # | Mechanism | Evidence |
|---|---|---|
| B1 | The adversarial confirmation pass exists **only** in `steps/phase-06-config.md:420` and `:508` — i.e. only over the R-rules and C-rules. `phase-05-deepdives.md` has no equivalent step. | `grep -c "adversar\|REFUTED" steps/phase-05-deepdives.md` → **0**. Cross-tab: every CONFIRMED/PARTIAL/UNVERIFIED row is mechanical; every unmarked row is judgement. The label measures **which phase emitted the row**, not truth. |
| B2 | `confidence == "CONFIRMED"` buys **+1 severity** (`phase-07-synthesis.md:132`), and `validate-egress.py:368` hardcodes `"confidence": "CONFIRMED"` on every R-rule row **at emission, before anything is attacked**. `phase-07-synthesis.md:70,107-108` re-derives the same conclusion from *"scanners are mechanical ground truth"* — false for these two, which are heuristics over an LLM-authored inventory. | The least precise family gets an automatic rung. |
| B3 | `validate-collection-scoping.py:610-617` synthesises `knows:any_<entity>_id`, `reads:any_<entity>_metadata` and `reads:any_<entity>_pii` from the entity name and the profile's `pii_cols` **with no check that the collection is actually unscoped**. `compose-attack-paths.py:813-819` then escalates every contributing finding in an unprivileged→crown-jewel chain **straight to CRITICAL, no cap** — against `phase-07-synthesis.md:121-123`'s "±1 rung regardless of how many triggers fire". | **47%** of all capability tags in the composition graph (531 of 1120) were minted by the C-rules. **53 of 73** HIGH+ C-rule findings ended CRITICAL — while **72 of 73** were false. 31 of the 44 false HIGH+ C-rule findings carry a `reads:*_pii` tag they did not earn. |

So a false positive stopped being a local triage cost and became a
**severity-inflation engine** that escalates its neighbours, including true
findings.

**`KNOWN-GAPS.md:195` predicted the C5 template blindness and dismissed it:**
*"the failure direction is a **false positive** — which a human closes — not a
silent pass."* That reasoning was sound in v2.3 and became false in v2.5 the
moment findings started minting capabilities. Nobody re-checked it.

> **Standing rule adopted by this epic:** a low-evidence finding must not be able
> to raise the severity of anything — itself or its neighbours. Any future
> "the failure direction is safe" argument must be re-checked against every
> downstream consumer of the finding, not just against the reader.

### 1.4 The two mechanical failures, at source level

**C-rules — `_strip_literals()` is not template-aware.**
`lib/validate-collection-scoping.py:510` treats a backtick identically to `'` and
`"`, so the entire body of a tagged template — including its `${…}`
interpolations — is blanked. `predicate_binds_caller()` (`:541`) tokenises the
*stripped* text and derives `components` from it too (`:551-552`, `:560`), so
both matching paths are blinded. Fatal on any drizzle/Kysely codebase, where the
caller predicate lives inside a tagged template by construction.

Stacked on top: `_CALLER_TOKENS` (`:126-134`) has no entry for the Postgres GUC
idiom, and a GUC name is a **single-quoted string literal** — precisely what
`_strip_literals` correctly discards for the case in its own docstring
(`eq(decks.scope, 'session')`). Neither fix alone is sufficient. Reproduced
against the shipped module:

| case | v2.5.0 | template-aware | + GUC lexicon | want |
|---|---|---|---|---|
| A tagged `` sql`…` `` + RLS GUC | False | False | **True** | True |
| B tagged `` sql`…` `` + `${session.teammateId}` | False | **True** | True | True |
| C drizzle builder API | True | True | True | True |
| D `eq(decks.scope, 'session')` — the docstring's motivating FP | False | False | False | **False** |
| E untagged `` `session expired` `` | False | False | False | **False** |
| F literal-only SQL predicate (`status = 'published'`) | False | False | False | **False** |
| G `` sql`path <@ current_setting('app.user_org_path')::ltree` `` | False | False | **True** | True |

A failed C5 does not cost one finding: `:723` rewrites `scope = "unscoped"`, so
C1 fires on the same row. The run contains matched pairs at identical
`file:line`. **Every false C5 costs two HIGH+ findings.**

Secondary, distinct source: the `fabricated` branch (`:692-697`) declares a scope
claim fabricated when the inventoried predicate is not a token subsequence of the
cited source window. It fires against handlers whose predicate is genuinely
present but two frames up the call stack. The rule is anti-laundering by design
and stays — but *"the predicate is not at the cited line"* and *"there is no
predicate"* are different claims and it files them with identical text and
severity.

**R-rules — a free-text resource name used as a cross-layer join key.**
`lib/validate-egress.py:384-424` builds a per-resource `floor` = the strongest
gate rank observed *anywhere* for that resource, joining on `serves_resource` —
**a free-text string an inventory agent wrote**. Everything sharing the string is
compared to everything else regardless of layer, process or trust boundary.
Three compounding effects:

- **(a) `_KIND_RANK` sets unreachable floors.** `:75-87` maps `capability` and
  `verification` to `GATE_VERIFIED` (3), reachable only by the keywords
  `2fa|mfa|otp|verif|step-up|…` (`:63-65`). Request-scoped RLS GUCs inventoried
  as kind `capability` gave every resource they touch floor 3 in an app with no
  step-up auth — so the **correctly gated** branch was filed HIGH.
- **(b) `gate_rank()` ranks unrecognised text as `GATE_NONE`.** Combined with (a)
  and the severity rule at `:448` (`CRITICAL if br == GATE_NONE and floor >=
  GATE_AUTHZ`), the emergent behaviour is that **the more precisely an analyst
  describes a real control, the more likely it is to rank 0 and be filed
  CRITICAL**. A paragraph of genuine, correct hardening containing none of the
  ranker's keywords was filed CRITICAL/CONFIRMED.
- **(c) R5 compares gates across layers that share no caller.** `:409-420` lets a
  non-byte-serving resolve-layer surface set the floor. Of 306 raw rows
  (R2 125 / R5 116 / R3 64 / R4 1), the triage found **115 compare an HTTP RBAC
  gate to a cron HMAC gate on `emits_bytes:false` surfaces**. A Vue click handler
  cannot enforce a gate; a cron worker's HMAC is not a weaker sibling of an HTTP
  RBAC check. Neither is a bug in the *idea* of R5 — both are the consequence of
  joining on an untyped string.

### 1.5 Four substantive errors — distinct from noise

Places where the report asserted something incorrect that a reader would act on.

| # | Error | Consequence |
|---|---|---|
| E1 | **A wrong refutation buried a real HIGH.** A refutation true of one module (*"the key never leaves the module"*) was generalised to a system property, in the **"What is sound"** table. Two call sites hand a GitHub App signing key to a function that puts it in an `Authorization: Bearer` header. | **The most dangerous class in the report.** A false positive costs a triager minutes and is self-correcting. A wrong refutation files a real HIGH under a heading the reader is told to trust and *stops* them reading the code. Nothing downstream reopens it. |
| E2 | **Right finding, wrong fix — twice, contradicting each other.** Six findings on one Postgres-TLS defect. Five prescribed a nine-site `ssl: { rejectUnauthorized… }` change plus CA bundling; one prescribed a **one-word** `?sslmode=verify-full` substitution and cited the driver source proving it. The correct one was in the minority and the report merged the wrong text into its priority list. | Fix text is what gets executed; it currently inherits the finding's confidence for free. |
| E3 | **A subsystem-wide remediation was wrong for 11 of 16 members.** *"Add `requireRegionScope` across `admin/reconciliation/**`"* — but the pivotal table has no region column, so 11 handlers have nothing to clamp. Adding one either no-ops or denies every region admin. Separately, the exemption list had one backwards: an unclamped cross-region hard `DELETE` on a table that *does* carry `region_id`. | **A subsystem-wide remediation is a claim about every member of the subsystem** and needs the same evidence bar as a finding. |
| E4 | **A ratified design record was overridden by inference.** The report filed a deliberate, documented asymmetry as the finding, writing *"the asymmetry **is** the finding"* — while the project's decision record named the twin control and the plan review confirmed the clamps are real and one policy arm is a tautology that can never deny. A narrow defect survives; the theme as filed does not. | Acting on the remediation would have added a call that cannot fire, against the design record. |

Severity inflation compounds all four. In one cluster, **13 of 15 findings
arrived CRITICAL**; eight of the fifteen were asserted **LOW or INFO** by the
analyst who wrote them (`LOW→CRITICAL` ×5, `INFO→CRITICAL` ×3) — the composer,
not the analyst, made them CRITICAL. The sharpest single case was asserted LOW
and computed CRITICAL for a dev-mode path that is **structurally unreachable** in
every deployed environment (an allowlist of `{local, sandbox}` with a fail-closed
`unknown` default), and it displaced real work at the top of a priority list.

### 1.6 The tool finds instances, not classes

34 defects (1 CRITICAL, 14 HIGH, 10 MEDIUM, 7 LOW, 2 INFO) were found by the
triagers and not filed. The distribution across clusters is even, so this is not
one weak partition. **The pattern is the finding: they are overwhelmingly the
second, third and fourth site of a defect the audit found once.**

| Defect class | Audit filed | Actual surface |
|---|---:|---:|
| Region-root placement writers | 2 | **4** |
| …and the seeds that plant the root | 1 | **3** |
| `postgres()` with no `ssl` option | 4 ("all four call sites") | **10** |
| Mutable GitHub Action tags | 4 | **10** of 12 |
| `'admin'` inside the RLS region bypass | 1 policy (and misnamed) | **25 clauses across 10 migrations** |
| Tests that create a non-owner role | 1 | **2** |
| Plain-HTTP downgrade (`? https : http`) | 1 | **7** |

Each of those counts is a **one-line grep**. A mechanical sweep does not get
bored at nine; both the tool and eight engineers did. This is also the consumer
project's own documented recurring failure mode (`feedback_walk_the_sibling_paths`
— *"recurred 5× across #201/#203"*), which makes it cheap and high-value rather
than a research problem.

Two of the 34 are genuinely novel classes and mark the edge of the detection
catalogue:

- **Local-filesystem exfil.** A repo-steerable state dir makes a hook write the
  live access token **into the attacker's own working tree**. No network call, so
  no egress rule can see it. `lib/egress-detection.md` models network modalities
  only.
- **Availability/integrity with no confidentiality component.** An uncapped
  provisioning call lets a developer mint enough empty rows to displace every
  real one from a downstream fixed-size scan, producing an estate-wide silent
  attribution stop. Nothing in the rule set looks for one.

---

## 2. What v2.6 does about it

Four waves. Waves 1 and 2 are entangled — both feed severity — and land
together. The contract change in **Wave 0** is a hard prerequisite for
everything else and lands on the epic branch before any fan-out.

### Wave 0 — the evidence contract (blocking, no parallel work before it merges)

`confidence` today conflates three orthogonal things: where the row came from,
whether anyone attacked it, and how much to trust the fix. Split them.

| Change | File |
|---|---|
| `evidence_class` ∈ `{external_scanner, heuristic_inventory, agent_judgement}` — **required** | `lib/finding-schema.json` |
| `attacked` ∈ `{not_attempted, confirmed, partial, refuted}` — replaces the un-owned `verification_status` (which appears **nowhere** in the skill; it is a run-level artifact of §6.19/§6.20) | `lib/finding-schema.json` |
| `fix_confidence` ∈ `{verified, inferred, untested}`; `verified` requires a cited line **in the dependency/driver/API being asserted about** | `lib/finding-schema.json` |
| `sibling_sites[]` + `sibling_pattern` — required on every HIGH+ finding | `lib/finding-schema.json` |
| `refutation_scope` — required on any refutation | `lib/finding-schema.json` |
| `deployment_reachability` ∈ `{reachable, gated_by_runtime_flag, structurally_unreachable}`; a cited line is **required** when not `reachable` (see §2.1) | `lib/finding-schema.json` |
| `rule_family`, `rules_fired`, and stable finding `id` carried into SARIF `properties` | `lib/finding-schema.json`, `lib/sarif-postprocess.md` |
| Category enum gains `linddun`; `owasp_ids` pattern accepts `LINDDUN-*` | `lib/finding-schema.json` (bug R7 #6 — LINDDUN findings are currently smuggled through `config`) |

### Wave 1 — severity integrity (P0)

| # | Story | File(s) | Closes |
|---|---|---|---|
| 1.1 | Only `evidence_class == external_scanner` grants the `+1` promotion. Amend §7.3 — *"scanners are mechanical ground truth"* is a category error for `validate-*.py`; require the source detail to name an **external** tool (semgrep, trivy, osv-scanner, gitleaks, trufflehog, hadolint) | `steps/phase-07-synthesis.md:70,107-108,132` | B2 |
| 1.2 | Delete the hardcoded `"confidence": "CONFIRMED"` at emission | `lib/validate-egress.py:368` | B2 |
| 1.3 | Gate capability minting on a *verified* unscoped determination; record per-tag provenance so a chain built on heuristic tags is visible in ORPHAN CAPABILITIES | `lib/validate-collection-scoping.py:610-617`, `lib/compose-attack-paths.py` | B3 |
| 1.4 | **Evidence-aware escalation** — see §2.1 below for the full resolution | `lib/compose-attack-paths.py:813-819`, `steps/phase-07-synthesis.md:121-123,137-139`, `lib/finding-schema.json`, `lib/report-template.md` | B3, §1.5 inflation |
| 1.5 | The report may **never** print a band mixing attacked-mechanical with unattacked-judgement findings. Report reading order by `evidence_class`, not by `attacked` | `lib/report-template.md`, `steps/phase-07-synthesis.md` | B1 |
| 1.6 | **The L1 age gate was keyed on the same broken label.** `compose-attack-paths.py:563` fired only on `confidence == "CONFIRMED"` HIGH+ findings — so the gate that exists to stop a real finding rotting for 96 days pointed at the 9.6%-true population and skipped the 92.1%-true one. Re-key on `evidence_class`, excluding only `heuristic_inventory`. *(Found during Wave 0 implementation; not in the calibration analysis.)* | `lib/compose-attack-paths.py:563` | B1, second consumer |

**Decided:** we do **not** extend adversarial confirmation to the deep-dives.
That was the alternative on the table; §1.5 E1 is direct evidence that refutation
is the dangerous direction, and pointing that machinery at the one 96.6%-precise
population risks the asset to fix a labelling bug. Budget goes to Wave 3 instead.

#### 2.1 Story 1.4 in full — the ±1 cap vs. the composer

The prose (`phase-07-synthesis.md:121-123,137-139`) says ±1 rung "regardless of
how many triggers fire". The code (`compose-attack-paths.py:813-819`) sets
CRITICAL outright, producing 7 `INFO→CRITICAL` and 38 `LOW→CRITICAL`. **The code
is right in principle; the prose is wrong and gets amended.** The resolution has
four parts and one deliberate asymmetry.

**Why the cap does not win.** v2.5's founding case was a MEDIUM whose own
description named the HIGH, in the same document, that supplied the capability
its mitigation assumed nobody had — unremediated 96 days, downgraded to LOW at
the next baseline, fixed only after a live `curl`. If the composer may bump one
rung, that finding becomes HIGH and the epic's thesis dies. **Composition is not
a calibration nudge.** The ±1 cap governs §7.4's context signals and nothing
else; these are two mechanisms and they get two rules, stated plainly.

**Why the composer is nonetheless not the main cause of the blowout.** 47% of the
graph's capability tags were minted by the C-rules with no evidence check, and 53
of 73 HIGH+ C-rule findings ended CRITICAL while 72 of 73 were false. Stories 1.3
(gate minting on a verified determination) and 2b.3 (annexed rows leave the graph
entirely) remove that at source. **Implement 1.4, then measure the residual
escalation volume before adding anything further** — do not stack two corrections
on one cause.

**The defect that survives that argument.** The dev-mode persona finding was
asserted LOW and computed CRITICAL on genuine tags and a genuine chain — yet
`isDemoCapableEnv` allowlists only `{local, sandbox}` with a fail-closed
`unknown` default, so dev, staging and production are **structurally**
unreachable. The analyst who rated it LOW already knew this. **The information
existed and had no channel to reach the composer.** That is the real bug: the
composer overrides an asserted severity *blind*, without seeing the reasoning
that produced it. The fix is to give that reasoning a field.

**The four parts:**

1. **Amend the prose.** §7.4's ±1 cap applies to context-signal adjustment only.
   R3 chain composition is uncapped and documented as a distinct mechanism. A
   reader calibrating on §7.4 currently mis-reads every composed severity.
2. **New optional finding field `deployment_reachability`** ∈
   `{reachable, gated_by_runtime_flag, structurally_unreachable}`, set by the
   analyst at assertion time, with a **required cited line** when not
   `reachable`. R3 escalation is suppressed only when a member of the
   contributing slice is `structurally_unreachable` *with a cite*.
   `contributing_slice()` (`:273`) already walks back and drops bystanders, so
   every member is load-bearing by construction — one unreachable member means
   the chain is not deployable, and no special-casing of the chain "entry" is
   needed.
3. **`gated_by_runtime_flag` does NOT suppress.** A flag an admin can toggle in a
   deployed environment is live, not theoretical — §1.5 E1's case is exactly that
   ("App mode is toggled at runtime by admins, so this is live"). Only a
   build-time or deploy-time structural constraint counts. This discriminator is
   the one the triage itself drew.
4. **Suppressed escalations are reported, never silent.** A
   `SUPPRESSED ESCALATIONS` block mirroring ORPHAN CAPABILITIES, listing what
   would have been CRITICAL and the cite that stopped it. Plus `rules_fired` and
   the escalating chain recorded on every composed finding — an unexplained
   CRITICAL is what made this run hard to triage.

**The asymmetry is deliberate and fail-open toward escalation.** Missing a
reachable chain is unrecoverable; escalating an unreachable one costs triage
time. So escalation stands by default and only positive, cited evidence stops it.
Part 4 exists because **suppression is now the dangerous direction** — the same
lesson as E1, where a wrong refutation buried a live HIGH under a heading readers
are told to trust. Making suppression loud is what stops `deployment_reachability`
becoming the next `CONFIRMED`.

### Wave 2 — mechanical precision (P0)

| # | Story | File(s) |
|---|---|---|
| 2.1 | Template-aware `_strip_literals`: preserve every `${…}` interpolation verbatim; when the backtick is **tagged** (preceded, modulo whitespace, by `[A-Za-z0-9_$)\]]`) preserve the body too — a tagged template body is *code*, not a data literal. **Length-preserving** (`_statement_at` depends on it) | `lib/validate-collection-scoping.py:489-538` |
| 2.2 | Pre-pass scoring `current_setting('app.user_*' \| 'rls.user*' \| 'request.jwt*')` as caller-bound **before** single-quoted literals are blanked, since the GUC name *is* a literal. Same tokens into `_CALLER_TOKENS` | `lib/validate-collection-scoping.py:126-134` |
| 2.3 | Split the two C5 messages: `fabricated=True` and `not predicate_binds_caller(pred)` are different claims with different follow-ups and must not share a finding shape or severity | `lib/validate-collection-scoping.py:692-697` |
| 2.4 | **Type the egress join.** A `layer` field on sinks/surfaces defaulted from the partition; `floor` computed per `(resource, layer)` so a browser component, a CLI script, a cron worker and an HTTP handler stop enforcing each other's gates | `lib/validate-egress.py:384-424`, `lib/sink-schema.json`, `lib/surface-schema.json` |
| 2.5 | Exclude non-network sinks — a `0600` write to the device's own home and a `console.log` to the invoking developer's stdout are not egress to an untrusted caller. Either excluded or given their own rule and severity | `lib/egress-detection.md`, `lib/validate-egress.py` |
| 2.6 | Cap a kind-derived floor at `GATE_AUTHZ` unless a real gate text at rank 3 is observed somewhere for that resource | `lib/validate-egress.py:75-87` |
| 2.7 | `gate_rank_hint` — a structured rank the inventory agent sets explicitly, with the keyword ranker demoted to fallback. A rich, correct gate description ranking 0 is the worst-case behaviour | `lib/validate-egress.py:112-127`, `lib/sink-schema.json` |
| 2.8 | **Three silent-corruption bugs** (all shipped in v2.5.0): `IndexError` on a sink whose `reachable_via` is present-but-empty (`.get(k, default)[0]` only defaults on a *missing* key) — **crashed §6.19 entirely**; neither validator reads an ignore file (only `validate-partition-coverage.py:148` does) — scanned an unrelated cloned repo under `tmp/`; `_norm` uses `str(p).lstrip("./")`, a **character set**, so `.output/` → `output/` — and it is imported into the collection validator at `:102`, so one bug in two validators | `lib/validate-egress.py:439,179`, `lib/validate-collection-scoping.py:102` |

**On 2.8:** bugs 2 and 3 together produced **64 phantom coverage failures that
masked 7 real credential gaps and 129 real collection gaps**. These are
fail-closed gates failing in the *noisy* direction, which is the specific way a
fail-closed gate stops being trusted. Sixty-four phantom failures is exactly the
volume at which an operator starts skimming.

### Wave 2b — the mechanical families become an annex, not findings

**The decisive fact:** of the 17 true mechanical findings, **15 are restatements
of a deep-dive finding on the same line** — the verdict text says so almost
verbatim each time. The only pair with no deep-dive twin is an ACCEPTED_RISK.
**The mechanical rules did not surface a single unique CRITICAL in this run.**
Any claim that they "found 16 real defects" is double-counting.

But they are not worthless, and deleting them is the wrong call for three reasons
that survive that correction:

1. **They produced the complete fix surface, mechanically.** The deep-dive found
   the credential-exfil *class*; R2/R3/R5 enumerated its **nine distinct legs at
   exact line granularity**. Precision is the wrong metric for a rule whose
   product is a surface rather than a conclusion.
2. **Deleting them trades a mechanical guarantee for an agent's diligence** — and
   §1.6's 34 misses are direct evidence that LLM analysts do not reliably
   enumerate.
3. **The C-rule concept has never actually been tested.** Its 1.4% rate measures
   `_strip_literals`, not C1/C5. Judging the rule on this run would retire a
   sound idea for an unrelated bug.

So: **re-cast, don't delete.** R/C output attaches to the deep-dive finding on
the same line as a **fix-surface annex** ("this class has these nine legs"),
rather than being filed as independent findings.

| # | Story | File(s) |
|---|---|---|
| 2b.1 | Annex model: mechanical rows join to a judgement finding by `(file, line)` then `(file, cwe)`; joined rows populate that finding's `sibling_sites[]` and never carry their own severity | `steps/phase-07-synthesis.md`, `lib/finding-schema.json` |
| 2b.2 | **Orphan annexes** — mechanical rows with no judgement twin — surface as an explicitly-labelled low-confidence lead list, capped out of the headline band. This is the recall preservation; it must not be dropped | `lib/report-template.md`, `steps/phase-07-synthesis.md` |
| 2b.3 | Annexed rows are excluded from the capability graph entirely | `lib/compose-attack-paths.py` |

This removes ~154 HIGH+ rows from the findings stream **by construction** rather
than by threshold tuning, and removes the B3 escalation path at its source.

### Wave 3 — assert less, verify more (P1)

| # | Story | File(s) | Closes |
|---|---|---|---|
| 3.1 | **Sibling sweep.** Every finding surviving to HIGH+ requires one mechanical pass: derive the defect's shape as a grep/AST pattern, run it repo-wide, report the full site list — *or state explicitly that the cited site is the only one*. `sibling_sites: []` is a **claim**, not a silent omission | `steps/phase-07-synthesis.md` (post-§7.3), `steps/phase-05-deepdives.md` | §1.6 — ~20 of 34 misses |
| 3.2 | **Scope every refutation.** A refutation carries the boundary of what was examined. A "What is sound" row backed by a single module may not make a system-level assertion. When a finding alleges *credential X reaches sink Y* and the analyst refutes it by reading X's producer, require a **caller enumeration of the accessor** before the refutation is accepted. Surface refutations at *lower* default confidence than findings — a negative claim over a large surface is harder to establish than a positive claim about one line | `steps/phase-05-deepdives.md`, `lib/report-template.md` | E1 |
| 3.3 | **`fix_confidence`, plus a contradiction check:** two findings on the same defect with the same CWE whose `suggested_fix` texts disagree ⇒ flag for reconciliation rather than shipping both | `lib/finding-schema.json`, `steps/phase-07-synthesis.md` | E2 |
| 3.4 | **A subsystem-wide remediation must enumerate its members.** "Add X across `path/**`" is not emittable without an enumerated member list carrying the same evidence bar as a finding | `lib/report-template.md`, `steps/phase-07-synthesis.md` | E3 |
| 3.5 | **Design-record deference.** When a decision record ratifies an asymmetry, the burden shifts: an inference that "the asymmetry *is* the finding" requires an explicit rebuttal of the record. The sentence *"the asymmetry is the finding"* is precisely the one to be suspicious of when a decision record exists | `steps/phase-05-deepdives.md`, `steps/phase-00-discovery.md` (design-doc discovery) | E4 |

### Wave 4 — hygiene and catalogue (P2)

| # | Story | File(s) |
|---|---|---|
| 4.1 | **Dedup on id as a first pass; assert id uniqueness before writing SARIF.** 1361 rows carried only 1256 distinct ids; seven `config` ids appeared **six times each** (three distinct payloads among the six) and the ASVS ids four times each. `§7.2` dedups on `(file, line, category, fingerprint)` and only 420 of 1361 rows carry a `fingerprint` at all. Nine surplus rows were inside the HIGH+ population, so the headline counts were all slightly overstated | `steps/phase-07-synthesis.md:78` |
| 4.2 | `asvs-l2.md` is headed *"OWASP ASVS 5.0 Level 2"* and enumerates 4.0.3's category set. Fix the content or retitle — the report currently has to caveat its own ASVS claim | `lib/asvs-l2.md:1` |
| 4.3 | **New modality: local-filesystem exfil.** A repo-steerable path that lands a live credential in an attacker-readable location is exfil with no network call. Extend the sink model past network egress | `lib/egress-detection.md`, `lib/sink-schema.json` |
| 4.4 | **New class: availability/integrity attack paths with no confidentiality component.** Resource-exhaustion-into-silent-data-loss currently matches nothing | `steps/deepdive/`, `lib/capability-lexicon.md` |
| 4.5 | **Standing calibration control.** Record each rule family's last measured true-positive rate in the skill; a family below threshold cannot enter the headline severity band. Converts this one-off calibration into a permanent gate | `manifest.yaml`, `steps/phase-07-synthesis.md` |
| 4.6 | `scripts/calibration-report.py` — join a `phase-07-findings-computed.jsonl` to a verdict file and emit the §1.2 tables. Makes the *next* calibration a command rather than eight engineers | `scripts/` |

---

## 3. Acceptance tests

**A re-run measures change, not truth.** Re-running v2.6 on the same target
produces a new finding set but no new labels — it can show the C-rules dropped
from 73 HIGH+ to 3, but not whether those 3 are true. So every criterion below is
a predicate checkable against the v2.5.0 run or against a fixture, not a claim
about precision.

### 3.1 Unit — the `_strip_literals` truth table

Seven synthetic cases in `tests/fixtures/collection-scoping/`, exactly the table
in §1.4. **Cases A, B and G must flip to `True`; cases D, E and F must stay
`False`** — including `eq(decks.scope, 'session')`, the false positive the
docstring exists to prevent. A patch that fixes A/B/G by also flipping D/E/F has
traded one failure mode for another and fails this gate.

### 3.2 Regression — the recall floor

The 17 mechanical findings the triage returned REAL or ACCEPTED_RISK, by rule and
site. After the Wave 2b re-cast they become annex legs rather than findings, but
**every one of these sites must still appear somewhere in the output**:

| rule | site | what it is |
|---|---|---|
| R2/R3 | `otel-headers-helper.sh:120` | refresh-grant curl to a repo-chosen host |
| R2/R3 | `otel-headers-helper.sh:283` | `/bearer` presentation curl |
| R2/R3 | `landed-check.mjs:54` | live access token to an unvalidated host |
| R2 | `project-check.mjs:90` | same pattern, `/project-resolve` leg |
| R2 | `plugin-runtime.mjs:77` | `node:http` downgrade on the POST body |
| R5 | `otlp-forwarder.mjs:150`, `:146` | both legs of the unauthenticated relay |
| R5 | `otlp-capture-server.mjs:22`, `:23` | argv-controlled write |
| R5 | `backfill.mjs:469` | the POST leg |
| R5 | `otlp-forwarder.mjs:123` | unauthenticated `/healthz` |
| R2/R3 | `setup/enroll.post.ts:145` | ACCEPTED_RISK — provisional emit-only credential |
| C5 | `cost-centres.ts:151` | genuine resolve-then-check ordering gap |

**A silent drop here is a recall regression and blocks the release**, regardless
of how good the precision number looks.

### 3.3 Regression — the sibling-sweep target

Story 3.1 must surface the full surface, not the first instance, for each class
in §1.6. Each is one grep; a run that files 1 of 25 RLS bypass clauses, or 4 of
10 `postgres()` call sites, has not passed.

### 3.4 Invariant — severity integrity

- No finding with `evidence_class != external_scanner` receives the `+1` promotion.
- No capability tag in the composition graph originates from an unverified
  heuristic determination.
- Every finding computed CRITICAL names the composition rule that made it so.
- The prose cap in `phase-07-synthesis.md` and the behaviour of
  `compose-attack-paths.py` agree — asserted by a fixture, not by reading.

**Escalation fixtures** (extending `tests/fixtures/attack-paths/`):

| fixture | asserts |
|---|---|
| `chain` (existing) | uncapped `LOW→CRITICAL` still fires for a reachable chain — the ±1 cap must **not** have leaked into R3 |
| `unreachable` (new) | a contributing member marked `structurally_unreachable` **with** a cite suppresses the escalation, and the finding appears in `SUPPRESSED ESCALATIONS` |
| `uncited` (new) | `structurally_unreachable` **without** a cite does **not** suppress — the field must not become a free pass |
| `flagged` (new) | `gated_by_runtime_flag` does **not** suppress |
| `bystander` (existing) | a member outside the contributing slice cannot suppress a chain it is not load-bearing in |

### 3.5 Invariant — the report

- No severity band mixes `evidence_class` values.
- No "What is sound" row makes a system-level assertion from a single-module
  examination.
- No `path/**`-shaped remediation without an enumerated member list.
- Id uniqueness asserted before SARIF is written.

---

## 4. Honest scope — what v2.6 does NOT claim

- **The 96.6% deep-dive rate is one run on one codebase.** It is a Nuxt/h3/drizzle
  TypeScript monolith. Nothing here establishes that rate on a polyglot repo, a
  Java monolith, or a Go service mesh.
- **The C-rule concept remains untested.** v2.6 fixes the mechanism that made its
  1.4% meaningless. Whether C1/C5 are *good rules* is still an open question and
  the next calibration is the first honest measurement of them.
- **We do not fix the fact that both reconciliations trust an agent-populated
  inventory** (`KNOWN-GAPS.md:87`). Typing the join key and capping kind-derived
  floors reduce the blast radius of a bad inventory row; they do not verify it.
- **The sibling sweep is grep-shaped.** It catches classes expressible as a
  pattern. A defect whose siblings differ structurally — the same bug written
  three different ways — remains an agent-diligence problem.
- **No runtime verification.** Everything here remains static analysis over
  source plus an LLM's reading of it.
- **The two novel classes in §1.6 are a catalogue extension, not a general
  solution.** Local-filesystem exfil and availability-only attack paths are now
  *modelled*; there is no claim that the model is complete for either.
