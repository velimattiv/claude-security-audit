# EPIC v2.5 — Sufficiency & Severity Arithmetic

**Status:** shipped
**Trigger:** an enhancement handoff filed against a live v2.4.0 run
(`audit_id 2b9bc21f05ba077e92fce5783d31a97a`, 2026-07-25) — target: a Nuxt 4 +
h3/Nitro platform, ~337k LOC, 246 HTTP surfaces, 38 tables, mode `full`, all six
scanners present, **no degraded mode**.

**One-line summary of the trigger:** the run produced a clean bill for an
endpoint that discloses every user's private data to any authenticated caller.

---

## 1. What actually failed

### 1.1 The defect

```ts
// server/api/content/tree.get.ts
export default defineEventHandler(async (event) => {
  const session = await requireRole(event, 'reader')             // :290  gate EXISTS
  ...
  .where(and(eq(decks.scope, 'user'), isNull(decks.deletedAt)))  // :231  no owner predicate
  ...
  const tree = applyCanWrite(rawTree, session)                   // :350  decorates, never filters
  return { data: tree }
})
```

Any authenticated user received a browsable directory of every other user's
private decks: UUID, title, description, slide count, owner roster. Chained with
a sibling endpoint admitting any known id, it yielded full slide markdown. Rated
CRITICAL by hand; **the audit machinery rated it nothing at all.**

### 1.2 Four root causes, not two

The handoff identified three. Reading the code found a fourth, and it is the
sharpest one.

| # | Mechanism | Why it passed |
|---|---|---|
| A1 | **cat-02 candidate filter** | The filter requires a path/query param matching `^(id\|[a-z]+Id\|[a-z]+_id)$`. A collection route `/resources` has **no id param**, so it never became a candidate — and cat-02's own invariant #2 ("list endpoints filter the result set by the authenticated scope") and its "Search / list endpoints" detection pattern were **structurally unreachable in practice**. The rule was on the page and could never fire. *(Found while implementing; not in the handoff.)* |
| A2 | **Phase 2 surface inventory** | Recorded `auth_required: true`, `roles_required: ['reader']`, `flags: []`. Every field records gate **presence**. No field could express *authentication was used where per-row authorization was required*. Negation-aware conservative ranking does not help — it fires on absent/ambiguous gates, and this gate is neither. |
| A3 | **Phase 1 partition → Phase 5 fan-out** | `server/api/content/` matched **no** partition path-glob and fell into a catch-all silently ("explicit partition membership: NONE"); its nearest partition ranked **#9** against a default `top_n: 8`. It got a deep dive only because a human promoted it by hand. |
| A4 | **Phase 6 §6.19 egress reconciliation** | The sink inventory admitted only **byte-emitting** sinks. This handler returns JSON, so it never entered `phase-02-sinks.json`. v2.4's flagship control targets "capability minted at layer A, never consumed at layer B"; this is a different shape — **the gate IS consumed, at the wrong granularity**. |

### 1.3 The second gap: severity was asserted, not computed

From the same product's 2026-03-15 audit, verbatim:

```
#### M6: Build output bypasses publish-link verification
- Confidence: CONFIRMED (found by Phase 1a)
- Description: ... build-output bypasses that if the deck UUID is known.
  Combined with H1, an attacker can identify published decks and access output directly.
```

`H1` — *"GET /api/decks returns ALL decks (including private) to any
authenticated reader — enables enumeration"* — was a **HIGH in the same
document**, supplying exactly the capability M6's mitigation ("if the deck UUID
is known") assumed nobody had.

M6 was filed **MEDIUM**. Unremediated for **96 days**; downgraded to **LOW** in
the 2026-04-26 baseline; the sibling endpoint affirmatively described as
*"well-defended" (INFO)*; fixed only after a live `curl` demonstration. Total
exposure ≥103 days.

**Chain detection was not the failure.** A human wrote the chain down, in prose,
in the finding's own description — and then assigned severity by category and
instinct, because nothing in the methodology gave that sentence power over the
rating.

### 1.4 A fifth defect, found during implementation

`phase-06-config.md §6.19` invoked `$SKILL_DIR/scripts/validate-egress.py`.
Installation copies **only** `skills/security-audit/` to
`~/.claude/skills/security-audit`; the repo-root `scripts/` directory is not
part of it. **v2.4's flagship deterministic control could not execute from any
real install.** A control with no enforcer — the exact bug class it was written
to detect, in the skill itself.

`validate-findings.py` also existed as two byte-divergent copies, only one of
which shipped.

---

## 2. What v2.5 does about it

Three deterministic gates plus one new category, following the v2.4
`validate-egress.py` pattern: a script, a fail-closed coverage gate, fixtures,
and CI.

### 2.1 Gap A — sufficiency

| Change | File |
|---|---|
| Collection row-scoping inventory (new Phase-2 artifact) | `lib/collection-schema.json`, `steps/phase-02-surface.md §2.12` |
| Deterministic reconciliation, rules C1–C5 + fail-closed coverage | `lib/validate-collection-scoping.py`, `steps/phase-06-config.md §6.20` |
| New deep-dive category 12 (`collection_scope`) | `steps/deepdive/cat-12-collection-scoping.md` |
| cat-02 scope boundary made explicit + cross-reference | `steps/deepdive/cat-02-idor-bola.md` |
| Partition coverage **asserted**, unmatched files fail Phase 1 | `lib/validate-partition-coverage.py`, `steps/phase-01-partition.md §1.6b` |
| Evidence-based partition promotion (surface evidence outranks a-priori rank, uncapped by `top_n`) | `steps/phase-02-surface.md §2.13` |
| New surface flags `RETURNS_OTHER_PRINCIPALS_ROWS`, `PERMISSION_DECORATION`; data breadth vetoes the dev-zone demotion | `steps/phase-02-surface.md §2.7`, `steps/phase-07-synthesis.md §7.4` |
| Egress sink kinds widened past bytes (`json_collection`, `json_metadata`, `identifier_list`) | `lib/sink-schema.json`, `lib/egress-detection.md` |

**The rules.**

- **C1** — a collection of a sensitive entity with no caller-bound predicate, no
  filtering visibility helper, and no `public_resources` entry (CWE-1220).
  `role_restricted` counts as unscoped unless the role is admin-tier.
- **C2** — authorization by decoration: a per-row permission computed and
  attached rather than applied (CWE-863). Write-permission decoration on a
  collection that was never read-filtered is a finding **by construction**.
- **C3** — `coverage: incomplete|caveat` surfaced as an open question, not a pass.
- **C4** — a sibling **test** asserting another principal's row is *present*
  (rather than absent/404). High-signal because someone wrote it deliberately:
  the insecure behaviour is the expected behaviour, so a correct fix looks like a
  broken test.
- **C5** — a `caller_bound` claim whose evidence predicate references no
  session/user/tenant/org value is rewritten to `unscoped`, and C1 then fires.
  **The whole design depends on an agent populating the inventory honestly, so
  the reconciliation does not take the claim on trust.**

### 2.2 Gap B — severity arithmetic and finding lifecycle

| Change | File |
|---|---|
| Capability grammar, personas, crown jewels | `lib/capability-lexicon.md`, `steps/phase-00-discovery.md §0.14` |
| `preconditions` / `postconditions` / `severity_asserted` / `severity_computed` / `severity_history` / `lifecycle` / `first_seen_at` | `lib/finding-schema.json` |
| The gate itself (R1–R4, L1–L3) | `lib/compose-attack-paths.py`, `steps/phase-07-synthesis.md §7.15` |
| Capability tagging enforced for access-control categories | `lib/validate-findings.py --require-capabilities`, `templates/subagent-prompt.md` |
| Lifecycle carried forward, never reset; **no baseline while governance fails** | `steps/phase-08-baseline.md §8.1/§8.4`, `lib/baseline-schema.json` |

**Two deliberate improvements over the reference implementation** shipped with
the handoff (`compose-attack-paths.py`, ~150 lines):

1. **Backward slice for R3.** The reference escalated *every* finding reachable
   by a persona to chain severity. That over-escalates bystanders. v2.5 walks
   back from the crown jewel through unmet preconditions and escalates only the
   findings that actually **contribute**. The `chain` fixture asserts a LOW
   crypto finding reachable by the same persona survives untouched.
2. **Project-agnostic personas, jewels, and id resolution.** The reference
   hard-coded deck-product personas, crown jewels, and a finding-id regex
   (`SHARE-[A-Z]+|ORCH|PRES|H|M|C|L`). v2.5 derives them from the profile
   (Phase 0 §0.14), falls back to capability *patterns* so R3 still works when
   Phase 0 fails to emit a lexicon, and resolves R2 references against the ids
   actually present in the corpus plus declared aliases.

**Plus an honesty feature the reference lacks:** the gate prints
**ORPHAN CAPABILITIES** — preconditions nothing supplies, postconditions nothing
consumes. A chain that should have composed and did not is now visible. An empty
orphan list is evidence the arithmetic ran; a long one means the gate is quietly
inert.

### 2.3 The install-path fix

All audit-time validators moved to `skills/security-audit/lib/` (the directory
that ships). Repo-root `scripts/` keeps thin shims so existing invocations, CI,
and docs keep working while divergence becomes structurally impossible. A CI
step now asserts **every** `$SKILL_DIR/<path>` referenced anywhere in the skill
resolves inside the shipped directory.

---

## 3. Acceptance tests

The handoff proposed four. All four ship, plus a negative control for each gate
— because a gate that fires on everything gets disabled, and a disabled gate
catches nothing.

| # | Acceptance test | Where |
|---|---|---|
| 1 | The `tree.get.ts` shape emits a finding **with no operator hint** about traversal, sharing, or enumeration | `tests/fixtures/collection-scoping/tree-bug/` |
| 2 | `A(post=[knows:ids])` HIGH + `B(pre=[knows:ids], post=[reads:content])` MEDIUM ⇒ B escalates to CRITICAL, exit non-zero | `tests/fixtures/attack-paths/chain/` |
| 3 | Prose-only fixture ("Combined with H1, …") with **zero** capability tags still escalates | `tests/fixtures/attack-paths/prose/` |
| 4 | MEDIUM→LOW with no reason fails the run | `tests/fixtures/attack-paths/ratchet/` |
| + | Zero false positives on a correctly-scoped collection and a genuinely public catalogue | `tree-bug/` (`me/decks.get.ts`, `products/index.get.ts`) |
| + | A downgrade **with** a recorded `fix_commit` reason passes | `ratchet/` (`app:auth:0002`) |
| + | An owned, unexpired risk acceptance is respected by L1 | `lifecycle/` (`app:auth:0002`) |
| + | Real-but-unchained findings exit 0 | `attack-paths/clean/` |
| + | A complete partition manifest passes | `test-collection-scoping.sh` |

Run: `bash tests/test-collection-scoping.sh && bash tests/test-attack-paths.sh`.
Both are wired into `.github/workflows/ci.yml`.

---

## 4. Honest scope — what v2.5 does NOT claim

- **A clean C1–C5 run is not a proof of absence.** A scope applied by an
  un-modelled mechanism (a base scope, a tenant-injecting repository, database
  RLS) is missed in the *conservative* direction — the reconciliation over-flags
  and the §6.20 adversarial pass retires the false positive by naming the
  file:line of the predicate. A query assembled entirely at runtime is recorded
  as `coverage: caveat`.
- **The composer can only compose what was tagged.** A capability nobody wrote
  down joins nothing. R2 backstops untagged chains named in prose; the orphan
  list backstops R2. Neither makes chain analysis complete.
- **Both reconciliations operate on an agent-populated inventory.** C5 and the
  coverage gates make dishonest or absent inventory *loud*, not impossible.
- **L1's 30-day threshold is a policy default,** not a derived constant. Tune it
  with `--max-age-days`; the point is that *some* threshold exists and is
  enforced mechanically.

## 5. Framing correction carried from the handoff

The audited product's own RCA concluded that *"several security audits and two
adversarial reviews failed to surface it"* and responded with a programme of
**detection** improvements. The repo's own artifacts contradict that: the issue
was surfaced **twice**, correctly, and lost in triage.

That is why roughly half of v2.5 is not detection at all. R4, L1–L3, the
lifecycle state machine, and Phase 8's refusal to write a baseline while
governance failures stand are aimed squarely at the gap between **found** and
**fixed** — the gap that a better scanner cannot close.
