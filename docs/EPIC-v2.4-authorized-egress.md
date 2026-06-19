# EPIC — v2.4: Authorized-Egress detection

Status: **BUILT** (2026-06-19). Design adversarially reviewed *before* implementation.
Motivating RCA: an external-2FA-sharing bug that survived multiple `/security-audit`
runs and two adversarial reviews (the operator's write-up, kept out of the repo).

## 1. Why this exists

A deck-sharing platform gated an external-share 2FA check **only at the discovery
layer** (a `/s/{shortId}` resolver that withholds the `deckId` until a signed
`__sv_` verification cookie is presented). The byte-serving content endpoints
(`build-output`, `external`, an asset-proxy middleware) **never read that cookie** —
they served whenever any active publish link existed, ignoring `requireVerification`.
Anyone who learned the `deckId` (handed to every viewer's browser as an iframe
`src`) could stream full content without completing 2FA.

One writer of the cookie, one reader (the resolver), **three byte-serving sinks that
read it zero times.** The asymmetry *is* the vulnerability. It generalizes to
sessions, CSRF tokens, signed URLs, capability tokens, feature-flag gates, licence
checks — the class is **"a control minted but never enforced on the path that
matters"** (confused deputy / capability-URL / missing-enforcer).

### Why the skill missed it (architectural, not a missing grep)

- Phase 5 fans out **per-partition × per-category**; the sub-agent template
  *enforces* local reasoning ("don't read outside scope", "handler ±40 lines"). The
  credential's writer and the resource's sink live in different partitions — each
  looks locally correct.
- Phase 2 inferred `auth_required` **per row** from a local check; the sink's authed
  branch reads as "authed", so its conditional unauthenticated-bypass branch is
  invisible.
- Delta mode carries a baseline gap forever (a pre-existing gap is not a *delta*).
- Nothing inventoried **egress of sensitive data** or built a credential
  mint→consume map.

The skill's core strength — exhaustive partitioned fan-out with tight per-handler
context — is the exact mechanism that makes this class invisible. The fix is partly
**anti-architectural**: a global, path-sensitive pass plus a deterministic engine.

## 2. Objective and honest scope

**Objective (operator-stated):** reliably catch this *and any other path that returns
sensitive data without the required permission*, including cross-layer gaps.

**What we claim (and ship in SKILL.md + the report):** we reliably catch the
confused-deputy / capability-URL / missing-enforcer class (incl. conditional-bypass
branches and cross-layer gates) and raise recall across the egress family, backed by
a **fail-closed coverage gate** so a silent omission breaks the run. **A clean
reconciliation is high-signal but NOT a proof of absence.** The universal "catches
ANY path" claim is unmeetable by an agent-populated-inventory + rules approach; we
do not make it. CDN-edge egress with no code path, and modalities outside
`lib/egress-detection.md`, are surfaced as caveats — never silently dropped.

## 3. Design — three layers

The RCA's key lesson is *don't rely on the agent noticing* (the skill already had
auth invariants + a review pass and still missed it). So detection is mechanical
where it can be:

1. **Deterministic candidate extraction (no LLM)** — `lib/egress-detection.md` +
   the extractor in `scripts/validate-egress.py` grep per-framework anchors for
   every egress modality and credential site. Ground truth for coverage.
2. **Agent enrichment, fail-closed** — Phase 2 §2.11 builds path-sensitive
   `phase-02-sinks.json` + `phase-02-credentials.json`. The agent must **account for
   every candidate** (a sink with per-branch `guarded_paths`, or a `dismissed[]`
   entry with a reason). Any unaccounted candidate, or any `coverage: incomplete`,
   FAILS the run.
3. **Deterministic reconciliation + adversarial confirmation** — Phase 6 §6.19 runs
   `validate-egress.py` (rules R1–R5) over the global inventories, then an
   attack-not-summarize sub-agent fan-out ("construct the unauthenticated request
   that returns the bytes, or prove it impossible") writes the `verification_probe`.

**Sensitivity = default-deny.** Every served entity is sensitive unless on an
agent-proposed, report-surfaced `public_resources` allowlist. Join key is the
canonical `data_model` entity id.

### Rule ↔ failure-mode map

| Rule | Fires when | CWE | Catches |
|---|---|---|---|
| R2 | R served by ≥2 sinks with differing min-branch gates | 862 | the weaker sibling sink |
| R3 | a byte-serving branch ungated / gated only by "identifier known" on a sensitive R | 639/441 | capability-URL / id-as-secret |
| R4 | a credential is minted (writers≠∅) but has **zero readers anywhere** | 862 | pure theatre — issued credential with no consumer |
| R5 | R's strongest gate sits only on a resolve/identify surface, not a byte sink | 862 | **the cross-layer deck bug** |

Gates are ranked **negation-aware** (an absent control described in prose ranks
NONE; conservative — over-flag, never silently pass). A credential protecting R
raises R's floor, so an ignored credential on the byte path surfaces as an R5/R2
deficit. (The v2.4-draft "R1" substring-consumption rule was **removed** in the
post-build review — it false-positived on credentials enforced in middleware.)

## 4. The adversarial review (pre-build) and how each finding was addressed

An independent reviewer red-teamed the first design against the objective. It found
the lean design would have *missed the very bug it targeted* (3 of 4 original rules
silent). Every P0/P1 was folded into the shipped design:

| Review finding | Resolution in v2.4 |
|---|---|
| **P0 path-insensitive model** — couldn't express "authed branch + bypass branch" | `guarded_paths[]` per **branch**; reconciliation evaluates each branch; `coverage: incomplete` is a fail-closed deficit |
| **P0 GIGO / "mechanical" is a misnomer** — green run reads as "proven safe" | **Fail-closed coverage gate**: deterministic extractor candidates must each be accounted-for or dismissed, else the run FAILS. Honest framing everywhere: clean ≠ proof of absence |
| **P0 Express-biased anchors** — misses GraphQL/gRPC/SSE/presigned/proxy/auto-serializers | `lib/egress-detection.md` per-framework catalogue; extractor recall is itself CI-tested over a synthetic polyglot app |
| **P1 rules don't fire on the real bug** — gate lived at a non-sink layer | **R5 cross-layer** added; R4 reframed to per-path partial-consume |
| **P1 sensitivity boundary wrong** — real sensitivity was a share gate, not owner/pii cols | **Default-deny** + `access_mechanisms` (share/2FA) force sensitivity; `public_resources` allowlist for precision |
| **P2 delta contradiction** + resource-rename masks the join | Egress inventories + §6.19 **always regenerate globally**, never carried from baseline; resource-id rename invalidates egress findings |
| **P2 tests stub the hard step** | Synthetic **source app** (extractor recall tested from real source) + **metamorphic battery** (gate-moved, conditional-bypass, resource-rename, sink-kind-swap) each asserted caught |

Reviewer's blunt verdict — *"the universal objective is unmeetable by this approach;
either commit to the harder build or drop the universal claim"* — was taken
literally: **we built the harder version AND dropped the universal claim.**

### 4b. Second adversarial review — of the BUILT CODE (the 2× gate)

The project's standing methodology is a **2× adversarial gate**. The first pass
(above) reviewed the *design*; a second independent pass reviewed the *built code*
and found three P0 bugs a design review structurally cannot catch — each fixed
before merge:

| P0 | Defect (in the built `validate-egress.py`) | Fix |
|---|---|---|
| P0-1 | **Negation-blind ranker** — a vulnerable branch described in prose ("unauthenticated", "no role check") ranked as *gated* (it contains "auth"/"role") ⇒ the flagship class produced **0 findings**. | `gate_rank()` is now negation-aware: negation/no-gate markers dominate ⇒ NONE; unrecognized text ⇒ NONE (conservative). Regression fixture `prose-gap/`. |
| P0-2 | **Coverage gate file-granular ⇒ fail-OPEN** — one inventoried sink "accounted for" every other sink in the same file. | Coverage is now **line-scoped** (±15-line tolerance). Regression fixture `line-mask/`. |
| P0-3 | **Substring consumption ⇒ false positives** — R1/R4 inferred credential "consumption" from substring-in-gate-text, firing 2 FPs on the correctly-gated `Invoice` in the demo fixture itself. | R1 removed (credential raises the floor ⇒ R5/R2 catches ungated paths); R4 redefined as **zero-readers-anywhere** theatre (FP-safe). Tests now assert **exact counts + zero FPs on Invoice**. |

Also addressed: extractor expanded toward the catalogue (redirect/async/gRPC/Go/
Rails/more Python), `public_resources`-absent NOTE (default-deny visibility),
CI now schema-checks `tests/fixtures/egress/**`, and the tests upgraded from
substring-presence to **exact-finding-set + precision** assertions. The reviewer's
verdict was **"NOT mergeable as-is"**; all four required fixes landed and the test
suite now asserts the regressions it previously missed.

## 5. File inventory

**New:** `scripts/validate-egress.py`, `lib/egress-detection.md`,
`lib/sink-schema.json`, `lib/credential-ledger-schema.json`,
`tests/test-egress.sh`, `tests/fixtures/egress/**` (deck-bug, omitted-sink,
source-app, metamorphic/m1–m4), this EPIC.

**Changed:** `lib/finding-schema.json` (+`verification_probe`),
`lib/profile-schema.json` (+`access_mechanisms`, `public_resources`, entity `id`),
`lib/surface-schema.json` (+`serves_resource`/`intended_gate`/`emits_bytes`/
`guarded_paths`), `lib/cwe-map.json` (+CWE-441), `lib/delta-mode.md`,
`lib/report-template.md`, `steps/phase-00-discovery.md`, `steps/phase-02-surface.md`,
`steps/phase-06-config.md` (§6.19), `steps/phase-07-synthesis.md`,
`steps/deepdive/cat-01/02/03`, `manifest.yaml`, `SKILL.md`, `.github/workflows/ci.yml`,
`VERSION` (2.4.0), `CHANGELOG.md`, `README.md`, `docs/INSTALL.md`.

## 6. Definition of done

- [x] Deterministic reconciliation catches the deck bug (R3/R4/R5 + CRITICAL) with a probe.
- [x] Fail-closed coverage gate fails on an omitted sink.
- [x] Extractor recall verified across modalities from real source.
- [x] Metamorphic battery (4 mutants) all caught.
- [x] All static validators green (`validate-schemas.sh`, schema validation, `test-egress.sh`).
- [x] VERSION/CHANGELOG/README/INSTALL/manifest bumped to 2.4.0; pins consistent.
- [ ] Live-container E2E (agent builds the inventory from source end-to-end) — the
  one un-run gate, blocked by the pre-existing Claude-auth requirement for the local
  E2E harness (same blocker as prior releases). The synthetic `source-app` is wired
  as the target for it.

## 7. Verification

```bash
bash tests/test-egress.sh        # deck-bug + coverage gate + extractor recall + metamorphic battery
bash scripts/validate-schemas.sh # repo-wide schema/ref/CWE/pin validation
python3 scripts/validate-egress.py tests/fixtures/egress/deck-bug/*.json --partition deck  # → exit 1, R3/R4/R5
```
