---
name: security-audit
description: "Comprehensive polyglot security audit across 60+ frameworks. Runs a SARIF scanner bundle, fans out 12 parallel deep-dive categories (incl. supply-chain, MCP/agentic and collection-scoping/BOLA-at-list-level), computes severity over composed attack paths rather than asserting it per finding, and emits an OWASP-methodology-tagged report. Invoke when the user says 'run security audit', 'security audit', 'audit security', or passes args like 'mode: delta' / 'scope: services/api' / 'categories: crypto,mitm,secrets' / 'output: docs/security-audit-output'. Typical run 15-60 min (full) or 2-5 min (delta). MANDATORY ARTIFACT CONTRACT: every run MUST write (1) .claude-audit/current/ as your FIRST tool action via mkdir -p; (2) per-phase phase-NN-*.json AND a phase-NN.done marker for each completed phase 0-7 (8 if mode=full) BEFORE moving to the next phase; (3) findings.sarif (SARIF 2.1.0) where EVERY results[] row carries properties.security-severity (CVSS-style numeric) AND properties.cwe (e.g. 'CWE-798' — required for downstream tooling, lookup in lib/cwe-map.json) AND optionally properties.category (one of: auth, idor, token_scope, collection_scope, mitm, crypto, secret_sprawl, deployment, injection, llm, supply_chain, agentic, config); (4) human report LAST, not first. Producing only the human report without the .claude-audit/current/ blackboard is INVALID — delta mode breaks, GitHub Security tab integration breaks, CI gating breaks. If you find yourself reasoning 'the user just wants a summary' — STOP and write the artifacts first. The artifacts ARE the deliverable; the report is the cover page."
---

# Mandatory contract before you do anything else

This skill produces **two kinds of output** on every run. Both are required:

1. **Machine-readable blackboard artifacts** under `.claude-audit/current/`:
   - `phase-00-profile.json` … `phase-08-baseline.json` (per-phase artifacts)
   - `phase-NN.done` saga markers (one per completed phase)
   - `findings.sarif` (SARIF 2.1.0)
   - `findings.cyclonedx.json` (SBOM skeleton)
2. **A human-readable Markdown report** plus deliverable copies under the
   resolved **output directory** (default `docs/security-audit-output/`):
   `security-audit-report.md`, `findings.sarif`, `findings.cyclonedx.json`,
   and the pruned `security-audit-baseline.json`. The skill asks you where to
   write these on first run (honors an `output:` arg and a persisted choice;
   defaults non-interactively). See [lib/output-routing.md](lib/output-routing.md).

⛔ **Neither kind of output may contain a credential.** Both enforcers are
mandatory and neither is optional hardening:

- `phase-04-scanners.md §4.4b` — run
  [lib/redact-scanner-output.py](lib/redact-scanner-output.py) over
  `phase-04-scanners/` the moment the scanners finish, before anything reads
  them. `gitleaks detect --no-git` deliberately ignores `.gitignore`, and its
  SARIF holds the matched secret verbatim.
- `phase-07-synthesis.md §7.10` and `phase-08-baseline.md §8.4` — run
  [lib/verify-deliverable.py](lib/verify-deliverable.py) before every copy into
  the output directory.

Through v2.6.0 neither existed, and the audit committed live credentials that
the audited repository had correctly kept untracked — it was the sole reason
they entered git history. The full chain and the reasoning behind the two-layer
fix are in [lib/secret-redaction.md](lib/secret-redaction.md). **If you find
yourself reasoning "the scanner output is just working state" — it is copied
verbatim into a tracked deliverable in §7.8.1. Run the redactor.**

**Producing only the report is INVALID.** A run that writes the human
report but skips the blackboard artifacts breaks downstream value:
delta mode fails (no baseline), GitHub Security tab integration fails
(no SARIF), CI gating on CRITICAL counts fails (no structured findings).
**If you find yourself reasoning "I'll just produce the final
report" — STOP. The artifacts come first.**

# First action — read workflow.md and run its preflight

The blackboard creation + `$SKILL_DIR` resolution + version check are
defined as a single multi-line Bash command in
[workflow.md](workflow.md) under "First action — execute literally as
your first Bash tool call". Run that command verbatim before doing
anything else. It writes `.claude-audit/.skill-dir` (the bare path of
this skill's install location), which every later phase reads.

# Then follow the workflow

Read [workflow.md](workflow.md) and follow every phase in order. Each
phase has a "verify before exit" check that confirms its artifact
landed; do not proceed past a phase whose verification fails.

# Stamp every artifact

The skill version is in [VERSION](VERSION). Stamp it into every artifact
you emit (`skill_version` field) so the user can reason about cross-run
comparability.

# Authorized-Egress reconciliation (v2.4)

Phase 2 additionally inventories **egress of sensitive data** (`phase-02-sinks.json`)
and a **credential mint/consume ledger** (`phase-02-credentials.json`); Phase 6
§6.19 runs a deterministic reconciliation (`lib/validate-egress.py`) that
catches the **control-with-no-enforcer / confused-deputy / capability-URL** class
— a security claim minted at one layer but never consumed on the byte-serving
path (incl. conditional unauthenticated-bypass branches and cross-layer gates
that per-partition deep-dives structurally miss). A **fail-closed coverage gate**
makes a silently-omitted sink break the run rather than pass quietly.

**Honest scope (state this in the report, do not oversell):** this reliably
catches the named class and raises recall across the egress family, but a clean
reconciliation is **NOT a proof of absence**. Detection depends on Phase 2
recording each byte-serving branch and its gate; gate descriptions are ranked
**negation-aware and conservatively** (an absent/ambiguous gate is treated as *no
gate*, so the tool over-flags rather than misses). CDN-edge egress with no code
path, and any modality outside [lib/egress-detection.md](lib/egress-detection.md),
remain out of mechanical reach and are surfaced as caveats, never silently.

# Sufficiency & severity arithmetic (v2.5)

v2.4 asked "is there a gate?". v2.5 asks the two questions that let a CRITICAL
authorization defect pass a full audit with a clean bill:

**1. Is the gate SUFFICIENT?** A handler can be gated, unambiguously and
correctly-looking, and still return every other user's rows — because
*authentication was used where per-row authorization was required*. Phase 2 §2.12
inventories row scoping (`phase-02-collections.json`), Phase 5 category 12
deep-dives it, and Phase 6 §6.20 runs a deterministic reconciliation
([lib/validate-collection-scoping.py](lib/validate-collection-scoping.py), rules
C1–C6) with a fail-closed coverage gate. C5 re-checks each scoping *claim*
against the source at the cited `file:line` (a predicate that is not there is
refused) and C2b catches a denied decoration the handler plainly performs. Those
are the two claims most likely to be wrong; neither is a general proof that an
agent-written inventory is honest. Phase 1 §1.6b additionally asserts partition coverage — an unmatched
handler directory now fails the phase instead of vanishing into a catch-all.

**2. Is the severity COMPUTED or merely ASSERTED?** Findings declare
`preconditions`/`postconditions`
([lib/capability-lexicon.md](lib/capability-lexicon.md)); Phase 7 §7.15
([lib/compose-attack-paths.py](lib/compose-attack-paths.py)) composes them into
attack paths from attacker personas and re-rates: **R1** an undischarged
mitigation cannot lower severity, **R2** prose that says "combined with X" is
binding, **R3** any unprivileged path to a crown jewel is CRITICAL, **R4**
severity may not decrease across runs without a recorded reason. **L1–L3** then
force the action: a CONFIRMED HIGH+ open past 30 days with no fix and no owned,
unexpired acceptance fails the run, and Phase 8 refuses to write a baseline while
governance failures stand — so a downgrade cannot launder itself by re-running.

**3. Can this finding raise anything's severity, and has it earned that? (v2.6)**
Every finding declares an `evidence_class`: `external_scanner` (an independent
tool), `heuristic_inventory` (this skill's own reconcilers, which are heuristics
over an inventory a sub-agent *wrote*), `agent_judgement` (a deep-dive read the
code), or `governance` (a claim about the audit's own state). **Only
`external_scanner` earns the §7.4 +1 promotion.** Mechanical rows are annexed to
the judgement finding they restate — they enumerate its fix surface and carry no
severity of their own — and are excluded from the capability graph. R3 chain
escalation still runs uncapped, but is suppressed when a load-bearing member of
the chain is `structurally_unreachable` **with a cited line**, and every
suppression is printed.

> **The invariant, stated once:** a low-evidence finding must not be able to
> raise the severity of anything — itself or its neighbours.

**Honest scope (state this in the report):** C1–C6 make the collection class
expressible and checkable, and make an omitted collection loud — but a clean run
is **not** a proof of absence. A scope applied by an un-modelled mechanism is
missed conservatively (over-flagging, then retired by the §6.20 adversarial
pass), and a runtime-assembled query is recorded as a caveat. The composer can
only compose what was tagged; R2 backstops untagged chains named in prose, and
the **ORPHAN CAPABILITIES** list backstops that. What changed is that these
failures are now loud instead of silent.

**Why over-flagging stopped being free, and what it cost (v2.6).** The paragraph
above is v2.5 doctrine and it is still right — a missed CRITICAL is
unrecoverable, a false positive costs triage time. But that trade holds only
while a false positive is **locally** expensive, and by v2.5 it was not:
over-flagged findings minted capability tags that escalated their *neighbours*,
including true findings, to CRITICAL. `docs/KNOWN-GAPS.md` had predicted the
precise defect and dismissed it — *"the failure direction is a false positive,
which a human closes"* — reasoning that was correct when written and expired
silently when the composer landed. Measured over an externally triaged run: the
two mechanical families were 60% of all HIGH+ findings and 15% of the true ones,
and the confidence marker was anti-correlated with truth (`CONFIRMED` 9.6% true,
unlabelled 92.1%).

> **Therefore:** a "the failure direction is safe" argument is scoped to the
> consumers that existed when it was written. Adding a downstream consumer of a
> finding — a composer, a gate, a ranking — obliges you to re-check every such
> argument against it. This is the most transferable lesson in the release.
