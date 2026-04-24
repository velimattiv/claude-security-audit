# Phase 5 — Parallel Deep Dives (9 categories)

**Goal.** For each top-N partition, run 9 category-specific sub-agents in
parallel. Each sub-agent consumes the Phase 0/1/2/3/4 artifacts and writes
JSONL findings to disk. Only JSON summaries return through tool output.

**Inputs.** All prior-phase artifacts in `.claude-audit/current/`, plus
per-partition scope from `partitions.json` and Phase 2's surface inventory.

**Outputs.**
- `.claude-audit/current/phase-05-<category>-<partition>.jsonl` — one file
  per (category, partition) pair. Each line conforms to `lib/finding-schema.json`.
- `.claude-audit/current/phase-05-<category>-<partition>.done` — saga marker.
- `.claude-audit/current/phase-05.done` — umbrella marker once all (cat, part)
  pairs are finished.

**Execution model.** `partitions.full_depth_count × 9` sub-agents.
Concurrency cap: **8 in flight** (see `workflow.md §5`). Partitions over the
500K-token soft ceiling return `needs_recursion`; the orchestrator splits
them and re-fans-out.

---

## 5.1 — Categories

Each deep-dive category lives in its own file under
`steps/deepdive/cat-<NN>-<slug>.md`. All nine are required for a full audit
unless the user passes `categories: "<subset>"`.

| # | Category | File | Fan-out gate |
|---|---|---|---|
| 1 | Auth & Authz | `cat-01-auth-authz.md` | always |
| 2 | IDOR / BOLA | `cat-02-idor-bola.md` | always |
| 3 | Token / API Key Scope | `cat-03-token-scope.md` | always (gated further inside the category if no token system exists) |
| 4 | MITM / Transport | `cat-04-mitm.md` | always |
| 5 | Cryptography | `cat-05-crypto.md` | always |
| 6 | Secret Sprawl | `cat-06-secret-sprawl.md` | always |
| 7 | Deployment Posture | `cat-07-deployment.md` | always |
| 8 | Injection / SSRF / Deserialization | `cat-08-injection-ssrf.md` | always |
| 9 | LLM-specific | `cat-09-llm.md` | only if `profile.llm_usage.detected == true` and `kind != "internal"` |

## 5.2 — Fan-out procedure

For each partition `p` with `p.depth == "full"`:
  For each category `c` in §5.1:
    If `c` has a gate that fails against `profile`, skip.
    Otherwise enqueue sub-agent with:
      - `description`: `"Deep dive <c.slug> on <p.id>"`
      - `subagent_type`: `general-purpose`
      - `model`: `opus`
      - `prompt`: the filled template from `templates/subagent-prompt.md`
        with `phase-specific-method-body` = the full contents of
        `cat-<NN>-<slug>.md`.

Partitions with `p.depth == "inventory-only"` are **not** deep-dived. Their
Phase 2 surface rows still appear in the Phase 7 report, but they receive
no finding sub-agents.

## 5.3 — Finding schema (enforced on every sub-agent)

Each `.jsonl` line conforms to `lib/finding-schema.json`. Sub-agents MUST
populate:
- `id`, `severity`, `confidence`, `category`, `partition`, `file`, `line`
- `cwe` — look up in `lib/cwe-map.json`; fall back to `CWE-1007` only if
  absolutely no better mapping exists
- `owasp_ids[]` — see §5.4 below
- `title` (≤120 chars), `description` (≤800 chars)
- `sources[]` — at least one source (grep, scanner, manual, or subagent)

Strongly encouraged: `suggested_fix`, `attack_scenario`, `surface_id`,
`remediation_effort`, `fingerprint` (stable across title drift; see
`phase-07-synthesis.md §7.2`).

**Enforcement (v2.0.1).** Every sub-agent MUST run the schema validator
before emitting its RETURN SHAPE:

```bash
python3 scripts/validate-findings.py \
    --schema skills/security-audit/lib/finding-schema.json \
    .claude-audit/current/phase-05-<cat>-<partition>.jsonl
```

Exit 0 is required to proceed. On non-zero exit, the sub-agent fixes
every reported issue and re-validates. The orchestrator's first
post-sub-agent step is a second invocation of the validator — if the
sub-agent skipped it or lied about passing, the orchestrator catches
it and retries the sub-agent once. Second failure records a placeholder
INFO-level finding and moves on.

## 5.4 — OWASP tagging

Every finding gets at least one OWASP identifier:
- **ASVS 5.0** category id, e.g., `ASVS-V6.2.1`
- **API Top 10 (2023)**: `API1:2023` … `API10:2023`
- **LLM Top 10 (2025)**: `LLM01:2025` … `LLM10:2025`

Category-specific mapping guidance lives inside each `cat-<NN>` file.

## 5.5 — Confidence calibration

- **CONFIRMED** — finding verified by ≥2 independent sources (e.g., a
  grep pattern AND a scanner rule, or surface-row flag AND handler-body
  inspection).
- **LIKELY** — one strong source (scanner with high specificity, or a
  textually unambiguous grep match).
- **POSSIBLE** — single grep hit with ambiguity (e.g., `eval()` that might
  be on user-controlled input or might not — needs Phase 7 cross-reference).

## 5.6 — Cross-referencing scanner findings

When a sub-agent's own grep hits overlap with a Phase 4 slim-SARIF finding
(same file + similar line), the finding receives BOTH a `grep` source and a
`scanner` source. Confidence automatically becomes `CONFIRMED`. Slim SARIF
files to consult: `phase-04-scanners/*.slim.json`.

## 5.7 — Determining recursion

A sub-agent that realizes its scoped partition exceeds 500K raw code
tokens MUST return (stdout, JSON):

```json
{
  "status": "needs_recursion",
  "reason": "partition too large: ~720K raw tokens across 4 sub-modules",
  "suggested_split": [
    {"id": "p-subA", "paths_included": ["services/api/users/**"]},
    {"id": "p-subB", "paths_included": ["services/api/orders/**"]}
  ]
}
```

The orchestrator reads the `suggested_split`, creates the sub-partitions,
and re-fans-out.

## 5.8 — Error / timeout handling

- Sub-agent stdout not JSON → retry once with a corrected prompt; second
  failure produces a placeholder INFO-level finding and moves on.
- Sub-agent hangs → orchestrator's 80-turn budget expires; record timeout.
- Sub-agent returns empty findings → valid; record as `findings_count: 0`.

## 5.9 — Report to user

After all (category, partition) combinations finish:

> Phase 5 complete — <total> findings across <N> partitions × <9 - gated>
> categories. Breakdown: <count> CRITICAL, <count> HIGH, ... Proceeding to
> Phase 6 (Config + Methodology Spine).

Never echo finding contents to the user in the phase report. Full content
is in the JSONL files; Phase 7 synthesis is the user-facing consolidation.

---

## Verify before exit (MANDATORY)

Before declaring this phase complete and proceeding, run:

```bash
test -f .claude-audit/current/phase-05-*.jsonl # (at least one per non-gated category) \
  && test -f .claude-audit/current/phase-05.done \
  && echo "phase-05 verified" \
  || { echo "phase-05 INCOMPLETE — re-write artifact + .done marker before proceeding" >&2; exit 1; }
```

Do not advance to the next phase until this check prints "phase-05 verified". Producing only a downstream artifact (e.g. the final report) without the per-phase artifact + marker is an INVALID run.
