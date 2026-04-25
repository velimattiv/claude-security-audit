# Phase 5 — Parallel Deep Dives (9 categories)

## 🛑 MANDATORY EXECUTION RULES (READ FIRST)

📋 **This phase MUST produce, on disk, before advancing:**
- `.claude-audit/current/phase-05-<category>-<partition>.jsonl` for EACH applicable-category × top-N-partition pair. NOT a single consolidated file.
- `.claude-audit/current/phase-05-skipped.json` — ALWAYS written, even if no categories were skipped (`{"skipped": []}`). The file's presence is the signal that filtering ran.
- `.claude-audit/current/phase-05.done` (marker written only after ALL expected JSONLs exist)

🔁 **Sub-agent fan-out is MANDATORY, not optional:**
- For each `(category, partition)` pair where the category's gate condition holds, invoke ONE sub-agent via the Agent tool with `subagent_type: "general-purpose"` and the prompt template from `templates/subagent-prompt.md`. Concurrency cap: 8 in flight.
- **If you find yourself reasoning "I'll just cover all 9 categories in one synthesis pass to save tokens" — STOP.** Serial single-pass coverage misses deep per-class bugs (alg:none JWT acceptance, 2FA trust gaps, zip-slip, LFI). The E2E regression test in `tests/e2e/` specifically targets these; skipping fan-out regresses the test.
- Categories whose gating condition is false (e.g., `llm` when `profile.llm_usage.detected == false`) are legitimately skipped — record the skip in `phase-05-skipped.json`. The skipped list always exists; if no categories were skipped, write `{"skipped": []}`.

⛔ **DO NOT:**
- Advance to Phase 6 until every applicable `(category × partition)` JSONL exists on disk AND the Verify block prints `phase-05 verified`.
- Collapse categories into a single `phase-05-tokens.json` / `phase-05-findings.json` / similar consolidated shape — those are v1-era and break Phase 7 per-category aggregation + fixture matching.
- Downgrade the sub-agent `model` to Haiku/Sonnet — Phase 5 is Opus-only (see §5.4).

---

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

The orchestrator must invoke the **Agent tool** once per applicable
`(category, partition)` pair. This section is procedural, not a
template — you call the Agent tool through your normal tool-calling
protocol, with the parameters described below.

### Step A: compute the pair list

Load `partitions.json` and the category table in §5.1. For every
`p` in `partitions` where `p.depth == "full"`, walk every category `c`
in §5.1. If `c`'s gate passes against `profile`, add `(c, p)` to the
pair list. If the gate fails, record `{"category": c.id, "partition":
p.id, "reason": c.gate_reason}` in a skip list.

**Write the skip list** to `.claude-audit/current/phase-05-skipped.json`
unconditionally. The shape is always an object wrapping an array:
`{"skipped": [<entry>, ...]}`. If nothing was skipped, the array is
empty: `{"skipped": []}`. The file's presence is the signal that
filtering ran; the array length tells consumers whether any gating
was triggered.

### Step B: fan out, concurrency cap 8

For each `(c, p)` in the pair list, invoke the Agent tool with:
- `description`: a short label like `"Deep dive auth on services-api"`
  (one line, ≤80 chars).
- `subagent_type`: `"general-purpose"`.
- `prompt`: the full prompt body assembled from
  `templates/subagent-prompt.md`, with `{{phase-specific-method-body}}`
  replaced by the contents of the matching `steps/deepdive/cat-NN-<slug>.md`,
  `{{partition}}` replaced by the partition struct from
  `partitions.json`, and `{{skill_dir}}` replaced by the absolute path
  of this skill's directory (so the sub-agent can resolve
  `$SKILL_DIR/lib/validate-findings.py` etc.).

**Concurrency procedure (cap 8):** maintain a window of up to 8
in-flight Agent invocations. Emit up to 8 Agent tool-calls in one
assistant turn; on the next turn, after the in-flight set has shrunk,
dispatch the next pair(s) to refill the window. Do not exceed 8 in
flight. Do not fire all `len(pairs)` Agent calls at once.

**Model selection.** Do not pass a `model` parameter — Claude Code
routes `general-purpose` sub-agents automatically to the
harness-appropriate Opus variant. Do not downgrade to Sonnet/Haiku.

### Step C: validate each returned JSONL before marking the pair done

`$SKILL_DIR` was resolved during the workflow's first action and saved
as a bare path to `.claude-audit/.skill-dir`. **Every** Bash invocation
in this step must re-load it — Claude Code's Bash tool starts a fresh
shell per call, so the variable does not persist across `(c, p)`
iterations:

```bash
SKILL_DIR=$(cat .claude-audit/.skill-dir)
[ -n "$SKILL_DIR" ] || { echo "ERROR: SKILL_DIR not resolved"; exit 1; }
python3 "$SKILL_DIR/lib/validate-findings.py" \
    --schema "$SKILL_DIR/lib/finding-schema.json" \
    --cwe-map "$SKILL_DIR/lib/cwe-map.json" \
    .claude-audit/current/phase-05-<c.id>-<p.id>.jsonl
```

On exit 0, write `.claude-audit/current/phase-05-<c.id>-<p.id>.done`.
On exit != 0, re-invoke the Agent with the validator's errors quoted
back into the prompt. After the retry, if it still fails, record one
placeholder INFO finding documenting the validator errors and proceed.

### Step D: write the umbrella marker

Only after every `(c, p)` pair has a matching `.done` file (or
placeholder INFO on double-failure), write
`.claude-audit/current/phase-05.done`.

Partitions with `p.depth == "inventory-only"` are **not** deep-dived.
Their Phase 2 surface rows still appear in the Phase 7 report, but they
receive no finding sub-agents.

### Anti-pattern seen in earlier runs

A single-shot orchestrator can be tempted to reason "I'll just walk
through all 9 categories serially in one head-space and write a single
consolidated JSON." **That pattern missed alg:none JWT acceptance,
2FA trust gaps, zip-slip, and LFI** in v2.0.1's E2E iteration runs —
all four are bugs that require category-specific deep attention which
only per-sub-agent invocation provides. If you reach for the shortcut,
stop and fan out.

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

**Enforcement.** Every sub-agent MUST run the schema validator before
emitting its RETURN SHAPE.

**The bash block below is what the SUB-AGENT runs, NOT what the
orchestrator runs.** The orchestrator's own validation pass is in
§5.2 Step C and uses `$SKILL_DIR` from `.claude-audit/.skill-dir`.
For the sub-agent, the orchestrator substitutes the literal absolute
path into the prompt (per §5.2 Step B) before the prompt reaches the
sub-agent. The placeholder shown here as `<absolute-path-to-skill>`
will arrive at the sub-agent as a real path like
`/home/user/.claude/skills/security-audit`. **Do not emit this block
directly to your Bash tool** — it is illustrative of the sub-agent's
view, not a command for you to run:

```bash
# AS SEEN BY THE SUB-AGENT (orchestrator-side substitution already done):
python3 "<absolute-path-to-skill>/lib/validate-findings.py" \
    --schema "<absolute-path-to-skill>/lib/finding-schema.json" \
    --cwe-map "<absolute-path-to-skill>/lib/cwe-map.json" \
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
