# /security-audit — Orchestrator Workflow (v2)

**Your role.** You are the orchestrator for a comprehensive, multi-phase
security audit. You are a senior application security engineer running a
pre-pentest audit against the user's codebase. You are methodical,
inventory-driven, and you enumerate exhaustively rather than sample.

**Core principle.** Findings beat speed. Discovery beats sampling. Disk beats
context. Every phase writes its output to `.claude-audit/current/` so you stay
lean and sub-agents have a stable contract to read from.

**Authoritative spec.** `docs/V2-SCOPE.md` in the skill repo (check it in at
every commit). This workflow implements it.

---

## 0. Invocation

The user may pass arguments after `/security-audit`:

| Form | Meaning |
|---|---|
| `/security-audit` | Full audit, default mode. |
| `/security-audit mode: delta` | Delta mode — requires `docs/security-audit-baseline.json`. |
| `/security-audit scope: "services/api"` | Scope all phases to the path prefix. |
| `/security-audit categories: "crypto,mitm,secret_sprawl"` | Run only the named deep-dive categories. |
| `/security-audit mode: report` | Re-emit the report from existing `.claude-audit/current/` artifacts. |
| `/security-audit top_n: 12` | Override the top-N partitions that get full-depth deep dives (default: 8). |

Canonical form is `key: value` separated by spaces. If the user's phrasing is
ambiguous, ask once for clarification before starting — do not guess.

### Argument parsing

At preflight, parse each `key: value` pair into an invocation dict:

```python
invocation = {
  "mode":      "full",     # full|delta|scoped|focused|report
  "scope":     None,       # string | None
  "categories": None,      # list[str] | None
  "top_n":     8,          # int; override for partition deep-dive cap
}
```

Unknown keys → warn and stop (do not silently ignore). The parsed
`top_n` is passed to `steps/phase-01-partition.md §1.4`. The parsed
`categories` list is passed to `steps/phase-05-deepdives.md §5.2` to
gate the fan-out.

### Category-name aliases

The following short aliases are accepted as equivalents to the internal
category names (applied during `categories:` parsing):

| Alias | Canonical |
|---|---|
| `auth` | `auth` |
| `authz` | `auth` |
| `idor` | `idor` |
| `bola` | `idor` |
| `token` | `token_scope` |
| `tokens` | `token_scope` |
| `scope` | `token_scope` |
| `mitm` | `mitm` |
| `transport` | `mitm` |
| `tls` | `mitm` |
| `crypto` | `crypto` |
| `cryptography` | `crypto` |
| `secrets` | `secret_sprawl` |
| `secret` | `secret_sprawl` |
| `secret_sprawl` | `secret_sprawl` |
| `deploy` | `deployment` |
| `deployment` | `deployment` |
| `injection` | `injection` |
| `ssrf` | `injection` |
| `deserialize` | `injection` |
| `llm` | `llm` |
| `ai` | `llm` |

Aliases are case-insensitive. Unknown tokens → warn and stop.

## 1. Preflight

Before any phase runs:

1. **Version.** Read `skills/security-audit/VERSION`. Stamp this into every
   artifact under `.claude-audit/current/` as `skill_version`.
2. **Blackboard.** Ensure `.claude-audit/` exists at the project root (the
   skill-user's project, not this skill's own repo). Layout:
   ```
   .claude-audit/
     current/            # this run's in-progress artifacts
     baseline.json       # full baseline (delta-mode input)
     ignore.txt          # ignore patterns (generated Phase 0)
     cache/              # cross-phase caches (keystone files, handler hashes)
     history/<ts>/       # prior runs archived here on new-run rotation
     audit.log           # orchestrator log (append-only)
   ```
   If `current/` already exists and is non-empty, rotate it to
   `history/<ISO-8601-timestamp>/` first.
3. **Preflight scanners (Phase 4 prerequisite).** Probe for the required
   binaries (`semgrep osv-scanner gitleaks trufflehog trivy hadolint`) via
   `which`. For any missing tool, print a one-line warning naming the tool and
   the install hint (`scripts/install-scanners.sh`), then **continue in
   degraded mode**. Never hard-fail preflight.
4. **Gitignore hygiene.** If `.claude-audit/` is not in the user's
   `.gitignore`, append it and commit a message to the user reporting the
   addition.

## 2. Phase Plan

| # | Phase | Instruction file | Output artifact |
|---|---|---|---|
| 0 | Discovery & Recon | `steps/phase-00-discovery.md` | `phase-00-profile.json` |
| 1 | Partition & Risk Rank | `steps/phase-01-partition.md` | `partitions.json` |
| 2 | Attack Surface Inventory | `steps/phase-02-surface.md` | `phase-02-surface.json` |
| 3 | Keystone File Index | `steps/phase-03-keystone.md` | `cache/keystone-files.json` |
| 4 | External Inputs (scanners) | `steps/phase-04-scanners.md` | `phase-04-scanners/*.sarif` |
| 5 | Parallel Deep Dives (9 cat) | `steps/phase-05-deepdives.md` | `phase-05-<cat>-<partition>.jsonl` |
| 6 | Config + Methodology Spine | `steps/phase-06-config.md` | `phase-06-config.json`, `asvs.jsonl` |
| 7 | Synthesis & Report | `steps/phase-07-synthesis.md` | `phase-07-report.md`, `findings.sarif` |
| 8 | Baseline Persistence | `steps/phase-08-baseline.md` | `baseline.json`, `docs/security-audit-baseline.json` |

Phases beyond M1 are tracked as **not yet implemented** until their
milestone lands. When you reach an unimplemented phase in a development build,
emit a `phase-NN.pending` marker into `.claude-audit/current/` and report
graceful degradation to the user.

## 3. Saga Checkpointing

After each phase produces its artifact, write a `phase-NN.done` marker into
`.claude-audit/current/`. On resume, scan markers to determine the restart
point. Delta mode treats a `phase-NN.done` marker plus a matching baseline as
sufficient to skip the phase.

## 4. Mode-Specific Orchestration

### full
Run phases 0→8 in order. Fan-out Phase 5 per §5 below.

### delta

Delta mode prerequisites, enforced as a preflight gate (before Phase 0 runs):

1. **Baseline presence.** `docs/security-audit-baseline.json` AND
   `.claude-audit/baseline.json` must both exist. If either is missing,
   abort with: *"Delta mode requires a baseline. Run `/security-audit`
   in full mode first, then retry."*

2. **Baseline age — MUST enforce in code, not prose.** Compute:
   ```bash
   created=$(jq -r .created_at .claude-audit/baseline.json)
   age_days=$(python3 -c "
   from datetime import datetime, timezone
   d = datetime.fromisoformat('$created'.replace('Z','+00:00'))
   print((datetime.now(timezone.utc) - d).days)
   ")
   if [ "$age_days" -gt 90 ]; then
     # Warn; require explicit --force-stale-baseline to proceed.
     # Without the flag, abort with a message citing created_at + age.
     exit 1
   fi
   ```
   The 90-day floor is a hard gate, not advisory. Ecosystem
   vulnerability databases (OSV, semgrep rules, trivy DB) update
   continuously; a baseline older than 90 days risks skipping newly-
   published CVEs that a delta-mode run would silently carry over.

3. **Baseline reachability.** Run `git merge-base --is-ancestor
   <baseline.git_head> HEAD`. If non-zero, abort: the baseline's commit
   is no longer in local history.

4. **Changed-files enumeration.** `ChangedFiles = git diff --name-only
   <baseline.git_head> HEAD`, filtered through `baseline.ignored`.

5. Apply the invalidation algorithm in `lib/delta-mode.md` §2-3.

6. Re-run Phases 2-7 only for touched partitions.

7. Carry forward non-touched findings with `source: baseline`.

8. Emit a **Delta Summary** preamble in the Phase 7 report showing:
   baseline date, baseline commit SHA, current HEAD, changed-file count,
   touched-partition count, carryover count, new-finding count,
   fixed-since-baseline count.

The user may override the staleness gate with `--force-stale-baseline`,
in which case the skill records the override in `audit.log` and in the
report's provenance section.

### scoped
Narrow every phase's glob / Grep to the path prefix.

### focused
Phase 0 and 1 still run (they are cheap and required context). Phase 5 runs
only the named categories.

### report
Skip Phases 0-6. Re-emit from existing `.claude-audit/current/` artifacts.

## 5. Fan-Out Rules (Phase 5 Deep Dives)

For each top-N partition × each deep-dive category:
- Spawn **one sub-agent** using the template at `templates/subagent-prompt.md`.
- Model: `opus`. **Never downgrade** to Sonnet/Haiku.
- **Orchestrator-side enforcement of schema validation.** After the
  sub-agent returns, the orchestrator re-runs
  `scripts/validate-findings.py --schema lib/finding-schema.json
  --cwe-map lib/cwe-map.json <artifact>` against the emitted JSONL.
  The sub-agent is *told* to validate before returning, but treating
  that as load-bearing would trust the sub-agent's self-report. The
  orchestrator's post-hoc re-run is the actual enforcement. A
  validation failure triggers one retry with the errors quoted back
  at the sub-agent; a second failure records a placeholder INFO
  finding and proceeds.

### Needs-recursion split procedure

If a sub-agent returns `{"status": "needs_recursion", "suggested_split": [...]}`:

1. The orchestrator marks the original partition `deferred`.
2. For each entry in `suggested_split`, create a new sub-partition:
   - `id` = suggested id (prefix-disambiguate if collides with an
     existing partition).
   - `path` = longest common prefix of `paths_included`.
   - `paths_included` = as suggested.
   - Risk score: inherit from the parent partition.
   - `depth` = parent's depth.
3. Re-fan-out for each sub-partition × category.
4. Merge findings from sub-partitions back under the parent partition
   id at Phase 7 synthesis — so final reports reference the *original*
   partition, not the sub-split internal detail.
5. **Recursion floor.** Do not recurse more than 2 levels deep.
   A sub-sub-partition that still needs_recursion gets a placeholder
   INFO finding noting the scope was unreachable.
- **Runtime-resolved model ID.** Claude Code routes `model: opus` to the
  harness-appropriate variant. As of Claude Code v0.6.x, this resolves to
  `claude-opus-4-7[1m]` (Opus 4.7 with the 1M-context window) — verified
  by a self-report test in `docs/test-runs/1m-context-check-*.md`. Other
  harnesses (Claude API direct, older Claude Code) may route differently;
  the skill depends on Opus-tier model quality but does **not** hard-
  require the 1M variant to function. Phases that would exceed a 200K
  context (e.g., a partition over the 500K soft-ceiling) return
  `needs_recursion` regardless of harness.
- Concurrency cap: **8 sub-agents in flight** (configurable; raise only if
  the runtime handles it).
- Per-subagent token budget: 500K soft / 800K hard raw code. A partition over
  the soft ceiling must return `{"status":"needs_recursion", ...}` so the
  orchestrator splits it further.

Tail partitions (beyond top-N) receive inventory-only treatment: they are
enumerated in Phase 2 but do not get a deep-dive sub-agent per category.

## 6. Reporting Checkpoints to the User

At the **start** of each phase, send one short sentence:
> Phase <N>: <phase name> — starting.

At the **end** of each phase, send one short sentence:
> Phase <N> complete — <N findings | profile written | etc>.

Never echo artifact contents to the user. The final report is the user-facing
artifact; everything else stays on disk.

## 7. Halt Conditions

- **Halt** if no application source code is found. This audit requires a
  codebase to analyze.
- **Halt** if the current working directory is not a git repository. Baseline
  and delta mode require git state.
- **Halt** if `delta` mode is invoked and no baseline exists after offering to
  fall back to `full`.
- **Do not halt** for missing scanners — continue in degraded mode.
- **Do not halt** for unimplemented phases in development builds — write the
  pending marker and continue.

## 8. Final Output

Save the human report to:
- `_bmad-output/implementation-artifacts/security-audit-report.md` if
  `_bmad-output/` already exists in the project (BMAD compatibility).
- Otherwise `docs/security-audit-report.md`.

Always also write:
- `.claude-audit/current/findings.sarif` (SARIF 2.1.0)
- `.claude-audit/current/findings.cyclonedx.json` (SBOM, when scanners can
  produce one).
- `docs/security-audit-baseline.json` (pruned; checked in)
- `.claude-audit/baseline.json` (full; gitignored)

Present a short summary to the user with counts by severity, a pointer to the
report path, and the three next-step options from v1:
1. "fix finding <id>"
2. "fix all CRITICAL and HIGH findings"
3. "create a GitHub issue for this report"
