# Phase 8 — Baseline Persistence

**Goal.** After a successful full audit, write a baseline JSON that future
`mode: delta` runs can diff against for sub-minute incremental audits.

**Inputs.** All Phase 0-7 artifacts in `.claude-audit/current/`.

**Outputs.**
- `.claude-audit/baseline.json` — full baseline (gitignored, detailed).
- `docs/security-audit-baseline.json` — pruned baseline (checked in).
- `.claude-audit/history/<ISO-timestamp>/` — previous `current/` archived
  (rotation happens at the next run's preflight, not here).
- `.claude-audit/current/phase-08.done`

**Execution.** Single orchestrator pass. No sub-agents.

---

## 8.1 — When Phase 8 runs

Phase 8 runs **only if**:
1. `mode == "full"` (delta mode re-uses an existing baseline; it does not
   overwrite it unless the user passes `--refresh-baseline`).
2. Phase 7 completed successfully (`phase-07.done` exists).
3. No hard errors (gate: count of CRITICAL runtime errors in audit.log
   must be zero; findings CRITICAL-severity is fine and expected).

If any gate fails, skip Phase 8 and note in `notes[]`. The existing
baseline (if any) stays untouched.

## 8.2 — Baseline schema

Per `lib/baseline-schema.json`. The shape:

```json
{
  "schema_version": 2,
  "audit_id": "...",
  "skill_version": "2.0.0-mX",
  "git_head": "abc123def",
  "git_branch": "main",
  "created_at": "ISO-8601",
  "repo_topology": { "kind": "...", "tool": null, "partitions": [...]},
  "partition_manifest": {...},                 // copied from partitions.json (pruned)
  "surface": [...],                             // array of surface rows (pruned — id, file, handler_hash, auth_required, trust_zone only)
  "keystone_files": [...],                      // array of paths + reasons
  "auth_matrix": [...],                         // per (role, surface) allow/deny derived from cat-01 sub-agent output
  "idor_candidates": [...],                     // from cat-02 candidates (regardless of finding status)
  "config": {                                   // from phase-06-config.json
    "cors_origins": [...],
    "csp": "...",
    "cookie_flags": {...},
    "security_headers": {...}
  },
  "findings_carryover": [...],                  // findings from phase-07 tagged with their fingerprint — delta mode brings them forward unless invalidated
  "scanner_versions": {                         // provenance
    "semgrep": "1.82.0",
    "osv-scanner": "1.9.2",
    "gitleaks": "8.21.2",
    ...
  },
  "methodology_coverage": {                     // summary from phase-07
    "asvs_pct": 78.4,
    "api_top10_counts": {...},
    ...
  },
  "ignored": [...]                               // .claude-audit/ignore.txt contents
}
```

## 8.3 — Two files, two audiences

### `.claude-audit/baseline.json` (full)

Gitignored. Contains **all** findings with full descriptions, attack
scenarios, suggested fixes. Delta mode reads this to restore context
cheaply without re-running Phase 5.

### `docs/security-audit-baseline.json` (pruned, checked in)

Committed to the user's repo. Keeps only:
- `schema_version`, `skill_version`, `audit_id`
- `git_head`, `created_at`
- `partition_manifest` (id, path, risk, depth only)
- `surface` (id, file, handler_hash — no full params, no notes)
- `keystone_files` (paths + reason-count only)
- `findings_carryover`: finding fingerprints + titles + severities
  (no body, no attack scenarios — users who want the full text read
  from the full baseline)
- `methodology_coverage`
- `ignored`

Size target: ≤100KB for a 100K-LOC repo baseline. The full file can be
multi-MB; the pruned file is lightweight enough to diff in PRs.

## 8.4 — Write procedure

1. Read all inputs listed above.
2. Assemble the full baseline struct in memory.
3. Validate against `lib/baseline-schema.json` (re-read your JSON).
4. Write `.claude-audit/baseline.json`.
5. Produce the pruned form by walking the full struct and copying only
   the fields listed in §8.3.
6. Ensure the output directory exists: `mkdir -p docs`.
7. Write `docs/security-audit-baseline.json`.
8. Write `.claude-audit/current/phase-08.done`.

## 8.5 — Rotation of previous runs

Phase 8 does NOT rotate history. Rotation happens at the **next** run's
preflight (`workflow.md §1.2`). The ordering is:
- Run N completes → baseline.json written.
- Run N+1 starts → preflight sees existing `current/`, moves it to
  `history/<N's created_at>/`, then starts N+1's new `current/`.

This way, if a user aborts Phase 8 or the process crashes mid-write, the
previous run is still intact under `history/`.

## 8.6 — Delta-mode lifecycle reference

(Reminder of how the baseline is consumed — full procedure in
`workflow.md §4 "mode: delta"`.)

1. `mode: delta` requires `docs/security-audit-baseline.json`.
2. Preflight computes `git diff --name-only <baseline.git_head> HEAD`
   (the set of changed files).
3. Invalidation rules (`docs/V2-SCOPE.md §5`):
   - A surface row is **stale** if its `file ∈ ChangedFiles` OR its
     current `handler_hash` ≠ baseline's.
   - A partition is **stale-whole** if >20% of its files changed OR its
     manifest changed (package.json, go.mod, Cargo.toml, etc.).
   - Any change to a keystone file invalidates every auth_matrix row.
   - Any change under `config/`, `*.config.*`, framework-specific config
     files re-runs Phase 6 in full.
   - Any lockfile change re-runs Phase 4 in full.
4. Phases 2-7 run ONLY on touched partitions + their adjacent
   partitions (where "adjacent" means shares a keystone file with a
   touched partition).
5. Non-touched findings carry forward with `source: baseline` appended
   and `confidence: unchanged`.

## 8.7 — Staleness threshold

If the baseline is older than **90 days**, delta mode **refuses** to
run and the skill falls back to full mode with a clear message:

> Baseline dated 2025-12-01 is >90 days old. Delta mode would miss
> ecosystem CVE updates. Running full audit — Phase 8 will refresh
> the baseline at the end.

This is a floor, not a policy — users can override with
`--force-stale-baseline`. The rationale is that OSV / gitleaks rule
updates land continuously; 90 days is the conservative outer bound.

## 8.8 — Report to user

> Phase 8 complete — baseline written.
>   - Full: `.claude-audit/baseline.json` ({{full_size}})
>   - Pruned (check in): `docs/security-audit-baseline.json` ({{pruned_size}})
>
> Future runs: `/security-audit mode: delta` to re-audit only changed
> surfaces (typical <5 min after baseline exists).

## 8.9 — Edge cases

- **First run** — no baseline exists. Phase 8 writes both files
  normally; next run can use `mode: delta`.
- **Dirty git tree** — phase-00 captured `git.dirty == true`.
  Baseline records this, and delta-mode compares against the baseline's
  git_head (not dirty-vs-dirty). A user who commits after a dirty-tree
  audit still gets a valid delta — the invalidation is slightly
  noisier (every changed file triggers a re-analyze) but correct.
- **Branch switch between runs** — delta-mode still works; it compares
  against the baseline's `git_head` regardless of current branch. The
  only requirement is that the baseline's commit is reachable via
  `git merge-base`.
- **Shallow clone** — baseline records the shallow state; delta-mode
  warns if `git rev-parse --is-shallow-repository` returns true AND
  the baseline's git_head isn't in the local history.
