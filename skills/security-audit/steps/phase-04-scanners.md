# Phase 4 — External Inputs (Scanner Orchestration)

## 🛑 MANDATORY EXECUTION RULES (READ FIRST)

📋 **This phase MUST produce, on disk, before advancing:**
- `.claude-audit/current/phase-04-scanners/*.slim.json` (one per scanner that ran: semgrep, osv-scanner, gitleaks, trufflehog, trivy, hadolint — whichever are installed)
- `.claude-audit/current/phase-04-scanners/security-review-*.md` (Claude Code `/security-review` output)
- `.claude-audit/current/phase-04-scanners/adversarial-*.md` (adversarial-review sub-agent output)
- `.claude-audit/current/phase-04.done`

⛔ **DO NOT advance to Phase 5** until the scanner directory has at least one `slim.json` AND the Verify block prints `phase-04 verified`. Missing scanner binaries are NOT fatal — degrade gracefully, but still emit the marker after the attempt.

📖 Phase 7 synthesis cross-references scanner findings against skill findings to tag CONFIRMED vs LIKELY confidence. No scanner artifacts ⇒ every skill finding drops to LIKELY or POSSIBLE.

---

**Goal.** Run the standardized scanner bundle + Claude Code's built-in
reviews in parallel. Emit SARIF per scanner for later cross-referencing.
Never hard-fail: any missing scanner becomes a degraded-mode warning.

**Inputs.**
- `.claude-audit/current/phase-00-profile.json` — gates conditional scanners
- `.claude-audit/current/partitions.json` — bounds per-partition reviews

**Outputs.**
- `.claude-audit/current/phase-04-scanners/<tool>.sarif` (raw SARIF per tool)
- `.claude-audit/current/phase-04-scanners/<tool>.slim.json` (post-processed)
- `.claude-audit/current/phase-04-scanners/summary.json` (tool status, counts)
- `.claude-audit/current/phase-04-scanners/security-review-<partition>.md`
  (one per partition — built-in `/security-review` output)
- `.claude-audit/current/phase-04-scanners/adversarial-<partition>.md` (one
  per partition — vendored adversarial-review output)
- `.claude-audit/current/phase-04.done` (saga marker)

---

## 4.1 — Preflight

Run `scripts/install-scanners.sh --check` (or equivalent inline probe).
Build two lists:

- `present`: scanners detected on `PATH`.
- `missing`: scanners in the required / conditional sets not on `PATH`.

For every missing required scanner, append one line to the audit log:

> Scanner `<name>` missing. Install with
> `scripts/install-scanners.sh`. Degraded mode: skipping this scanner.

**Do not halt.** Proceed with whatever is present.

## 4.2 — Required scanner bundle

Run these six in parallel (max 4 concurrent — scanners are heavy I/O):

| Tool | Invocation | Notes |
|---|---|---|
| **semgrep** | `semgrep scan --config p/security-audit --config p/owasp-top-ten --config p/jwt --sarif --output phase-04-scanners/semgrep.sarif --timeout 600 --metrics=off` | Uses named community rulesets (no telemetry). `--config auto` is the alternate path — it gives broader coverage but requires `--metrics=on`. The skill opts out of metrics by default (per Q4 no-telemetry decision); document as a trade-off. |
| **osv-scanner** | `osv-scanner scan --recursive --format sarif --output phase-04-scanners/osv.sarif .` | Ecosystem auto-detected from manifests. Skipped if no lockfiles present — warn, do not fail. |
| **gitleaks (working tree)** | `gitleaks detect --no-git --report-format sarif --report-path phase-04-scanners/gitleaks.sarif` | Fast — scans the checked-out tree only. |
| **gitleaks (git history)** | `gitleaks git . --report-format sarif --report-path phase-04-scanners/gitleaks-history.sarif` | Slow; separate sub-agent with 20 min timeout. Non-blocking for Phase 7 synthesis. |
| **trufflehog** | `trufflehog git file://. --json --only-verified > phase-04-scanners/trufflehog.json` | Emits JSONL, not SARIF; convert in §4.5. |
| **trivy** | `trivy fs --scanners vuln,secret,misconfig,license --format sarif --output phase-04-scanners/trivy.sarif .` | Also run `trivy config -f sarif -o trivy-iac.sarif .` if IaC files detected. |
| **hadolint** | `for f in $(find . -name Dockerfile -not -path ./node_modules/*); do hadolint --format sarif "$f"; done > phase-04-scanners/hadolint.sarif` | Conditional: only if `Dockerfile*` present. |

### Invocation shell (reference)

Each scanner runs via one sub-agent using the template (`templates/subagent-prompt.md`) with `{{phase-specific-method-body}}` = "Bash the invocation above, then validate SARIF parses with `jq -e .runs .`". The sub-agent returns `{ tool, exit_code, sarif_path, finding_count, notes }`.

Keep the orchestrator out of the scanner process memory; only JSON summary returns.

## 4.3 — Conditional adds

Gate on `phase-00-profile.json`:

| Scanner | Gate condition |
|---|---|
| **brakeman** | `frameworks[*].framework` contains `Rails` |
| **checkov** | `deployment.iac.terraform` is non-empty |
| **kube-linter** | `deployment.k8s.manifests` or `.helm_charts` non-empty |
| **grype** | `deployment.docker.dockerfiles` non-empty (optional; EPSS prioritization) |
| **govulncheck** | `languages[*].name` contains `Go` |
| **psalm** (`--taint-analysis`) | `languages[*].name` contains `PHP` |
| **zizmor** | `.github/workflows/*.yml` present |

Invocation per conditional scanner documented in `lib/scanner-bundle.md`.

## 4.4 — Claude Code built-in reviews per partition

**`/security-review`** — run once per partition whose `depth: full`. The
built-in review skill is designed for diffs; we adapt by passing the
partition's scope hint. Execute via a sub-agent with:

```
TASK: Invoke /security-review on files under <partition.paths_included>.
SCOPE: limit the review to the partition path prefix.
OUTPUT: save the Markdown findings list to
  .claude-audit/current/phase-04-scanners/security-review-<partition-id>.md
```

If the partition is above 500K raw tokens, fall back to sampling: sub-agent
returns `needs_recursion` suggesting the split.

**Vendored adversarial-review** — run once per partition whose `depth: full`.
Execute via a sub-agent that reads
`skills/security-audit/vendored/adversarial-review/SKILL.md` and applies it
with scope hint. Save to
`phase-04-scanners/adversarial-<partition-id>.md`.

## 4.5 — Format normalization

### Trufflehog JSONL → SARIF

Trufflehog emits one JSON object per line (`{source, source_type, raw, ...}`).
Convert to SARIF 2.1.0 minimally:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "trufflehog" } },
    "results": [ /* one per verified secret */ ]
  }]
}
```

See `lib/sarif-postprocess.md` for the field mapping.

### Hadolint SARIF concatenation

`hadolint --format sarif` emits one SARIF document per Dockerfile. Merge
into a single `runs[]` array (one run per file keeps tool-driver name
consistent; multiple runs is fine).

## 4.6 — Post-process: slim SARIF

For each raw SARIF, produce a slim JSON keeping only the fields needed by
Phase 5-7:

```json
{
  "tool": "semgrep",
  "tool_version": "1.x",
  "results": [
    {
      "rule_id": "python.flask.security.audit.render-template-with-variable",
      "level": "error",
      "file": "app/views.py",
      "start_line": 42,
      "message": "Use of user-controlled template variable..."
    }
  ]
}
```

Discard: full locations beyond file+line, fingerprints, fixes, tags,
artifacts[], invocations[]. This cuts ~80% of SARIF bulk and makes Phase 7
diffing much cheaper. The raw SARIF is kept on disk for users who want to
upload it to GitHub's Security tab directly.

See `lib/sarif-postprocess.md` for the exact field-mapping procedure.

## 4.7 — Summary emission

After all scanners complete (or time out), write
`phase-04-scanners/summary.json`:

```json
{
  "schema_version": 2,
  "skill_version": "...",
  "audit_id": "...",
  "generated_at": "...",
  "scanners": [
    {"name": "semgrep", "status": "ok", "finding_count": 34, "raw_path": "semgrep.sarif", "slim_path": "semgrep.slim.json", "duration_ms": 48000},
    {"name": "osv-scanner", "status": "ok", "finding_count": 12, "raw_path": "osv.sarif", ...},
    {"name": "trivy", "status": "timeout", "finding_count": null, "raw_path": null, "notes": "exceeded 600s"},
    {"name": "hadolint", "status": "skipped", "finding_count": null, "notes": "no Dockerfile detected"}
  ],
  "built_in_reviews": [
    {"kind": "security-review", "partition": "juice-shop", "output": "security-review-juice-shop.md", "finding_count_estimate": 23},
    {"kind": "adversarial", "partition": "juice-shop", "output": "adversarial-juice-shop.md", "finding_count_estimate": 15}
  ]
}
```

Write `phase-04.done`.

## 4.8 — Report to user

> Phase 4 complete — ran <N> scanners, <K> skipped, <T> timed out. Total
> raw findings: <count>. Per-partition built-in reviews: <M>. Slim SARIF
> written to phase-04-scanners/. Proceeding to Phase 5 (deep dives).

## 4.9 — Error handling

- **Scanner returns non-zero but writes valid SARIF**: accept it. Most
  scanners exit non-zero when findings exist.
- **Scanner writes nothing + non-zero exit**: record `status: "error"` with
  the last 500 chars of stderr in `notes`; move on.
- **Scanner hangs**: the sub-agent's own timeout clause kills it;
  orchestrator records `status: "timeout"`.
- **SARIF file parses but has no `runs` key**: record `status: "malformed"`;
  do not include in Phase 7 synthesis.

## 4.10 — Rate-limit safety

The required bundle at 4 concurrent still makes Bash calls, not Claude API
calls, so the Claude rate limits don't apply to scanner invocations
directly. The `/security-review` and `adversarial-review` sub-agents DO
consume API — they are bounded by the orchestrator's 8-concurrent cap for
all sub-agents combined (Phase 4 scanner sub-agents + Phase 4 review
sub-agents + any other concurrent phase).

## 4.11 — Git-history secrets as a long-running side task

Per V2-SCOPE §10.9, `gitleaks git` on a ≥10k-commit repo can take several
minutes. Execute this as a dedicated sub-agent with `timeout 1200` (20 min).
If it times out, mark `status: "timeout"` and **do not block Phase 7** —
Phase 7 synthesis proceeds with whatever finished; gitleaks history
findings merge into the report if they land in time, else they are filed
as a follow-up note.

---

## Verify before exit (MANDATORY)

Before declaring this phase complete and proceeding, run:

```bash
test -f .claude-audit/current/phase-04-scanners/summary.json  \
  && test -f .claude-audit/current/phase-04.done \
  && echo "phase-04 verified" \
  || { echo "phase-04 INCOMPLETE — re-write artifact + .done marker before proceeding" >&2; exit 1; }
```

Do not advance to the next phase until this check prints "phase-04 verified". Producing only a downstream artifact (e.g. the final report) without the per-phase artifact + marker is an INVALID run.
