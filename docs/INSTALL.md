# Installation

This guide installs the `/security-audit` skill at user-level so
Claude Code can resolve it from any project. It also covers the
optional Phase 4 scanner bundle for full coverage.

## Requirements

- Claude Code CLI 2.1.0+ (`claude --version`)
- `git`, `bash`, `python3` (3.10+) — should already be present
- Linux or macOS (Linux container is the canonical target;
  WSL works; native Windows is not supported)
- Optional: `pip install jsonschema pyyaml` for full assertion-suite
  coverage if you'll run the E2E

## Quick install (recommended)

```bash
# 1. Clone the source somewhere persistent
git clone --depth 1 --branch v2.0.2 \
  https://github.com/velimattiv/claude-security-audit.git \
  ~/Code/claude-security-audit

# 2. Install the skill at user-level. Claude Code prefers
#    ~/.claude/skills/ over project-local installs.
cp -R ~/Code/claude-security-audit/skills/security-audit \
  ~/.claude/skills/security-audit

# 3. Verify
cat ~/.claude/skills/security-audit/VERSION                  # 2.0.2
ls  ~/.claude/skills/security-audit/manifest.yaml            # must exist
ls  ~/.claude/skills/security-audit/lib/validate-findings.py # must exist

# 4. Install the Phase 4 scanner bundle (optional but recommended).
#    Without it, the skill runs in degraded mode — fewer
#    corroborating sources, every finding drops to LIKELY/POSSIBLE.
bash ~/Code/claude-security-audit/scripts/install-scanners.sh
```

## Smoke test

After installing, in any small repo:

```bash
cd <some-project>
claude --dangerously-skip-permissions
```

Then in the Claude session:

```
/security-audit
```

Watch for the orchestrator's first Bash tool call — it should be the
preflight `mkdir -p .claude-audit/...` etc., resolving `$SKILL_DIR` and
writing `.claude-audit/.skill-dir`. If you see the orchestrator going
straight to reading project files without that preflight, something
is wrong with the install.

## Migrating from a different `security-audit` skill

If you already have a `security-audit` skill from a different
project (e.g. an older BMAD-flavoured wrapper around `/security-review`),
**there is no in-place upgrade path** — v2.0.2 is a fundamentally
different skill (polyglot SARIF audit with 9-phase orchestration,
not a review-orchestrator).

```bash
# Back up your existing skill OUTSIDE ~/.claude/skills/. Files
# under ~/.claude/skills/ are scanned by Claude Code's resolver
# and would appear as a separate slash-command, causing confusion.
mkdir -p ~/.claude/.archive-skills
mv ~/.claude/skills/security-audit \
   ~/.claude/.archive-skills/security-audit-pre-v2.0.2

# Then proceed with the Quick install steps above.
```

## Validating the install (full E2E)

If you want to validate the install end-to-end before trusting it
on real projects, run the local E2E against a known-vulnerable
fixture (OWASP Juice Shop):

```bash
bash ~/Code/claude-security-audit/scripts/run-e2e-test.sh
```

Expected outcome:
- ~30-60 min wall time
- `PASS — all structural + fixture checks green`
- 12/12 fixtures matched (8 hard + 4 soft)
- 400+ findings across ~60 unique CWEs
- Valid SARIF, baseline, report under `/tmp/e2e-target/.claude-audit/`

The full reference run is documented at
[`docs/test-runs/e2e-full-run-v2.0.2-2026-04-25T0250Z.md`](test-runs/e2e-full-run-v2.0.2-2026-04-25T0250Z.md).

## What gets installed

| Path | Purpose |
|---|---|
| `~/.claude/skills/security-audit/SKILL.md` | Activation + description |
| `~/.claude/skills/security-audit/workflow.md` | Orchestrator entry point |
| `~/.claude/skills/security-audit/manifest.yaml` | Per-phase contract (machine-readable) |
| `~/.claude/skills/security-audit/steps/phase-00..08-*.md` | Per-phase procedures |
| `~/.claude/skills/security-audit/steps/deepdive/cat-01..09-*.md` | Per-category deep-dive prompts |
| `~/.claude/skills/security-audit/lib/*.json` | Schemas (profile, partitions, surface, finding, baseline, cwe-map) |
| `~/.claude/skills/security-audit/lib/validate-findings.py` | Sub-agent self-validation script |
| `~/.claude/skills/security-audit/templates/subagent-prompt.md` | Sub-agent prompt template |

The scanner bundle install (step 4 above) places binaries at:

| Tool | Default install path |
|---|---|
| semgrep | `~/.local/share/semgrep` (pip user install) |
| osv-scanner | `~/.local/bin/osv-scanner` |
| gitleaks | `~/.local/bin/gitleaks` |
| trufflehog | `~/.local/bin/trufflehog` |
| trivy | `~/.local/bin/trivy` |
| hadolint | `~/.local/bin/hadolint` |

Make sure `~/.local/bin/` is on your `PATH`.

## Invocation forms

| Form | Meaning |
|---|---|
| `/security-audit` | Full audit, default mode. 30-60 min on a 100K-LOC repo. |
| `/security-audit mode: delta` | Delta mode — requires a prior baseline. Sub-minute typical. |
| `/security-audit scope: services/api` | Scope all phases to the path prefix. |
| `/security-audit categories: crypto,mitm,secrets` | Run only the named deep-dive categories. |
| `/security-audit mode: report` | Re-emit the report from existing `.claude-audit/current/` artifacts. |
| `/security-audit top_n: 12` | Override the top-N partitions that get full-depth deep dives (default: 8). |

## Updating

To pull a newer version:

```bash
cd ~/Code/claude-security-audit
git fetch --tags
git checkout v2.0.X    # or `main` for unreleased
rm -rf ~/.claude/skills/security-audit
cp -R skills/security-audit ~/.claude/skills/security-audit
cat ~/.claude/skills/security-audit/VERSION
```

The skill writes `skill_version` into every artifact it produces, so
old artifacts in `.claude-audit/baseline.json` remain readable across
versions (delta mode invalidates per the rules in
`steps/phase-08-baseline.md`).

## Uninstalling

```bash
rm -rf ~/.claude/skills/security-audit
```

The scanner bundle uninstalls per their respective install methods —
`pip uninstall semgrep` for semgrep, `rm ~/.local/bin/<tool>` for the
others.

## Troubleshooting

**`/security-audit` doesn't appear in slash-command autocomplete.**
Verify the install path: `ls ~/.claude/skills/security-audit/SKILL.md`.
Restart Claude Code if needed.

**Audit produces only `docs/security-audit-report.md`, no
`.claude-audit/`.**
This is the v2.0.1-era failure mode. v2.0.2's in-skill mandate
prevents it; if you see this, the install may be incomplete.
Re-run the verify step (cat VERSION, ls manifest.yaml).

**`SKILL_DIR not resolved` errors.**
The preflight Bash chain failed to find the skill at any of:
`$HOME/.claude/skills/security-audit`, `./.claude/skills/security-audit`,
`./skills/security-audit`. Check that the user-level install actually
landed at the expected path.

**Phase 4 scanners missing → audit runs in degraded mode.**
This is by design — missing scanners are warnings, not failures.
Run `bash scripts/install-scanners.sh` to fix.
