# Installation

This guide installs the `/security-audit` Agent Skill for Claude Code or GitHub
Copilot CLI. It also covers the optional Phase 4 scanner bundle for full
coverage.

## Requirements

- One supported harness: Claude Code CLI 2.1.0+ (`claude --version`) or
  GitHub Copilot CLI (`copilot --version`)
- `git`, `bash`, `python3` (3.10+) — should already be present
- Linux or macOS (Linux container is the canonical target;
  WSL works; native Windows is not supported)
- Optional: `pip install jsonschema pyyaml` for full assertion-suite
  coverage if you'll run the E2E

## Install the Agent Skill

Clone the repository, then use the installer so every referenced resource is
copied and an existing installation is backed up:

```bash
git clone --depth 1 --branch v2.6.1 \
  https://github.com/velimattiv/claude-security-audit.git ~/Code/csa
bash ~/Code/csa/scripts/install-skill.sh --harness copilot
# or: --harness claude
```

For one repository only:

```bash
bash ~/Code/csa/scripts/install-skill.sh --harness copilot \
  --scope project --project-root /path/to/project
```

Copilot personal installs honor `COPILOT_HOME`; the default is
`~/.copilot/skills/security-audit`. Do not use `copilot skill add` with only
the `SKILL.md` URL or path for this skill, because the workflow, schemas,
validators, and templates are also required.

## Recommended install: isolated full container

The canonical deployment shape — and the only one that doesn't put
six security tools with auto-updating databases on your daily-driver
host — runs the entire audit inside a disposable container. The agent
harness, skill, scanner bundle, and audit target all live
in the container; nothing leaks to your host.

Common container shapes:

- **VS Code Dev Container / GitHub Codespaces** — declare `git`, `python3`,
  and `claude` or `copilot` in `.devcontainer/devcontainer.json`.
- **`cw` / similar tmux-based launchers** — boot a fresh container
  per audit, throw it away after.
- **Plain Docker / Podman** — `docker run --rm -it` a base image,
  install dependencies, mount the project read-only.

Inside the container:

```bash
# 1. Clone the audit target inside the container
git clone <your-target-repo> /workspace/target

# 2. Install one supported harness and authenticate in this container only
copilot login

# 3. Install the skill at user-level inside the container
git clone --depth 1 --branch v2.6.1 \
  https://github.com/velimattiv/claude-security-audit.git ~/Code/csa
bash ~/Code/csa/scripts/install-skill.sh --harness copilot

# 4. Verify
cat ~/.copilot/skills/security-audit/VERSION                  # 2.6.1
ls  ~/.copilot/skills/security-audit/manifest.yaml            # must exist
ls  ~/.copilot/skills/security-audit/lib/validate-findings.py # must exist

# 5. Install the scanner bundle directly. Inside an isolated
#    container, host pollution is a non-concern — scanners belong
#    in the container that's about to be thrown away.
bash ~/Code/csa/scripts/install-scanners.sh
bash ~/Code/csa/scripts/install-scanners.sh --check    # all six [OK]?

# 6. Run the audit
cd /workspace/target
copilot
> Use /security-audit to audit this repository.
```

For Claude Code, replace `copilot login` with `claude login`, pass
`--harness claude` to the installer, and invoke `/security-audit` directly.

When the audit completes, the container is disposable. Auth tokens,
scanner binaries, rule databases — all gone with the container.

## Acceptable: Path B (scanners-only-in-container, harness on host)

If a supported harness is already installed and authenticated on your daily-
driver host and you don't want to set up a full container per audit,
Path B isolates the scanner bundle alone:

```bash
# Build the scanner-isolation image (one-time, ~3-5 min)
bash ~/Code/csa/scripts/run-audit-in-container.sh --build
bash ~/Code/csa/scripts/run-audit-in-container.sh preflight
```

The wrapper uses Podman (preferred, rootless) or Docker. Container
hardening: `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
`--read-only` rootfs, non-root `audit` user. Target repo bind-mounted
read-only.

Path B leaves the agent harness itself on your host. The skill orchestrator
runs there; that's the larger trust boundary, but for one-off audits
it's a reasonable simplification of the recommended pattern.

## Strongly discouraged: host install (Path A direct)

```bash
# Don't do this on your daily-driver host without a strong reason.
bash ~/Code/csa/scripts/install-scanners.sh
```

Six security tools with auto-updating detection databases on your
laptop is invasive host state for a tool that may run once a week.
**Don't half-install** — a partial host install (some scanners
present, some missing) is worse than no install because the audit
report won't tell you which scanner-corroborated categories silently
skipped. If `install-scanners.sh --check` reports any scanner
missing, either fully fix the failure (e.g. `pipx` for semgrep) and
re-run, or roll back the partial install and switch to one of the
container patterns above.

Without scanners at all, the skill runs in degraded mode — fewer
corroborating sources, every finding drops to LIKELY/POSSIBLE
confidence.

## Smoke test

After installing, in any small repo:

```bash
cd <some-project>
copilot
```

Then in Copilot:

```
Use /security-audit to audit this repository.
```

In Claude Code, start `claude` and enter `/security-audit`. In an existing
Copilot session, run `/skills reload` after installation and verify with
`/skills info security-audit`.

Watch for the orchestrator's first Bash tool call — it should be the
preflight `mkdir -p .claude-audit/...` etc., resolving `$SKILL_DIR` and
writing `.claude-audit/.skill-dir`. If you see the orchestrator going
straight to reading project files without that preflight, something
is wrong with the install.

## Migrating from a different `security-audit` skill

If you already have a `security-audit` skill from a different
project (e.g. an older custom wrapper around `/security-review`),
**there is no in-place upgrade path** — this is a fundamentally
different skill (polyglot SARIF audit with 9-phase orchestration,
not a review-orchestrator).

```bash
# The installer stages and validates the new bundle, then moves any existing
# installation to a timestamped .security-audit.backup-* sibling.
bash ~/Code/csa/scripts/install-skill.sh --harness copilot
```

If both Claude and Copilot copies exist at different versions, runtime
preflight fails rather than silently mixing the activated `SKILL.md` with stale
resources. Remove the stale copy or set `AUDIT_SKILL_DIR` to the exact bundle
for that run.

## Validating the install (full E2E)

If you want to validate the install end-to-end before trusting it
on real projects, run the local E2E against a known-vulnerable
fixture (OWASP Juice Shop):

```bash
bash ~/Code/claude-security-audit/scripts/run-e2e-test.sh --harness copilot
```

Expected outcome:
- ~30-60 min wall time
- `PASS — all structural + fixture checks green`
- 12/12 fixtures matched (8 hard + 4 soft)
- 400+ findings across ~60 unique CWEs
- Valid SARIF, baseline, report under `/tmp/e2e-target/.claude-audit/`

The full reference run is documented at
[`docs/test-runs/e2e-full-run-v2.0.2-2026-04-25T0250Z.md`](test-runs/e2e-full-run-v2.0.2-2026-04-25T0250Z.md).

The Copilot E2E path uses `--allow-all` because it is non-interactive and must
run many shell tools and subagents. Run it only against the disposable target
clone in the recommended isolated environment. A complete Copilot E2E, not the
static compatibility suite, is the release gate for claiming runtime
equivalence.

## What gets installed

| Path | Purpose |
|---|---|
| `<skill-root>/SKILL.md` | Activation + description |
| `<skill-root>/workflow.md` | Orchestrator entry point |
| `<skill-root>/manifest.yaml` | Per-phase contract (machine-readable) |
| `<skill-root>/steps/phase-00..08-*.md` | Per-phase procedures |
| `<skill-root>/steps/deepdive/cat-01..12-*.md` | Per-category deep-dive prompts |
| `<skill-root>/lib/*.json` | Schemas (profile, partitions, surface, finding, baseline, cwe-map) |
| `<skill-root>/lib/validate-findings.py` | Sub-agent self-validation script |
| `<skill-root>/templates/subagent-prompt.md` | Sub-agent prompt template |

`<skill-root>` is `~/.claude/skills/security-audit` for Claude Code or
`${COPILOT_HOME:-$HOME/.copilot}/skills/security-audit` for Copilot CLI.
Project installs use `.claude/skills/security-audit` and
`.github/skills/security-audit`, respectively. Copilot also discovers
`.agents/skills`, but the installer uses `.github/skills` as its deterministic
project destination.

**Path A — host install** places binaries at:

| Tool | Default install path |
|---|---|
| semgrep | `~/.local/share/semgrep` (pip user install — needs `pipx` or `pip3 --user`) |
| osv-scanner | `~/.local/bin/osv-scanner` |
| gitleaks | `~/.local/bin/gitleaks` |
| trufflehog | `~/.local/bin/trufflehog` |
| trivy | `~/.local/bin/trivy` |
| hadolint | `~/.local/bin/hadolint` |

Make sure `~/.local/bin/` is on your `PATH`. Run
`scripts/install-scanners.sh --check` to verify all six landed.

**Path B — container-isolated** doesn't touch the host. The
`run-audit-in-container.sh` wrapper builds a Podman/Docker image with
all six scanners pre-baked and runs each scanner ephemerally with
hardening flags (`--cap-drop=ALL`, `--security-opt=no-new-privileges`,
`--read-only` rootfs, non-root `audit` user, bind-mounted target
read-only). See `scripts/run-audit-in-container.sh --help` for the
full command surface.

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
bash scripts/install-skill.sh --harness copilot
```

The skill writes `skill_version` into every artifact it produces, so
old artifacts in `.claude-audit/baseline.json` remain readable across
versions (delta mode invalidates per the rules in
`steps/phase-08-baseline.md`).

## Uninstalling

```bash
rm -rf ~/.copilot/skills/security-audit  # Copilot default
rm -rf ~/.claude/skills/security-audit   # Claude Code
```

The scanner bundle uninstalls per their respective install methods —
`pip uninstall semgrep` for semgrep, `rm ~/.local/bin/<tool>` for the
others.

## Troubleshooting

**`security-audit` is not discovered.**
For Copilot, run `/skills reload` then `/skills info security-audit`, and verify
`ls "${COPILOT_HOME:-$HOME/.copilot}/skills/security-audit/SKILL.md"`. For
Claude Code, verify `ls ~/.claude/skills/security-audit/SKILL.md` and restart
the session if needed.

**Audit produces only the report (under `docs/security-audit-output/`), no
`.claude-audit/`.**
This is the v2.0.1-era failure mode. The in-skill blackboard-first mandate
prevents it; if you see this, the install may be incomplete.
Re-run the verify step (cat VERSION, ls manifest.yaml).

**`SKILL_DIR not resolved` errors.**
The preflight Bash chain failed to find the skill at any of:
the Claude, Copilot, `.agents/skills`, project, or in-repo locations. Check the
installer's reported path. If multiple copies have different versions, remove
the stale copy or set `AUDIT_SKILL_DIR`.

**Phase 4 scanners missing → audit runs in degraded mode.**
This is by design — missing scanners are warnings, not failures.
Run `bash scripts/run-audit-in-container.sh --build` (Path B) or
`bash scripts/install-scanners.sh` (Path A) to fix.

**Path A install half-succeeded (some scanners present, some
missing).** Don't run the audit in this state — the report won't
tell you which categories ran fully. Either:
1. Fix the underlying issue (e.g. install `pipx` if semgrep
   failed; verify network for binary fetch failures) and re-run
   `scripts/install-scanners.sh`, OR
2. Roll back and use Path B:
   ```bash
   rm -f ~/.local/bin/{osv-scanner,gitleaks,trufflehog,trivy,hadolint}
   pip3 uninstall semgrep   # if it landed
   bash scripts/run-audit-in-container.sh --build
   bash scripts/run-audit-in-container.sh preflight
   ```
