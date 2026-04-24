# Troubleshooting

Common issues running `/security-audit` and how to fix them.

## Install

### "command not found: semgrep" (after running install-scanners.sh)

The script installs `semgrep` via `pip3 --user`, which lands in
`~/.local/bin/`. If that directory isn't on `PATH`, the binary exists but
the shell can't find it. Fix:

```bash
export PATH="$HOME/.local/bin:$PATH"   # add to ~/.bashrc / ~/.zshrc
```

### "Permission denied: /usr/local/bin"

`install-scanners.sh` prefers `/usr/local/bin` if writable. On systems
where it is owned by root (typical macOS + Linux), the script falls back
to `~/.local/bin`. Either add that to `PATH` (see above) or re-run with
`SUDO=sudo`:

```bash
SUDO=sudo scripts/install-scanners.sh
```

### Trivy "failed to download vulnerability DB: context deadline exceeded"

Trivy downloads a ~91MB DB from `mirror.gcr.io/aquasec/trivy-db:2` on
first run. On slow / metered / air-gapped networks this times out. Workarounds:

1. **Pre-seed the DB** on a box with good network and copy to `~/.trivy/`.
2. **Skip vuln scanning** temporarily: the skill degrades to
   `trivy config` (IaC scan only) automatically when the DB is
   unreachable.
3. **Mirror the DB** inside your network and point trivy at it:
   ```bash
   export TRIVY_DB_REPOSITORY=your-mirror.example.com/trivy-db
   ```

### "docker" asked to run but you don't use Docker

The skill does not require Docker. Container images are an **optional**
convenience; the skill runs natively on macOS / Linux with just the
scanner bundle. If you see a Docker prompt, it's from a specific scanner
(trivy image scanning, osv-scanner container mode) — check the scanner's
own docs.

## Discovery (Phase 0)

### Profile shows `loc_total: 0` or a tiny number

Your host likely lacks both `cloc` and `tokei`. The skill falls back to
`git ls-files | wc -l` for rough sizing. Install one:

```bash
# macOS
brew install cloc   # or: cargo install tokei

# Debian/Ubuntu
sudo apt install cloc
```

### Framework not detected

`lib/framework-detection.md` covers 30+ frameworks across 15 languages.
If yours isn't listed, the skill emits `framework: null` with the
manifest path it checked. Open an issue with the manifest + a one-line
framework identifier and we'll add the recipe.

## Scanner phase (Phase 4)

### Semgrep "Cannot create auto config when metrics are off"

`--config auto` requires metrics to be ON (semgrep sends the detected
languages to the registry to pick rules). The skill's default opts OUT
of telemetry and uses explicit rulesets instead
(`p/security-audit` + `p/owasp-top-ten` + `p/jwt`). If you want the
broader `auto` set, set an env var before the skill runs:

```bash
export SEMGREP_SEND_METRICS=on
```

### OSV-scanner returns 0 findings on a repo with known CVEs

OSV-scanner requires a lockfile (`package-lock.json`, `pnpm-lock.yaml`,
`go.sum`, etc.). If your repo commits only the manifest (`package.json`,
`go.mod` without `go.sum`, etc.), OSV has nothing to evaluate. Either:
1. Commit the lockfile, or
2. Run `npm/pnpm/yarn install` / `go mod download` before the audit.

The skill will warn when manifests exist without lockfiles.

### "trufflehog: only verified" misses known test secrets

By default trufflehog's `--only-verified` flag filters to secrets that
were actually confirmed valid via vendor API calls. Test fixtures and
revoked keys are filtered out. To see everything, override the flag in
your Phase 4 sub-agent invocation (documented in
`skills/security-audit/steps/phase-04-scanners.md`).

## Deep dives (Phase 5)

### Sub-agent returns `needs_recursion`

Your partition exceeds the 500K-token soft limit. The orchestrator
should auto-split it; if it doesn't, manually narrow the scope:

```
/security-audit scope: "services/api/users"     # a sub-path of a huge partition
```

### "Findings spam" on intentionally-vulnerable demo apps

Expected. Juice Shop / DVWA / etc. are designed to fail audits. Use the
baseline-mode diff to filter to *new* findings across runs. The skill's
Phase 7 report includes a "Unique-to-skill" section so you can see which
findings the scanner bundle didn't already flag.

## Synthesis (Phase 7)

### Report fails to save to `docs/security-audit-report.md`

Check whether `_bmad-output/implementation-artifacts/` exists. If it
does, the report goes there instead (BMAD compatibility). If neither
path is writable, the report stays in `.claude-audit/current/phase-07-report.md`
and the skill prints a warning.

### SARIF upload to GitHub rejected

GitHub's Security tab accepts SARIF 2.1.0 with strict schema. The skill's
emitter validates before writing, but very occasionally a deeply-nested
finding breaks validation. If `gh api` / GitHub Action upload errors:

1. Run `jq -e '.runs[0].results[0:5]' .claude-audit/current/findings.sarif`
   to spot any malformed rows.
2. File an issue with the offending row — we'll fix the emitter.

## Delta mode

### "Baseline >90 days old — falling back to full"

Rule of thumb: re-run a full audit quarterly. The 90-day floor is
conservative because OSV / gitleaks rule updates land continuously and
would be skipped in delta. Override:

```bash
/security-audit mode: delta --force-stale-baseline
```

### "Baseline git_head unreachable from HEAD"

Your baseline was created on a commit that's no longer in your local
history (e.g., after a rebase or a shallow pull). Re-run full mode; the
new baseline supersedes the old.

## Reporting bugs

Open an issue at
[github.com/velimattiv/claude-security-audit/issues](https://github.com/velimattiv/claude-security-audit/issues)
with:
- The skill version (`cat skills/security-audit/VERSION`).
- Your OS + arch.
- The `scripts/install-scanners.sh --check` output.
- The first ~20 lines of `.claude-audit/current/audit.log` if the run
  failed.
