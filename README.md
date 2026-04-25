# /security-audit — Claude Code Skill

[![ci](https://github.com/velimattiv/claude-security-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/velimattiv/claude-security-audit/actions/workflows/ci.yml)
[![codeql](https://github.com/velimattiv/claude-security-audit/actions/workflows/codeql.yml/badge.svg)](https://github.com/velimattiv/claude-security-audit/actions/workflows/codeql.yml)
[![license: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A thorough, multi-phase security audit skill for [Claude Code](https://code.claude.com).
Goes beyond generic vulnerability scanning by enumerating every attack
surface (HTTP, gRPC, GraphQL, WebSocket, queue consumers, serverless
handlers, mobile/desktop IPC — polyglot across 60+ frameworks), running an
OWASP-methodology-tagged scanner bundle, and executing 9 parallel deep-dive
categories (Auth/Authz, IDOR/BOLA, Token Scope, MITM, Crypto, Secrets,
Deployment, Injection/SSRF, LLM-specific).

**Supported runtime:** Claude Code only. Other harnesses are not supported.

## Version

- **v2.0.5** (current) — Phase 4 ↔ Path B wrapper integration.
  The skill now actually uses the container wrapper when host
  scanners aren't on PATH (or when `$AUDIT_FORCE_PATH_B=1`).
  Closes the gap that made Path B half-implemented in v2.0.2-2.0.4.
  Plus wrapper hardening (`$AUDIT_CONTAINER_RUNTIME` override,
  `docker build --load`, `--build` exits after build) and
  `run-e2e-test.sh --path-b` flag.
- **v2.0.4** — case-insensitive checksum match in
  `install-scanners.sh` (fixes silent hadolint install failure
  caused by the hadolint vendor publishing its `.sha256` file body
  in lowercase while the asset URL uses capital-L `Linux`).
- **v2.0.3** — Path B Containerfile fix (PEP 668) + regression gate
  (`tests/e2e/test-path-b-build.sh`).
- **v2.0.2** — in-skill artifact mandate (no external
  `--append-system-prompt`); E2E PASS against juice-shop@v19.2.1
  with 12/12 fixtures matched, 474 findings, 60 unique CWEs.
  See `docs/test-runs/e2e-full-run-v2.0.2-2026-04-25T0250Z.md`.
- **v2.0.0** — full polyglot audit, 9 deep-dive categories, 6
  required + 6 conditional scanners, SARIF + SBOM + delta-mode baseline.
  See `docs/V2-SCOPE.md` for the design spec.
- **v2.1 candidates** — listed in `docs/ROADMAP.md`.

## What it does

1. **Discover** — builds a Project Map: languages, frameworks, monorepo
   topology, ORM schemas, PII columns, LLM SDK usage, trust zones
   (Phase 0).
2. **Partition** — splits the repo into audit partitions and risk-ranks
   them so deep-dive budget goes where it matters (Phase 1).
3. **Inventory the attack surface** — not just HTTP routes: queues,
   schedulers, webhooks, file uploads, serverless, mobile/desktop IPC,
   admin/debug endpoints (Phase 2).
4. **Keystone index** — the files whose change cascades invalidation
   (Phase 3).
5. **Run the scanner bundle in parallel** — semgrep, osv-scanner,
   gitleaks, trufflehog, trivy, hadolint; optional brakeman, checkov,
   kube-linter, govulncheck, psalm, zizmor by detected context. All
   SARIF (Phase 4).
6. **Deep-dive 9 categories** — each as a Claude Opus 4.7 sub-agent,
   fanned out per partition × category (Phase 5).
7. **Config audit + methodology spine** — CORS/CSP/cookies/headers plus
   ASVS L2 / API Top 10 / LLM Top 10 / LINDDUN / STRIDE (Phase 6).
8. **Synthesize** — dedupe, cross-reference, rank, tag with OWASP /
   CWE methodology IDs. Emit human Markdown report, SARIF 2.1.0, and
   CycloneDX SBOM (Phase 7).
9. **Baseline** — persist for sub-minute delta-mode re-audits on PRs
   (Phase 8).

Typical run: 15–60 minutes (full mode) or 2–5 minutes (delta mode after
baseline exists).

## Install

User-level (available in every project), pinned to a tagged release:

```bash
git clone --depth 1 --branch v2.0.5 \
  https://github.com/velimattiv/claude-security-audit.git ~/Code/claude-security-audit
cp -R ~/Code/claude-security-audit/skills/security-audit ~/.claude/skills/security-audit
cat ~/.claude/skills/security-audit/VERSION   # → 2.0.2
```

Project-level (just this repo):

```bash
git clone --depth 1 --branch v2.0.5 \
  https://github.com/velimattiv/claude-security-audit.git /tmp/csa
mkdir -p .claude/skills
cp -R /tmp/csa/skills/security-audit .claude/skills/security-audit
```

For a step-by-step install (with backup of any existing
`security-audit` skill, smoke-test, full-E2E validation, troubleshooting,
and uninstall), see **[`docs/INSTALL.md`](docs/INSTALL.md)**.

## Scanner prerequisites

The skill brings six security tools (semgrep, osv-scanner, gitleaks,
trufflehog, trivy, hadolint) plus their rule databases. **The
recommended deployment shape is to run the entire audit — Claude
Code, the skill, the scanners, and the project clone — inside an
isolated container.** That keeps your daily-driver host clean and
matches CI/production isolation.

### Recommended — isolated container (everything inside)

Use any container shape that gives you a clean working environment
with `git`, Node 20+, Python 3.10+, plus a way to run `claude`. Common
patterns:

- **VS Code Dev Container / GitHub Codespaces** — declare
  `git`/`claude`/`python3` in `.devcontainer/devcontainer.json`,
  open the project, run the scanner installer + audit inside.
- **`cw` launcher / similar tmux-based container launchers** — boot
  a fresh container per audit, install everything inside, throw
  the container away after.
- **Plain Docker / Podman** — `docker run --rm -it` a base image,
  install dependencies, mount the project read-only.

Inside the isolated container:

```bash
# Clone the audit target inside the container
git clone <your-target-repo> /workspace/target

# Install Claude Code (https://docs.anthropic.com/claude-code/install)
# and authenticate in this container instance only
claude login

# Install the skill at user-level inside the container
git clone --depth 1 --branch v2.0.5 \
  https://github.com/velimattiv/claude-security-audit.git ~/Code/csa
cp -R ~/Code/csa/skills/security-audit ~/.claude/skills/security-audit

# Install the scanner bundle (Path A — direct install). This is the
# right install model for an isolated container: scanners are part
# of the container's purpose, host pollution is a non-concern.
bash ~/Code/csa/scripts/install-scanners.sh

# Run the audit
cd /workspace/target
claude --dangerously-skip-permissions
> /security-audit
```

When the audit's done, the entire container is disposable —
including the auth, the scanner binaries, and any cached rule
databases. Nothing leaks to your host.

### Acceptable — Path B (scanners-only-in-container, Claude on host)

If you really want Claude running on your daily-driver host (e.g. you
already have Claude Code installed and authenticated there, and the
audit is one-off), Path B isolates only the scanner bundle:

```bash
scripts/run-audit-in-container.sh --build      # one-time
scripts/run-audit-in-container.sh preflight    # verify
scripts/run-audit-in-container.sh scan semgrep # per-scanner runs
```

The wrapper uses Podman (preferred, rootless) or Docker. Container
hardening: `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
`--read-only` rootfs, non-root `audit` user. Target repo bind-mounted
read-only; only `.claude-audit/` is writable.

This still leaves Claude Code on your host. The skill orchestrator
runs there and is the larger trust boundary.

### Strongly discouraged — Path A on your daily-driver host

```bash
scripts/install-scanners.sh    # only if you really mean it
```

Six security tools on your laptop is invasive host state for a tool
that may run once a week. The scanners auto-update their detection
databases — that's continuous host churn from a security tool you
installed *to look at security*. Use the isolated-container pattern
above unless you genuinely have no option.

If you do go this route: don't half-install. A partial host install
(some scanners present, some missing) is worse than no install —
the audit report won't tell you which scanner-corroborated categories
silently skipped. Run `scripts/install-scanners.sh --check` to verify
all six landed; if any failed, fully fix the failure and re-run.

Supported hosts: macOS (Homebrew), Debian/Ubuntu (apt), Fedora (dnf),
Arch (pacman). Windows is **not** supported — use WSL or the isolated
container pattern.

**What Path B does NOT isolate.** The skill's orchestrator
(`workflow.md`), deep-dive sub-agents (Phase 5), built-in-review
sub-agents (Phase 4's `/security-review`, adversarial-review), and
synthesis (Phase 7) all run in whatever runtime Claude Code uses.
Treat Path B as "sandboxed scanners," not "sandboxed audit."

### Required scanner bundle (six, all SARIF-emitting, free / open-source)

- **semgrep** — polyglot SAST, community ruleset.
- **osv-scanner** — SCA across all manifest ecosystems.
- **gitleaks** — secrets in working tree + git history.
- **trufflehog** — verified-secret sweep.
- **trivy** — IaC + Dockerfile + vulns + SBOM.
- **hadolint** — Dockerfile lint.

Conditional adds (installed on demand by context): brakeman (Rails), checkov
(Terraform-heavy), kube-linter (Kubernetes), govulncheck (Go reachability),
psalm (PHP taint), zizmor (GitHub Actions).

If any scanner is missing, the skill prints a degraded-mode warning and
continues with whatever is installed. **Never hard-fails** for a missing
scanner.

## Use

In Claude Code, invoke with:

```
/security-audit                                   # full audit
/security-audit mode: delta                       # requires baseline
/security-audit scope: "services/api"             # narrow to a path
/security-audit categories: "crypto,mitm,secrets" # run only named deep-dives
/security-audit mode: report                      # re-emit from artifacts
/security-audit top_n: 12                         # override partition cap
```

Reports land in `docs/security-audit-report.md` (or
`_bmad-output/implementation-artifacts/security-audit-report.md` if a
BMAD output directory is already present in the project).

## CI integration

See `docs/ci-examples/github-actions/security-audit.yml` for a working
example: runs on push / PR / nightly, uploads SARIF to the Security tab,
and fails the PR on CRITICAL findings. Adaptations to GitLab / Buildkite /
CircleCI are mechanically similar; PRs welcome.

## Runtime state

The skill writes its working state under `.claude-audit/` at the project
root. Add `.claude-audit/` to the project's `.gitignore` (the skill will
offer to do this on first run). The baseline for delta mode is stored in
two places: the pruned `docs/security-audit-baseline.json` (checked in)
and the full `.claude-audit/baseline.json` (gitignored).

## Troubleshooting

See `docs/TROUBLESHOOTING.md` for common issues (scanner install,
network-blocked vuln DB, semgrep auto-vs-explicit rulesets, delta-mode
staleness, SARIF upload rejection).

## Licensing & attribution

- This skill: MIT (see `LICENSE`).
- The adversarial review prompt under
  `skills/security-audit/vendored/adversarial-review/` is vendored
  unmodified from [bmad-method](https://github.com/bmad-code-org/BMAD-METHOD)
  by BMad Code, LLC, under MIT.
- `skills/security-audit/lib/cwe-map.json` reproduces CWE IDs and names
  from MITRE's Common Weakness Enumeration under CC BY 4.0.
- `skills/security-audit/lib/asvs-l2.md` references OWASP ASVS 5.0
  category topics (canonical text at https://github.com/OWASP/ASVS).
- See `NOTICE.md` for full per-file attribution and scanner bundle
  license transparency.
- CodeQL is **excluded by default** because its CLI is license-restricted to
  OSI-approved OSS repositories. Users on eligible repos can enable it
  manually; see `NOTICE.md` and the conditional-scanner docs.
