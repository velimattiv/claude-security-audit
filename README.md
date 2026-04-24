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

- **v2.0.0** (current) — full polyglot audit, 9 deep-dive categories, 6
  required + 6 conditional scanners, SARIF + SBOM + delta-mode baseline.
  See `docs/V2-SCOPE.md` for the design spec. Dogfooded against OWASP
  Juice Shop; test-run evidence in `docs/test-runs/`.
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

User-level (available in every project):

```bash
git clone https://github.com/velimattiv/claude-security-audit.git /tmp/csa
mkdir -p ~/.claude/skills
cp -r /tmp/csa/skills/security-audit ~/.claude/skills/
```

Project-level (just this repo):

```bash
git clone https://github.com/velimattiv/claude-security-audit.git /tmp/csa
mkdir -p .claude/skills
cp -r /tmp/csa/skills/security-audit .claude/skills/
```

## Scanner prerequisites

Two install paths. Pick based on whether you want the six scanners on
your host or isolated in a container.

### Path A — host install (simple, default)

```bash
scripts/install-scanners.sh            # install required set
scripts/install-scanners.sh --check    # report current state
scripts/install-scanners.sh --help
```

Supported hosts:

- **macOS** (Homebrew)
- **Debian / Ubuntu** (apt)
- **Fedora** (dnf)
- **Arch** (pacman)

Windows is **not** supported — run inside WSL or Path B. The installer
**verifies published checksums** for every downloaded binary (v2.0.1+);
mismatches abort the install.

### Path B — container-isolated scanner execution

**Scope clarification.** This path isolates the *scanner bundle*
(semgrep, osv-scanner, gitleaks, trufflehog, trivy, hadolint) — not the
full skill orchestration. Claude Code and its deep-dive sub-agents still
run on the host (or wherever Claude Code is installed); only the
scanner phase's binaries live in an ephemeral container. For many
users that's the point: scanners are the new dependency the skill
introduces; Claude Code was already installed.

```bash
# One-time: build the scanner-isolation image (size depends on your base — expect a few hundred MB of scanners + dependencies on top of debian:bookworm-slim)
scripts/run-audit-in-container.sh --build

# Run preflight (scanner presence check) in the container
scripts/run-audit-in-container.sh preflight

# Run a specific scanner against the target repo from inside the container
scripts/run-audit-in-container.sh scan semgrep
scripts/run-audit-in-container.sh scan osv-scanner
scripts/run-audit-in-container.sh scan gitleaks
scripts/run-audit-in-container.sh scan trufflehog
scripts/run-audit-in-container.sh scan trivy
scripts/run-audit-in-container.sh scan hadolint

# Drop into a container shell for ad-hoc runs
scripts/run-audit-in-container.sh shell
```

The wrapper uses Podman (preferred, rootless) or Docker — whichever
you have. Container hardening: `--cap-drop=ALL`,
`--security-opt=no-new-privileges`, `--read-only` rootfs, non-root
`audit` user. The target repo is bind-mounted read-only; only
`.claude-audit/` is writable.

**What Path B does NOT isolate.** The skill's orchestrator
(`workflow.md`), deep-dive sub-agents (Phase 5), built-in-review
sub-agents (Phase 4's `/security-review`, adversarial-review), and
synthesis (Phase 7) all run in whatever runtime Claude Code uses.
Treat Path B as "sandboxed scanners," not "sandboxed audit."

### Required scanner bundle (both paths)

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

Required scanner bundle (six, all SARIF-emitting, free / open-source):

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
