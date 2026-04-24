# /security-audit — Claude Code Skill

A thorough, multi-phase security audit skill for [Claude Code](https://code.claude.com).
Goes beyond generic vulnerability scanning by enumerating every attack
surface (HTTP, gRPC, GraphQL, WebSocket, queue consumers, serverless
handlers, mobile/desktop IPC — polyglot across 60+ frameworks), running an
OWASP-methodology-tagged scanner bundle, and executing 9 parallel deep-dive
categories (Auth/Authz, IDOR/BOLA, Token Scope, MITM, Crypto, Secrets,
Deployment, Injection/SSRF, LLM-specific).

**Supported runtime:** Claude Code only. Other harnesses are not supported.

**Status.** v2 is in active development. The milestone sequence (M1-M7) is
tracked in [`docs/V2-SCOPE.md`](docs/V2-SCOPE.md). Each milestone is a
self-contained increment: after M1 you can already run Phase 0 (Discovery)
and Phase 1 (Partition & Risk Rank); full audits unlock at M5.

## What it does (v2 target)

1. **Discover** — builds a Project Map: languages, frameworks, monorepo
   topology, ORM schemas, PII columns, LLM SDK usage, trust zones.
2. **Partition** — splits the repo into audit partitions and risk-ranks
   them so deep-dive budget goes where it matters.
3. **Inventory the attack surface** — not just HTTP routes: queues,
   schedulers, webhooks, file uploads, serverless, mobile/desktop IPC,
   admin/debug endpoints.
4. **Run the scanner bundle in parallel** — semgrep, osv-scanner, gitleaks,
   trufflehog, trivy, hadolint; optional brakeman, checkov, kube-linter,
   govulncheck, psalm, zizmor by detected context. All SARIF.
5. **Deep-dive 9 categories** — each as a separate Claude Opus 4.7 sub-agent,
   fanned out per partition × category.
6. **Synthesize** — dedupe, cross-reference, rank, tag with OWASP ASVS /
   API / LLM / LINDDUN / STRIDE / CWE methodology IDs.
7. **Emit** — human Markdown report, SARIF 2.1.0, CycloneDX SBOM, baseline
   JSON for delta mode.

Typical run: 15–60 minutes (full mode) or 2-5 minutes (delta mode after
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

From M3 onwards the skill's Phase 4 runs an external scanner bundle. Install
with:

```bash
scripts/install-scanners.sh            # required set
scripts/install-scanners.sh --check    # show current state
scripts/install-scanners.sh --help
```

Supported hosts:

- **macOS** (Homebrew)
- **Debian / Ubuntu** (apt)
- **Fedora** (dnf)
- **Arch** (pacman)

Windows is **not** supported — run inside WSL or a container. A container
image is an **optional** convenience, not a prerequisite — the skill runs on
any host with Claude Code plus the scanner bundle.

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

## Runtime state

The skill writes its working state under `.claude-audit/` at the project
root. Add `.claude-audit/` to the project's `.gitignore` (the skill will
offer to do this on first run). The baseline for delta mode is stored in
two places: the pruned `docs/security-audit-baseline.json` (checked in)
and the full `.claude-audit/baseline.json` (gitignored).

## Licensing & attribution

- This skill: MIT (see `LICENSE`).
- The adversarial review prompt under `skills/security-audit/vendored/adversarial-review/`
  is vendored unmodified from [bmad-method](https://github.com/bmad-code-org/BMAD-METHOD)
  by BMad Code, LLC, under MIT. See `NOTICE.md` and the vendored folder's
  `LICENSE` and `README.md` for full details.
- CodeQL is **excluded by default** because its CLI is license-restricted to
  OSI-approved OSS repositories. Users on eligible repos can enable it
  manually; see M7 documentation.
