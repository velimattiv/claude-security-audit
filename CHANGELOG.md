# Changelog

All notable changes to this project. Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing queued. The skill is pre-release; open a Discussion issue to
propose v2.1 work.

## [2.0.1] — 2026-04-24

### Changed
Correctness fixes from two rounds of adversarial review. Because the
project is pre-release (no external users), breaking schema changes
were applied cleanly without backwards-compatibility aliases.

Tier 0 (correctness):
- **Phase 2 surface rows** now record `handler_file` and
  `registration_file` as distinct required fields. `handler_hash` is
  computed against the handler body file. Delta-mode invalidation keys
  off either file being in `git diff --name-only`. The v2.0.0 `file`
  alias has been dropped cleanly (pre-release; no users to migrate).
- **Baseline fingerprint** switched from `sha1(file:line:title)` to
  `sha1(handler_file:line:cwe:category)`. Stable across title drift.
  Finding schema documents the formula; sub-agents may emit the
  `fingerprint` field directly.
- **Severity promotion capped at ±1 rung**. Any strengthening signal
  (CONFIRMED, public zone, write data-op) contributes +1; the dev zone
  contributes −1; net positive promotes one rung, net negative demotes
  one, net zero is unchanged. Capped regardless of signal count.
- **`top_n` invocation arg wired through** to `phase-01-partition.md`.
  Previously advertised, not implemented.
- **90-day staleness check now enforced** in `mode: delta` preflight
  (was prose-only in v2.0.0).
- **Severity promotion** symmetric: `dev` trust zone demotes by 1
  rung.

### Added
Tier 1 evidence + validation:
- **Polyglot dogfood runs** against Go (gosec, 20 MITM findings) and
  PHP (DVWA, 40 injection findings). All Go + PHP grep patterns from
  cat-04/cat-08 now have execution evidence.
- **`scripts/validate-findings.py`** — JSONL schema validator that
  every Phase 5 / Phase 6 sub-agent MUST run before returning.
- **`scripts/verify-unique-findings.py`** — independent recount of the
  "unique-to-skill" claim; run it against the final SARIF + Phase 5
  JSONL to reconcile with the synthesis sub-agent's self-report.

Tier 2 docs:
- **`docs/ANTI-PATTERNS.md`** — the consolidated catalog the deepdive
  category files reference.
- **`CHANGELOG.md`** (this file).
- **`SECURITY.md`** — how to report vulnerabilities in *this skill*.
- **`CONTRIBUTING.md`** — branch convention, commit signing, test
  expectations.
- **Missing CWE entries** added to `lib/cwe-map.json`: CWE-208, 215,
  598, 1004.
- **Category-name aliases** documented in `workflow.md §0` (e.g.,
  `secrets → secret_sprawl`, `transport → mitm`).
- **Container-isolated execution** option — ship `scripts/Dockerfile.audit`
  and `scripts/run-audit-in-container.sh` so scanners can run in an
  ephemeral container, not on the host. README documents both paths.

Tier 3 installer hardening:
- **Checksum verification** for every downloaded binary; the installer
  refuses to install mismatched tarballs.
- **Trufflehog `curl | sh` replaced** with a direct release-tarball
  download + checksum verify (matches gitleaks pattern).
- **Permission-fail path** fixed: installer falls back to
  `$HOME/.local/bin` if `$PREFIX` isn't writable, consistently across
  all `install_*` functions.
- **Stale-version warning** via the `--check` path: each tool's pinned
  version is compared against the vendor's latest release tag.

Tier 4 automated testing + CI:
- **`scripts/validate-schemas.sh`** — sanity-checks every JSON
  schema parses, every cat-*.md referenced CWE exists in the map,
  every installer shell script passes `bash -n`.
- **`scripts/validate-findings.py`** accepts `--cwe-map` for a
  semantic check (every finding's `cwe` must exist in the map, not
  just match the `CWE-\d+` regex).
- **`.github/workflows/ci.yml`** — runs the validation suite on push +
  PR; catches schema drift / broken references before merge. Runs a
  regex-compile check on cat-*.md patterns as a polyglot regression
  guard.
- **`tests/fixtures/`** — minimal findings JSONL used by the validator
  tests.
- **`.github/CODEOWNERS`** — routes all PR reviews to @velimattiv.

Round 2 of adversarial review — additional fixes:
- Surface schema `file` alias dropped (pre-release cleanup).
- Severity rule rewritten: ±1 rung cap, any signal counts.
- `run-audit-in-container.sh` renamed semantically: the wrapper
  isolates the SCANNER phase, not the full audit. README and script
  comments now say so explicitly.
- `validate-findings.py` gained `--cwe-map` for semantic CWE
  validation (closes the "CWE-99999 passes" hole).
- CI adds a regex-compile check for cat-*.md grep patterns (catches
  pattern drift without a full sub-agent run).
- `Dockerfile.audit` restructured: single USER toggle (root → audit
  at the end), not the v2.0.1-initial three-toggle muddle.
- `check_stale_versions` in installer reads `GITHUB_TOKEN` env var
  to avoid the 60-req/hr unauthenticated rate limit when set.
- 1M-context claim toned down in `docs/test-runs/1m-context-check-*.md`
  from "verified" to "self-report evidence" with an honest caveat.
- ROADMAP.md updated — v2.0.1-delivered items removed from the
  candidate list.
- `docs/ANTI-PATTERNS.md` reworked as a pure index (one-line summary +
  link to the canonical cat-*.md). No duplicated pattern content.
- `validate-schemas.sh` documents its markdown-link-check limitation
  (catches `[text](path)` only; reference-style links unchecked).

### Fixed
- Broken references in `cat-*.md` to `docs/ANTI-PATTERNS.md` now
  resolve to a file that actually exists.
- Category-name mismatch between user-facing examples
  (`categories: "secrets"`) and internal enum (`secret_sprawl`);
  aliases resolve both.

## [2.0.0] — 2026-04-24

### Added
Initial v2 release. Complete polyglot security-audit skill.

- **9-phase workflow** (Phase 0 Discovery → Phase 8 Baseline).
- **171 attack surfaces** enumerated on OWASP Juice Shop dogfood;
  polyglot coverage for 15+ languages via framework-detection +
  surface-detection catalogs.
- **6 required scanners** orchestrated (semgrep, osv-scanner, gitleaks,
  trufflehog, trivy, hadolint) + 6 conditional (brakeman, checkov,
  kube-linter, grype, govulncheck, psalm, zizmor).
- **9 deep-dive categories** with language-specific grep catalogs.
- **5 modes**: full, delta, scoped, focused, report.
- **SARIF 2.1.0 emitter** + CycloneDX SBOM skeleton.
- **Baseline persistence** for delta-mode sub-minute PR reviews.
- **OWASP methodology tagging**: ASVS L2, API Top 10 (2023), LLM Top
  10 (2025), LINDDUN, STRIDE.

### Deferred to v2.1
See `docs/ROADMAP.md` for 12+ candidate improvements (AST handler
hashing, ASVS L3 support, non-English framework detection, pre-commit
recipe, pruned-baseline compression, Phase 2+3 fusion for single-
partition repos).

## [1.0.0] — 2025-xx-xx

Initial single-file `/security-audit` skill for Node/Nuxt. Replaced
in-place by 2.0.0.
