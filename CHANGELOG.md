# Changelog

All notable changes to this project. Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing queued. The skill is pre-release; open a Discussion issue to
propose v2.1 work.

## [2.0.4] — 2026-04-25

### Fixed — silent hadolint install failure on case-mismatched checksum file

`scripts/install-scanners.sh:fetch_checksum_from_release()` did a
case-sensitive `awk` match against the asset filename inside the
vendor's `.sha256` file. Hadolint publishes its release asset as
`hadolint-Linux-x86_64` (capital L, in the URL) but the body of the
accompanying `hadolint-Linux-x86_64.sha256` file lists the filename
as `hadolint-linux-x86_64` (lowercase). The match failed; the script
returned an empty hash; `download_verified` aborted with
`cannot fetch checksum for hadolint-Linux-x86_64`; the user was
left with 5 of 6 scanners installed and no clear pointer to the
case-mismatch root cause.

The fix adds a fallback case-insensitive comparison using POSIX
`awk`'s `tolower()`. The exact-case match is still tried first
(unchanged behaviour for vendors who get this right); only on a
miss does the lowercased fallback run. Any future vendor with the
same case-quirk gets handled transparently.

Caught in production by a downstream user running v2.0.3's
`install-scanners.sh` on Fedora — same dogfood loop that caught
the v2.0.3 PEP 668 issue.

## [2.0.3] — 2026-04-25

### Fixed — Path B Containerfile build (release-blocker for the recommended scanner-isolation path)

`scripts/Dockerfile.audit` line 75 used `pip3 install --user
jsonschema==4.22.0`, which fails on the Debian 12 (bookworm) base
image with `error: externally-managed-environment` (PEP 668). The
fix adds `--break-system-packages` to that line, matching the
fallback chain `install-scanners.sh` already uses for semgrep
(lines 252-258 of that script). We're in a container — there's no
system Python to protect.

This bug shipped in v2.0.2 because the v2.0.2 E2E only validated
the host-install path (Path A inside the test environment). Path B
(`scripts/run-audit-in-container.sh --build`) was never built in
the E2E loop, so the regression went undetected. Caught by a real
user trying the recommended path on Fedora/Podman.

### Added — Path B regression gate

New `tests/e2e/test-path-b-build.sh` smoke test that:
1. Detects the container runtime (Podman preferred, Docker fallback).
2. Runs `scripts/run-audit-in-container.sh --build` end-to-end.
3. Runs preflight inside the built image and asserts ≥5 of 6
   scanners report `[OK]`.

Cheap (~3-5 min on first build, ~30s on rebuild with layer cache),
so it can run alongside the deep audit E2E without doubling wall
time. This is the regression gate that should have existed in
v2.0.2 — without it, any Dockerfile breakage ships silently.

### Changed — install docs reframe

`README.md` and `docs/INSTALL.md` reframe scanner installation:

- **Recommended pattern: isolated full container** (everything
  inside — `git`, `claude`, the skill, the scanner bundle, the
  audit target). Use `cw`, Codespaces, dev containers, or plain
  Docker — whichever isolation primitive you have. Path A install
  inside the disposable container is the right model: scanners
  belong there, host pollution is a non-concern.
- **Acceptable: Path B** (scanners-only-in-container, Claude on
  host). Reasonable for one-off audits where Claude Code is already
  installed on the host.
- **Strongly discouraged: Path A on your daily-driver host.** Six
  security tools with auto-updating rule databases on your laptop
  is invasive state for a tool that may run once a week.

The previous framing led at least one downstream system Claude to
default to host install when Podman was available and would have
been better served by container isolation.

## [2.0.2] — 2026-04-25

### Changed — reliability patch, no new capability

This is a patch release. **No new capability, no new artifacts, no
public-API changes.** (The E2E harness's invocation shape *does*
change — `--append-system-prompt` is gone — see the Honest Scope Note
below.) The patch moves the v2.0.1 artifact contract from external
runtime injection (the `--append-system-prompt` mandate in
`scripts/run-e2e-test.sh`) into the skill itself, so `/security-audit`
is self-mandating for every invocation shape — `claude -p`, interactive
chat, or external harness.

**Why this is a patch, not a minor.** The skill already *claims* to
produce machine-readable artifacts (per SKILL.md, per workflow.md's
MANDATORY ARTIFACT CONTRACT, per every phase's "Verify before exit"
block). It just failed to honor those claims reliably without the
external mandate. v2.0.2 makes the skill self-honor its existing
contract — by definition a bug fix.

#### What moved in-skill

- **`SKILL.md` description field** now carries the imperative artifact
  contract (the `MANDATORY ARTIFACT CONTRACT` text that was previously
  only in the `--append-system-prompt` injection). The description is
  loaded into model context on every skill invocation, so the mandate
  travels with the skill regardless of how the user invokes it.

- **Every `steps/phase-NN.md`** now leads with a
  `## 🛑 MANDATORY EXECUTION RULES (READ FIRST)` block (BMAD-shaped —
  emphatic, emoji-flagged, listing required outputs + sub-agent fan-out
  + DO-NOT anti-patterns). Pattern borrowed from the
  `bmad-create-architecture` skill in the BMAD installation.

- **Phase 5 §5.2 rewrite** — the fan-out procedure is now an explicit
  Agent-tool invocation procedure with the exact tool-call shape, not
  descriptive prose. Single-shot orchestrator mode can no longer
  interpret "Phase 5 fans out to sub-agents" as "cover all 9 categories
  in one head-space" — the missed-bug anti-pattern from E2E runs 2-3 is
  now called out explicitly.

- **Phase 6 §6.9, §6.12, §6.13 rewrite** — ASVS, LINDDUN, and STRIDE
  methodology fan-outs similarly made literal.

- **`skills/security-audit/manifest.yaml`** — new structured machine-
  readable version of the per-phase contract (schema-versioned). The
  prose files remain authoritative for orchestrator behavior; the
  manifest is authoritative for downstream tooling (E2E assertion
  suite, future CI checks, delta-mode preflight).

#### What moved out of the E2E harness

- **`scripts/run-e2e-test.sh` drops `--append-system-prompt`.** The
  E2E run now validates that the in-skill mandate is sufficient. If a
  future regression re-breaks report-only output, the E2E fails and
  the fix belongs in-skill, not as external scaffolding. A comment
  in the script records this principle.

#### Delivery note

v2.0.1's E2E PASS (documented in
`docs/test-runs/e2e-full-run-2026-04-24T232300Z.md`) relied on the
external `--append-system-prompt` mandate. **v2.0.2 produces a clean
PASS on the same Juice Shop @ v19.2.1 fixture *without* the mandate**
— validated 2026-04-25 in
`docs/test-runs/e2e-full-run-v2.0.2-2026-04-25T0250Z.md`. Highlights:

- **12/12 fixtures matched** (vs 8/12 in v2.0.1) — the four soft
  misses (alg:none, 2FA trust, zip-slip, LFI) are all caught now,
  thanks to Phase 5 fan-out actually fanning out.
- **474 findings** (vs 25 in v2.0.1, 19× depth) across **60 unique
  CWEs** (vs 21).
- **Phase 5 emitted 64 per-(category × partition) JSONLs** + matching
  `.done` markers, vs v2.0.1's single consolidated `phase-05-tokens.json`.
- **17 ASVS L2 sub-agents** ran (V1-V17), each writing per-category
  intermediates concatenated into the canonical `phase-06-asvs.jsonl`.
- 51m 41s wall time — slower than v2.0.1's 7m, but trading minimum-
  viable for genuinely deep per-(cat, part) analysis.

#### Honest scope note

This patch removes the external `--append-system-prompt` mandate from
`scripts/run-e2e-test.sh`. That is a behavioural change to the E2E
harness even though there is no public API change. Any local user
copying `run-e2e-test.sh`'s mandate text for their own GHA harness
should know that the in-skill MANDATORY blocks are now the only place
the contract lives — there is no second source of truth to fall back
on.

Round 4 of adversarial review — additional fixes integrated into the
[2.0.1] entry below:
- `cwe-map.json` gains a `$schema` declaration for consistency with
  other lib/*.json files.
- `validate-findings.py` load_cwe_map hard-fails on missing /empty
  `mappings` instead of silently passing every CWE.
- `tests/fixtures/surface-minimal.json` contradictory row replaced
  with a consistent `NO_AUTH_WRITE` surface (auth_required=false).
- `.github/dependabot.yml` adds a `docker` ecosystem watcher so the
  Dockerfile.audit base-image digest pin doesn't decay.
- `run-audit-in-container.sh scan <tool>` now passes extra args
  through to the inner scanner command (e.g., `--config p/python`).
- Phase 0 §0.5 documents the multi-framework conflict rule: emit one
  entry per detected framework, don't silently pick one.
- Phase 1 §Axis-6 documents proactive partition pre-splitting at
  125K LOC instead of reactive-only needs_recursion.
- `.github/PULL_REQUEST_TEMPLATE.md` + `.github/ISSUE_TEMPLATE/*.md`
  make contribution expectations visible at submission time.
- Severity rule rationale in `phase-07-synthesis.md §7.4` rewritten
  to be internally consistent — no more contradictory framings.
- `workflow.md §5` adds an honest caveat: orchestrator-side
  re-validation is defense-in-depth, not cryptographic enforcement.
- `workflow.md §5` explicitly documents the file-lock convention
  (disjoint per-(cat,partition) paths; concurrency cap enforces
  non-overlap).
- `docs/test-runs/README.md` annotates superseded content (M5
  fingerprint formula + M6 surface.file lookup) so readers know
  which writeups reflect v2.0.1 state.
- `validate-patterns.py` gains a `--verbose` flag for debugging
  false negatives.
- `CODEOWNERS` notes the single-maintainer risk explicitly.
- README dropped the unmeasured "~500 MB image size" claim.

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
