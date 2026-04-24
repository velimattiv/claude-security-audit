# v2.1 Roadmap Candidates

Surfaced during M1-M7 dogfooding and development. Not committed work —
these are items to consider for a future v2.1 release. Ordered by
severity of the underlying problem (highest impact first).

## Correctness refinements

### Phase 2 handler-file tracking (M2 follow-up)

**Problem.** The Phase 2 sub-agent records `file: <registration-site>`
(e.g., `server.ts` for Express routes) rather than
`<handler-body-file>` (e.g., `routes/login.ts`). When a handler body
file changes, the delta-mode `file ∈ changed_files` rule doesn't fire.

**Fix.** Add `handler_file` alongside `registration_file` in the
Phase 2 surface row, compute `handler_hash` against the handler body
file, and have the delta algorithm check both.

**Impact.** Tightens delta-mode invalidation from "relies on keystone
cascade" to "direct file-match" for modular-routing repos (Express,
Django, FastAPI with imported routers).

### AST-based handler hashing (supersedes content hashing)

**Problem.** Content hashing in `lib/handler-hash.md` over-invalidates:
whitespace-only formatting changes are stable, but any reordering
of independent statements is treated as a semantic change.

**Fix.** Replace `sha1(normalized_body)` with a lexer-derived token
stream hash (tokens only; no whitespace, no comments, no string
literal content). Requires per-language lexer (tree-sitter or
handler-rolled).

**Impact.** Reduces spurious delta-mode re-audits on refactor-heavy
PRs. Locked as v2.1 per Q10 at bootstrap.

### Fingerprint-off-CWE (baseline stability)

**Problem.** Finding fingerprints are `sha1(file:line:title)`. Title
drift between runs — e.g., sub-agent rephrases the same finding —
produces a "new" finding instead of a stable reference.

**Fix.** Compute fingerprint off
`file:line:cwe:rule_short_or_category`. Title drift no longer
changes the hash.

**Impact.** Cleaner baseline-diff noise-to-signal.

## Install / install-path ergonomics

### OSV-scanner lockfile warning

**Problem.** OSV-scanner on repos without a lockfile silently returns
0 findings — a dangerous false negative.

**Fix.** Phase 4 preflight detects manifest-without-lockfile (e.g.,
`package.json` without any of `package-lock.json`, `pnpm-lock.yaml`,
`yarn.lock`) and either:
  1. Runs `npm/pnpm/yarn install --frozen-lockfile` first (opt-in), or
  2. Emits a clear warning in the report's coverage section.

### Pre-commit hook recipe

**Problem.** `/security-audit mode: delta` is slow enough that it
doesn't fit a typical pre-commit budget, but stripped-down checks
(secrets, hardcoded keys, direct grep hits) could run in <5 sec.

**Fix.** Ship a `docs/ci-examples/pre-commit/` recipe that runs a
subset: semgrep on staged files + gitleaks staged + Phase 2 surface
re-enumeration for changed routes only. No Phase 5 / Phase 6.

### Installer progress UI

**Problem.** Trufflehog and trivy install via vendor install.sh scripts
that print their own progress bars; users see confusing interleaved
output.

**Fix.** Wrap install calls with `--quiet` where possible and emit
per-scanner `[installing trufflehog...]` / `[OK]` lines at the skill
installer level.

## Coverage / analysis

### Windows / WSL native support

**Problem.** Several scanners (osv-scanner, gitleaks) have native
Windows binaries; trivy and hadolint do. Semgrep does not. Full
native Windows is infeasible; full WSL support is already viable.

**Fix.** Document WSL-only officially; attempt a smaller Windows
binary bundle (semgrep-less) for audits that skip SAST.

### CodeQL integration (OSI-license auto-detection)

**Problem.** CodeQL is excluded by default because the CLI is
license-restricted to OSI-approved OSS. Eligible users currently have
to enable it manually.

**Fix.** Phase 0 heuristically detects OSI-approved licenses (parse
`LICENSE` / `LICENSE.md` / `package.json.license`). If matched, offer
(but don't auto-enable) CodeQL in the Phase 4 bundle.

### Non-English codebase support

**Problem.** Framework detection regex assumes English identifiers.
Known limitation documented in `lib/framework-detection.md`.

**Fix.** Expand detection to include common non-English naming patterns
for the top 5 languages where non-English codebases are significant
(Chinese, Japanese, Russian).

## Performance

### Pruned-baseline gzip for huge monorepos

**Problem.** 53KB pruned baseline for a 103K-LOC monolith; linear
scaling suggests ~500KB for a 1M-LOC 8-partition monorepo. Diffable,
but larger than necessary.

**Fix.** gzip the pruned baseline (`docs/security-audit-baseline.json.gz`)
if size exceeds 200KB. Check-in impact is small.

### Phase 2 + Phase 3 fusion for single-partition repos

**Problem.** Single-partition repos pay two sub-agent spawn costs for
Phase 2 + Phase 3 when the data flows sequentially.

**Fix.** Detect single-partition case in workflow §5 and run Phase 2
and Phase 3 as a single sub-agent.

## Methodology / tagging

### ASVS L3 support

**Problem.** Currently targets L2 only. Some regulated industries need
L3 coverage (finance, healthcare).

**Fix.** Add an optional `--asvs-level L3` flag; ship a sub-agent
prompt per V* L3 sub-item.

### Full LINDDUN expansion

**Problem.** Dogfood produced minimal LINDDUN coverage (4 entity
family rows). Full LINDDUN is 7 threats × per-PII-data-flow.

**Fix.** Expand `steps/phase-06-config.md §6.12` into a per-threat
sub-agent fan-out gated on PII column density.

## Documentation / UX

### Interactive "fix this finding" workflow

**Problem.** The report says "ask me to fix finding <id>", but the
flow from report → Claude Code chat → code diff isn't documented.

**Fix.** Add a "Fix flow" section to README and wire an explicit
`--fix <id>` sub-command.

### GitHub Issue creation from report

**Problem.** V1 had `gh issue create` from report; v2 mentions it in
Phase 7 but the actual invocation is manual.

**Fix.** Add a dedicated `/security-audit mode: issue` that spawns
the gh call with the correct body format.
