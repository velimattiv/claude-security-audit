# End-to-End Testing

The skill's v2.0.1 shipped with per-phase dogfood evidence (7 milestone
writeups in `docs/test-runs/`) but no single `/security-audit` invocation
had ever been run start-to-finish. This doc describes the E2E fix:
`scripts/run-e2e-test.sh` + `tests/e2e/`.

## Why it exists

Per-phase dogfooding validates that individual sub-agents produce valid
artifacts, but does not prove the orchestrator can compose them. Real
failure modes the E2E catches that per-phase runs don't:

- **Fan-out composition.** Phase 5 spawns N partitions × 12 categories
  in parallel at 8-concurrent. Individual sub-agents have been tested;
  the orchestrator's concurrency cap + aggregation has not.
- **Phase transition artifacts.** The sub-agent RETURN SHAPE is the
  interface; the orchestrator parsing it on 50+ returns in one run is
  where schema drift bites.
- **Built-in reviews.** Phase 4's `/security-review` +
  `adversarial-review` per-partition sub-agents have been documented
  but never exercised in any dogfood.
- **Synthesis at full input scale.** Phase 7 synthesized partial Juice
  Shop data (2 of 9 cats = ~80 findings); the full run will land at
  200-400 findings with the accompanying Phase 6 methodology rows.
  SARIF size, report size, and context pressure are untested at
  full load.
- **Multi-pass artifact write-ordering.** Saga markers, baseline
  rotation, report path resolution — all have code paths that only
  fire on a complete run.

## Scope: local host harness

`scripts/run-e2e-test.sh --harness claude|copilot` invokes the selected
developer-host harness and its existing authentication. Claude remains the
default for backward compatibility. The script does NOT containerize the
orchestrator because:

1. **Interactive subscriptions keep host-local auth.** Claude Max and Copilot
   CLI login state live outside a fresh container. Mounting host credentials
   into a disposable image is a security-sensitive pattern we deliberately
   avoid.
2. **CI requires separately governed credentials and budget.** Claude API keys
   and Copilot GitHub tokens have different scopes, billing, and policy
   implications; neither should be inferred from a developer's login.
3. **Headless execution differs by harness.** The E2E runner adapts flags and
   validates their presence, but hosted-runner authentication remains an
   explicit deployment decision.

Scanners MAY run in the container-isolated path
(`scripts/run-audit-in-container.sh`) regardless — the E2E script is
orthogonal to that choice.

## GHA path (deferred)

Prerequisites before GHA can land:

| # | Blocker | Resolution |
|---|---|---|
| 1 | Auth strategy | Dedicated Claude API key or scoped Copilot GitHub token |
| 2 | Budget envelope | $5-20 per run × cadence decision (nightly = ≈$150/month) |
| 3 | Pre-artifact-upload secret scan | gitleaks + trufflehog on `.claude-audit/` before upload, in case the skill ever wrote a secret into its own trace |
| 4 | Artifact retention | 7-day retention at most; secrets cost here is asymmetric |
| 5 | Usage cap | Harness-specific credit/token cap + timeout fallback |

Tracked in `docs/ROADMAP.md` under "v2.1 candidates."

## Known false-pass conditions

From `tests/e2e/README.md §"False passes"`:

1. If `scripts/validate-findings.py` has a bug, schema violations pass.
2. If a fixture's `(file, cwe, category)` tuple coincidentally matches
   an unrelated finding at the same location. Risk low because the
   fixture is curated from Juice Shop's challenges.yml, not scanned.
3. Structural grep on the report checks headers, not body content.
4. Single-run evidence only. A non-deterministic sub-agent that
   sometimes fails is harder to catch — nightly runs (when GHA lands)
   would surface intermittent failure.

## Contributor workflow

When making changes that could affect skill behavior:

1. Run `scripts/validate-schemas.sh` first (fast; free).
2. Run `scripts/run-e2e-test.sh --dry-run` against a prior run's
   artifacts to validate the assertion suite still matches (free;
   catches fixture drift early).
3. Before merging any PR that touches `steps/deepdive/cat-*.md`,
   `steps/phase-05-deepdives.md`, or `steps/phase-07-synthesis.md`:
   run the full E2E on your host with the client whose behavior is affected,
   for example `scripts/run-e2e-test.sh --harness copilot`. This is expensive
   but unavoidable for claims about end-to-end orchestration.

4. For harness-only changes, always run the credential-free compatibility
   suite first:
   ```bash
   bash tests/test-harness-compat.sh
   ```

`CONTRIBUTING.md §Testing` documents this expectation.
