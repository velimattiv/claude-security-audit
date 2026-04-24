# CI Integration Examples

Working example workflows for running `/security-audit` in CI. Copy the
relevant file into your repo's CI directory and wire in the secret(s).

## GitHub Actions

See `github-actions/security-audit.yml`.

Behavior:
- **Push to `main`**: run `full` mode; commit the refreshed baseline
  back to the repo with `[skip ci]`.
- **Pull request**: run `delta` mode if a baseline exists, else `full`.
  Uploads SARIF to the Security tab and **fails** the PR on CRITICAL
  findings.
- **Nightly**: full audit (catches new CVEs published against pinned
  dependencies).

Required repo configuration:
- Secret `ANTHROPIC_API_KEY`.
- Permission `security-events: write` (in the workflow file).

## GitLab CI, Buildkite, CircleCI

Not provided as first-party examples. The workflow is mechanically
equivalent to the GitHub Actions one:

1. Full-history checkout.
2. Run `scripts/install-scanners.sh`.
3. Invoke `claude --skill security-audit "/security-audit mode: <mode>"`.
4. Upload `.claude-audit/current/findings.sarif` to your pipeline's
   SARIF consumer (DefectDojo, Codacy, etc.).
5. (Optional) Gate on CRITICAL count.

PRs welcome if you adapt the GitHub example to another CI system.
