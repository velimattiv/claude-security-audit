# Security Policy — /security-audit skill

## Reporting a vulnerability

If you find a vulnerability in this skill itself — e.g., prompt
injection through a crafted target repo, a scanner invocation that
leaks the operator's env, an installer that executes untrusted code —
please report it privately.

**Preferred:** [GitHub private vulnerability report](https://github.com/velimattiv/claude-security-audit/security/advisories/new).

**Alternate:** email `veli-matti@vanamo.com` with subject
`[security-audit vuln] <short summary>`. We aim to respond within 72
hours.

Do **not** file a public issue for a security bug. Do **not** disclose
on Twitter / Mastodon / Bluesky before a fix ships.

## Scope

In scope:
- The skill's orchestrator (`workflow.md`, `steps/phase-*.md`).
- The scanner installer (`scripts/install-scanners.sh`).
- The sub-agent prompt templates (attack: malicious targets prompting
  the sub-agent to do something outside its allotted tool use).
- The CI example (`docs/ci-examples/`) — attack: a malicious PR that
  coerces the GHA workflow into exposing `GITHUB_TOKEN` or secrets.
- JSON Schemas (attack: crafted findings that cause synthesis crashes).

Out of scope (report to the respective vendor):
- Vulnerabilities in the scanner bundle itself (semgrep, osv-scanner,
  gitleaks, trufflehog, trivy, hadolint) — forward to those projects.
- Vulnerabilities in Claude Code's runtime — report to Anthropic.
- Vulnerabilities discovered *by* the skill in someone else's code —
  those are audit findings, not skill bugs.

## Supply chain

This skill installs six external scanners over the public network and
copies them into `$PREFIX`. The installer has been hardened to verify
vendor-published checksums on every download (v2.0.1+); prior to v2.0.1
only HTTPS transport was enforced. If you were using v2.0.0, we
recommend re-running the installer after upgrading to v2.0.1+ to
re-verify checksums against the latest vendor releases.

For hosts where installing scanners globally is undesirable, use the
container-isolated execution mode: `scripts/run-audit-in-container.sh`
runs the full audit inside an ephemeral OCI container, leaving the host
filesystem untouched.

## Coordinated disclosure

For confirmed reports we will:
1. Acknowledge receipt within 72 hours.
2. Publish a draft fix privately for reporter review within 7 days.
3. Ship a patched release + GitHub Security Advisory within 14 days.
4. Credit the reporter in the advisory (unless they prefer anonymity).

Thank you for helping keep users of the skill safe.
