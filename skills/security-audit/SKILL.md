---
name: security-audit
description: "Comprehensive polyglot security audit. Discovers the attack surface across 60+ frameworks, runs a SARIF scanner bundle, executes 9 parallel deep-dive categories, and produces machine-readable artifacts (.claude-audit/current/phase-NN-*.json + findings.sarif + baseline) PLUS an OWASP-methodology-tagged human report. The artifacts are mandatory outputs, not optional ceremony. Invoke when the user asks to 'run security audit', 'security audit', 'audit security', or passes args like 'mode: delta' / 'scope: services/api' / 'categories: crypto,mitm,secrets'. Typical run 15-60 minutes (full) or 2-5 minutes (delta)."
---

# Mandatory contract before you do anything else

This skill produces **two kinds of output** on every run. Both are required:

1. **Machine-readable blackboard artifacts** under `.claude-audit/current/`:
   - `phase-00-profile.json` … `phase-08-baseline.json` (per-phase artifacts)
   - `phase-NN.done` saga markers (one per completed phase)
   - `findings.sarif` (SARIF 2.1.0)
   - `findings.cyclonedx.json` (SBOM skeleton)
2. **A human-readable Markdown report** at `docs/security-audit-report.md`
   (or `_bmad-output/implementation-artifacts/security-audit-report.md` if
   that BMAD directory exists in the project).

**Producing only the report is INVALID.** A run that writes the human
report but skips the blackboard artifacts breaks downstream value:
delta mode fails (no baseline), GitHub Security tab integration fails
(no SARIF), CI gating on CRITICAL counts fails (no structured findings).
**If you find yourself reasoning "I'll just produce the final
report" — STOP. The artifacts come first.**

# First action — execute literally before anything else

Before reading workflow.md in full, run this Bash command to establish
the blackboard:

```bash
mkdir -p .claude-audit/current/phase-04-scanners .claude-audit/cache .claude-audit/history && touch .claude-audit/.skill-acknowledged
```

If `.claude-audit/.skill-acknowledged` does not exist on disk after
the audit, the audit is INVALID and must be retried.

# Then follow the workflow

Read [workflow.md](workflow.md) and follow every phase in order. Each
phase has a "verify before exit" check that confirms its artifact
landed; do not proceed past a phase whose verification fails.

# Stamp every artifact

The skill version is in [VERSION](VERSION). Stamp it into every artifact
you emit (`skill_version` field) so the user can reason about cross-run
comparability.
