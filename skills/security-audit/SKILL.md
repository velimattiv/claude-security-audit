---
name: security-audit
description: "Comprehensive polyglot security audit across 60+ frameworks. Runs a SARIF scanner bundle, fans out 9 parallel deep-dive categories, and emits an OWASP-methodology-tagged report. Invoke when the user says 'run security audit', 'security audit', 'audit security', or passes args like 'mode: delta' / 'scope: services/api' / 'categories: crypto,mitm,secrets'. Typical run 15-60 min (full) or 2-5 min (delta). MANDATORY ARTIFACT CONTRACT: every run MUST write (1) .claude-audit/current/ as your FIRST tool action via mkdir -p; (2) per-phase phase-NN-*.json AND a phase-NN.done marker for each completed phase 0-7 (8 if mode=full) BEFORE moving to the next phase; (3) findings.sarif (SARIF 2.1.0) where EVERY results[] row carries properties.security-severity (CVSS-style numeric) AND properties.cwe (e.g. 'CWE-798' — required for downstream tooling, lookup in lib/cwe-map.json) AND optionally properties.category (one of: auth, idor, token_scope, mitm, crypto, secret_sprawl, deployment, injection, llm, config); (4) human report LAST, not first. Producing only the human report without the .claude-audit/current/ blackboard is INVALID — delta mode breaks, GitHub Security tab integration breaks, CI gating breaks. If you find yourself reasoning 'the user just wants a summary' — STOP and write the artifacts first. The artifacts ARE the deliverable; the report is the cover page."
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

# First action — read workflow.md and run its preflight

The blackboard creation + `$SKILL_DIR` resolution + version check are
defined as a single multi-line Bash command in
[workflow.md](workflow.md) under "First action — execute literally as
your first Bash tool call". Run that command verbatim before doing
anything else. It writes `.claude-audit/.skill-dir` (the bare path of
this skill's install location), which every later phase reads.

# Then follow the workflow

Read [workflow.md](workflow.md) and follow every phase in order. Each
phase has a "verify before exit" check that confirms its artifact
landed; do not proceed past a phase whose verification fails.

# Stamp every artifact

The skill version is in [VERSION](VERSION). Stamp it into every artifact
you emit (`skill_version` field) so the user can reason about cross-run
comparability.
