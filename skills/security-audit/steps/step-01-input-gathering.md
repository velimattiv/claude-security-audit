# Phase 1: Gather External Inputs

**Goal:** Run existing security review tools to collect broad findings that the systematic audit phases will cross-reference and build upon.

## Actions

### 1.1 — Run Built-in Security Review (Agent)

Launch an Agent (subagent_type: general-purpose) with this prompt:

> Run the `/security-review` skill against this codebase. Collect all findings including severity ratings, affected files, and descriptions. Return the complete findings list as structured markdown.

If `/security-review` is not available or fails, note this and continue — it's an input, not a blocker.

### 1.2 — Run Adversarial Review (Agent)

Launch an Agent (subagent_type: general-purpose) with this prompt:

> Read and follow the instructions in `skills/security-audit/vendored/adversarial-review/SKILL.md` (the vendored adversarial review prompt derived from bmad-method). Apply it to this codebase with also_consider: "Focus especially on: authentication bypass paths, authorization gaps, privilege escalation vectors, API token/key scoping, data access control, information disclosure through error messages or logs, and any path where one user could access another user's data." Return the complete findings list.

### 1.3 — Run Dependency Audit (Bash, in parallel)

While the agents run, execute via the Bash tool:

```bash
# Detect package manager and run appropriate audit
if [ -f pnpm-lock.yaml ]; then
  pnpm audit --json 2>/dev/null || pnpm audit 2>/dev/null
elif [ -f yarn.lock ]; then
  yarn audit --json 2>/dev/null || yarn audit 2>/dev/null
elif [ -f package-lock.json ]; then
  npm audit --json 2>/dev/null || npm audit 2>/dev/null
elif [ -f bun.lockb ]; then
  bun audit 2>/dev/null || echo "bun audit not available"
else
  echo "No lock file found — cannot run dependency audit"
fi
```

Also check for known risky dependencies by searching `package.json` for:
- `eval`-based packages
- Known supply-chain-compromised packages
- Deprecated packages with known security advisories

### 1.4 — Collect and Stage Findings

Compile all findings from 1.1, 1.2, and 1.3 into a single working document:

```
## Phase 1 Findings (External Inputs)

### From /security-review
- [finding 1]
- [finding 2]
- ...

### From Adversarial Review
- [finding 1]
- ...

### From Dependency Audit
- [critical/high vulns]
- ...
(or: "Clean — no known vulnerabilities")
```

These findings will be cross-referenced in Phase 5 (Synthesis) to identify issues caught by multiple tools (higher confidence) and issues only this audit found (unique value).

Report a brief summary to the user: "Phase 1 complete — collected N findings from external tools. Proceeding to route inventory."
