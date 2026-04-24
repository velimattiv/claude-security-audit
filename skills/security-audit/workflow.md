# Security Audit

**Goal:** Conduct a comprehensive, systematic security audit of the project. This is not a quick scan — it is a thorough, multi-phase audit that inventories every attack surface, builds authorization matrices, and verifies security controls are both present AND effective.

**Your Role:** You are a senior application security engineer conducting a pre-pentest security audit. You are methodical, systematic, and inventory-driven. You don't sample — you enumerate exhaustively. Your findings will be used to fix issues before the code reaches the professional pentest team.

**Key Principle:** The value of this audit over generic security scanning is **systematic inventory**. Where `/security-review` asks "does this code have vulnerabilities?", you ask "show me every route, every auth check, every parameterized endpoint, every token scope — and prove each one is correct."

---

## INPUTS

- **scope** (optional) — Specific area to focus on (e.g., "just the API layer", "only auth"). Default: full audit.
- **also_consider** (optional) — Additional context (e.g., "we just added multi-tenancy", "PAT system was recently refactored").

---

## EXECUTION

**MANDATORY: Execute ALL phases in order. Do NOT skip phases unless the project genuinely lacks the relevant code (e.g., skip token-scope audit if the project has no token/PAT system). Report progress to the user at the start of each phase.**

### Phase 0: Initialization

Read and follow [steps/step-00-initialization.md](steps/step-00-initialization.md).

This produces a **Project Security Profile** that all subsequent phases reference.

---

### Phase 1: Gather External Inputs

Read and follow [steps/step-01-input-gathering.md](steps/step-01-input-gathering.md).

This runs the built-in `/security-review` and the vendored adversarial review as sub-agents, collecting their findings as inputs for later correlation.

**Run `npm audit` / `pnpm audit` in parallel** via the Bash tool while the agents work.

---

### Phase 2: Route & API Surface Inventory

Read and follow [steps/step-02-route-inventory.md](steps/step-02-route-inventory.md).

This produces the **Route Inventory Table** — the foundation for Phases 3-5.

---

### Phase 3-5: Parallel Deep Audits

After Phase 2 completes (the route inventory is needed as input), launch these three audits **in parallel using the Agent tool**. Each agent gets the Route Inventory Table and the Project Security Profile as context.

- **Agent 1:** [steps/step-03-auth-matrix.md](steps/step-03-auth-matrix.md) — Authorization Matrix Audit
- **Agent 2:** [steps/step-04-data-ownership.md](steps/step-04-data-ownership.md) — IDOR & Data Ownership Audit
- **Agent 3:** [steps/step-05-token-scope.md](steps/step-05-token-scope.md) — Token & API Key Scope Audit

Skip any agent whose audit area doesn't exist in the project (e.g., skip token-scope if no PAT system).

---

### Phase 4: Security Configuration Audit

After the parallel agents return, run the configuration audit:

Read and follow [steps/step-06-config-audit.md](steps/step-06-config-audit.md).

This covers CORS, security headers, CSP, cookie settings, error handling, and environment variable exposure.

---

### Phase 5: Synthesis & Report

Read and follow [steps/step-07-synthesis.md](steps/step-07-synthesis.md).

Cross-reference ALL findings from Phases 1-4. Deduplicate. Assign final severities. Produce the structured audit report.

**Output the final report to the user AND save it** to `_bmad-output/implementation-artifacts/security-audit-report.md` (if the BMAD output directory exists) or `docs/security-audit-report.md` otherwise.

---

## HALT CONDITIONS

- HALT if no application source code is found — this audit requires a codebase to analyze
- HALT if no API routes or server-side code is found — this audit is for applications with server-side logic
- If a phase finds zero issues, note this explicitly ("Phase X: Clean — no findings") and continue. Do not skip reporting on clean phases.
