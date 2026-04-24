# /security-audit — Claude Code Skill

A thorough, multi-phase security audit skill for [Claude Code](https://docs.anthropic.com/claude/docs/claude-code).
Goes beyond generic vulnerability scanning by enumerating every route, building
authorization matrices, verifying token scopes, and cross-referencing findings
across multiple independent passes.

**Supported runtime:** Claude Code only. Other harnesses are not supported.

## What it does

1. Gathers external inputs — runs Claude Code's built-in `/security-review` and
   a vendored adversarial review as parallel sub-agents, plus `npm/pnpm audit`.
2. Builds a complete route/API inventory.
3. In parallel, runs three deep audits: authorization matrix, IDOR & data
   ownership, token/PAT scope.
4. Audits security configuration (CORS, CSP, cookies, error handling).
5. Synthesizes, deduplicates, and reports — with confidence and severity.

Typical run: 15–30 minutes on a medium codebase.

## Install

User-level (available in every project):

```bash
git clone https://github.com/<owner>/claude-security-audit.git /tmp/csa
mkdir -p ~/.claude/skills
cp -r /tmp/csa/skills/security-audit ~/.claude/skills/
```

Project-level (just this repo):

```bash
git clone https://github.com/<owner>/claude-security-audit.git /tmp/csa
mkdir -p .claude/skills
cp -r /tmp/csa/skills/security-audit .claude/skills/
```

## Use

In Claude Code:

```
/security-audit
```

Optional scope/context hints are supported — e.g. `/security-audit scope: "API layer only"`.

## Licensing & attribution

- This skill: MIT (see `LICENSE`).
- The adversarial review prompt under `skills/security-audit/vendored/adversarial-review/`
  is vendored unmodified from [bmad-method](https://github.com/bmad-code-org/BMAD-METHOD)
  by BMad Code, LLC, under MIT. See `NOTICE.md` and the vendored folder's
  `LICENSE` and `README.md` for full details.
