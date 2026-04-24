# Phase 6 — Config + Methodology Spine

**Goal.** Audit whole-application configuration (CORS, security headers,
cookies, error handling, env-var exposure, transport config, outbound-
client config, CI/CD pipeline) AND apply the structured OWASP
methodology spines (ASVS, API Top 10, LLM Top 10, LINDDUN, STRIDE).

**Inputs.** All Phase 0-5 artifacts in `.claude-audit/current/`.

**Outputs.**
- `.claude-audit/current/phase-06-config.json` — config findings.
- `.claude-audit/current/phase-06-asvs.jsonl` — ASVS checklist coverage
  per category (one line per ASVS sub-item where relevant).
- `.claude-audit/current/phase-06-api-top10.jsonl` — API Top 10 mapping
  per attack-surface row.
- `.claude-audit/current/phase-06-llm-top10.jsonl` — LLM Top 10 (if LLM
  usage detected; else empty).
- `.claude-audit/current/phase-06-linddun.jsonl` — LINDDUN privacy review
  (if PII detected; else empty).
- `.claude-audit/current/phase-06-stride/<partition>.md` — STRIDE table
  per top-N partition.
- `.claude-audit/current/phase-06.done`

**Execution.** Single orchestrator pass for §6.1-6.7 (config). Fan-out
sub-agents for §6.8-6.12 (methodology spines) — one per methodology per
partition, 8 concurrent cap.

---

## 6.1 — CORS configuration

For each detected CORS setup (from `cors_config` keystone tags + Phase 0
data), verify:

| Rule | Severity if violated |
|---|---|
| `origin: "*"` with `credentials: true` | **CRITICAL** / CWE-346 |
| Wildcard origin on authenticated endpoints | **HIGH** |
| Origin validation via `.includes()` / partial match | **HIGH** (bypassable: `evil-example.com` contains `example.com`) |
| Overly permissive methods (PUT/DELETE when GET suffices) | **MEDIUM** |
| Overly permissive headers | **MEDIUM** |
| Missing `Vary: Origin` when origin is dynamic | **LOW** |

Emit one finding per partition where CORS lives. Tag: `category: config`,
`owasp_ids: ["ASVS-V14.5.1", "API8:2023"]`.

## 6.2 — Security headers

Per-partition, verify these headers are set (by the app, or by a
clearly-attached CDN/proxy). Required rubric:

| Header | Expected | Severity if missing |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (≥1 year) | **HIGH** / CWE-319 |
| `X-Content-Type-Options` | `nosniff` | **MEDIUM** |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | **MEDIUM** |
| `Content-Security-Policy` | Defined; `default-src 'self'` or stricter | **MEDIUM** |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter | **LOW** |
| `Permissions-Policy` | Defined (camera, microphone, geolocation) | **LOW** |
| `X-XSS-Protection` | `0` (modern) or absent (legacy OK either way) | **INFO** |

Check sources in priority order: framework config (nuxt.config,
next.config, helmet(), Spring SecurityConfig, django.middleware.security),
reverse-proxy config (if detectable), HTML `<meta>` tags.

## 6.3 — Cookie security

For each cookie-setting call site (grep `setCookie|Set-Cookie|cookie.*options`):

| Attribute | Rule | Severity |
|---|---|---|
| `httpOnly` | MUST be true for session/auth cookies | **HIGH** / CWE-1004 |
| `secure` | MUST be true in prod (or `secure: env === 'production'`) | **HIGH** / CWE-614 |
| `sameSite` | MUST be `Lax` or `Strict` (or `None` with explicit justification) | **HIGH** / CWE-1275 |
| expiry | Session cookies shouldn't exceed 30 days | **MEDIUM** |
| payload | Only session IDs; no PII / tokens in non-HttpOnly cookies | **HIGH** |

## 6.4 — Error handling & info disclosure

For production error paths (grep `stack.trace|err\.stack|createError|throw new Error|catch`):

- Stack traces returned in API responses → **HIGH** / CWE-209.
- Database errors leaked (table names, query syntax) → **HIGH** / CWE-209.
- Distinct 403 vs 404 for IDOR surfaces → **MEDIUM** / CWE-209.
- Debug endpoints accessible when `NODE_ENV != development` → **HIGH** /
  CWE-215.

Cross-reference the profile's deployment CI workflow — if `NODE_ENV` /
`DJANGO_DEBUG` / similar is set at CI but falls through in k8s
manifests, flag.

## 6.5 — Environment variable security

- `.env` / `.env.local` / `.env.production` tracked in git → **CRITICAL** /
  CWE-538 (cross-ref cat-06).
- Client-exposed env vars (`NUXT_PUBLIC_*`, `VITE_*`, `NEXT_PUBLIC_*`)
  that contain secret-looking names → **HIGH**.
- Fallback default for secrets (`process.env.SECRET || 'default-secret'`)
  → **HIGH** / CWE-798.
- `runtimeConfig.public` (Nuxt) or equivalent containing secrets → **HIGH**.

## 6.6 — Rate limiting

Endpoints that SHOULD be rate-limited (from Phase 2 surface inventory):
- Login, register, password reset, 2FA verify, token create, webhook
  receivers, file upload.

Missing rate limit → **MEDIUM** / CWE-307 / CWE-770.

## 6.7 — Transport & outbound-client config

In addition to cat-04 (MITM) findings on outbound TLS clients:
- **Egress proxy** — is one configured? Presence or absence of
  `HTTPS_PROXY` / `NO_PROXY` settings informs M4's SSRF recommendations.
- **IMDS blocking** — in cloud deployments, does the app block
  `169.254.169.254`? Check SSRF defenses centrally.
- **Mixed content** — HTTP endpoints served from HTTPS pages (if SSR
  templates or config show `http://` resource URLs).

## 6.8 — CI/CD configuration

From `profile.deployment.ci.*`:
- **GitHub Actions**: pinned actions (`uses: org/action@sha` not `@v1`),
  workflow-level `permissions:` block, no `pull_request_target` + PR
  head checkout, secrets only in non-fork workflows.
- **GitLab CI**: `protected:` on secret variables, `tags:` restrict
  secret-exposing jobs to trusted runners.
- **CircleCI / Buildkite**: similar — pin versions, scope secrets.

Cross-reference zizmor SARIF if present. Findings tagged
`category: deployment`, `owasp_ids: ["ASVS-V14.1", "API8:2023"]`.

## 6.9 — ASVS 5.0 Level 2 spine

Fan-out one sub-agent per ASVS category (17 total). Each sub-agent gets:
- The ASVS Level 2 category spec (verbatim from OWASP — the skill
  ships a curated subset in `lib/asvs-l2.md`).
- Project files filtered by a category-specific grep (e.g., V6 Crypto →
  `lib/crypto-imports.md` seed).

Each sub-agent emits `.claude-audit/current/phase-06-asvs.jsonl` rows:
```json
{"asvs_id":"V6.2.1","status":"PASS|FAIL|N/A","file":"...","line":0,"message":"...","severity":"..."}
```

Aggregate at the end; compute coverage percentage for the report.

## 6.10 — API Top 10 (2023) mechanical mapping

For each HTTP/gRPC/GraphQL surface in Phase 2:
- API1 (BOLA) — cat-02 findings
- API2 (Broken Auth) — cat-01 findings
- API3 (BOPLA) — cat-02 mass-assignment rows
- API4 (Unrestricted Resource Consumption) — cat-09 (for LLM) + cat-01
  rate-limiting
- API5 (BFLA) — cat-01 admin-role findings
- API6 (Unrestricted Business Flow Access) — out-of-scope for automated
  detection; note as manual review item in report
- API7 (SSRF) — cat-08 SSRF findings
- API8 (Security Misconfiguration) — §6.1-6.8 above
- API9 (Improper Inventory Management) — out-of-scope (manual)
- API10 (Unsafe Consumption of APIs) — outbound_tls surfaces + cat-04

Emit `phase-06-api-top10.jsonl` with one line per API-* category
containing counts and pointers into the underlying findings.

## 6.11 — LLM Top 10 (2025) — conditional

Skip if `profile.llm_usage.detected == false` or `kind == "internal"`.
Otherwise, ALL cat-09 findings get aggregated here with additional
context mapping (system-prompt sources, tool-calling scope).

## 6.12 — LINDDUN — conditional

Skip if `profile.pii.detected == false`. Otherwise, run one sub-agent
that walks the 7 LINDDUN threat categories (Linkability, Identifiability,
Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance)
over the PII columns in `profile.data_model.entities[]`. Output:
`phase-06-linddun.jsonl` one line per (entity × threat) pair.

## 6.13 — STRIDE per surface

For each top-N partition, spawn a sub-agent that produces a 6-column
(S/T/R/I/D/E) table in Markdown per attack-surface item. Write to:
`.claude-audit/current/phase-06-stride/<partition>.md`.

The STRIDE sub-agent reads:
- `phase-02-surface.json` scoped to the partition
- `profile.auth`, `profile.data_model`, `profile.trust_zones`
- Phase 5 `auth` and `idor` findings for the partition

Output Markdown, not JSONL (STRIDE is inherently tabular-narrative).

## 6.14 — Emit

Write all JSONL files, the STRIDE Markdown files, and
`phase-06-config.json` (the §6.1-6.8 findings in structured form).
Write `phase-06.done`.

## 6.15 — Report to user

> Phase 6 complete — ASVS coverage: <X%> passed, <Y%> failed, <Z%> N/A.
> API Top 10 mapping: <count> findings across <N> categories. <LLM/LINDDUN
> status>. STRIDE tables written for <K> partitions. Proceeding to Phase 7.
