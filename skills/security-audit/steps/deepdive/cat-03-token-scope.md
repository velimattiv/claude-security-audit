# Deep Dive #3 — Token / API Key Scope

**Category.** `token_scope`.

**OWASP tags.**
- ASVS: V2.10 (Service Authentication), V13.2 (REST Web Service — API
  Key / Token scope).
- API Top 10: `API2:2023`, `API5:2023`, `API10:2023` (Unsafe Consumption
  of APIs).

**Baseline CWEs:** 285, 287, 522, 538, 798, 863.

**Gate.** Skip the whole category if neither `profile.auth.kinds` nor
`phase-02-surface.json` show token / PAT / API-key mechanisms. Record
`notes: "no token system detected — category skipped"` in the sub-agent's
RETURN SHAPE.

---

## Invariants to verify

1. Every PAT / API key is created with an explicit scope list; no `"*"` /
   `"all"` wildcard.
2. Scopes are enforced at **both** creation (creator can't grant broader
   than their own scope) and use (handler verifies token.scope ⊇ required).
3. The scope string format is consistent — if the codebase uses `read:x`
   alongside `x.read`, the inconsistency is a finding.
4. Tokens expire (explicit TTL) AND expiry is checked on every request.
5. Revocation is a first-class operation; revoked tokens fail within one
   request cycle.
6. Tokens are not transmitted in URL query strings (logged by
   intermediaries) — only in `Authorization` headers.
7. Token creation endpoints are rate-limited (see cat-01 §"Rate limiting").
8. New tokens inherit the issuer's role or lower — never higher.

## Discovery (once per audit)

1. **Where are tokens issued?** grep for:
   `createToken|issueToken|generateToken|signToken|apiKey|personal.access`
2. **What scopes exist?** grep definitions:
   `scope|scopes|SCOPES|Permissions|PERMISSIONS|Capability`
3. **Where are tokens validated?** Phase 0's `auth.middleware_paths` +
   additional grep for `validateToken|verifyToken|checkApiKey|bearer`.

Build a **Scope × Endpoint matrix** locally (in-sub-agent, not persisted
unless findings emerge). For each endpoint requiring a token, note the
required scope and the actually-enforced scope. Mismatches are findings.

## Detection patterns

### No scope check — endpoint accepts any valid token

Pattern: handler reads `Authorization` header / `req.user.token`, calls
`validateToken(...)`, then proceeds **without** inspecting
`token.scope`/`token.scopes`/`token.permissions`. Flag → **HIGH** /
CWE-285.

### Wildcard default scope

```typescript
const token = await createToken({ scopes: scopes || ['*'] });
const apiKey = generateApiKey({ permissions: req.body.permissions ?? 'all' });
```
→ **HIGH** / CWE-732.

### Scope inheritance — creation does not limit to issuer's scope

Token creation handler accepts an arbitrary scope list from `req.body`
without verifying `requestedScopes ⊆ issuer.scopes`. → **HIGH** / CWE-285.

Pattern: grep for `createToken` call sites where `req.user` is used but
the handler does not intersect scopes.

### Scope check uses `includes` / partial match

```go
if strings.Contains(token.Scope, "read") { ... }
```

vs the correct `slices.Contains(token.Scopes, "read:users")`. Flag as
**MEDIUM** / CWE-863.

### Token in URL

grep for:
- `?token=`, `?api_key=`, `?apiKey=`, `?access_token=` in logged URLs,
  Ajax calls, redirect URLs.
- Backend handler reading `req.query.token` / `request.GET.get('token')`.

Both emissions and ingestions are findings. → **MEDIUM** / CWE-598
(SDLC — sensitive info in URL) / CWE-200.

### No expiry / never-expires tokens

- JWT issued with `exp` missing OR set to absurd future (`Number.MAX_SAFE_INTEGER`, `9999999999`).
- Database-stored tokens with `expires_at` column nullable and nullable is the norm.

→ **MEDIUM** / CWE-613.

### No revocation path

- No revocation endpoint (`DELETE /tokens/:id`, `POST /tokens/revoke`).
- Revocation endpoint exists but the validation middleware doesn't
  re-check the revocation list on each request.

→ **MEDIUM** / CWE-613.

### Admin scope bypass

Admin endpoints that accept any authenticated token rather than one with
`admin:*` / `role:admin` scope. → **HIGH** / CWE-863.

### Token leakage in logs / responses

grep for:
- `console.log(.*token)`, `logger.(info|debug).*token`, `log.*apiKey`
- `res.json({ ..., token })` on non-auth endpoints
- Error messages including token values

→ **HIGH** / CWE-532.

### Scope naming inconsistency

If different files check `'items:read'` / `'read:items'` / `'read_items'`
for the same resource, the inconsistency creates a bypass surface. Flag
→ **MEDIUM** / CWE-285.

## Output

Write JSONL to `phase-05-token_scope-<partition_id>.jsonl`.
