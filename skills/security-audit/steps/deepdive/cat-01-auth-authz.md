# Deep Dive #1 — Auth & Authz

**Role.** Sub-agent loaded via `templates/subagent-prompt.md` with this file
as the `phase-specific-method-body`.

**Category.** `auth`.

**OWASP tags to apply.**
- ASVS: V2 (Authentication), V3 (Session Mgmt), V4 (Access Control),
  V13 (API & Web Service).
- API Top 10: `API1:2023` (BOLA — also see cat-02), `API2:2023` (Broken
  Authentication), `API3:2023` (BOPLA), `API5:2023` (Broken Function
  Authorization).
- LLM Top 10: not applicable.

**Baseline CWEs:** 284, 285, 287, 288, 306, 307, 352, 384, 521, 613, 640,
862, 863.

---

## Invariants to verify per surface

1. Every `http | grpc | graphql | websocket | queue_consumer` surface whose
   `data_ops` contains write/delete/exec has `auth_required: true` OR an
   explicit `@Public` marker.
2. Auth middleware is present **before** the handler in the request
   lifecycle — not bypassable by header ordering, method override, or
   framework wildcard routes.
3. Session regeneration occurs on login (`req.session.regenerate`,
   `SessionStore.create_new`, `CookieJar.rotate`). Absence after a
   successful login is a session-fixation risk.
4. OAuth / SSO handlers verify `state` (CSRF prevention) and `nonce`
   (replay prevention).
5. Password reset flows use single-use tokens with ≤60 min expiry and
   server-side invalidation on use.
6. JWT implementations pin the algorithm (`alg: HS256` or `RS256` etc.);
   `alg: none` is never accepted; `alg` is never read from the untrusted
   header.
7. Rate limiting is present on login, registration, password reset,
   2FA verification, and token issuance endpoints.
8. Mass-assignment: update/create endpoints explicitly allow-list the
   fields they accept. No `Object.assign(user, req.body)` patterns; no
   `@ModelAttribute User user` that maps `role`/`isAdmin` from body.
9. Role / scope checks exist on admin endpoints and use `===` or
   equivalent exact comparison, not `includes`/partial match.

## Detection patterns (polyglot)

### Missing auth on write handlers

For every Phase-2 surface row in scope with `flags[]` containing
`NO_AUTH_WRITE` or `AUTH_UNKNOWN`, read the handler file and verify
invariant #1. Absence → **HIGH** finding.

### Session regeneration on login

For each handler path matching `login|signin|authenticate` in
`auth.middleware_paths`:
- JS/TS: grep for `req.session.regenerate` / `session.regenerate` /
  `cookies.rotate`.
- Python: grep for `request.session.cycle_key()` (Django),
  `session.regenerate_id()` (Flask-Session).
- Rails: `reset_session`.
- Spring: `SecurityContextHolder.clearContext()` + new session.

Missing → **MEDIUM** / CWE-384 session fixation.

### JWT algorithm pinning

Grep for:
```
verify\s*\(\s*token\s*,\s*[^,]+\s*(?:,\s*\{[^}]*algorithm[^}]*\})?
jwt\.decode\s*\(\s*token\s*[^,)]*\)
algorithms\s*=\s*\["?HS256\"?\]
```

Flag any call to `jwt.verify`/`jwt.decode` **without** an `algorithms:
[...]` whitelist → **HIGH** / CWE-327.

Flag any string containing `alg.*none`/`\"alg\":\"none\"` → **CRITICAL** /
CWE-287.

### Mass assignment

Grep patterns (per language):
- JS/TS: `Object\.assign\s*\(\s*\w+\s*,\s*req\.body\b`, `...req\.body`
  spread in user update handlers, Sequelize `Model.update(req.body,...)`
  without `fields:` whitelist.
- Ruby/Rails: `update\(params\[:.+\]\)` without `permit(...)`.
- Python/Django: `SerializerClass(instance, data=request.data, partial=True).save()` where serializer has no `Meta.fields` whitelist.
- Java/Spring: `@ModelAttribute` on an entity that includes `role` /
  `isAdmin`.

Matches → **HIGH** / CWE-915.

### OAuth state / nonce

Grep for `oauth|passport|openid|auth0|clerk` usage, verify:
- Request URL includes `state=` parameter.
- Callback validates `state` matches the session-stored value.
- If OIDC: validates `nonce` on the ID token.

Missing → **HIGH** / CWE-352 (CSRF on OAuth flow).

### Rate limiting on sensitive endpoints

Phase 0 surface-row paths matching `/login|/signin|/register|/signup|/password|/reset|/forgot|/mfa|/2fa|/otp|/token|/tokens|/apikeys|/apikey` must have a rate-limit middleware in their registration chain. Grep for:
- `express-rate-limit`, `rateLimit(`
- `django_ratelimit`
- `flask_limiter` / `Limiter`
- `@RateLimit` (Spring via Resilience4j)
- `Rack::Attack`

Missing → **MEDIUM** / CWE-307.

### Admin role enforcement

For every surface with `path` matching `/admin|/super|/internal` or
`roles_required` containing `admin`-flavored values, verify:
- The role check uses exact match (`role === 'admin'`, not
  `role.includes('admin')`).
- The check happens before any data read.

Weak comparison → **HIGH** / CWE-863.

## False-positive notes

- **Test handler routes** (`/test/...`, `/__test__/...`) are often
  authenticated via test-only middleware; verify the middleware is
  NOT wired in production (`if (env.TEST)` guards).
- **Health / metrics endpoints** may legitimately skip auth; do not flag
  `/health`, `/healthz`, `/ready`, `/metrics` unless they expose process
  internals.
- **Framework-generated boilerplate** (e.g., NextAuth `[...nextauth].ts`)
  sometimes appears to skip auth because auth IS the endpoint's purpose.

## Output

Write JSONL findings to:
```
.claude-audit/current/phase-05-auth-<partition_id>.jsonl
```

Each line matches `lib/finding-schema.json`. Example:

```json
{"id":"juice-shop:auth:0001","severity":"HIGH","confidence":"LIKELY","category":"auth","partition":"juice-shop","file":"routes/login.ts","line":42,"cwe":"CWE-287","owasp_ids":["ASVS-V2.1.1","API2:2023"],"title":"JWT verification missing algorithm whitelist","description":"...","sources":[{"kind":"grep","detail":"jwt-verify-no-alg-whitelist"}],"suggested_fix":"Pass {algorithms: ['HS256']} to jwt.verify().","attack_scenario":"Attacker crafts a token with alg:none that verifies without a signature."}
```

Emit completion marker when done:
```
.claude-audit/current/phase-05-auth-<partition_id>.done
```
