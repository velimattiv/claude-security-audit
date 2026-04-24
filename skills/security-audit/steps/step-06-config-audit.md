# Phase 6: Security Configuration Audit

**Goal:** Audit security-relevant configuration across the application — CORS, security headers, CSP, cookie settings, error handling, environment variables, and rate limiting.

## Actions

### 6.1 — CORS Configuration

Find and analyze CORS configuration:

```
Grep: cors|Access-Control|allowOrigin|allowMethods|allowHeaders|allowCredentials
```

Check for:
- **[CRITICAL]** `Access-Control-Allow-Origin: *` with `credentials: true` — this is always wrong
- **[HIGH]** Wildcard origin (`*`) on authenticated endpoints
- **[HIGH]** Origin validation using `includes()` or partial string matching (bypassable: `evil-example.com` contains `example.com`)
- **[MEDIUM]** Overly permissive methods (allowing PUT/DELETE/PATCH when only GET/POST is needed)
- **[MEDIUM]** Overly permissive headers
- **[LOW]** Missing `Vary: Origin` header when origin is dynamic

For Nuxt/Nitro, check `nuxt.config.*` for `routeRules` with CORS settings and any CORS middleware.

### 6.2 — Security Headers

Check what security headers the application sets. Look in:
- Server middleware
- Nuxt config / nitro config
- Express/Fastify middleware
- Meta tags in HTML

Required headers and their correct values:

| Header | Expected | Severity if Missing |
|--------|----------|-------------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | HIGH |
| `X-Content-Type-Options` | `nosniff` | MEDIUM |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | MEDIUM |
| `Content-Security-Policy` | Defined and restrictive | MEDIUM |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter | LOW |
| `Permissions-Policy` | Defined (camera, microphone, geolocation) | LOW |
| `X-XSS-Protection` | `0` (modern approach) or absent | INFO |

Note: For SPAs/SSR apps, some headers may be set at the CDN/proxy level rather than in app code. Flag as INFO if there's evidence of a reverse proxy config but headers aren't set in the app.

### 6.3 — Cookie Security

Find cookie-setting code:

```
Grep: setCookie|Set-Cookie|cookie.*options|cookieOptions|session.*cookie
```

Check for:
- **[HIGH]** Session cookies without `httpOnly: true`
- **[HIGH]** Session cookies without `secure: true` (or `secure: process.env.NODE_ENV === 'production'`)
- **[HIGH]** Cookies without `sameSite` or set to `none` without justification
- **[MEDIUM]** Overly long cookie expiry for session tokens
- **[MEDIUM]** Sensitive data stored in cookies (beyond session ID)

### 6.4 — Error Handling & Information Disclosure

Check how errors are handled in production:

```
Grep: stack.*trace|stackTrace|err\.stack|error\.stack|console\.error
Grep: createError|throw.*Error|catch
```

Look for:
- **[HIGH]** Stack traces returned in API responses
- **[HIGH]** Database error details leaked to clients (table names, query syntax)
- **[MEDIUM]** Verbose error messages that reveal internal structure
- **[MEDIUM]** Different error responses for "not found" vs "forbidden" (information leakage)
- **[LOW]** Debug/development endpoints accessible in production mode

Check nuxt.config/nitro config for error handling configuration.

### 6.5 — Environment Variable Security

Check `.env.example`, `.env*` patterns, and environment variable usage:

```
Grep: process\.env|import\.meta\.env|useRuntimeConfig|runtimeConfig
Glob: .env*
```

Look for:
- **[CRITICAL]** `.env` files committed to git (check `.gitignore`)
- **[CRITICAL]** Secrets in client-side code (`NUXT_PUBLIC_*` / `VITE_*` / `NEXT_PUBLIC_*` containing secrets)
- **[HIGH]** Missing `.env.example` (team members won't know what vars are needed)
- **[HIGH]** Default/fallback values for secrets in code (`process.env.SECRET || 'default-secret'`)
- **[MEDIUM]** Secrets in `nuxt.config.*` runtimeConfig `public` section

For Nuxt specifically, verify that secrets are in `runtimeConfig` (server-only) not `runtimeConfig.public` (client-exposed).

### 6.6 — Rate Limiting

Check for rate limiting on sensitive endpoints:

```
Grep: rateLimit|rate.limit|throttle|limiter|brute
```

Endpoints that SHOULD have rate limiting:
- Login/authentication endpoints
- Token creation endpoints
- Password reset endpoints
- Registration endpoints
- Any endpoint that sends emails/SMS

Flag as **[MEDIUM]** if no rate limiting is found on auth-related endpoints.

### 6.7 — Report Findings

Compile all configuration findings with severity, location, and fix suggestions. Return to the orchestrating workflow.
