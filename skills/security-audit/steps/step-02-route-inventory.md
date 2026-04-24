# Phase 2: Route & API Surface Inventory

**Goal:** Build a complete, exhaustive inventory of every API route and server-side endpoint in the project. This is the foundation for the auth matrix, IDOR, and token scope audits.

**Principle:** Do NOT sample. Enumerate EVERY route. A single missing route in the inventory could be the one with the auth gap.

## Actions

### 2.1 — Enumerate All Routes

Use the **Project Security Profile** from Phase 0 to determine the routing pattern, then enumerate accordingly:

#### Nuxt / Nitro
```
Glob: server/api/**/*.{ts,js,mjs}
Glob: server/routes/**/*.{ts,js,mjs}
```
- Each file = one route. The filename determines the HTTP method and path.
- `server/api/users/[id].get.ts` → `GET /api/users/:id`
- `server/api/users/index.post.ts` → `POST /api/users`
- `server/api/users/[id].delete.ts` → `DELETE /api/users/:id`
- Files without a method suffix handle ALL methods — flag these for review.
- Check for `defineCachedEventHandler` vs `defineEventHandler`.

#### Express / Fastify / Hono / Koa
```
Grep: app\.(get|post|put|patch|delete|all|use)\s*\(
Grep: router\.(get|post|put|patch|delete|all|use)\s*\(
Grep: fastify\.(get|post|put|patch|delete|all)\s*\(
```
- Parse route registrations from application code.
- Follow router imports to find all route files.

#### Next.js (App Router)
```
Glob: app/**/route.{ts,js}
Glob: pages/api/**/*.{ts,js}
```

#### Generic Fallback
If framework detection didn't match known patterns, search for:
- HTTP handler registrations
- Route decorators (`@Get`, `@Post`, `@Controller`)
- OpenAPI/Swagger spec files (`openapi.yaml`, `swagger.json`)

### 2.2 — Enumerate Middleware

Find all middleware and determine application order:

#### Nuxt / Nitro
```
Glob: server/middleware/**/*.{ts,js,mjs}
```
- Nitro middleware runs on ALL routes unless filtered internally.
- Read each middleware file to understand what it does.

#### Express / Fastify
- Look for `app.use(middleware)` calls and their order.
- Look for per-route middleware: `app.get('/path', authMiddleware, handler)`.

### 2.3 — Map Auth to Routes

For EACH route found, determine:

1. **Is auth middleware applied?** (global middleware, per-route middleware, or in-handler check)
2. **What auth check is performed?** (authenticated? specific role? specific permission/scope?)
3. **What parameters does it accept?** (path params like `:id`, query params, body fields)
4. **Does it read/write data?** (GET = read, POST/PUT/PATCH/DELETE = write)

### 2.4 — Produce Route Inventory Table

Format as a markdown table:

```markdown
## Route Inventory

| # | Method | Path | Auth | Roles/Permissions | Params | Data Op | Handler File |
|---|--------|------|------|-------------------|--------|---------|-------------|
| 1 | GET | /api/users | session | admin | - | read | server/api/users/index.get.ts |
| 2 | GET | /api/users/:id | session | admin, self | id (path) | read | server/api/users/[id].get.ts |
| 3 | POST | /api/uploads | PAT | upload:write | body | write | server/api/uploads/index.post.ts |
| 4 | GET | /api/public/health | NONE | - | - | read | server/api/public/health.get.ts |
| 5 | DELETE | /api/items/:id | session | owner | id (path) | write | server/api/items/[id].delete.ts |
```

### 2.5 — Flag Immediate Concerns

While building the inventory, flag:

- **[CRITICAL] Routes with NO auth** that appear to handle non-public data
- **[HIGH] Routes that handle ALL HTTP methods** without method-specific auth
- **[HIGH] Inconsistent auth** — e.g., GET is protected but DELETE on the same resource is not
- **[MEDIUM] Routes with auth but no role/permission check** — authenticated but any user can access
- **[INFO] Public routes** — confirm these are intentionally public

Report the route count and immediate flags to the user: "Phase 2 complete — found N routes (M API, K page). Flagged X immediate concerns. Proceeding to deep audits."
