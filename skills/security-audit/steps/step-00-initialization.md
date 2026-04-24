# Phase 0: Initialization

**Goal:** Discover the project structure, detect the tech stack, and build a Project Security Profile that all subsequent phases will reference.

## Actions

### 0.1 — Framework Detection

Search the project for configuration files and determine:

| Detection Target | How to Find |
|-----------------|-------------|
| **Web framework** | `nuxt.config.*` (Nuxt), `next.config.*` (Next.js), `vite.config.*` + express/fastify imports, `app.ts`/`app.js` with express/fastify/hono/koa |
| **API layer** | `server/api/` (Nitro), `pages/api/` (Next.js), route registration patterns (Express `app.get`, Fastify `fastify.route`, Hono `app.get`) |
| **ORM / DB** | `drizzle.config.*` or `drizzle/schema`, `prisma/schema.prisma`, `typeorm` imports, raw `pg`/`mysql2` imports, Knex config |
| **Auth system** | `nuxt-auth`/`@sidebase/nuxt-auth`, `next-auth`, `passport`, `lucia`, `better-auth`, `clerk`, custom middleware with session/token checks |
| **Package manager** | `pnpm-lock.yaml` (pnpm), `yarn.lock` (yarn), `package-lock.json` (npm), `bun.lockb` (bun) |

Use Glob and Grep to detect these. Do NOT guess — confirm each detection with actual file evidence.

### 0.2 — Auth Pattern Discovery

Identify the authentication and authorization patterns used in this project:

1. **How are users authenticated?** (session cookies, JWTs, API keys, PATs, OAuth tokens)
2. **Where is auth enforced?** (global middleware, per-route middleware, in-handler checks, decorator/annotation)
3. **What is the role/permission model?** (RBAC, ABAC, simple boolean flags, scoped tokens)
4. **Where are roles/permissions defined?** (DB enum, TypeScript enum, config file, hardcoded strings)

Search for patterns like:
- `defineEventHandler` with session/auth checks (Nitro)
- `getServerSession`, `getSession`, `requireAuth`, `useAuth`
- Middleware files in `server/middleware/` or `middleware/`
- Permission checking functions (`hasPermission`, `canAccess`, `authorize`, `checkRole`)
- Route guard or protected route patterns

### 0.3 — Data Model Discovery

Find the data model definitions:

1. Parse ORM schemas (Drizzle `schema.ts`, Prisma `schema.prisma`, etc.)
2. Identify entities with **ownership relationships** — look for:
   - `userId`, `user_id`, `createdBy`, `ownerId`, `organizationId`, `tenantId` columns/fields
   - Foreign key references to a users/accounts/organizations table
3. Identify entities that are **shared or public** (no ownership FK)
4. Map relationships: which entities belong to which parent entities?

### 0.4 — Project Security Profile Output

Produce a structured summary (keep in working memory for all subsequent phases):

```
## Project Security Profile

**Framework:** [detected framework + version]
**API Layer:** [detected API pattern]
**ORM/DB:** [detected ORM + database]
**Auth System:** [detected auth approach]
**Auth Enforcement:** [where/how auth is applied]
**Role Model:** [RBAC/ABAC/scopes/etc + where defined]
**Package Manager:** [detected]

### Owned Entities (IDOR candidates)
- [Entity]: owned by [User/Org] via [column]
- ...

### Auth Middleware/Functions Found
- [middleware/function name]: [file path] — [what it checks]
- ...

### Unprotected Paths Noted During Discovery
- [any routes noticed during discovery that appeared unprotected]
```

Report this profile to the user before proceeding to Phase 1.
