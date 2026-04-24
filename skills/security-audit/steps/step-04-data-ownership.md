# Phase 4: IDOR & Data Ownership Audit

**Goal:** For every parameterized endpoint that accesses data with ownership relationships, verify that the handler enforces ownership — preventing User A from accessing User B's resources by manipulating IDs.

**This phase is designed to run as a sub-agent.** It receives the Route Inventory Table and Project Security Profile as context.

## Inputs Required

- Route Inventory Table (from Phase 2) — specifically routes with path/query parameters
- Project Security Profile (from Phase 0) — specifically owned entities and their ownership columns
- Access to the project source code (Read, Grep, Glob tools)

## Actions

### 4.1 — Identify IDOR-Candidate Endpoints

From the Route Inventory, filter to endpoints that:
1. Accept an **ID parameter** (path params like `:id`, `:itemId`, `:userId`, or query params)
2. Access a **data entity with an ownership relationship** (from the owned entities list in the security profile)

These are IDOR candidates. Every one must be verified.

### 4.2 — Trace Data Access for Each Candidate

For EACH IDOR-candidate endpoint, read the handler code and trace:

1. **How is the ID used?** Follow the parameter from request extraction to database query.
2. **Is ownership checked?** Does the query include a filter for the authenticated user?

**Safe pattern (ownership enforced):**
```typescript
// The query filters by BOTH the resource ID and the user's ID
const item = await db.query.items.findFirst({
  where: and(eq(items.id, id), eq(items.userId, session.userId))
});
if (!item) throw createError({ statusCode: 404 });
```

**Vulnerable pattern (ownership NOT enforced):**
```typescript
// The query uses ONLY the resource ID — any user can access any item
const item = await db.query.items.findFirst({
  where: eq(items.id, id)
});
```

**Partially safe pattern (ownership checked after fetch):**
```typescript
// Fetches first, then checks — still reveals existence via timing
const item = await db.query.items.findFirst({ where: eq(items.id, id) });
if (item.userId !== session.userId) throw createError({ statusCode: 403 });
```
This is better but still leaks information (404 vs 403 reveals resource existence).

### 4.3 — Check Related Entity Access

IDOR often exists through related entities:

1. **Nested resource access:** Can User A access User B's item's comments via `/api/items/:itemId/comments`? Even if `/api/items/:id` is protected, the comments endpoint might not verify that the parent item belongs to the user.

2. **Bulk/list endpoints:** Does `/api/items` filter by the authenticated user, or return ALL items?

3. **Search endpoints:** Can a search query return results the user shouldn't see?

4. **Export/download endpoints:** Do file download endpoints verify ownership of the referenced resource?

### 4.4 — Check for Enumeration Vulnerabilities

Even if data access is denied, can an attacker enumerate valid IDs?

1. **Sequential IDs:** Are resource IDs auto-incrementing integers? (predictable)
2. **Timing differences:** Does the response time differ for "exists but forbidden" vs "doesn't exist"?
3. **Error message differences:** Does the API return "forbidden" vs "not found" (reveals existence)?
4. **UUID vs integer:** Are UUIDs used? (harder to enumerate, but not impossible if leaked elsewhere)

### 4.5 — Report Findings

For each IDOR finding:

```markdown
### [SEVERITY] IDOR: [Entity] accessible without ownership check

**Endpoint:** METHOD /path
**File:** path/to/handler.ts:LINE
**Entity:** [entity name] (owned by [user/org] via [column])
**Issue:** Handler accesses [entity] by ID without verifying the authenticated user's ownership
**Vulnerable Code:**
\`\`\`typescript
[the vulnerable query/access pattern]
\`\`\`
**Attack Scenario:** User A can access User B's [entity] by calling [METHOD /path] with User B's [entity] ID
**Suggested Fix:**
\`\`\`typescript
[the corrected query with ownership filter]
\`\`\`
```

Return ALL findings to the orchestrating workflow.
