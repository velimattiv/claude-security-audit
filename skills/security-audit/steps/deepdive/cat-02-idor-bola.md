# Deep Dive #2 — IDOR / BOLA

**Category.** `idor`.

**OWASP tags.**
- ASVS: V4.2.1 (Access control rules enforced by server), V4.3.2
  (Directory browsing disabled except where intentional).
- API Top 10: `API1:2023` (BOLA — Broken Object Level Authorization),
  `API3:2023` (BOPLA — Broken Object Property Level Authorization).

**Baseline CWEs:** 284, 285, 639, 862, 915.

---

## Invariants to verify

1. Every parameterized route whose handler accesses an entity with an
   ownership column (from `profile.data_model.entities[*].owner_cols`)
   scopes the query by the authenticated user / tenant / organization.
2. List endpoints filter the result set by the authenticated scope
   (no "return all rows" for a per-user resource).
3. Nested resource access (`/parents/:pid/children/:cid`) verifies the
   child belongs to the parent AND the parent belongs to the user.
4. GraphQL resolvers apply the same scoping at the field level
   (`@Resolver` class / field resolver).
5. Bulk endpoints (`/bulk-delete`, `/batch-update`) verify every id in the
   batch.
6. Search endpoints filter results by the caller's access.
7. File-download endpoints verify the caller can read the referenced
   resource (not just that they can authenticate).
8. Property-level: update endpoints don't allow mass-assigning
   `role`, `isAdmin`, `permissions`, `orgId`, etc. (See also cat-01
   §"Mass assignment".)

## Candidate surfaces

From `phase-02-surface.json`, filter to surfaces where:
- `category == http` or `graphql` or `trpc`, AND
- Any `param.source == "path"` OR `param.source == "query"` with a name
  matching `^(id|[a-z]+Id|[a-z]+_id)$`, AND
- The handler reads an ownership-columned entity.

Every candidate must be verified — do not sample.

## Detection patterns

### Query without ownership filter

Read the handler file. Look for database queries against an owned entity
where the `WHERE` clause references **only** the ID param, not the
user / tenant / org scope.

Examples of the **vulnerable** pattern:

```typescript
// Drizzle — missing ownership filter
const item = await db.query.items.findFirst({
  where: eq(items.id, params.id)
});
```
→ **HIGH** if sensitivity ≥2, else MEDIUM / CWE-639.

```python
# Django — using all() without user filter
item = Item.objects.get(pk=pk)
```
→ **HIGH** / CWE-639.

```ruby
# Rails
@item = Item.find(params[:id])
```
→ **HIGH** / CWE-639. The safe pattern is `@item = current_user.items.find(params[:id])`.

### Ownership check after fetch (timing-leak)

```typescript
const item = await db.query.items.findFirst({ where: eq(items.id, id) });
if (item.userId !== session.userId) throw createError({ statusCode: 403 });
```

Better than no check, but the 403 vs 404 distinction leaks existence. Flag
as **MEDIUM** / CWE-209 (information exposure through error message).
Suggest: return 404 uniformly for "not found" and "forbidden" on IDOR
surfaces.

### Nested resource access

For surfaces with `path` matching `:parentId.*:childId` or similar, read
the handler: does the query chain through parent ownership?

Safe: `parent.children.find(childId)` where `parent` was fetched via an
ownership-filtered query.

Vulnerable: direct lookup of child by id without verifying parent
ownership. → **HIGH** / CWE-639.

### Search / list endpoints

Handler calls `.findAll()` / `.all()` / `.list()` without a user scope.
Flag → **HIGH** / CWE-284. Suggest: `.where(userId = currentUser.id)`.

### GraphQL resolvers

For each `@Resolver` class method matching the BOLA surface criteria,
verify the resolver reads ownership. Graphql-armor / authz-middleware
presence helps but is not sufficient — the resolver body must still
scope.

### Bulk endpoints

Handler iterates over `req.body.ids` / similar. Each id must be scoped
to the caller; a single missed id equals a full IDOR. Flag any bulk
handler that passes the raw id list into `.destroyAll({where: {id: {in:
ids}}})` without an ownership filter.

### Property-level (BOPLA)

Grep patterns:
- JS/TS: `Object.assign(existing, req.body)` on user-profile update;
  `.update(req.body)` without a `fields:` whitelist.
- Rails: `@user.update(params[:user])` without `permit(:name, :email, ...)`.
- Django: serializer with no `fields` / `read_only_fields`.

Flag → **HIGH** / CWE-915.

### Predictable IDs (enumeration)

If the entity uses sequential integer ids and the endpoint allows
authenticated enumeration (the error message differs between "forbidden"
and "not found"), flag as **MEDIUM** / CWE-200.

## False-positive notes

- **Public resources.** Products, categories, blog posts — shared-read
  resources with no ownership column. Verify `profile.data_model.entities[].owner_cols` is empty for these entities before flagging.
- **Admin-only endpoints** that legitimately return everything. Cross-
  reference with `roles_required == ['admin']` on the surface row.
- **Soft-deleted rows.** `where: and(eq(id, ...), isNull(deletedAt))` is
  a valid non-ownership filter; not an IDOR gap on its own.

## Output

Write JSONL to `phase-05-idor-<partition_id>.jsonl`, marker
`phase-05-idor-<partition_id>.done`. Include `surface_id` on every
finding so Phase 7 can cross-link.
