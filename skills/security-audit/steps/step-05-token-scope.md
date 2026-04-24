# Phase 5: Token & API Key Scope Audit

**Goal:** Map every token type, PAT, API key, or scoped credential in the system. Verify that each endpoint correctly validates the required scope and that tokens cannot be used beyond their intended access level.

**This phase is designed to run as a sub-agent.** It receives the Route Inventory Table and Project Security Profile as context.

**Skip this phase** if the project does not use API tokens, PATs, or scoped API keys. Report "Phase 5: Skipped — no token/PAT/API key system detected" and return.

## Inputs Required

- Route Inventory Table (from Phase 2)
- Project Security Profile (from Phase 0)
- Access to the project source code (Read, Grep, Glob tools)

## Actions

### 5.1 — Discover Token System

Find and understand the token/PAT/API key system:

```
Grep: createToken|generateToken|signToken|issueToken|apiKey|pat|personal.access
Grep: token.*scope|scope.*token|permission.*token
Grep: Bearer|Authorization|x-api-key|api.key
```

Document:
1. **Token types:** What kinds of tokens exist? (session tokens, PATs, API keys, service tokens, refresh tokens)
2. **Token creation:** Where are tokens created? What scopes/permissions can be assigned?
3. **Token validation:** Where/how are tokens validated on incoming requests?
4. **Scope definitions:** What scopes exist? (e.g., `read:items`, `write:items`, `admin:users`)
5. **Token storage:** How are tokens stored? (DB, cache, stateless JWT)

### 5.2 — Map Scopes to Endpoints

Build a scope-to-endpoint mapping:

| Scope | Intended Endpoints | Actually Checked At |
|-------|-------------------|-------------------|
| `read:items` | GET /api/items, GET /api/items/:id | [verify in code] |
| `write:items` | POST /api/items, PUT /api/items/:id | [verify in code] |
| `admin:users` | GET /api/admin/users, DELETE /api/users/:id | [verify in code] |

For each endpoint:
1. Does it check for a specific scope?
2. Or does it just check "valid token" without scope verification?
3. Does the scope check match the operation? (a `read` scope shouldn't allow `write` operations)

### 5.3 — Identify Scope Gaps

Look for these common issues:

1. **No scope check:** Endpoint accepts any valid token regardless of scope
   ```typescript
   // BAD: checks token validity but not scope
   const token = await validateToken(authHeader);
   if (!token) throw createError({ statusCode: 401 });
   // proceeds without checking token.scopes
   ```

2. **Overly broad default scope:** New tokens get all scopes by default
   ```typescript
   // BAD: default scopes are too permissive
   const token = await createToken({ scopes: scopes || ['*'] });
   ```

3. **Scope inheritance issues:** A token with `read:items` can also `write:items` because the check only verifies the resource part, not the action

4. **Admin scope bypass:** Admin endpoints that accept any authenticated token, not specifically admin-scoped tokens

5. **Token privilege escalation:** Can a token be used to create a new token with broader scopes?
   ```
   // Can a token with scope "read:items" call POST /api/tokens
   // and create a new token with scope "admin:*"?
   ```

6. **Scope naming inconsistencies:** Are scopes checked consistently? (e.g., `items:read` vs `read:items` vs `read_items`)

### 5.4 — Check Token Lifecycle Security

1. **Token creation:** Who can create tokens? Is there a scope limit based on the creator's own permissions?
2. **Token expiry:** Do tokens expire? Is expiry enforced on validation?
3. **Token revocation:** Can tokens be revoked? Is revocation checked on every request?
4. **Token rotation:** Are long-lived tokens rotatable?
5. **Token leakage:** Are tokens logged, included in error responses, or exposed in URLs?
   ```
   Grep: console\.log.*token|logger.*token|log.*apiKey|token.*url|key.*query
   ```

### 5.5 — Report Findings

For each finding:

```markdown
### [SEVERITY] Token Scope: [Issue Title]

**Token Type:** [PAT/API key/etc]
**Affected Scope:** [scope name]
**Endpoint:** METHOD /path
**File:** path/to/handler.ts:LINE
**Issue:** [What's wrong with the scope enforcement]
**Attack Scenario:** A token with [limited scope] can [unauthorized action] because [reason]
**Suggested Fix:** [Specific code change to enforce correct scope]
```

Return ALL findings to the orchestrating workflow.
