# Phase 3: Authorization Matrix Audit

**Goal:** Build and verify the complete authorization matrix — which roles/users can access which endpoints via which HTTP methods. This catches privilege escalation, missing authorization checks, and inconsistent access control.

**This phase is designed to run as a sub-agent.** It receives the Route Inventory Table and Project Security Profile as context.

## Inputs Required

- Route Inventory Table (from Phase 2)
- Project Security Profile (from Phase 0)
- Access to the project source code (Read, Grep, Glob tools)

## Actions

### 3.1 — Identify All Roles and Permission Levels

From the Project Security Profile and codebase:

1. Find role definitions (enums, constants, database values):
   ```
   Grep: enum.*Role|role.*enum|ROLES|UserRole|Permission
   Grep: 'admin'|'user'|'viewer'|'editor'|'owner'|'member'|'guest'
   ```

2. Find permission/scope definitions:
   ```
   Grep: permission|scope|capability|grant|access_level
   ```

3. List ALL distinct roles/permission levels:
   ```
   Roles found: [superadmin, admin, member, viewer, guest/unauthenticated]
   ```

4. Identify special access contexts:
   - "Self" access (user accessing their own resources)
   - Organization/team membership
   - Resource ownership
   - Elevated/impersonation contexts

### 3.2 — Build the Authorization Matrix

For EACH route in the inventory, and for EACH role identified:

| Endpoint | superadmin | admin | member | viewer | unauth | Check Type |
|----------|-----------|-------|--------|--------|--------|------------|
| GET /api/users | ALLOW | ALLOW | DENY | DENY | DENY | role >= admin |
| GET /api/users/:id | ALLOW | ALLOW | SELF | DENY | DENY | role >= admin OR self |
| POST /api/items | ALLOW | ALLOW | ALLOW | DENY | DENY | role >= member |
| GET /api/items/:id | ALLOW | ALLOW | ALLOW | ALLOW | DENY | authenticated |
| DELETE /api/items/:id | ALLOW | ALLOW | OWNER | DENY | DENY | role >= admin OR owner |

Populate by reading the actual auth check code in each handler/middleware.

### 3.3 — Verify the Matrix

For EACH cell in the matrix, verify that the code actually enforces the expected access:

1. **Read the handler code** — trace the auth check from request entry to data access.
2. **Check for bypasses:**
   - Is the auth check in middleware that could be skipped? (e.g., conditional middleware application)
   - Does the handler do its own check that might differ from the middleware?
   - Are there `try/catch` blocks that swallow auth errors and continue?
   - Is there a fallthrough path where auth isn't checked?

3. **Check for inconsistencies:**
   - Same resource, different auth per HTTP method (e.g., GET allows viewer but PUT doesn't check at all)
   - Auth check present but returns wrong HTTP status (200 instead of 403)
   - Auth check compares wrong field (checks role name as string but role changed to enum)

### 3.4 — Identify Privilege Escalation Paths

Look for paths where a lower-privileged user could gain higher access:

1. **Direct escalation:** Can a `member` access an `admin` endpoint?
2. **Indirect escalation:** Can a `member` modify their own record to set `role: admin`?
   - Check user profile update endpoints for mass assignment vulnerabilities
   - Can a user set fields like `role`, `isAdmin`, `permissions` through regular update endpoints?
3. **Invitation/creation escalation:** Can a `member` invite a user with `admin` role?
4. **Token escalation:** Can a user create tokens with broader scopes than their role permits?

### 3.5 — Report Findings

For each finding, include:

```markdown
### [SEVERITY] Finding Title

**Endpoint:** METHOD /path
**File:** path/to/handler.ts:LINE
**Issue:** What's wrong
**Expected:** What should happen
**Actual:** What the code does
**Attack Scenario:** How an attacker would exploit this
**Suggested Fix:** Specific code change
```

Return ALL findings to the orchestrating workflow.
