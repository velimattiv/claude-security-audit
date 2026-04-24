# Phase 2 — Attack Surface Inventory

**Goal.** Enumerate **every** entry point to the application. Not just HTTP
routes — gRPC methods, GraphQL resolvers, queue consumers, schedulers,
webhooks, file uploads, serverless handlers, mobile / desktop IPC,
admin/debug endpoints, CLI/admin scripts, and outbound TLS clients. This is
the ground truth that Phases 3-7 cross-reference.

**Inputs.**
- `.claude-audit/current/phase-00-profile.json`
- `.claude-audit/current/partitions.json`
- `.claude-audit/ignore.txt`

**Output.** `.claude-audit/current/phase-02-surface.json` conforming to
`lib/surface-schema.json`, plus the saga marker `phase-02.done`.

**Execution model.** One sub-agent **per partition** using the shared
template at `templates/subagent-prompt.md`. The orchestrator caps
concurrency at 8 in-flight sub-agents. Inventory-only partitions still get
enumerated (Phase 5 will skip them, but Phase 2 runs for all).

**Principle.** Do **not** sample. Enumerate exhaustively. A missed surface
is a missed finding in every downstream phase.

---

## 2.1 — Per-Partition Sub-Agent

Invoke with the template. Fill `{{extra-inputs}}` to empty. Fill
`{{phase-specific-method-body}}` with the body of §2.2-2.5 below.

Return shape (per template): the count of surfaces written, the by-category
breakdown, and the artifact path.

## 2.2 — Detect frameworks in scope

Read the partition's `frameworks[]` from `partitions.json` and cross-
reference `lib/surface-detection.md`. Every framework entry maps to a
detection recipe (glob + grep pattern + extractor). Run only the recipes for
frameworks that appear in this partition; skip the rest.

## 2.3 — Enumerate each surface category

For **every** surface category in the table below, run the detection and
emit one surface row per entry point. Categories with no hits emit nothing
(do not emit a "category empty" placeholder).

| Category | Detection (in `lib/surface-detection.md`) |
|---|---|
| `http` | per-framework handler registration or file-based routing |
| `grpc` | `.proto` methods paired with server-side `BindService`/`RegisterService` |
| `graphql` | resolvers, `@Resolver`, `buildSchema`, `typeDefs` |
| `websocket` | `@WebSocketGateway`, `ws.Server`, `socket.io`, `ActionCable::Channel`, Phoenix `Channel` |
| `sse` | `Content-Type: text/event-stream` set; `EventSource` server endpoints |
| `trpc` | `router.query` / `router.mutation` / `initTRPC` |
| `queue_consumer` | `@KafkaListener`, `@RabbitListener`, `@SqsListener`, `Consumer`, `BullMQ.Worker`, `Sidekiq.Worker.perform`, `Celery @app.task` |
| `scheduler` | cron decorators, `@Scheduled`, `sidekiq-cron`, `BullMQ repeat`, `celery beat`, `Hangfire.RecurringJob`, `systemd timer` units, `crontab`, `schedule` modules |
| `webhook` | inbound POST handlers with signature-header processing (`X-Hub-Signature`, `Stripe-Signature`, etc.) |
| `file_upload` | `multipart/form-data` occurrence + framework upload primitive (`@UploadedFile`, `multer.single`, `ActiveStorage`) |
| `serverless` | handler signatures (`exports.handler`, `func.main`) paired with platform templates (`template.yaml`, `function.json`, `wrangler.jsonc`, `serverless.yml`) |
| `mobile_ipc` | Android `AndroidManifest.xml` with `exported="true"`, iOS URL schemes, deep links |
| `desktop_ipc` | `ipcMain.handle`/`ipcMain.on`, `#[tauri::command]`, Electron preload bridges |
| `admin_debug` | `/actuator/*`, `/debug/pprof`, `/__debug__`, framework admin consoles |
| `cli_admin` | `bin/*`, `lib/tasks/*.rake`, `app/Console/Commands/*`, `manage.py` subcommands, `rake`, `artisan`, `mix` tasks |
| `outbound_tls` | HTTP client imports (`fetch`, `axios`, `requests`, `reqwest`, `okhttp`, `HttpClient`, `net/http.DefaultClient`) — collected only so Phase 5 category 4 (MITM) can audit them |

## 2.4 — Per-entry required fields

Every surface row in `surfaces[]` MUST include:

| Field | Meaning |
|---|---|
| `id` | unique within the audit; format `<partition-id>:<category>:<idx>` (e.g., `juice-shop:http:0042`) |
| `partition` | partition id this surface belongs to |
| `category` | one of the categories in §2.3 |
| `method` | for http/grpc/graphql: method or verb; for others: `null` |
| `path` | the external identifier (URL path, queue name, gRPC service/method, cron cadence, topic name) |
| `file` | absolute-from-repo-root path to the handler file |
| `line_range` | `[start_line, end_line]` of the handler body |
| `handler_hash` | sha1 of the normalized handler body (see `lib/handler-hash.md`) |
| `auth_required` | `true` / `false` / `unknown` |
| `auth_middleware` | list of middleware / decorators applied (strings) |
| `roles_required` | list of role / scope strings asserted in the handler or middleware |
| `params` | list of `{name, source, sensitive}` where source ∈ `path|query|body|header|cookie` and sensitive is boolean |
| `trust_zone` | inherited from the partition by default; override if the surface is explicitly admin/internal |
| `data_ops` | list of data operations: `read|write|delete|exec|none` |
| `framework` | the framework that produced this surface (e.g., `Express`) |
| `notes` | free text (≤200 chars), optional |

## 2.5 — Handler body extraction & hashing

Refer to `lib/handler-hash.md` for the normalization rules. Summary:

1. **Identify the handler body.** For brace-delimited languages (JS/TS/Go/
   Java/Kotlin/Rust/C#/PHP), start at the opening `{` of the handler
   function and end at the matching `}` (track nested braces).
   For indent-delimited (Python), start at the handler `def` line and
   include all lines with strictly greater indentation.
   For decorator-based (annotations like `@GetMapping`), the handler body is
   the function the annotation is attached to.
2. **Normalize.** Strip `//`, `#`, `/* */`, `<!-- -->` comments; trim all
   whitespace (including newlines); lowercase.
3. **Hash.** `sha1(normalized_body)`.

If the body cannot be extracted (e.g., metaprogrammed registration), emit
`handler_hash: null` and add a note. Never guess.

## 2.6 — Auth inference

For each surface, infer `auth_required`:

1. **Middleware present at route registration** — `app.get('/x', auth, handler)` → `true`.
2. **Decorator on the handler** — `@Authenticated`, `@PreAuthorize`, `@Require(...)` → `true`.
3. **Global middleware mounted before this route** — check the Phase 0
   `auth.middleware_paths` entries; if the route registration file imports
   the middleware and registers the handler inside the middleware's scope,
   infer `true`.
4. **Explicit unauthenticated marker** — `@Public`, `permit_unauthenticated`,
   route under `/public/`, `/health`, `/metrics` → `false`.
5. **Otherwise** → `unknown`. Flag in `notes` so Phase 5 category 1 can
   verify manually.

For `roles_required`, grep the handler body for role / scope assertions
(`hasRole`, `requireRole`, `canAccess`, `@PreAuthorize("hasRole('ADMIN')")`,
`request.user.is_staff`).

## 2.7 — Immediate-flag pre-filter

While enumerating, pre-tag surfaces with any of:

- `NO_AUTH_WRITE` — data_ops contains `write`/`delete`/`exec` and `auth_required: false`.
- `NO_AUTH_READ_SENSITIVE` — data_ops contains `read` and the partition sensitivity ≥2, and `auth_required: false`.
- `AUTH_UNKNOWN` — `auth_required: unknown`.
- `WILDCARD_METHOD` — file-based routing without a method suffix (e.g., Nuxt
  `server/api/x.ts` handling ALL methods).
- `ADMIN_NO_ROLE` — path matches `/admin|/actuator|/debug` and
  `roles_required` is empty.

These tags go in the surface row's `flags[]` field. They are **not** findings
yet — Phase 5 turns them into severities.

## 2.8 — Emit the inventory

Write the consolidated surface document to
`.claude-audit/current/phase-02-surface.json` with top-level shape:

```json
{
  "schema_version": 2,
  "skill_version": "...",
  "audit_id": "...",
  "generated_at": "...",
  "by_category": { "http": 61, "file_upload": 4, "queue_consumer": 0, "..." : 0 },
  "flags_summary": { "NO_AUTH_WRITE": 3, "AUTH_UNKNOWN": 12, ... },
  "surfaces": [ ... per-entry fields from §2.4 ... ]
}
```

Write `phase-02.done` marker.

## 2.9 — Report to user

> Phase 2 complete — <N> surfaces across <M> categories (<http count> HTTP
> routes, <K> file uploads, ...). <F> pre-flags raised: <breakdown>.
> Proceeding to Phase 3 (Keystone).

## 2.10 — Edge cases

- **Metaprogrammed / reflection-based routing.** Rails `routes.rb` with
  `resources :items`, Django `path(..., include('app.urls'))`, Spring
  `@RequestMapping` on a class. Resolve by following the indirection one
  level; if the resolution is dynamic (runtime-only), emit a surface with
  `path: "<dynamic>"` and a `notes` entry.
- **Shared handler reused at multiple routes.** Emit one surface per
  registration site (different `id`), but the `handler_hash` is the same —
  Phase 5 will deduplicate by hash where relevant.
- **Vendor code.** Any path matching an `ignore.txt` pattern is skipped —
  no surface emitted regardless of apparent route-like structure.
