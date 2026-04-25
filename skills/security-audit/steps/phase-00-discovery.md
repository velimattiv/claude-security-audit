# Phase 0 — Discovery & Recon

## 🛑 MANDATORY EXECUTION RULES (READ FIRST)

📋 **This phase MUST produce, on disk, before advancing:**
- `.claude-audit/current/phase-00-profile.json` (schema-valid per `lib/profile-schema.json`)
- `.claude-audit/current/phase-00.done` (zero-byte marker)

⛔ **DO NOT advance to Phase 1** until both files exist AND the Bash verification block at the bottom of this file prints `phase-00 verified`.

📖 Writing only the final report without this artifact is an **INVALID run**. Every later phase (partition risk ranking, framework-driven surface enumeration, Phase 5 fan-out) reads `phase-00-profile.json` as authoritative input.

---

**Goal.** Build the Project Map — a single JSON document that every later
phase reads. Nothing deep happens until this is complete.

**Input.** The project root (the skill-user's working directory).

**Output.** `.claude-audit/current/phase-00-profile.json` conforming to
`lib/profile-schema.json`.

**Budget.** Single orchestrator pass. No sub-agents. Aim for ≤30 file reads
and 1-2 shell invocations.

**Principle.** Confirm every detection with file evidence. Never guess. If a
field cannot be derived with evidence, set it to `null` / `[]` and record the
reason in `notes[]`.

---

## 0.1 — Git state

Record:
- `git.head` — `git rev-parse HEAD`
- `git.branch` — `git rev-parse --abbrev-ref HEAD`
- `git.remote` — `git remote get-url origin` (null if missing)
- `git.dirty` — `true` if `git status --porcelain` has output

Compute `audit_id = sha256(git.head + top-level dir listing)` as the stable
run identifier.

## 0.2 — Repo size

Prefer `cloc --json --vcs=git .` if available. Fall back in order:
1. `tokei -o json`
2. Manual: enumerate files with `git ls-files`, classify by extension against
   a minimal extension→language map, count lines with `wc -l`.

Emit:
- `repo.loc_total`
- `repo.loc_by_language`: `{language_name: loc}`
- `repo.file_count`
- `repo.top_level_dirs`: the names of directories at the repo root (excluding
  `.git`, `node_modules`, `dist`, `build`, `target`, `.venv`, `__pycache__`).

## 0.3 — Topology detection

Probe for monorepo tools (stop at first match, record all that apply):

| Tool | Signal |
|---|---|
| nx | `nx.json` |
| turbo | `turbo.json` |
| pnpm workspaces | `pnpm-workspace.yaml` |
| yarn workspaces | `package.json` with `"workspaces"` key |
| npm workspaces | same as yarn |
| lerna | `lerna.json` |
| rush | `rush.json` |
| bazel | `WORKSPACE`, `WORKSPACE.bazel`, `MODULE.bazel` |
| go workspace | `go.work` |
| cargo workspace | `Cargo.toml` with `[workspace]` table |
| poetry workspaces | `pyproject.toml` with multi-project layout |
| multi-service | `services/*/Dockerfile` OR `packages/*/package.json` |
| submodules | `.gitmodules` present |

Emit:
- `topology.kind`: `monorepo` | `multi-service` | `single` | `unknown`
- `topology.tool`: first monorepo tool matched, else `null`
- `topology.workspaces`: list of workspace paths (resolved from the tool's
  config)
- `topology.services`: list of service paths (from Dockerfile probes)
- `topology.submodules`: list of submodule paths

## 0.4 — Language inventory

From `repo.loc_by_language`, emit `languages[]` sorted by LOC descending:
```json
[{"name": "TypeScript", "loc": 45000, "files": 120, "primary": true}]
```

`primary: true` on the top language, `false` on the rest. Skip languages with
<100 LOC unless they are config-only (YAML, TOML, Dockerfile, Terraform).

## 0.5 — Framework detection

For each language with significant LOC, probe the framework signals in
`lib/framework-detection.md`. Examples:

- **Python**: `pyproject.toml`/`requirements.txt`/`Pipfile` for `django`,
  `flask`, `fastapi`, `starlette`, `djangorestframework`.
- **Java/Kotlin**: `build.gradle*` or `pom.xml` for `spring-boot-starter-*`,
  `micronaut-*`, `quarkus-*`, `ktor-*`.
- **Go**: `go.mod` for `gin-gonic/gin`, `labstack/echo`, `go-chi/chi`,
  `gofiber/fiber`.
- **Ruby**: `Gemfile` for `rails`, `sinatra`.
- **PHP**: `composer.json` for `laravel/framework`, `symfony/*`,
  `wordpress`.
- **.NET**: `*.csproj` for `Microsoft.AspNetCore.*`.
- **Rust**: `Cargo.toml` dependencies for `axum`, `actix-web`, `rocket`.
- **Elixir**: `mix.exs` for `phoenix`.
- **JS/TS**: `package.json` dependencies for `next`, `nuxt`, `express`,
  `fastify`, `hono`, `koa`, `@trpc/server`, `@nestjs/core`.

Emit `frameworks[]`:
```json
[{"language": "TypeScript", "framework": "Nuxt", "version": "3.x", "evidence": "nuxt.config.ts"}]
```

If a language has unknown framework, emit one entry with `framework: null`
and set `evidence` to the manifest file you checked.

**Conflict resolution.** If multiple manifests for the same language
declare different frameworks (e.g., a Python project with both
`pyproject.toml` declaring `fastapi` and a legacy `requirements.txt`
declaring `flask`), emit **one entry per detected framework** with
distinct `evidence` paths. Downstream phases (Phase 2 surface
inventory) will then exercise each framework's detection patterns —
correct behavior for a migration-in-progress codebase. Do NOT pick
one and discard the other; that would silently skip surfaces from the
second framework.

## 0.6 — Non-HTTP surfaces (hint only — Phase 2 does inventory)

Probe for presence signals. Do **not** enumerate surfaces here — that is
Phase 2's job. Set booleans / lists on `surfaces_hint`:

| Field | Signal |
|---|---|
| `grpc` | any `*.proto` file |
| `graphql` | any `*.graphql`/`*.gql` file, or `graphql` import |
| `websocket` | `ws`/`socket.io`/`@WebSocketGateway`/`ActionCable`/Phoenix.Channel imports |
| `sse` | `text/event-stream` string occurrence |
| `trpc` | `@trpc/server` import |
| `queue` | list of detected systems: Kafka, RabbitMQ, SQS, NATS, Redis |
| `scheduler` | list: celery, sidekiq, bullmq, resque, hangfire, cron, systemd |
| `webhook` | route handler with `X-Hub-Signature` / `signature` header probe |
| `file_upload` | `multipart/form-data` occurrence or framework upload primitive |
| `serverless` | `template.yaml`/`function.json`/`wrangler.jsonc`/`serverless.yml` |
| `mobile` | `AndroidManifest.xml` / iOS `Info.plist` |
| `desktop` | `ipcMain.handle` / `#[tauri::command]` / Electron main |
| `admin_endpoints` | paths matching `/actuator/*`, `/debug/pprof`, `/__debug__` |
| `cli_admin` | `bin/` directory, `lib/tasks/`, `app/Console/Commands/` |

## 0.7 — Auth system

Search for auth patterns, record what you find:

- **Kinds** — detect presence of: `session`, `jwt`, `api_key`, `pat`, `oauth`.
- **Middleware paths** — files exporting functions matching
  `auth|authz|guard|require*|middleware|currentUser|getSession|protect`.
- **Frameworks** — `passport`, `next-auth`, `@sidebase/nuxt-auth`, `lucia`,
  `better-auth`, `clerk`, `spring-security-*`, `devise`, `django.contrib.auth`,
  `flask-login`, `laravel/sanctum`, `laravel/passport`.

Emit `auth` object with those three fields. If none detected, set arrays to
`[]` and add a `notes[]` entry.

## 0.8 — Data model

Find ORM / schema files:

| Stack | Signal |
|---|---|
| Drizzle | `drizzle.config.*`, `*/schema.ts` |
| Prisma | `schema.prisma` |
| TypeORM | imports of `typeorm` |
| Sequelize | imports of `sequelize` |
| Django ORM | `models.py` |
| SQLAlchemy | imports of `sqlalchemy` + `Base` usage |
| JPA/Hibernate | `@Entity` annotations |
| ActiveRecord | `app/models/*.rb` with `ApplicationRecord` |
| Eloquent | `app/Models/*.php` |
| Ecto | `schema do` blocks in Elixir |

For each detected schema file, extract:
- Entities (table/model names)
- Ownership columns: any column name matching `user_id|userId|ownerId|createdBy|organizationId|tenantId|accountId`
- PII columns: any column name matching `email|phone|dob|ssn|passport|address|ip|full_name|firstName|lastName|birthdate`

Emit:
```json
{
  "orm": "drizzle",
  "schema_files": ["drizzle/schema.ts"],
  "entities": [{"name": "User", "owner_cols": ["id"], "pii_cols": ["email"]}]
}
```

## 0.9 — Deployment

| Category | Signal |
|---|---|
| `docker.dockerfiles` | `**/Dockerfile`, `**/Dockerfile.*` |
| `docker.compose` | `docker-compose*.yml`, `compose*.yml` |
| `k8s.manifests` | `*.yaml`/`*.yml` with `kind:` in (`Deployment`, `StatefulSet`, `DaemonSet`, `Service`, `Ingress`) |
| `k8s.helm_charts` | `Chart.yaml` |
| `iac.terraform` | `*.tf`, `*.tfvars` |
| `iac.cloudformation` | `*.cf.yml` / `cloudformation/*.yaml` / `template.yaml` |
| `iac.bicep` | `*.bicep` |
| `ci.github_actions` | `.github/workflows/*.yml` |
| `ci.gitlab_ci` | `.gitlab-ci.yml` |
| `ci.circleci` | `.circleci/config.yml` |
| `ci.buildkite` | `.buildkite/pipeline.yml` |

Emit `deployment` object with each sub-field as a list of matched paths.

## 0.10 — Trust zones

Classify each partition-candidate as `public | internal | admin | dev`.

Evidence sources (in priority order):
1. **Ingress / gateway config** — parse `nginx.conf`, `alb-*.yaml`, API
   gateway route tables.
2. **OpenAPI `servers:`** — `openapi.yaml` / `openapi.json` may hint at
   production vs staging endpoints.
3. **README** — explicit mentions of "public API", "internal service", etc.
4. **Dir naming** — `services/public-*`, `services/admin-*`, `apps/dashboard`.
5. **Default** — if nothing else, mark `internal`.

Emit `trust_zones[]`:
```json
[{"name": "public", "sources": ["nginx.conf:42"], "paths": ["services/api"]}]
```

## 0.11 — LLM usage

Grep imports for `anthropic|openai|langchain|llamaindex|ollama|@anthropic-ai/sdk|@langchain/*`. If matches found, do a second pass to distinguish **user-facing** LLM features from **internal telemetry / tooling** usage:

- **User-facing** heuristic: the LLM SDK is imported in a file that also
  handles an HTTP route or WebSocket, or a file whose name contains `chat`,
  `assistant`, `agent`, `completion`.
- **Internal only** heuristic: SDK imported only in scripts/CLIs or background
  jobs.

Emit:
```json
{
  "detected": true,
  "kind": "user-facing" | "internal" | "mixed",
  "sdks": ["anthropic"],
  "evidence": ["server/api/chat.post.ts", "package.json:@anthropic-ai/sdk"]
}
```

The LLM deep-dive category (Phase 5 #9) is gated on `detected && kind != "internal"`.

## 0.12 — PII classification

From Phase 0.8, if any entity has PII columns, mark `pii.detected: true` and
collate:
```json
{
  "detected": true,
  "columns": ["users.email", "users.phone"],
  "frameworks_support": ["drizzle"]
}
```

This gates LINDDUN privacy review (Phase 6).

## 0.13 — Ignore list

Produce `ignore.txt` at `.claude-audit/ignore.txt` — patterns downstream
phases (especially Phase 5 greps) must respect. Seed with:

```
# Standard ignores
.git/
node_modules/
dist/
build/
target/
.venv/
venv/
__pycache__/
vendor/
.next/
.nuxt/
.output/
coverage/
.pytest_cache/
.tox/

# Generated code markers (add if detected)
**/*.generated.*
**/*.pb.go
**/*_pb2.py
**/*.d.ts
openapi-codegen/

# Test fixtures (matched by dir)
**/testdata/
**/fixtures/
**/__fixtures__/
**/test-fixtures/
```

Append project-specific additions based on what you discovered in 0.3 (monorepo
ignore paths) and 0.9 (build outputs).

## 0.14 — Emit the profile

Write the merged JSON to `.claude-audit/current/phase-00-profile.json` and
the done-marker to `.claude-audit/current/phase-00.done`.

Validate the output against `lib/profile-schema.json` (re-read your JSON to
check every required field is populated or explicitly null).

Report to the user:
> Phase 0 complete — detected <primary language + framework>, <topology
> kind>, <N entities>, LLM usage: <yes/no>, PII: <yes/no>. Proceeding to
> partition + risk rank.

---

## Verify before exit (MANDATORY)

Before declaring this phase complete and proceeding, run:

```bash
test -f .claude-audit/current/phase-00-profile.json  \
  && test -f .claude-audit/current/phase-00.done \
  && echo "phase-00 verified" \
  || { echo "phase-00 INCOMPLETE — re-write artifact + .done marker before proceeding" >&2; exit 1; }
```

Do not advance to the next phase until this check prints "phase-00 verified". Producing only a downstream artifact (e.g. the final report) without the per-phase artifact + marker is an INVALID run.
