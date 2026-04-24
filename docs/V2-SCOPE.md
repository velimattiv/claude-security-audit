# /security-audit v2 — Comprehensive Scope & Plan

Status: **DRAFT — awaiting review before implementation**.
Target runtime: Claude Code only.
Source material: 5 parallel research reports (language coverage, scanner tooling, threat modeling, orchestration, cross-language patterns) run 2026-04-24.

---

## 1. Design Principles

1. **Discovery-first.** Every efficient deep-dive requires a map. Phases 0-3 are reconnaissance. Nothing deep happens until the attack surface is inventoried and risk-ranked.
2. **Blackboard on disk, not in context.** Orchestrator stays small; sub-agents read inputs from `.claude-audit/`, write findings back to `.claude-audit/`. Only JSON summaries return through tool output.
3. **Saga checkpointing.** Each phase writes `phase-N.done` + artifact. Crash/interrupt resumable via `claude --continue`-friendly marker scan.
4. **Map-reduce per partition, per category.** Fan out along two axes: partition (service/package) × deep-dive category (9). Reduce into a single synthesis.
5. **Delta mode is first-class.** Baseline artifact lives with the repo. A fresh run against unchanged code is a sub-minute no-op. Incremental review on a PR is the v2 value-add.
6. **Stay within Claude Code constraints.** No experimental feature flags (no Agent Teams). Subagents don't spawn subagents — all fan-out is in the main skill.
7. **No skimping on tokens.** All sub-agents use Claude Opus 4.7 (1M context) — no tiered downgrade to Sonnet/Haiku. Security audits are the least cost-sensitive use case; always favor depth over efficiency.
8. **Partition for quality, not cost.** Sub-partitioning is triggered by reasoning-quality heuristics (partition >500K raw tokens of code ≈ 125K LOC). Rationale: "lost in the middle" — a sub-agent given 800K tokens produces measurably weaker findings than 5 parallel sub-agents each with 160K. Parallelism is additive token cost, paid gladly for better findings.

---

## 2. Architecture

```
┌──────────────────────── /security-audit skill (orchestrator) ────────────────────┐
│                                                                                  │
│   Phase 0  Discovery & Recon          → .claude-audit/current/phase-00-*.json    │
│   Phase 1  Partition & Risk Rank      → partitions.json                          │
│   Phase 2  Attack Surface Inventory   → phase-02-surface.json                    │
│   Phase 3  Keystone File Index        → cache/keystone-files.json                │
│   Phase 4  External Inputs            → phase-04-scanners/*.sarif                │
│   Phase 5  Parallel Deep Dives (9 cat)→ phase-05-{cat}-{partition}.jsonl         │
│   Phase 6  Config + Methodology Spine → phase-06-config.json, asvs.jsonl         │
│   Phase 7  Synthesis & Report         → phase-07-report.md + findings.sarif      │
│   Phase 8  Baseline Persistence       → baseline.json + docs/security-audit-*.md │
│                                                                                  │
│   Sub-agents (Explore/general-purpose, parallel):                                │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│   │ Auth/Authz   │  │ IDOR/BOLA    │  │ Crypto       │  │ MITM         │         │
│   │ Secret-spray │  │ Deployment   │  │ Injection    │  │ SSRF         │         │
│   │ LLM-specific │  │ Scanner-N    │  │ Scanner-M    │  │ Adversarial  │         │
│   └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘         │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Phase-by-Phase Specification

### Phase 0 — Discovery & Recon
**Goal.** Build the Project Map. Nothing else runs until this is complete.

**Inputs.** Repo root + optional user scope hint.

**Work done:**
- Repo size — LOC per language (`cloc --json` or `tokei`), file count, top-level dirs.
- Repo topology detection — monorepo tools (nx, turbo, pnpm workspaces, lerna, rush, bazel, go work, cargo workspace, poetry workspaces); multi-service (`services/*/Dockerfile`); submodules.
- Language inventory — all languages present, not just primary.
- Framework detection per language — Python (Django/Flask/FastAPI/Starlette/DRF), Java/Kotlin (Spring Boot, Micronaut, Quarkus, Ktor), Go (stdlib, Gin, Echo, Chi, Fiber), Ruby (Rails, Sinatra), PHP (Laravel, Symfony, WordPress), .NET (ASP.NET Core, Blazor, Minimal APIs), Rust (Axum, Actix, Rocket), Elixir (Phoenix), Scala (Play, Akka/Pekko), JS/TS (Nuxt, Next, Express, Fastify, Hono, Koa, tRPC, NestJS).
- Non-HTTP surfaces — gRPC (`.proto`), GraphQL (`schema.graphql`), WebSocket, SSE, tRPC, queue consumers (Kafka, RabbitMQ, SQS, NATS, Redis), schedulers (Celery, Sidekiq, BullMQ, Resque, Hangfire, cron, systemd timers), mobile (Android/iOS), desktop (Electron, Tauri), serverless (Lambda, Azure Functions, CF Workers, Vercel/Netlify).
- Auth system detection — session vs JWT vs API key vs PAT vs OAuth; middleware/filter location.
- Data model — ORM schemas, ownership columns (`userId`, `tenantId`, `organizationId`), PII columns (email/phone/dob/ssn/passport/address/ip).
- Deployment model — `Dockerfile`, `docker-compose.yml`, k8s manifests, Helm, Terraform, CloudFormation, Bicep, GitHub/GitLab CI.
- Trust zones — parse ingress configs, ALB rules, OpenAPI `servers:`, README; classify each partition as `public | internal | admin | dev`.
- LLM/AI usage detection — imports of `anthropic|openai|langchain|llamaindex|ollama` → gates LLM Top 10 deep-dive.
- PII classification — keyword + schema scan → gates LINDDUN privacy review.

**Output:** `phase-00-profile.json` — the Project Map. All subsequent phases reference it.

**Budget:** single orchestrator pass, ~20-30 file reads; no subagents needed. Produces ignore-list for downstream phases (standard ignores + generated-code markers + test fixtures).

---

### Phase 1 — Partition & Risk Rank
**Goal.** Split the repo into audit partitions and score each by risk so the deep-dive budget goes where it matters.

**Partitioning algorithm** (ranked preference):
1. Explicit monorepo configs → workspace members.
2. Container/service boundary → per Dockerfile/service.
3. Language boundary (secondary axis inside partition).
4. CODEOWNERS paths (when no explicit structure).
5. Dependency-graph communities (expensive; only if 1-4 fail).
6. LOC rebalancing — split >120K LOC, merge <3K LOC.
7. Git-log heat — prioritization signal (not partition signal).

**Risk score (0-9):** `exposure (0-3) + sensitivity (0-3) + age/complexity (0-3)`.
- **Exposure**: dev / internal / internet-behind-gateway / public-ingress.
- **Sensitivity**: no-data / metadata-only / PII / payments-auth-secrets.
- **Age**: <6mo / 6-24mo / >2y / >2y + `legacy|admin|v1` in name.

**Output:** `partitions.json` sorted by risk score. Deep-dives run full-depth on top-N (default 8); tail gets inventory-only on Haiku.

---

### Phase 2 — Attack Surface Inventory (supersedes v1 Route Inventory)
**Goal.** Enumerate **every** entry point, not just HTTP routes.

**Surface categories:**
| Category | Examples | Detection signal |
|---|---|---|
| HTTP routes | REST, SSR page handlers | `app.get`, framework-specific (per §4) |
| gRPC | RPC methods | `.proto` + `grpc.Server` / `BindService` |
| GraphQL | resolvers | `schema.graphql`, `@Resolver`, `initTRPC.create()` |
| WebSocket | socket handlers | `ws://`, `@WebSocketGateway`, `ActionCable`, Phoenix channels |
| SSE | streams | `text/event-stream`, `EventSource` |
| tRPC | procedures | `router.procedure` |
| Queue consumers | Kafka/RabbitMQ/SQS/NATS/Redis | `@KafkaListener`, `new Consumer`, `@SqsListener` |
| Schedulers | cron, timers, Celery, Sidekiq, BullMQ | decorator scan |
| Webhooks | inbound POST handlers | route + `signature`/`X-Hub-Signature` headers |
| File uploads | multipart, S3 presigned | `multipart/form-data`, `@UploadedFile` |
| Serverless | Lambda/Functions/Workers | handler signatures + `template.yaml`/`function.json`/`wrangler.jsonc` |
| Mobile IPC | exported components | `AndroidManifest.xml exported=true`, iOS URL schemes |
| Desktop IPC | Electron/Tauri | `ipcMain.handle`, `#[tauri::command]` |
| Admin/debug endpoints | actuator, pprof | `/actuator/*`, `/debug/pprof`, `/__debug__` |
| CLI/admin scripts | rake, artisan, mgmt commands | `bin/*`, `lib/tasks/`, `app/Console/Commands/` |
| Outbound TLS clients | for MITM analysis | HTTP client imports |

**Per-entry fields:** `id, partition, file, line_range, handler_hash, auth_required, auth_middleware[], roles_required[], params[{name,source,sensitive}], trust_zone, data_ops`.

**Output:** `phase-02-surface.json` — the ground truth for all subsequent audits.

---

### Phase 3 — Keystone File Index
**Goal.** Identify files whose change invalidates multiple audit rows (auth middleware, session config, crypto bootstrap, CORS config, error handlers). Powers delta-mode invalidation.

**Detection:** files exporting functions matching `auth|authz|guard|require*|middleware|currentUser|getSession`, config loaders (`nuxt.config.*`, `next.config.*`, `settings.py`, `application.yml`), crypto init (`cipher|signer|jwtVerifier` module exports), CORS/CSP config files.

**Output:** `cache/keystone-files.json` — list of paths. Any change to one invalidates all downstream findings touching that file's exports.

---

### Phase 4 — External Inputs (Scanner Orchestration + Built-in Reviews)
**Goal.** Run the standardized scanner bundle + Claude Code's built-in reviews in parallel, collect findings as inputs for cross-referencing.

**Minimum scanner bundle** (all emit SARIF, single-binary-ish, no paid APIs):
| Tool | Role | Install | Invocation |
|---|---|---|---|
| **semgrep** | SAST polyglot | `pip install semgrep` | `semgrep scan --config auto --sarif -o semgrep.sarif` |
| **osv-scanner** | SCA all ecosystems | Go binary | `osv-scanner scan source --recursive --format=sarif --output=osv.sarif $PWD` |
| **gitleaks** | Secrets (working tree + history) | `brew install gitleaks` | `gitleaks git . --report-format sarif --report-path gitleaks.sarif` |
| **trufflehog** | Verified-secret sweep | install.sh | `trufflehog git file://. --json --only-verified` |
| **trivy** | IaC + Dockerfile + vuln + SBOM | install.sh | `trivy fs --scanners vuln,secret,misconfig,license --format=sarif -o trivy.sarif .` + `trivy config -f sarif -o trivy-iac.sarif .` |
| **hadolint** | Dockerfile linting | binary | `hadolint --format sarif Dockerfile` |

**Conditional additions:**
- **brakeman** if Rails detected.
- **checkov** if Terraform-heavy (graph cross-resource).
- **kube-linter** if Kubernetes central.
- **grype** if EPSS prioritization wanted.
- **govulncheck** for Go reachability.
- **psalm --taint-analysis** for PHP taint.
- **zizmor** for GitHub Actions deep audit.

**Also:**
- `/security-review` (Claude Code built-in) — run per partition, not whole repo, to avoid budget blow-out.
- `vendored/adversarial-review/` — as today, applied per partition.

**Execution:** Each scanner runs in its own sub-agent invocation as a Bash call; output SARIF written to `phase-04-scanners/<tool>.sarif`. Orchestrator post-processes: keep only `ruleId, level, uri, startLine, message.text` to cut ~80% SARIF bulk.

---

### Phase 5 — Parallel Deep Dives (9 categories)
**Fan-out axes:** partition × category. For top-N risk partitions, spawn N × 9 sub-agents (or fewer if the skill rate-limits parallelism).

Each sub-agent reads `phase-00-profile.json` + `phase-02-surface.json` + partition scope from disk, runs grep-based + semantic checks, writes findings as JSONL to `phase-05-<cat>-<partition>.jsonl`.

| # | Category | What it verifies | Key patterns / tools |
|---|---|---|---|
| 1 | **Auth & Authz** | Every route/queue/job has auth; roles enforced; JWT alg pinned; session regen on login; OAuth state; password reset flow | §1 of `docs/ANTI-PATTERNS.md`; `semgrep p/jwt`; brakeman |
| 2 | **IDOR / BOLA** | Every ID-parameterized route scopes via `current_user.*`; GraphQL resolvers authz; no mass-assignment | §2; `semgrep p/owasp-top-ten`; graphql-armor |
| 3 | **Token / API Key Scope** | PATs/API keys scoped; scope enforced at grant AND use; no wildcard scopes | custom rules per partition |
| 4 | **MITM / Transport** *(NEW)* | No `verify=False`, `rejectUnauthorized:false`, `InsecureSkipVerify`, `AllowAllHostnameVerifier`; TLS 1.2+; redirects don't cross schemes; mobile pinning | §3 patterns, all languages |
| 5 | **Cryptography** *(NEW)* | No MD5/SHA1 for security; AEAD (GCM/ChaCha20-Poly1305) not ECB/CBC-raw; no static IV/nonce reuse; CSPRNG not `Math.random`; KDF cost ≥2026 OWASP (bcrypt≥12, PBKDF2≥600k, scrypt N≥2^17, Argon2id 19 MiB); JWT alg pinning | §4; `bandit B303-B505`; `semgrep p/cryptography` |
| 6 | **Secret Sprawl** *(NEW)* | Vendor-specific token regexes (AWS, GCP, Azure, GitHub, Slack, Stripe, Twilio, SendGrid); private keys; `.env*` tracked; Dockerfile `ENV` secrets; k8s ConfigMap secrets; Terraform state/tfvars; CI plaintext env | §5; `gitleaks`, `trufflehog` |
| 7 | **Deployment Posture** *(NEW)* | Dockerfile (USER root, :latest, no HEALTHCHECK, debug ports); k8s (`privileged`, `hostNetwork`, RBAC `*`); Terraform (0.0.0.0/0, public buckets, no encryption, IAM `*`); GitHub Actions (`pull_request_target` + head checkout, unpinned actions, secrets to forks) | §6; `trivy config`, `hadolint`, `kube-linter`, `zizmor` |
| 8 | **Injection / SSRF / Deserialization** *(NEW, combined)* | SQLi string-concat; command injection (`shell=True`, Runtime.exec, backticks); XXE (unhardened parsers); SSTI (Jinja2 render_template_string); SSRF (user-URL to HTTP client); unsafe deserializers (pickle, Marshal, BinaryFormatter, PyYAML.load, unserialize w/o allowed_classes) | §7-9; `semgrep p/ssrf`, `bandit B301-B506` |
| 9 | **LLM-Specific** *(NEW, conditional)* | Gated on detector from Phase 0. Covers OWASP LLM Top 10 (2025): prompt injection (user input into system prompt), sensitive info disclosure (PII/secrets in prompts), improper output handling (LLM output to eval/exec/SQL/`dangerouslySetInnerHTML`), excessive agency (unscoped tools), system prompt leakage, vector/embedding weaknesses, unbounded consumption (missing token/cost caps) | custom; flag to code-reviewer-agent |

Sub-agents return JSON summaries only (counts by severity + artifact path). Raw findings stay on disk.

**Model for every sub-agent: Claude Opus 4.7 (1M context).** No Sonnet/Haiku routing. Budget per sub-agent: 800K tokens raw code hard ceiling, 500K soft target. Partitions above 500K auto-split into parallel sub-agents for reasoning quality.

---

### Phase 6 — Config Audit + Methodology Spine
**v1 Phase 6 carried over**, expanded:
- CORS, security headers (HSTS/CSP/X-Frame-Options/etc), cookie flags, error handling, env vars, rate limiting (existing).
- **PLUS** transport config (TLS min version, cert pinning for mobile, mixed content), outbound-client config (egress proxy, IMDS blocking).
- **PLUS** CI/CD config (pinned actions, permissions block, OIDC trust policy breadth).

**Methodology spine applied in parallel:**
- **ASVS 5.0 Level 2** as a checklist — 17 categories × sub-agent per category, seeded with file list filtered by regex (V6 Crypto → crypto imports; V13 API → route files; etc.). Each finding tagged with ASVS ID.
- **API Security Top 10 (2023)** mechanical mapping per attack-surface item: BOLA/BFLA/BOPLA tables built from inventory.
- **LLM Top 10 (2025)** — if Phase 0 detected LLM SDKs.
- **LINDDUN** — if Phase 0 detected PII. Run privacy review sub-agent.
- **STRIDE per surface** — for each top-N partition, spawn a sub-agent that produces a 6-column (S/T/R/I/D/E) mitigation table per attack-surface item.
- **CWE tagging** — every finding includes its CWE ID (mapping table in `lib/cwe-map.json`). Consumers: DefectDojo, Phoenix, federal SSDF.

---

### Phase 7 — Synthesis & Report
**Goal.** Collect all findings, deduplicate, rank, produce consumable output.

**Steps:**
1. Load all JSONL from `phase-04-scanners/` + `phase-05-*.jsonl` + `phase-06-*.jsonl`.
2. Deduplicate: same file+line+ruleId → merge with `sources[]`.
3. Cross-reference: same finding from 2+ independent sources → `confidence: CONFIRMED`; single source → `LIKELY`; grep-only heuristic → `POSSIBLE`.
4. Assign severity using consistent rubric (CRITICAL/HIGH/MEDIUM/LOW/INFO).
5. Identify unique-to-this-skill findings (not in `/security-review` or adversarial review output) — call out as skill's unique value.
6. Emit three output artifacts:
   - **`phase-07-report.md`** — human report with executive summary, findings tables by severity, attack surface summary, ASVS/API/LLM/LINDDUN coverage matrix, STRIDE tables, route inventory, risk-ranked partition scores.
   - **`findings.sarif`** — consolidated SARIF 2.1.0 for ingestion into GitHub Security tab, DefectDojo, Jira security projects.
   - **`findings.cyclonedx.json`** — SBOM (from trivy or syft) for VEX attachment.
7. Save final report to `docs/security-audit-report.md` (or `_bmad-output/implementation-artifacts/security-audit-report.md` if `_bmad-output/` exists — BMAD compatibility).

---

### Phase 8 — Baseline Persistence (for delta mode)
**Goal.** After a successful full audit, write a baseline JSON that future delta-mode runs can diff against.

**Baseline schema** (simplified — full schema in `lib/baseline-schema.json`):
```json
{
  "version": 2,
  "audit_id": "sha256-of-HEAD-and-toplevel",
  "git_head": "abc123",
  "created_at": "ISO-8601",
  "repo_topology": { "kind": "...", "partitions": [...] },
  "surface": [ { "id": "...", "file": "...", "handler_hash": "sha1", ... } ],
  "keystone_files": [ "src/auth/middleware.ts", "config/application.yml", ... ],
  "auth_matrix": [ { "route_id": "...", "role": "...", "allowed": "..." } ],
  "idor_candidates": [ ... ],
  "config": { "cors_origins": [...], "csp": "...", "cookie_flags": {...} },
  "findings_carryover": [ ... ],
  "ignored": [ "patterns used for ignore.txt" ]
}
```

**Storage:**
- `.claude-audit/baseline.json` (full, gitignored).
- `docs/security-audit-baseline.json` (pruned, suitable for version control).
- `.claude-audit/history/<timestamp>/` (archived previous runs).

---

## 4. Modes

| Mode | Invocation | Behavior |
|---|---|---|
| **full** (default) | `/security-audit` | All 9 phases. ~15-60 min depending on repo size. |
| **delta** | `/security-audit mode: delta` | Requires `docs/security-audit-baseline.json`. Computes changed files vs `baseline.git_head`, invalidates affected rows (see §5), runs Phases 2-7 only on touched partitions + adjacent. ~2-5 min typical. |
| **scoped** | `/security-audit scope: "services/api"` | Narrows all phases to a path prefix. Useful for targeted reviews. |
| **focused** | `/security-audit categories: "crypto,mitm,secrets"` | Runs only the named deep-dive categories. Skips others. |
| **report-only** | `/security-audit mode: report` | Regenerates report from existing `.claude-audit/current/` artifacts (no scanning). |

---

## 5. Delta Mode Invalidation Rules

1. `ChangedFiles = git diff --name-only <baseline.git_head> HEAD`.
2. A surface row is **stale** if its `file ∈ ChangedFiles` **OR** `handler_hash` diverges on re-parse.
3. A partition is **stale-whole** if `>20%` of its files are in `ChangedFiles` **OR** its manifest changed (`package.json`, `go.mod`, `Cargo.toml`, `pyproject.toml`, `build.gradle`, `*.csproj`).
4. **Keystone invalidation** — if any keystone file changed, invalidate all `auth_matrix` rows (not just the routes whose handler file changed).
5. **Config invalidation** — any change under `config/`, `*.config.*`, or framework-specific config files (nuxt.config, next.config, settings.py, application.yml) → re-run Phase 6 in full.
6. **Dependency invalidation** — any lockfile change → re-run Phase 4 (scanners) in full; rest of phases only for directly affected packages.

**Scoping equation:**
```
touched_partitions
  = { row.partition for row in stale_surface_rows }
  ∪ { partition(f) for f in changed_keystone_files }
  ∪ { partition(f) for f in changed_manifest_files }
```

Non-touched findings carry forward with `source: baseline` tag.

---

## 6. Sub-Agent Invocation Template

All audit sub-agents share this shape (see `templates/subagent-prompt.md` during implementation):

```
ROLE: Senior appsec engineer. <phase-name> audit for partition <id>.

INPUTS (read from disk):
  - .claude-audit/current/phase-00-profile.json
  - .claude-audit/current/phase-02-surface.json
  - .claude-audit/ignore.txt
  - .claude-audit/baseline.json            (delta mode only)

SCOPE:  <partition_id>  (analyze only files under this prefix)

TASK:   <phase-specific body from steps/step-NN.md>

METHOD:
  1. Load inputs via Read.
  2. For each surface row in scope, verify <phase-specific invariant>.
  3. Write findings as newline-delimited JSON to:
       .claude-audit/current/phase-<NN>-<partition>.jsonl
  4. Write completion marker:
       .claude-audit/current/phase-<NN>-<partition>.done

RETURN SHAPE (stdout, strictly):
  { "phase":"<NN-name>", "partition":"<id>", "surface_checked":<int>,
    "findings_count":<int>, "by_severity":{...},
    "artifact_path":"...", "done_marker":"...",
    "notes":"<=200 chars" }

CONSTRAINTS:
  - Never echo file contents. Write to disk only.
  - Model: claude-opus-4-7 (1M context). No downgrade.
  - If partition >500K raw code tokens, return {"status":"needs_recursion","suggested_split":[...]} so the orchestrator can fan out for reasoning quality.
  - maxTurns budget: 80.
```

---

## 7. Methodology Alignment

- **OWASP ASVS 5.0 Level 2** — primary checklist spine (17 categories).
- **OWASP API Security Top 10 (2023)** — applied mechanically to each surface row.
- **OWASP LLM Top 10 (2025)** — conditional on LLM SDK detection.
- **LINDDUN** — conditional on PII detection.
- **STRIDE** — applied per partition via sub-agent that produces a mitigation table.
- **CWE IDs** — tagged on every finding (mapping in `lib/cwe-map.json`).
- **NIST SSDF** — applied as a repo-metadata-level meta-check in Phase 7 (branch protection, signed commits, SBOM presence, dependabot/renovate config, CODEOWNERS).

---

## 8. Output Formats

| Artifact | Format | Audience |
|---|---|---|
| `docs/security-audit-report.md` | Markdown | Humans (check in to repo) |
| `.claude-audit/current/findings.sarif` | SARIF 2.1.0 | GitHub Security tab, DefectDojo, Jira |
| `.claude-audit/current/findings.cyclonedx.json` | CycloneDX 1.5 | SBOM + VEX workflows |
| `docs/security-audit-baseline.json` | JSON (pruned) | Delta-mode input; checked in |
| `.claude-audit/baseline.json` | JSON (full) | Delta-mode input; gitignored |
| `.claude-audit/history/<ts>/` | Tarball | Archived previous runs |

---

## 9. Implementation Milestones

| # | Milestone | Scope | Estimated effort |
|---|---|---|---|
| **M1** | Discovery + Partitioning scaffolding | Phases 0-1 + `.claude-audit/` blackboard + sub-agent template | 1-2 dev days |
| **M2** | Attack Surface Inventory + Keystone Index | Phases 2-3 + handler-hash logic | 1-2 days |
| **M3** | External Scanner Orchestration | Phase 4, all six scanners, SARIF post-processing | 2-3 days |
| **M4** | Deep Dives (9 categories) | Phase 5, one sub-agent prompt per category + grep-pattern catalog | 3-5 days |
| **M5** | Config + Methodology Spine + Synthesis | Phases 6-7, report templates, SARIF emitter | 2-3 days |
| **M6** | Delta mode + baseline persistence | Phase 8 + `mode: delta` flag + invalidation logic | 2-3 days |
| **M7** | Polish | README updates, NOTICE expansion, CWE map, pattern catalog doc | 1 day |

Total: ~12-19 dev days, spread across several sessions. Each milestone ships independently — user can run a partial v2 after M2 (recon only, no deep-dives yet) to validate the discovery output.

---

## 10. Risks & Open Questions

1. **Scanner install overhead.** Six scanners = six installs. Options:
   - (a) Document as prerequisites; skill fails fast if missing.
   - (b) Skill auto-installs on first run (ubuntu/macOS Homebrew paths).
   - (c) Provide a Podman/Docker image with everything baked in (aligns with existing `claude-worker` pattern).
   *Recommendation: (a) + (c). Document prereqs; provide an optional `cw-audit` container image.*
2. **Huge repos (>200K LOC).** Auto-recursive sub-partitioning — no size rejection. Each level of partitioning runs in parallel; depth is determined by per-partition code volume, not a global cap. Token cost scales linearly with codebase size, paid in service of audit quality.
3. **Handler-hash for semantic change detection.** Simple `sha1(handler body)` is fragile — refactoring that preserves logic invalidates baseline unnecessarily. Options:
   - Content hash (simple, conservative).
   - AST hash (better but needs parser per language).
   *Recommendation: start with content hash; revisit if FP re-audit rate is high.*
4. **CodeQL CLI license.** Free only for OSI-licensed OSS. Detect license heuristically and gate inclusion; default: exclude.
5. **Windows support.** None of the scanner bundle is Windows-native. Document as Linux/macOS only. Users on Windows should run inside WSL or a container.
6. **`/security-review` scope.** It was designed for diffs; running it per-partition is the adapter. If per-partition invocation blows budget on massive services, fall back to sampling.
7. **LLM Top 10 nuance.** Codebase may import Anthropic SDK only for telemetry/internal use, not user-facing LLM features. False-positive of whole category if detection is naive. Add confirmation: detect tool-calling loops, user-input → prompt concatenation before activating LLM category.
8. **Non-English codebases.** Framework detection regex assumes English identifiers. Mention in README as a known limitation.
9. **Git history secret scans on huge repos.** Full-history `gitleaks git` can take minutes on 10k+ commit repos. Make it a Phase 4 sub-agent with its own long timeout; don't block synthesis on it.
10. **Baseline staleness.** If baseline is >90 days old, force a full re-audit. Document in `mode: delta` failure message.

---

## 11. Out of Scope (intentional)

- **Dynamic analysis / DAST.** Tools like ZAP/Nuclei need a running target — different workflow. Mention availability in report; don't integrate.
- **Cloud posture scanning (CSPM).** Prowler/ScoutSuite need cloud credentials — different workflow.
- **Runtime container security.** Falco/Sysdig are runtime tools.
- **Manual business-logic flaws.** The skill can't detect "coupon stacking" or application-specific abuse — flag the *places* to look (Phase 5 category 1 surfaces high-value endpoints) and leave judgment to humans.
- **Pentest-team replacement.** Skill is *preparation* for a pentest, not a substitute.

---

## 12. Decisions Required Before Implementation

1. Confirm scanner bundle (6 primary + conditional set).
2. Confirm ASVS **Level 2** (not L1 or L3).
3. Confirm `.claude-audit/` as the blackboard dir name.
4. Confirm `docs/security-audit-baseline.json` as the checked-in baseline path.
5. Confirm modes set: full / delta / scoped / focused / report-only.
6. Confirm milestone ordering (start with M1 or different ordering?).
7. Confirm handler-hash strategy: content-hash initial, AST later? Or AST from day one for top 3 languages?
8. Confirm CodeQL exclusion (default off, enable only on OSS-licensed repos).
9. Confirm container-image approach for scanner install (optional, not mandatory).

---

## 13. References (selected)

- Claude Code — Skills: https://code.claude.com/docs/en/skills
- Claude Code — Subagents: https://code.claude.com/docs/en/sub-agents
- OWASP ASVS 5.0: https://github.com/OWASP/ASVS
- OWASP API Top 10 2023: https://owasp.org/API-Security/editions/2023/en/
- OWASP LLM Top 10 2025: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- LINDDUN: https://linddun.org/
- osv-scanner: https://github.com/google/osv-scanner
- Semgrep auto ruleset: https://registry.semgrep.dev/ruleset/auto
- Trivy: https://trivy.dev/
- Gitleaks: https://github.com/gitleaks/gitleaks
- Trufflehog: https://github.com/trufflesecurity/trufflehog
- RepoAudit (multi-agent paper): https://arxiv.org/html/2501.18160v1
- LangGraph checkpointing: https://docs.langchain.com/oss/python/langgraph/persistence
- CVE-2024-3094 xz backdoor: https://www.crowdstrike.com/en-us/blog/cve-2024-3094-xz-upstream-supply-chain-attack/
- polyfill.io supply chain: https://www.sonatype.com/blog/polyfill.io-supply-chain-attack-hits-100000-websites-all-you-need-to-know
- OWASP Password Storage Cheat Sheet (2026 work factors): https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

Full research reports will be committed to `docs/research/` during M1.
