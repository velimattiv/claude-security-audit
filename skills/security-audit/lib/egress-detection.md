# Egress-Sink & Credential Detection — anchor catalogue (v2.4)

This file is the **deterministic ground truth** for the Authorized-Egress analysis
(`scripts/validate-egress.py`). It enumerates, per framework, the code shapes that
can **emit a resource's bytes to a caller** (egress sinks) and the shapes that
**mint or consume a credential/claim** (the credential ledger). The extractor in
`validate-egress.py` greps these anchors to produce a *candidate* set; the Phase-2
agent must then **account for every candidate** — classify it a real sink/credential
(with per-branch authz) or `dismissed[]` it with a reason. Any unaccounted candidate
**fails** the run (fail-closed coverage). This closes the "a sink that's never
inventoried is never reconciled" hole.

> Recall, honestly bounded: this catalogue is the *known* egress surface. A clean
> reconciliation means "every candidate this catalogue can see was accounted for and
> gated" — **not** "no unauthorized path exists." CDN-edge egress with no code path,
> and any modality not listed here, are out of mechanical reach and surface as report
> caveats, never silently. Extend this file when a new modality is found.

## Why egress, not just ingress

The Phase-2 surface inventory catalogues **entry points** and infers `auth_required`
per row. A confused-deputy / missing-enforcer bug hides on the **egress** side: the
control exists at one layer (a resolver) while the byte-serving layer re-derives
authority from mere possession of an identifier. So we additionally enumerate *what
emits sensitive bytes* and check **every branch** of every emitter against the served
resource's **strongest intended gate** (computed per resource across all paths).

## Sink kinds (the `kind` enum in `lib/sink-schema.json`)

`file`, `stream`, `db_entity`, `proxy`, `static`, `graphql_field`, `presigned_url`,
`websocket`, `sse`, `template`, `redirect`, `async_job`, `cdn`.

## Egress anchors by modality (regex, language/framework-tagged)

Anchors are intentionally broad (recall over precision); the agent prunes false
candidates into `dismissed[]`. `validate-egress.py` embeds a compiled subset of these.

### Node / Express / Koa / Fastify / Nest / Nuxt / Next
- file / stream:  `\bres\.(sendFile|download)\b`, `\bcreateReadStream\b`,
  `\.pipe\(\s*res\b`, `\bsendStream\b`, `\bstreamFile\b`, `reply\.(sendFile|send)\(`
- auto-serializer: `\bres\.(json|send|end)\(`, `reply\.send\(`, `return\s+.*\b(deck|user|account|order|invoice|file|document|record)\b` (entity-return heuristic)
- static / proxy: `express\.static\(`, `serveStatic\(`, `createProxyMiddleware\(`,
  `http-proxy`, `\bproxy\(`, `sendFile\(`
- template / SSR: `res\.render\(`, `reply\.view\(`, `renderToString\(`
- redirect-with-data: `res\.redirect\([^)]*\?[^)]*(token|key|data|payload)`
- presigned URL: `getSignedUrl\(`, `\.presign(ed)?(Url|Post)?\(`, `createPresignedPost\(`, `generateSignedUrl\(`
- websocket / SSE: `\.(send|emit)\(`, `socket\.emit\(`, `ws\.send\(`,
  `res\.write\(\s*['"]?data:`, `text/event-stream`

### Python / Django / DRF / FastAPI / Flask
- `JsonResponse\(`, `StreamingHttpResponse\(`, `FileResponse\(`, `HttpResponse\(`,
  `send_file\(`, `FileResponse\(`, `return\s+\w+Serializer\(`, `Response\(serializer`,
  `\.render\(`, `RedirectResponse\(`, `StreamingResponse\(`, `return\s+[A-Z]\w+\b` (Pydantic model return)

### Ruby / Rails
- `render\s+json:`, `send_data\b`, `send_file\b`, `render\s+(plain|xml|html):`,
  `redirect_to\b`, `ActionController::Live`, `response\.stream`

### Java / Spring / Kotlin
- `@ResponseBody`, `ResponseBodyAdvice`, `ResponseEntity\.(ok|of)\(`,
  `StreamingResponseBody`, `produces\s*=`, `@GetMapping`.*`return\s+\w+` (entity return),
  `Files\.copy\(`, `InputStreamResource\(`

### Go
- `json\.NewEncoder\(\s*w\s*\)\.Encode\(`, `w\.Write\(`, `io\.Copy\(\s*w`,
  `http\.ServeContent\(`, `http\.ServeFile\(`, `c\.JSON\(`, `c\.File\(`, `c\.Stream\(`

### .NET / ASP.NET
- `return\s+File\(`, `PhysicalFile\(`, `return\s+Ok\(`, `FileStreamResult`,
  `[Pp]roduces`, `Results\.(File|Stream|Json)\(`

### GraphQL (all languages)
- `@ResolveField`, `@FieldResolver`, `resolve\s*[:=]`, `Query\s*:`, `fieldResolver`,
  `buildSchema`, `@Resolver` — every field resolver that returns a sensitive column is a sink.

### gRPC (all languages)
- `stream\.Send\(`, `return\s+&pb\.`, `return\s+\w+Reply\b`, `responseObserver\.onNext\(`

### Async / off-request egress
- `@(KafkaListener|RabbitListener|SqsListener)`, `\.perform_async\b`, `@app\.task`,
  `BullMQ`, `exportToCsv\(`, `generateReport\(`, `\.upload\(.*public`, `putObject\(.*ACL.*public`

### CDN / cache (header-level — no code path; report-caveat class)
- `Cache-Control:\s*public`, `s-maxage`, `CDN`, `CloudFront`, `Surrogate-Control`
  — flagged as `kind: cdn`, `coverage: caveat` (cannot be mechanically gated).

## Credential mint / consume anchors (the ledger, `lib/credential-ledger-schema.json`)

A credential is anything **issued** that later gates access. For each, the extractor
finds WRITE sites (mint) and READ sites (consume); the agent records both. The
asymmetry (writers without consuming readers on the byte path) is the core signal.

- cookies / capability: `set-?[Cc]ookie`, `cookies\.set\(`, `res\.cookie\(`,
  `serialize\(\s*['"]\w+`, `__\w+`, `setHeader\(\s*['"]Set-Cookie` ;
  consume: `cookies\.get\(`, `req\.cookies\b`, `parse\(\s*cookieHeader`
- JWT / session: `sign\(`, `jwt\.sign\(`, `createToken\(`, `req\.session\b`,
  `getServerSession\(`; consume: `verify\(`, `jwt\.verify\(`, `decode\(`
- CSRF: `csrf`, `xsrf`
- signed/presigned URL: `getSignedUrl\(`, `presign`, `hmac`, `createHmac\(`
- api key / PAT: `apiKey`, `personal.?access`, `x-api-key`
- feature flag / licence gate: `isEnabled\(`, `flag\(`, `entitled\(`, `licen[cs]e`

For every minted credential C the agent records `protects_resources[]` (which
resources C is supposed to gate). A credential that protects R raises R's **gate
floor**, so any byte-serving path to R weaker than that floor is flagged as a
deficit; a credential with **zero readers anywhere** is flagged as theatre (R4).

## Ranking & coverage semantics (so the agent writes useful inventories)

- **Gate ranking is negation-aware.** Each branch's `enforced_gate` is ranked
  NONE < AUTHN < AUTHZ < VERIFIED by keyword, but a description of an *absent*
  control ("no role check", "unauthenticated", "missing ownership") ranks **NONE**
  even though it contains positive keywords, and unrecognized text ranks NONE.
  Write what is *actually enforced on the branch* (or "none") — over-describing a
  gap as a gate is the one way to defeat the detector, and the ranker defends
  against it by failing conservative (over-flag, never silently pass).
- **Coverage is line-scoped.** Each candidate `(file, line)` must be matched by a
  sink/credential/dismissal in the same file within ~15 lines. One inventoried
  sink does **not** account for another sink elsewhere in the same file — list
  every emitting site or dismiss it explicitly.
