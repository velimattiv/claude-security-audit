# Deep Dive #9 — LLM-Specific (OWASP LLM Top 10 2025)

**Category.** `llm`.

**Gate.** Only run if `profile.llm_usage.detected == true` AND
`profile.llm_usage.kind != "internal"`. An "internal" detection means the
SDK is imported only for dev tooling / telemetry; no user-facing LLM
surface to audit. Skip with a note in that case.

**OWASP tags.**
- LLM Top 10 (2025): LLM01 (Prompt Injection), LLM02 (Sensitive Info
  Disclosure), LLM03 (Supply Chain), LLM04 (Data & Model Poisoning),
  LLM05 (Improper Output Handling), LLM06 (Excessive Agency), LLM07
  (System Prompt Leakage), LLM08 (Vector / Embedding Weaknesses), LLM09
  (Misinformation), LLM10 (Unbounded Consumption).

**Baseline CWEs:** 20, 94, 200, 400, 502, 770, 918, 1059.

---

## Invariants

1. User-controlled input is never concatenated directly into a system
   prompt or role-prompt.
2. LLM output is not executed (`eval`, `exec`, `Function()`), injected
   into SQL, rendered as HTML without sanitization, passed to
   `dangerouslySetInnerHTML`, or written to shell commands.
3. Tool / function-calling endpoints have scoped permissions — not
   "the LLM can call any HTTP API" or "the LLM has shell access".
4. PII / secrets are not included in prompts by default (scrub before
   sending).
5. System prompt is not returned in any user-visible response — no
   echo of the prompt, no leaking through error messages.
6. Vector store ingestion validates source (no arbitrary document
   ingestion from user-provided URLs without scan).
7. Token / cost caps enforced per request AND per user AND per tenant.
8. Retry / error handling doesn't leak model behavior (e.g., returning
   raw 401 from the vendor API).
9. Rate limiting on generation endpoints.

## Detection patterns

### User input in system prompt (Prompt Injection — LLM01)

```
# JS/TS (Anthropic SDK)
messages\s*:\s*\[\s*\{\s*role\s*:\s*['"]system['"]\s*,\s*content\s*:\s*[^}]*\$\{.*req\.
system\s*:\s*[^,]*\$\{.*req\.
system_prompt\s*=\s*f"[^"]*\{user.*\}

# Python (OpenAI / Anthropic)
messages\s*=\s*\[\s*\{\s*"role"\s*:\s*"system"\s*,\s*"content"\s*:\s*f".*\{user_input
system\s*=\s*f".*\{request\.\w+
```

→ **HIGH** / CWE-94 / LLM01.

### Improper Output Handling (LLM05)

LLM output piped to dangerous sinks:
```
# JS
eval\s*\(\s*response\.(content|text|message)
new\s+Function\s*\(.*response
innerHTML\s*=\s*response
dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*response
execSync\s*\(\s*response

# Python
exec\s*\(\s*response
eval\s*\(\s*response
subprocess\.(run|check_output)\s*\(\s*response
```

→ **CRITICAL** / CWE-94 / LLM05.

LLM output used as SQL:
```
cursor\.execute\s*\(\s*response
db\.query\s*\(\s*response
sequelize\.query\s*\(\s*response
```

→ **CRITICAL** / CWE-89 / LLM05.

### Excessive Agency (LLM06)

Tool registrations with unscoped permissions:

```
# Anthropic tool use / function calling
tools\s*:\s*\[\s*\{\s*name\s*:\s*['"]execute_shell['"]
tools\s*:\s*\[\s*\{[^}]*fetch_url[^}]*\}
tools\s*:\s*\[\s*\{[^}]*delete_any[^}]*\}
```

Any tool that allows arbitrary HTTP / shell / database access without
scope → **HIGH** / LLM06.

### System Prompt Leakage (LLM07)

```
# Response includes prompt in debug mode
JSON\.stringify\s*\(\s*\{[^}]*prompt
return\s*\{[^}]*system_prompt

# Error handlers that echo the upstream error
\.catch\s*\(\s*err\s*=>\s*res\.send\s*\(\s*err\.response
raise HTTPException.*detail=str\(e\)     # if e is a vendor API error
```

→ **MEDIUM** / CWE-200 / LLM07.

### Unbounded Consumption (LLM10)

- No `max_tokens` / `max_completion_tokens` on the API call.
- No per-user request quota.
- Streaming responses without a hard cut-off.

```
\.messages\.create\s*\(\s*\{(?![^)]*max_tokens)
openai\.Completion\.create\s*\(\s*[^)]*(?!max_tokens)
```

→ **MEDIUM** / CWE-770 / LLM10.

### Sensitive Info in Prompts (LLM02)

```
messages\s*:\s*\[.*user\.email.*\]        # PII in prompt
system\s*:\s*.*\{apiKey
system\s*:\s*.*\{secret
```

Check: is the prompt loaded from a config / secrets store and sent as
the request body? If yes, the LLM vendor can log it. → **MEDIUM** /
CWE-200 / LLM02.

### Vector / Embedding Weaknesses (LLM08)

If the codebase uses a vector store (`chromadb`, `pinecone`,
`weaviate`, `qdrant`, `faiss`):
- Does ingestion validate the source URL / domain?
- Are embeddings scoped per-tenant?
- Can a user query retrieve another tenant's embeddings?

Missing scoping → **HIGH** / LLM08 / CWE-284.

### SSRF via LLM (combining cat-08 + LLM06)

If a tool/function allows the LLM to fetch arbitrary URLs based on user
intent, the SSRF defenses from cat-08 apply. Specifically flag tools
that do `fetch(model_chose_url)` without the private-range / IMDS
blocklist. → **HIGH** / CWE-918 / LLM06.

## False-positive notes

- **Internal-only LLM usage** — tooling that summarizes logs or
  generates commits. If no user-facing surface exists, Phase 0 should
  have gated this category off.
- **Read-only tools** — tools that only query public data with narrow
  scope may be fine to skip max_tokens; note but don't flag HIGH.
- **Streaming endpoints that have timeout-based cutoffs** — the
  `max_tokens` check may miss these; verify the actual cutoff before
  flagging.

## Output

`phase-05-llm-<partition>.jsonl`.
