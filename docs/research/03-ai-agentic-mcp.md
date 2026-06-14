# Research 03 — AI / Agentic / MCP Security (refresh for `/security-audit` v2.0.6)

**Author angle:** AI / Agentic / MCP application-security.
**Research window:** ~2026-01 → 2026-06-14 (skill's last round: 2026-04-24).
**Subject:** Static-audit coverage of LLM, agentic, and MCP threats. The skill today has a single conditional cat-09 "LLM-specific" deep-dive keyed to OWASP LLM Top 10 (2025). Verified gaps: zero coverage of MCP, agentic workflows, model-file deserialization, or RAG/vector poisoning beyond a single LLM08 stub.

## TL;DR

- **OWASP shipped a brand-new "Top 10 for Agentic Applications (2026)", published 2025-12-09**, with risk IDs **ASI01–ASI10** (Goal Hijack → Rogue Agents). This is the single biggest taxonomy change since the skill's last round and is **completely unmapped** in cat-09. The OWASP LLM Top 10 itself is still the **2025** edition (English published 2025-03-12); no newer numbered release exists, so `LLM01:2025…LLM10:2025` tags remain correct.
- **MCP is now a CVE-rich, real-world-exploited surface.** A systemic Anthropic MCP STDIO/SDK design flaw was disclosed **2026-04** (OX Security; "user input → STDIO MCP config" → RCE; 10 CVEs incl. CVE-2026-30623 LiteLLM, CVE-2026-30615 Windsurf; ~7,000 exposed servers). Three Anthropic `mcp-server-git` flaws (**CVE-2025-68143/68144/68145**) chain prompt-injection→RCE (disclosed 2026-01). The skill has **zero** MCP detection.
- **Tool poisoning** (malicious instructions hidden in MCP tool descriptions/metadata) is now the most-cited client-side MCP class; the MCPTox benchmark found most of 20 agents vulnerable across 45 servers. This is a *static, code-readable* surface (tool docstrings/`description` fields) the skill can detect cheaply.
- **Model-file deserialization is a confirmed, under-defended supply-chain vector.** `torch.load()` without `weights_only=True`, `pickle.load`, and `from_pretrained()` on untrusted hubs execute arbitrary code; **CVE-2025-1716** + JFrog/Sonatype 2025 zero-days bypass `picklescan`. ~half of popular HuggingFace repos still ship pickle. cat-09 mentions none of this.
- **Framework CVEs are landing fast:** **CVE-2025-68664 / -68665 (LangChain core, CVSS 9.3 / 8.6, Dec 2025)** — serialization-injection secret exfiltration triggerable *via prompt injection* through `dumps()`/`dumpd()`. Version-pin detection is implementable today via lockfiles.
- **MCP authorization spec hardened** (rev **2025-11-25**, building on 2025-06-18): servers are OAuth Resource Servers; **token pass-through is explicitly forbidden** (confused-deputy); scopes must be tool-level. These are detectable config anti-patterns.
- **Recommendation in one line:** add a **NEW cat-10 "MCP & Agentic"** deep-dive (gated on MCP/agent-framework signals, independent of cat-09's LLM gate), expand cat-09 with model-deserialization + RAG-poisoning detections, add `ASI01:2026…ASI10:2026` to the OWASP tag vocabulary, and add **CWE-1426** to `cwe-map.json`. This is also dogfood-relevant: the repo ships a Claude Code skill (agent tool-permission scopes, sub-agent prompt-injection surface) — currently it defines no MCP servers, but the *audit-target* class includes them.

## What changed since 2026-01

> Confidence legend: **[C]** confirmed against a primary/credible secondary source; **[S]** speculative / single-source / inferred. No CVE IDs are invented — every ID below was returned verbatim by a cited source. Where I could not reach the canonical CVE record (e.g. NVD), treat the ID as "reported, verify before shipping".

### Taxonomy

- **2025-12-09 — OWASP Top 10 for Agentic Applications 2026 released. [C]** Five-document suite: threat taxonomy, architectural threat-modelling (**MAESTRO** framework), developer/operator controls, the ranked **ASI01–ASI10** list, and governance mapping. Introduces **"Least-Agency"** (least-privilege extended to autonomy) and **Strong Observability** as design principles. (genai.owasp.org; NeuralTrust; Teleport.)
  - **ASI01 Agent Goal Hijack** — attacker manipulates objectives/decision pathway (often via indirect prompt injection).
  - **ASI02 Tool Misuse & Exploitation** — legit tool used unsafely (e.g. unsanitised LLM-generated SQL params).
  - **ASI03 Identity & Privilege Abuse** — agent escalates via its own identity or *inherited* tool/service creds.
  - **ASI04 Agentic Supply-Chain** — poisoned models / RAG data / tool definitions / third-party MCP servers.
  - **ASI05 Unexpected Code Execution (RCE)** — agent induced to generate+run malicious code (code-interpreter sink).
  - **ASI06 Memory & Context Poisoning** — persistent corruption of vector stores / knowledge graphs / long-term memory.
  - **ASI07 Insecure Inter-Agent Communication** — interception/forgery/replay across multi-agent channels.
  - **ASI08 Cascading Failures** — one fault → escalating destructive retries.
  - **ASI09 Human-Agent Trust Exploitation** — fabricated justification tricks a human approver.
  - **ASI10 Rogue Agents** — autonomous drift / reward-misalignment with no external attacker.
- **OWASP LLM Top 10 remains the 2025 edition. [C]** English published 2025-03-12; translations through 2025-07-22; no 2026 numbered release. The skill's `LLMxx:2025` tags are still current — **do not bump to ":2026"** for the LLM list (that namespace is the *Agentic* list, ASI). (genai.owasp.org/llm-top-10.)

### MCP vulnerabilities & spec

- **2026-04 — Systemic Anthropic MCP design flaw (OX Security, "Mother of all AI supply chains"). [C]** Root cause: STDIO transport + official SDKs across all languages let **user input flow directly into STDIO MCP configuration** → arbitrary command execution. Blast radius cited: 150M+ downloads, ~7,000 exposed servers, up to ~200K vulnerable instances. **10 CVEs**, e.g. **CVE-2026-30623 (LiteLLM)**, **CVE-2026-30615 (Windsurf)**, **CVE-2026-30617 (Langchain-Chatchat)**. Four exploit families incl. zero-click prompt injection in Cursor/Windsurf. [C for the disclosure; individual CVE records [S] — verify on NVD before quoting severities.]
- **2026-01 — Anthropic `mcp-server-git` (official reference server): three flaws. [C]** **CVE-2025-68143** path traversal in `git_init`; **CVE-2025-68144** argument injection in `git_diff`/`git_checkout`; **CVE-2025-68145** `--repository` flag bypass — chainable to **RCE via prompt injection**. (thehackernews.com 2026-01.)
- **2025 cluster (context for the skill's audit targets). [C]** **CVE-2025-49596** MCP Inspector unauthenticated RCE (proxy accepts arbitrary stdio commands from browser; fixed 0.14.1); **CVE-2025-6514** `mcp-remote` OS command injection; **CVE-2025-53109/53110** Filesystem MCP sandbox escape; **CVE-2025-54136** Cursor; **CVE-2025-54994** `@akoskm/create-mcp-server-stdio`. First **malicious MCP packages** appeared in public registries from ~Sep–Oct 2025 (typosquatting, fake "official" servers, Postmark backdoor; Smithery hosting compromise Oct 2025). (Recorded Future, Oligo, authzed timeline.)
- **MCP authorization spec rev 2025-11-25 (builds on 2025-06-18 changelog). [C]** Servers are OAuth 2.1 **Resource Servers**; PKCE mandatory for public clients; **MUST NOT accept tokens not issued for the server itself**; **MUST NOT pass through the client token** (explicit confused-deputy guard); MUST NOT use sessions for auth; scopes defined **at tool level**. (Den Delimarsky; Auth0; Descope.) These map to detectable config/code anti-patterns.

### Model files / frameworks / RAG

- **Pickle/torch supply chain. [C]** **CVE-2025-1716** — bypasses `picklescan` static analysis; JFrog + Sonatype each disclosed multiple 2025 picklescan zero-days; bit-flipped ZIP headers / non-standard extensions hide payloads that `torch.load()` still executes. Brown University 2025 study: ~half of popular HuggingFace repos still ship pickle models (incl. Meta/Google/MS/NVIDIA). Mitigation: `weights_only=True`, prefer **safetensors**, trusted hubs only. (Sonatype, JFrog, HiddenLayer "Silent Sabotage", HF docs.)
- **LangChain core serialization injection. [C]** **CVE-2025-68664** (CVSS 9.3, Python `langchain-core` < 0.3.81 / < 1.2.5) and **CVE-2025-68665** (CVSS 8.6, `@langchain/core` JS) — `dumps()`/`dumpd()` fail to escape free-form dicts containing an `lc` key; attacker-controlled LLM response fields (`additional_kwargs`, `response_metadata`) become "trusted" LangChain objects on deserialize → env-var/secret exfiltration, **triggerable via prompt injection** in streaming. Disclosed Dec 2025. (Snyk, SoCRadar, thehackernews.) No credible LlamaIndex/vLLM/Haystack RCE CVE surfaced in this window — **[S]: absence of evidence, not evidence of absence; re-check at audit time.**

## Concrete detections

All signals are static (grep/import/file/lockfile). Severity defaults are starting points for sub-agent calibration. CWE IDs verified present in `lib/cwe-map.json` unless flagged ADD.

### 1. MCP server / tool definitions (NEW)
File signals (presence ⇒ this repo *is* an MCP server → run cat-10):
```
# config / manifest
**/mcp.json, **/.mcp.json, **/mcpServers* , claude_desktop_config.json, **/*.mcp.json
# Python imports
^\s*from\s+mcp(\.server)?(\.fastmcp)?\s+import|^\s*import\s+mcp\b|FastMCP\(
# TS/JS imports
@modelcontextprotocol/sdk|new\s+(McpServer|Server)\(|server\.(tool|registerTool)\(
```
Tool registration sites (the audit anchor):
```
@mcp\.tool\(|@(\w+)\.tool\(|\.registerTool\(|server\.tool\(\s*['"]
```

### 2. Tool poisoning / prompt injection via tool metadata (ASI01/ASI02, LLM01)
The tool **description/docstring** is fed to the model verbatim — treat it as an injection sink and as an injection *source* if it interpolates external data:
```
# description built from runtime/external data (poisoning vector)
description\s*[:=]\s*f?["'].*\{.*(env|os\.|fetch|requests\.|input|arg)
# imperative-instruction smells inside tool docstrings (manual review flag)
(ignore (all )?previous|disregard|system:|<important>|do not tell the user)
```
→ tool description w/ interpolated external data: **HIGH** / CWE-94 / ASI02,LLM01. Imperative text in description: **MEDIUM** manual.

### 3. Command/arg injection inside MCP tool handlers (ASI05, the `mcp-server-git` class)
Within a `@*.tool`/`server.tool` handler body, unsanitised arg → shell/path/git:
```
subprocess\.(run|Popen|call)\([^)]*shell\s*=\s*True
os\.system\(|os\.popen\(|exec[lv]p?\(
child_process\.(exec|execSync)\(
# path traversal: handler arg used in a filesystem path without resolve/normalise check
(open|Path|fs\.(readFile|writeFile))\([^)]*\b(path|repo|file|dir)\b   # cross-ref no allow-list
```
→ **CRITICAL** / CWE-78 (shell), CWE-77 (arg), CWE-22 (path) / ASI05.

### 4. Token pass-through / confused deputy (ASI03, MCP auth spec)
```
# forwarding the inbound client token to a downstream service = spec violation
headers\s*[:=].*Authorization.*(req\.headers|request\.headers|incoming.*token|ctx\.token)
# static long-lived secret as the only credential for a tool
(API_KEY|ACCESS_TOKEN|PAT)\s*=\s*os\.(getenv|environ)   # then used directly in tool calls
```
→ token passthrough: **HIGH** / CWE-285 (+ note confused-deputy / ASI03). Static-PAT-only: **MEDIUM** / CWE-522.

### 5. Unsafe MCP transport / config (the 2026-04 systemic class)
```
# user input flowing into stdio server spec (command/args)
StdioServerParameters\(|"command"\s*:\s*.*\{|"args"\s*:\s*\[[^\]]*\$\{
transport\s*=\s*['"]stdio['"]            # combined with externally-sourced command = flag
# server bound to all interfaces / 0.0.0.0 with no auth (Inspector class)
0\.0\.0\.0|host\s*=\s*['"]0\.0\.0\.0['"]
```
→ external-input→stdio-command: **CRITICAL** / CWE-78 / ASI04,ASI05.

### 6. Model-file deserialization (NEW; ASI04, LLM03/04)
```
torch\.load\((?![^)]*weights_only\s*=\s*True)      # missing weights_only=True
pickle\.load\(|pickle\.loads\(|joblib\.load\(|dill\.load\(
from_pretrained\(\s*["'][^"']*/[^"']+["']           # then check: is the repo id user/var-controlled?
revision\s*=\s*None|trust_remote_code\s*=\s*True     # trust_remote_code=True = arbitrary code
\.h5|\.pkl|\.pt|\.bin|\.ckpt loaded from a download/URL
```
→ `torch.load` w/o `weights_only`: **HIGH** / CWE-502 / LLM03. `trust_remote_code=True`: **HIGH** / CWE-94. `pickle.load` on model/untrusted: **CRITICAL** / CWE-502.

### 7. RAG / vector-store & memory poisoning (ASI06, LLM08)
```
# ingestion from user/URL-supplied source without validation
(add_documents|upsert|add_texts|from_documents)\([^)]*\b(url|user|request|uploaded)\b
chromadb|pinecone|weaviate|qdrant|faiss|pgvector      # store present → check tenant scoping
# long-term agent memory written from tool/LLM output unchecked
(memory|conversation_buffer|save_context)\([^)]*(response|tool_result|llm_output)
```
→ unscoped/unvalidated ingestion: **HIGH** / CWE-829,CWE-20 / LLM08,ASI06.

### 8. LLM-output → dangerous sink (existing cat-09, keep + extend with code-interpreter / ASI05)
Already covered for `eval/exec/SQL/innerHTML`. **Add** agent code-interpreter sinks:
```
PythonREPLTool|PythonAstREPLTool|exec_python|code_interpreter|e2b|sandbox\.run
```
→ **CRITICAL** / CWE-94 / ASI05,LLM05. Recommend tagging generative-output-validation gaps **CWE-1426** (ADD to map).

### 9. Framework version pins (lockfile/manifest scan)
```
langchain-core <0.3.81 or <1.2.5  ; @langchain/core (vuln range)  → CVE-2025-68664/68665
@modelcontextprotocol/inspector <0.14.1                            → CVE-2025-49596
mcp-remote (vuln range)                                            → CVE-2025-6514
```
Implement as a small known-vuln map consulted against `requirements*.txt` / `package-lock.json` / `pnpm-lock.yaml` / `poetry.lock`. → severity per CVE / CWE-1035 (vuln 3rd-party component).

## Mapping to the skill

Two complementary moves; do **both**.

1. **NEW deep-dive category `cat-10-mcp-agentic.md`** (category id **`mcp_agentic`**; suggested `properties.category` value **`agentic`**).
   - **Why separate from cat-09:** cat-09's gate is `llm_usage.detected && kind != "internal"` (a *user-facing LLM feature*). MCP servers and agent frameworks are a **different surface** — an MCP server may expose tools with *no* user-facing chat at all, so it would be wrongly skipped by the cat-09 gate. A repo can also be an MCP server while using zero LLM SDK itself.
   - **New gate:** run if `profile.mcp_agentic.detected == true`, where Phase 0 sets this from §-1/§-2 file+import signals (mcp.json / `from mcp` / `@modelcontextprotocol/sdk` / `@*.tool` / agent frameworks: langgraph, crewai, autogen, llama-index agents). Independent of `llm_usage.kind`.
   - **Covers:** ASI01–ASI10, tool poisoning, command/arg/path injection in tool handlers, token passthrough/confused-deputy, unsafe stdio config, inter-agent comms, memory poisoning.
   - **Phase-0 plumbing:** add an `mcp_agentic` object to `profile-schema.json` mirroring `llm_usage` (`detected`, `frameworks[]`, `is_server` bool, `evidence[]`); add detection prose to `phase-00-discovery.md §0.11`/new §0.13; add the row to the §5.1 category table in `phase-05-deepdives.md` with gate `profile.mcp_agentic.detected == true`.

2. **Expand existing `cat-09-llm.md`** (keep id `llm`) with the model-deserialization (§6), RAG/memory-poisoning hardening (§7), code-interpreter sink (§8), and supply-chain framework-pin (§9) detections — these belong with LLM03/04/05/08 and apply even when no MCP/agent surface exists.

3. **OWASP tag vocabulary (`phase-05-deepdives.md §5.4`):** add **`ASI01:2026 … ASI10:2026`** (Agentic Applications 2026) alongside the existing `LLMxx:2025`. Keep LLM tags at `:2025` (no newer edition). Document the cat→ASI crosswalk inside cat-10.

4. **`lib/cwe-map.json`:** **ADD `CWE-1426`** (Improper Validation of Generative AI Output) — currently missing; it is the natural CWE for output-validation/agentic-output gaps. All other CWEs the new detections need (502, 94, 77, 78, 22, 285, 522, 829, 20, 770, 918, 1035) are already present.

5. **Dogfood:** this repo ships a Claude Code skill and spawns sub-agents (Agent tool) with tool scopes. It currently defines **no** MCP servers and no `settings.json` permission allowlist (verified). The new cat-10 should explicitly enumerate *Claude Code skill/agent* surfaces as audit targets: `.mcp.json`/`mcpServers`, `.claude/settings*.json` permission scopes, and sub-agent prompt templates that interpolate untrusted repo content (prompt-injection-into-subagent). This makes the skill self-auditable.

## Prioritized recommendations

| ID | Rec | Effort | Rationale |
|----|-----|--------|-----------|
| **P0** | Add **cat-10 `mcp_agentic`** deep-dive + Phase-0 `mcp_agentic` detection + schema field + §5.1 row | **M** | The dominant net-new attack surface (real CVEs, live exploitation, 0% current coverage). Independent gate is required — bolting onto cat-09 mis-gates pure MCP servers. |
| **P0** | Add **model-file deserialization** detections (`torch.load` w/o `weights_only`, `pickle.load`, `trust_remote_code=True`) to cat-09 | **S** | Confirmed RCE supply-chain class (CVE-2025-1716, picklescan bypasses); a handful of high-signal greps; very low FP. |
| **P0** | Add **`ASI01:2026…ASI10:2026`** to OWASP tag list (§5.4) and crosswalk in cat-10 | **S** | Pure-doc change; makes findings traceable to the new standard reviewers will expect. |
| **P1** | Add **framework known-vuln version map** (LangChain 68664/68665, MCP Inspector 49596, mcp-remote 6514) scanned against lockfiles | **M** | Deterministic, high-value, exploitable-via-prompt-injection CVEs; complements (doesn't duplicate) the SARIF scanner bundle. Verify each CVE/range on NVD before pinning. |
| **P1** | Add **`CWE-1426`** to `cwe-map.json` | **S** | One-line map entry; unblocks correct tagging of generative-output-validation findings. |
| **P1** | Add **RAG/memory-poisoning + code-interpreter-sink** detections to cat-09 (ASI06, ASI05) | **S** | Extends existing LLM08 stub from "tenant scoping" to ingestion-source validation + agent-memory writes. |
| **P2** | **Dogfood pass:** enumerate Claude Code skill/agent surfaces (`.mcp.json`, `.claude/settings*.json` scopes, sub-agent prompt interpolation) as first-class cat-10 targets | **M** | Self-auditability + marketing story; modest because detections from cat-10 mostly already apply. |
| **P2** | Add **token-passthrough / confused-deputy** + **unsafe-stdio-config** detections (ASI03/ASI04) to cat-10 | **M** | Maps to hardened MCP auth spec (2025-11-25) and the 2026-04 systemic class; some FP tuning needed on header forwarding. |

**Sequencing note:** P0 cat-10 + model-deser + ASI tags is one coherent PR (the "agentic refresh"). Framework-pin map (P1) is independent and parallelizable. Dogfood (P2) should land after cat-10 so it reuses the same detections.

## Sources

- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ — confirms Agentic Applications 2026 exists, **released 2025-12-09**, five-doc suite, download entry point.
- https://neuraltrust.ai/blog/owasp-top-10-for-agentic-applications-2026 — full **ASI01–ASI10** names + per-risk examples (goal hijack, tool misuse, memory poisoning, rogue agents).
- https://goteleport.com/blog/owasp-top-10-agentic-applications/ — MAESTRO, Least-Agency, Strong Observability principles.
- https://genai.owasp.org/initiatives/agentic-security-initiative/ — Agentic Security Initiative scope (taxonomy, controls, governance).
- https://genai.owasp.org/llm-top-10/ — full **LLM01:2025–LLM10:2025** names; confirms **no edition newer than 2025** (English 2025-03-12).
- https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf — canonical LLM 2025 PDF (for exact wording when expanding cat-09).
- https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/ — **2026-04** systemic Anthropic MCP STDIO/SDK flaw; scope (~7,000 servers); 10 CVEs incl. CVE-2026-30623, -30615, -30617.
- https://thehackernews.com/2026/01/three-flaws-in-anthropic-mcp-git-server.html — **CVE-2025-68143/68144/68145** `mcp-server-git`, prompt-injection→RCE chain.
- https://www.recordedfuture.com/blog/anthropic-mcp-inspector-cve-2025-49596 — **CVE-2025-49596** MCP Inspector unauthenticated RCE (stdio proxy, fix 0.14.1); related CVE-2025-54994, CVE-2025-54136.
- https://authzed.com/blog/timeline-mcp-breaches — chronology incl. **CVE-2025-6514** (mcp-remote cmd-injection), **CVE-2025-53109/53110** (Filesystem MCP), first malicious MCP packages (Sep–Oct 2025).
- https://www.practical-devsecops.com/mcp-security-vulnerabilities/ — MCPTox benchmark (20 agents / 45 servers mostly vulnerable); tool-poisoning as top client-side class.
- https://den.dev/blog/mcp-november-authorization-spec/ — MCP authz spec **2025-11-25**: Resource Server model, no token passthrough, tool-level scopes, PKCE.
- https://www.descope.com/blog/post/mcp-server-security-best-practices — over-scoped tools, static-PAT, missing-auth (≈2,000 servers exposed), don't-trust-the-model anti-patterns.
- https://www.descope.com/blog/post/mcp-auth-spec / https://auth0.com/blog/mcp-specs-update-all-about-auth/ — 2025-06-18 authz changelog, Resource Indicators, confused-deputy guard.
- https://github.com/modelcontextprotocol/python-sdk — canonical `FastMCP` / `@mcp.tool()` patterns (detection anchors).
- https://www.sonatype.com/blog/bypassing-picklescan-sonatype-discovers-four-vulnerabilities + https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/ — **CVE-2025-1716** + picklescan bypasses (model-deser detection rationale).
- https://www.hiddenlayer.com/research/silent-sabotage — safetensors-conversion hijack on HuggingFace (supply-chain).
- https://huggingface.co/docs/hub/en/security-pickle — HF guidance: `weights_only=True`, prefer safetensors, trusted sources (mitigation wording).
- https://arxiv.org/html/2508.19774v1 — stealthy pickle-based model supply-chain poisoning (depth on bypass techniques).
- https://security.snyk.io/vuln/SNYK-PYTHON-LANGCHAINCORE-14560681 + https://thehackernews.com/2025/12/critical-langchain-core-vulnerability.html — **CVE-2025-68664** (CVSS 9.3) / **CVE-2025-68665** (8.6); `dumps()/dumpd()` `lc`-key injection, prompt-injection-triggerable secret exfil; fix versions 0.3.81 / 1.2.5.
- https://arxiv.org/abs/2603.22489 — MCP threat modelling: prompt injection with tool poisoning (academic grounding).
- https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf — NSA MCP security guidance (authoritative control set for cat-10 controls).
