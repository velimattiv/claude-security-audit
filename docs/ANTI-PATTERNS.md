# Anti-Patterns Catalog

Consolidated index of vulnerability patterns the skill detects, organized by
deep-dive category. This file is referenced from `steps/deepdive/cat-*.md`
("§N of `docs/ANTI-PATTERNS.md`"). Each `§` below summarizes the invariants
and grep catalogs that live in full detail in the corresponding category
file; this doc is the stable cross-reference target.

## §1 Auth & Authz — see `steps/deepdive/cat-01-auth-authz.md`

- Missing auth on write handlers (invariant #1)
- Missing session regeneration on login (CWE-384)
- JWT algorithm not pinned; `alg: none` accepted (CWE-327, CWE-287)
- Mass assignment (CWE-915)
- OAuth state / nonce missing (CWE-352)
- Rate limiting missing on sensitive endpoints (CWE-307)
- Admin role checks via `includes()` / partial match (CWE-863)

## §2 IDOR / BOLA — see `steps/deepdive/cat-02-idor-bola.md`

- Query without ownership filter (CWE-639)
- Ownership check after fetch — 403/404 timing leak (CWE-209)
- Nested resource access without parent-ownership verification (CWE-639)
- Bulk endpoints without per-id ownership check (CWE-639)
- Search / list endpoints without user scope (CWE-284)
- Mass-assignment / BOPLA (CWE-915)
- Predictable IDs with authenticated enumeration (CWE-200)

## §3 Token / API Key Scope — see `steps/deepdive/cat-03-token-scope.md`

- No scope check on endpoint (CWE-285)
- Wildcard default scope (CWE-732)
- Scope inheritance — creation doesn't limit to issuer's scope (CWE-285)
- Scope check uses `includes` / partial match (CWE-863)
- Token in URL query string (CWE-598)
- No expiry / never-expires tokens (CWE-613)
- No revocation path (CWE-613)
- Admin scope bypass (CWE-863)
- Token leakage in logs / responses (CWE-532)

## §4 MITM / Transport — see `steps/deepdive/cat-04-mitm.md`

- Disabled certificate verification across 8 languages:
  - Node: `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`
  - Python: `verify=False`, `ssl._create_unverified_context`
  - Go: `InsecureSkipVerify: true`
  - Java/Kotlin: `AllowAllHostnameVerifier`, `HostnameVerifier { return true }`
  - PHP: `CURLOPT_SSL_VERIFYPEER => false`
  - .NET: `ServerCertificateValidationCallback = (...) => true`
  - Ruby: `OpenSSL::SSL::VERIFY_NONE`
  - Rust: `danger_accept_invalid_certs(true)`
- TLS <1.2 explicit reference (CWE-327)
- Outbound `ws://` or gRPC `grpc.insecure()` (CWE-319)
- Missing mobile certificate pinning (CWE-295)
- SSH `InsecureIgnoreHostKey()` (extended Go pattern)

## §5 Cryptography — see `steps/deepdive/cat-05-crypto.md`

- MD5 / SHA1 for security operations (CWE-327, CWE-328)
- ECB mode or raw CBC without MAC (CWE-327)
- Static IV / nonce reuse (CWE-329)
- Weak PRNG (`Math.random`, `rand.Intn`) for security (CWE-338)
- Password hashing work factor below 2026 OWASP baselines:
  - bcrypt cost < 12 (CWE-916)
  - PBKDF2 < 600k iterations
  - scrypt N < 131072
  - Argon2id memory < 19 MiB
- Hardcoded keys / salts (CWE-321, CWE-798)
- UUIDv1 (time+MAC) used for session / token IDs (CWE-330)
- Non-constant-time comparison of passwords / HMACs (CWE-208)

## §6 Secret Sprawl — see `steps/deepdive/cat-06-secret-sprawl.md`

- Tracked secret files: `.env*`, `*.pem`, `*.key`, `id_rsa*`, `credentials.json`
  (CWE-538)
- Vendor-specific token regexes (AWS, GCP, Azure, GitHub, Slack, Stripe,
  Twilio, SendGrid) cross-referenced with Phase 4 scanners (CWE-798)
- Dockerfile `ENV` secrets (CWE-538)
- Kubernetes `ConfigMap` secret leak (CWE-538)
- Terraform `.tfvars` / `.tfstate` with real values tracked (CWE-538)
- CI plaintext secrets in workflow YAML (CWE-798)
- Secrets in logs (CWE-532)
- Secrets in error responses (CWE-209)

## §7 Deployment Posture — see `steps/deepdive/cat-07-deployment.md`

- Dockerfile: no `USER` drop from root (CWE-276), `:latest` base,
  `EXPOSE` of debug ports (6060/9229/5005), `curl | sh` installs (CWE-829)
- Kubernetes: `privileged: true`, `hostNetwork: true`, RBAC `*:*`,
  `allowPrivilegeEscalation: true` (CWE-732)
- Terraform: `0.0.0.0/0` SG ingress, public buckets, unencrypted storage,
  IAM `Action: *` / `Resource: *` (CWE-284)
- GitHub Actions: `pull_request_target` + PR head checkout (CWE-829,
  CRITICAL), unpinned `@v1` actions (CWE-829, MEDIUM), missing
  `permissions:` block (CWE-1035)
- NPM `postinstall` / `preinstall` supply-chain exposure (CWE-829)
- `.dockerignore` missing or incomplete (CWE-200)

## §8 Injection / SSRF / Deserialization — see `steps/deepdive/cat-08-injection-ssrf.md`

- SQL injection via string concatenation across 7 languages (CWE-89)
- NoSQL injection (Mongo `$where`, `$regex`) (CWE-943)
- Command injection (`shell: true`, `exec`, `system`, backticks) (CWE-77,
  CWE-78)
- XXE in XML parsers without `setFeature(..external-dtd, false)` (CWE-611)
- SSTI (user input into template constructor) (CWE-94)
- SSRF: user-URL to HTTP client without IP allowlist / IMDS block
  (CWE-918)
- Unsafe deserialization: `pickle.loads`, `yaml.load`, PHP `unserialize`
  without `allowed_classes`, `BinaryFormatter.Deserialize`, `Marshal.load`
  (CWE-502)
- File upload without MIME/ext/magic validation (CWE-434)
- Open redirect (CWE-601)

## §9 LLM-Specific — see `steps/deepdive/cat-09-llm.md`

- User input concatenated into system prompt (LLM01, CWE-94)
- LLM output to `eval`, SQL, `dangerouslySetInnerHTML` (LLM05, CWE-94/89)
- Tool/function calling with unscoped permissions (LLM06)
- System prompt leakage in responses / error messages (LLM07, CWE-200)
- Missing `max_tokens` / per-user cost caps (LLM10, CWE-770)
- PII / secrets in prompts sent to vendor (LLM02, CWE-200)
- Vector store without per-tenant scoping (LLM08, CWE-284)
- SSRF via LLM tool calls (LLM06 + CWE-918)

---

## Polyglot coverage

The §§ above describe what's detected regardless of language. Language-
specific regex catalogs live inline in each `cat-*.md` file. The v2.0.1
remediation run validated Go (cat-04 on gosec) and PHP (cat-08 on DVWA)
polyglot patterns end-to-end; see `docs/test-runs/polyglot-*.md`.
