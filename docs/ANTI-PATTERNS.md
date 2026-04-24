# Anti-Patterns Catalog — Index

**This file is an index, not a source of truth.** Each deep-dive
category's full invariants, grep patterns, severity guidance, and
false-positive notes live in its respective
`skills/security-audit/steps/deepdive/cat-NN-*.md`. Editing patterns
here without editing the canonical file will not affect the skill's
behavior — and vice versa.

The index exists because `docs/V2-SCOPE.md` and several phase files
reference "§N of `docs/ANTI-PATTERNS.md`"; this file gives those
references a stable target and a one-line summary per category. For
the actual patterns, always consult the linked category file.

## §1 Auth & Authz
Canonical: [`cat-01-auth-authz.md`](../skills/security-audit/steps/deepdive/cat-01-auth-authz.md). Verifies every write handler has auth, JWT algorithms pinned, session regeneration on login, OAuth state, rate limiting on sensitive endpoints, mass-assignment prevention. Baseline CWEs: 284/285/287/288/306/307/352/384/521/613/640/862/863/915.

## §2 IDOR / BOLA
Canonical: [`cat-02-idor-bola.md`](../skills/security-audit/steps/deepdive/cat-02-idor-bola.md). Verifies every parameterized route scopes queries by the authenticated user / tenant, nested resource access verifies parent ownership, bulk endpoints verify each id, search/list results filter by caller. Baseline CWEs: 284, 285, 639, 862, 915.

## §3 Token / API Key Scope
Canonical: [`cat-03-token-scope.md`](../skills/security-audit/steps/deepdive/cat-03-token-scope.md). Verifies every PAT has an explicit scope list, creation can't grant broader than issuer, use-time scope check, no tokens in URL query strings, no wildcard defaults. Baseline CWEs: 285, 287, 522, 538, 598, 798, 863.

## §4 MITM / Transport
Canonical: [`cat-04-mitm.md`](../skills/security-audit/steps/deepdive/cat-04-mitm.md). Detects disabled TLS certificate verification across 8 languages, TLS <1.2 references, plaintext `ws://` or gRPC insecure clients, missing mobile pinning. Baseline CWEs: 295, 297, 319, 923.

## §5 Cryptography
Canonical: [`cat-05-crypto.md`](../skills/security-audit/steps/deepdive/cat-05-crypto.md). MD5/SHA1 for security, ECB / raw CBC, static IV, weak PRNG for tokens, password-hash work factors below 2026 OWASP baselines, hardcoded keys, non-constant-time comparison. Baseline CWEs: 208, 311, 321, 326, 327, 328, 329, 330, 331, 338, 522, 916.

## §6 Secret Sprawl
Canonical: [`cat-06-secret-sprawl.md`](../skills/security-audit/steps/deepdive/cat-06-secret-sprawl.md). Tracked secret files, Dockerfile ENV secrets, k8s ConfigMap leaks, Terraform tfvars, CI plaintext secrets, secrets in logs / error responses. Cross-references Phase 4's gitleaks + trufflehog output. Baseline CWEs: 200, 522, 532, 538, 798.

## §7 Deployment Posture
Canonical: [`cat-07-deployment.md`](../skills/security-audit/steps/deepdive/cat-07-deployment.md). Dockerfile `USER root` / `:latest` / debug ports, Kubernetes `privileged` / `hostNetwork` / RBAC wildcards, Terraform 0.0.0.0/0 ingress / public buckets / IAM `*`, GitHub Actions `pull_request_target` + PR head checkout, unpinned actions. Baseline CWEs: 276, 284, 732, 749, 829, 1035.

## §8 Injection / SSRF / Deserialization
Canonical: [`cat-08-injection-ssrf.md`](../skills/security-audit/steps/deepdive/cat-08-injection-ssrf.md). SQLi via string concat across 7 languages, NoSQLi, command injection, XXE, SSTI, SSRF with no IP allowlist, unsafe deserialization (pickle / yaml.load / unserialize / BinaryFormatter / Marshal.load), file upload without validation, open redirect. Baseline CWEs: 20, 22, 77, 78, 79, 89, 91, 94, 434, 502, 601, 611, 918, 943.

## §9 LLM-Specific (OWASP LLM Top 10 2025)
Canonical: [`cat-09-llm.md`](../skills/security-audit/steps/deepdive/cat-09-llm.md). User input in system prompt (LLM01), LLM output to eval/SQL/HTML (LLM05), tool-calling with unscoped permissions (LLM06), system prompt leakage (LLM07), missing max_tokens/cost caps (LLM10), PII in prompts (LLM02), unscoped vector stores (LLM08). Baseline CWEs: 20, 94, 200, 400, 502, 770, 918, 1059.

---

## Polyglot coverage evidence

Language-specific regex catalogs live inside each canonical `cat-*.md`
file. v2.0.1 validated:

- **Go** — cat-04 MITM patterns fire on gosec; see `docs/test-runs/polyglot-go-*.md`.
- **PHP** — cat-08 injection patterns fire on DVWA (and do NOT fire on DVWA's `impossible.php` safe variants); see `docs/test-runs/polyglot-php-*.md`.
- **TypeScript/JavaScript** — cat-01 and cat-08 exercised on OWASP Juice Shop; see `docs/test-runs/m4-*.md`.

CI (`scripts/validate-patterns.py`) compile-checks every regex in
`cat-*.md` on push + PR — catches pattern drift before it ships even
without a full sub-agent run.
