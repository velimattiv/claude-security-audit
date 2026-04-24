# Deep Dive #6 — Secret Sprawl

**Category.** `secret_sprawl`.

**OWASP tags.**
- ASVS: V2.10 (Service Authentication — credentials in config), V14.5
  (Validation of Config).
- API Top 10: `API8:2023`.

**Baseline CWEs:** 200, 522, 532, 538, 798.

---

## Invariants

1. No secrets tracked in git — `.env*` files, `*.pem`, `*.key`, `*.pfx`,
   `id_rsa*`, `*_rsa`, `credentials.json`.
2. No secrets hardcoded in source (cross-ref cat-05 §"Hardcoded keys").
3. No secrets in Dockerfile `ENV` directives that survive to runtime.
4. Kubernetes `ConfigMap` does not contain secret-like values (belongs
   in `Secret`).
5. Terraform state / `.tfvars` with real values not checked in.
6. CI environment-variable dumps (`env`, `printenv`) not executed by
   default in workflows.
7. Logs don't emit token / password / API-key strings.

## Detection sweeps

### Tracked secret files (git ls-files check)

```
\.env(\..+)?$         # .env, .env.local, .env.production, .env.staging
^id_rsa(\..+)?$       # SSH keys
^id_dsa(\..+)?$
^id_ed25519(\..+)?$
.*\.pem$
.*\.key$
.*\.pfx$
.*\.p12$
credentials\.json
service-account\.json
gcp-.*\.json
aws-credentials
\.npmrc(-.+)?$        # may contain auth tokens
```

For each match, verify it's actually tracked (not just in the working
tree). Flag → **CRITICAL** (for keys/.env with actual content) /
**HIGH** (for .env.example) / CWE-538.

### Vendor-specific token regexes (supplement Phase 4 scanners)

Cross-reference gitleaks and trufflehog output. For each finding in
`phase-04-scanners/gitleaks.slim.json` AND `trufflehog.slim.json`,
create a `secret_sprawl` finding with:
- `confidence: CONFIRMED` (scanner-backed)
- `cwe: "CWE-798"`
- `sources`: `[{kind: "scanner", detail: <scanner>:<ruleId>}]`

If a given file has multiple scanner hits for the same line, merge.

### Dockerfile ENV secrets

Grep Dockerfiles for:
```
^ENV\s+(?:.*_KEY|.*_SECRET|.*_TOKEN|.*_PASSWORD|API_KEY|JWT_SECRET)\s*=?\s*["']?[A-Za-z0-9_\-]{8,}
```

→ **HIGH** / CWE-538. Suggest: use build-time secrets (`RUN --mount=type=secret`)
or runtime env injection from orchestrator.

### Kubernetes ConfigMap leak

For each `kind: ConfigMap` manifest, check data keys for names matching
secret patterns. Flag → **HIGH** / CWE-538 (should use `Secret`).

### Terraform / IaC

Grep `.tfvars` files for tokens / keys / passwords. If tracked, flag
→ **CRITICAL**.

State files (`.tfstate`, `.tfstate.backup`) tracked in git → **CRITICAL**
/ CWE-538.

### CI plaintext secrets

grep `.github/workflows/*.yml`, `.gitlab-ci.yml`, `.circleci/config.yml`
for literal-looking secrets (pattern: assignment of 20+ char string that
isn't a `${{ secrets.X }}` reference).

→ **HIGH** / CWE-798.

zizmor already catches most GHA issues if installed — cross-ref its SARIF.

### Secrets in logs

Pattern (per language):
```
console\.(log|error|info|debug)\s*\([^)]*(?:token|secret|key|password|credential)[^)]*\)
logger\.(info|warn|error)\s*\(.*(?:token|secret|key|password)
log\.(debug|info)\s*\(.*(?:token|secret|api_key)
printf\b.*(?:token|password)
```

→ **HIGH** / CWE-532.

### Secrets in error responses

grep for:
```
res\.json\s*\(\s*\{[^}]*(?:token|apiKey|secret)
throw new Error\s*\(\s*.*(?:token|apiKey).*\)
raise .*(?:token|secret).*
```

Include token / apikey / secret in error message text → **MEDIUM** /
CWE-209.

## False-positive notes

- **.env.example / .env.sample** often contains placeholder values. If
  every value is literally `your-api-key-here` / `replace-me`, INFO only.
- **Test fixtures** with `test_token_xyz` → LOW (still risky because
  sometimes copy-pasted into prod config, but not a direct exposure).
- **Public JWT in OIDC discovery documents** (`jwks.json`) is intended
  to be public — not a finding.
- **Logging a hashed secret** (e.g., sha256 of a token for correlation)
  is fine.

## Output

`phase-05-secret_sprawl-<partition>.jsonl`.
