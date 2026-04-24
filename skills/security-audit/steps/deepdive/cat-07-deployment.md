# Deep Dive #7 — Deployment Posture

**Category.** `deployment`.

**OWASP tags.**
- ASVS: V14 (Configuration), V10 (Malicious Code), V12 (Files &
  Resources).
- API Top 10: `API8:2023`.

**Baseline CWEs:** 276, 284, 732, 749, 829, 1035.

---

## Invariants

1. Dockerfiles drop root (`USER <nonroot>` near the end).
2. Base images are pinned to a specific tag (`image:1.2.3`) — no `:latest`.
3. `HEALTHCHECK` directive present.
4. No debug ports (`6060`, `9229`, `5005`) exposed in production images.
5. `.dockerignore` excludes `.git`, `.env*`, test fixtures.
6. Kubernetes: no `privileged: true`; no `hostNetwork: true`; no RBAC
   rules with `*` verb + `*` resource; pod securityContext drops capabilities.
7. Terraform: no `0.0.0.0/0` SG ingress on non-public services;
   S3/GCS/ABS buckets not public unless intentional; all storage
   encrypted-at-rest; IAM roles use least-privilege (no `*` actions).
8. GitHub Actions: no `pull_request_target` + checkout of PR head (RCE
   classic); actions pinned to SHA; `permissions:` block set; secrets
   not passed to fork runs.
9. NPM `postinstall` scripts reviewed for supply-chain exposure.

## Detection patterns

### Dockerfile

Cross-ref Phase 4 `hadolint.sarif` — most of these land there. Augment
with:

```
FROM .+:latest
USER\s+root                              (after midway)
EXPOSE\s+(6060|9229|5005|5858)
^RUN\s+.*(curl|wget).*\|\s*(sh|bash)    (pipe-to-shell install without verification)
```

For Dockerfiles missing `USER` entirely → **HIGH** / CWE-276.

### Kubernetes

Grep all `*.yaml` / `*.yml` under `profile.deployment.k8s.manifests` for:

```
privileged\s*:\s*true
hostNetwork\s*:\s*true
hostPID\s*:\s*true
allowPrivilegeEscalation\s*:\s*true
runAsUser\s*:\s*0
runAsNonRoot\s*:\s*false
automountServiceAccountToken\s*:\s*true   (if NOT actually needed)
```

RBAC wildcard:
```
verbs\s*:\s*\[\s*"\*"\s*\]
resources\s*:\s*\[\s*"\*"\s*\]
```

→ **HIGH** / CWE-732.

### Terraform

For each `*.tf` file:

- Security groups with `cidr_blocks = ["0.0.0.0/0"]` on non-public
  resources → **HIGH** / CWE-284.
- S3 buckets with `acl = "public-read"` or without `server_side_encryption_configuration` → **HIGH** / CWE-311.
- IAM with `Action = "*"` or `Resource = "*"` → **HIGH** / CWE-284.

Cross-ref Phase 4 `checkov.sarif` / `trivy config` output.

### GitHub Actions

For each `.github/workflows/*.yml`:

- `pull_request_target` + `actions/checkout@v* with: ref: ${{ github.event.pull_request.head.sha }}` → **CRITICAL** / CWE-829.
- `uses: some/action@main` or `@v1` (unpinned) → **MEDIUM** / CWE-829.
  Should be `@<sha>`.
- Missing `permissions:` block at workflow or job level → **MEDIUM** /
  CWE-1035 (over-permissive GITHUB_TOKEN).
- `secrets:` referenced inside a job that runs on `pull_request` from
  forks → **HIGH** / CWE-200.

Cross-ref zizmor output if installed.

### Dependency postinstall / preinstall

Grep `package.json` for `postinstall`/`preinstall` that execute
downloaded scripts. → **MEDIUM** / CWE-829. Suggest: pin SHA, verify
signature.

### .dockerignore hygiene

If Dockerfile exists but `.dockerignore` is absent or doesn't ignore
`.git` / `.env` / `node_modules` → **MEDIUM** / CWE-200 (risk of context
leak).

## False-positive notes

- **Intentionally-public endpoints** (health checks, public API docs)
  may have 0.0.0.0/0 ingress. Cross-ref `profile.trust_zones` — if the
  SG is attached to a resource in a `public` trust zone, it's fine.
- **Build jobs** may use `permissions: write-all` legitimately. Flag at
  LOW only if it's on the default workflow that runs on forked PRs.
- **Debug images** (Dockerfile.dev, Dockerfile.debug) may legitimately
  expose debug ports. Only flag if the image is tagged `prod` /
  `release` / referenced by a production compose / k8s manifest.

## Output

`phase-05-deployment-<partition>.jsonl`.
