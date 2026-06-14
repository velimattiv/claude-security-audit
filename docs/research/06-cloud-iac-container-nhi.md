# Cloud-Native / IaC / Container / NHI-Secrets Evolution — Static-Detection Research

> Research refresh for the `/security-audit` skill (v2.0.6). Angle: cloud-native,
> IaC, container, and non-human-identity (NHI) secret evolution. **Strictly
> static-repo detection** — CSPM and runtime container security stay out of
> scope. Anything needing live cloud creds or a running target is marked
> *out of scope: flag location, defer*.
>
> Window: developments NEW or CHANGED since ~2026-01 (last research 2026-04-24).
> Today: 2026-06-14. Verified against primary sources; CVE/GHSA IDs are only
> cited where confirmed on NVD/vendor advisories — none invented.

## TL;DR

- **Kyverno SSRF (CVE-2026-4789, CVSS 9.8, published 2026-03-30, affects 1.16.0–1.17.1)** is *statically detectable in the repo*: scan Kyverno policy YAML for `http.Get(`/`http.Post(` in CEL expressions and flag the chart version range. This is the strongest new k8s admission-controller finding for cat-07. **CONFIRMED** (NVD).
- **AWS Lambda Function URL `AuthType = NONE`** moved from theoretical to actively exploited — the **HazyBeacon C2 campaign (Qualys, 2026-06-02)** uses it as a public, AWS-trusted relay. Trivially static (`authorization_type = "NONE"`). Highest-value *new serverless* signal. **CONFIRMED**.
- **NHI / secret-zero is the dominant 2026 narrative.** GitGuardian *State of Secrets Sprawl 2026* (2026-03-17): **28.65M secrets** on public GitHub in 2025 (+34% YoY), **64% of 2022-valid secrets still valid Jan 2026**, AI-service leaks **+81%**, **24,008 secrets in MCP config files** (8.8% valid), and **AI-assisted commits leak at 3.2% vs 1.5% baseline**. OWASP NHI Top 10 (NHI6/NHI7) frames long-lived keys + OIDC misconfig as the core failure. **CONFIRMED**.
- **OIDC workload-identity-federation misconfig** is now first-class: wildcard / missing `sub` conditions in IAM trust policies. GitHub ships **immutable subject claims** (numeric IDs, auto-enforced **2026-07-15**); AWS adds **STS per-claim validation** (2026-02). Static signal: trust policies keyed only on `aud`, or `sub` containing `*` / `repo:org/*`. **CONFIRMED**.
- **Native sidecar containers went GA in Kubernetes v1.33** (`initContainers[].restartPolicy: Always`). Sidecars are full-lifecycle containers and must get the same securityContext scrutiny as app containers — a new static-parse case the skill doesn't yet cover. **CONFIRMED**.
- **CIS benchmark refresh wave:** Kubernetes **v2.0.0** (k8s 1.34/1.35), Azure Foundations **v6.0.0**, AWS Foundations **v7.0.0** — all 2026 H1. Trivy absorbed tfsec and added CFN `MetadataOptions`/IMDSv2 propagation (v0.71.0, 2026-06-01); Checkov added GitHub-OIDC trust-policy checks (CKV_AWS_393/358). **CONFIRMED** (CIS Kubernetes/Azure/AWS verified; GCP v5.0.0 *unverified — defer*).
- **IMDSv1-allowed (`http_tokens = "optional"`)** remains a high-value static SSRF-enabler and is not yet an explicit cat-07 signal. **CONFIRMED**.
- **New token detectors landed in 2026** (GitGuardian engine v2.162, 2026-04-27: GitLab fine-grained PAT + 16 detectors; TruffleHog Mar 2026: JFrog ref-tokens, MuleSoft OAuth2). cat-06 should rely on scanner cross-ref and add MCP-config-file scanning as a new sweep.

---

## What changed since 2026-01

### Kubernetes / admission control

- **CVE-2026-4789 — Kyverno CEL SSRF.** CVSS **9.8 Critical**, **published 2026-03-30**, NIST analysis complete 2026-04-03. Kyverno **1.16.0–1.17.1**: unrestricted CEL `http.*` functions let namespace-scoped users embed `http.Get`/`http.Post` in `NamespacedValidatingPolicy`/`NamespacedDeletingPolicy`, reaching `169.254.169.254` (IMDS). **Statically detectable**: regex `http\.(Get|Post)\(` in Kyverno policy YAML, plus flag the Helm/manifest chart version range. *CONFIRMED* — NVD CVE-2026-4789.
- **CVE-2020-8561 (webhook redirect, Medium 4.1) CVE record corrected 2026-06-01** per the kubernetes.io "Reconciling Unfixed Kubernetes CVEs" blog (2026-05-26). Not new behaviour, but scanners that key off the CVE record will newly surface it. Generic webhook hygiene (`failurePolicy: Ignore`, `apiGroups/resources: "*"`, missing `namespaceSelector`) remains the static signal. *CONFIRMED* — kubernetes.io blog.
- **Native sidecar containers GA in Kubernetes v1.33** ("Octarine", blog 2025-04-23; beta since 1.29). Sidecars are `initContainers[]` with `restartPolicy: Always` — they run the full pod lifecycle, so they need the same privileged/caps/hostPath scrutiny as regular containers. Static parsers that only walk `spec.containers[]` will *miss* a privileged sidecar. *CONFIRMED* — kubernetes.io v1.33 release.
- **CIS Kubernetes Benchmark v2.0.0** (May 2026 update): adds k8s 1.34/1.35 support, automated assessment content, 23 recommendations updated. *CONFIRMED* — cisecurity.org May 2026 update.
- Pod Security Standards/Admission unchanged in 2026 H1 (no policy overhaul). RBAC escalation primitives (`escalate`, `bind`, `impersonate`, write on webhook configs, `create` on `serviceaccounts/token`, `nodes/proxy`, `pods/exec`) are the long-standing canonical set in the kubernetes.io "RBAC Good Practices" doc — still the authoritative static checklist. *CONFIRMED* — kubernetes.io RBAC good-practices.

### Container / Dockerfile

- **NVIDIAScape — CVE-2025-23266 (CVSS 9.0)** is *statically detectable in Dockerfiles*: a three-line container escape via `ENV LD_PRELOAD=...` exploiting an OCI hook. Worth a Dockerfile `LD_PRELOAD` signal. *CONFIRMED* — Wiz writeup. (runc CVE-2025-31133 / -52565 / -52881, Nov 2025, are **runtime breakouts — not repo-detectable**; context only, *out of scope: defer*.)
- **hadolint:** latest release is **v2.14.0 (Sep 2024)** — **no 2026 release**, so no new Dockerfile lint rules to absorb. The skill's hadolint cross-ref is current; net-new Dockerfile signals must come from the skill itself (e.g. `LD_PRELOAD`, pinned-by-digest). *CONFIRMED* — hadolint releases.

### IaC / serverless

- **AWS Lambda Function URL `AuthType = NONE` → active C2.** **HazyBeacon** campaign (Qualys, **2026-06-02**; corroborated gbhackers, cyberpress) abuses public `*.on.aws` Function URLs as malware relays that inherit AWS-domain trust. Static: `aws_lambda_function_url.authorization_type = "NONE"` (TF) / `AWS::Lambda::Url AuthType: NONE` (CFN). Checkov **CKV_AWS_258**. *CONFIRMED*.
- **Bicep BCP446 trusted-registry enforcement** (Bicep v0.43.x, ~May 2026): OCI module restore now blocked from non-allowlisted registries — a supply-chain guard. Static signal: `module ... 'br:<non-allowlisted-registry>/...'`. *CONFIRMED (single secondary source — verify before quoting as authoritative)*.
- **CIS AWS Foundations Benchmark v7.0.0** (~2026-06-05) and **CIS Azure Foundations v6.0.0** (May 2026) released. **CIS GCP Foundations v5.0.0 is reported (2026-05-09) but NOT confirmed in the May CIS update page — treat as unverified, defer.** *AWS/Azure CONFIRMED; GCP UNVERIFIED*.
- **Trivy absorbed tfsec**; 2026 IaC work: v0.69.0 (2026-01-30) Ansible + CFN `Fn::ForEach`; v0.71.0 (2026-06-01) CFN `MetadataOptions` (IMDSv2) propagation + Terraform path-traversal fix. **Checkov 3.2.x** added GitHub-OIDC trust-policy checks (**CKV_AWS_393/358**, CKV_AZURE_249, CKV_GCP_125). *CONFIRMED* — Trivy/Checkov changelogs.
- **OpenTofu 1.10.x** state-encryption enhancements (external key providers, PBKDF2 chaining); pulled upstream fixes CVE-2025-58185/58187/58188 (real IDs, quoted from changelog). Reinforces that **Terraform/OpenTofu state is plaintext and must never be committed**. *CONFIRMED* — OpenTofu changelog.
- **Negative finding (correct a likely premise):** Terraform AWS provider **6.0 shipped 2025-06-18, not 2026**; the 2026 provider changelog (6.10→6.50) shows **no new security-default flips**. There is no "2026 provider default-drift" story to chase. *CONFIRMED-negative*.

### NHI / workload identity / secrets

- **GitGuardian *State of Secrets Sprawl 2026*** (**2026-03-17**): 28.65M public-GitHub secrets in 2025 (+34% YoY, largest jump on record); **64% of 2022-valid secrets still valid Jan 2026** (rotation failure); AI-service leaks 1,275,105 (+81% YoY); **24,008 secrets in MCP config files** (2,117 valid, 8.8%); **Claude-Code-assisted commits leak at 3.2% vs 1.5% baseline**. *CONFIRMED*.
- **GitHub immutable OIDC subject claims** (changelog **2026-04-23**): new `sub` format `repo:octocat@123456/my-repo@456789:ref:refs/heads/main` (immutable numeric IDs after `@`); **auto-enforced for new repos / renames / transfers from 2026-07-15**. Defeats name-recycling impersonation. *CONFIRMED*.
- **AWS STS Identity Provider Claims Validation** (2026-02-09): IAM trust policies can now condition on individual JWT claims (`repository_id`, `ref`, `environment`, `job_workflow_ref`) instead of only `sub` — so the *absence* of a `sub`/claim condition (trust keyed only on `aud`) is now an actionable static finding. *CONFIRMED*.
- **OIDC wildcard-trust exploitation** publicised (Datadog-sourced writeup, 2026-02-16): trust policies with `sub` = `repo:org/*` or no `sub` condition are exploitable across an org. *CONFIRMED (secondary)*.
- **New token detectors:** GitGuardian engine **v2.162** (2026-04-27) — GitLab fine-grained PAT + 16 detectors (Coder, Consul ACL, Cloudflare API v2, Datadog App key, Snyk v2); TruffleHog (Mar 2026) — JFrog Artifactory ref-token, MuleSoft OAuth2. *CONFIRMED*.

---

## Concrete detections

Implementable static signals: file-path glob + key/pattern. Grouped by domain.
Severities are suggestions for the deep-dive author to calibrate against the
skill's existing scale. "Cross-ref" = also reconcile with the named Phase-4 scanner.

### Kubernetes

| Glob | Key / pattern | Severity | Notes |
|---|---|---|---|
| `**/{role,clusterrole}*.{yaml,yml}` | `verbs:` contains `escalate`\|`bind`\|`impersonate` | CRITICAL | RBAC privesc primitives |
| RBAC rules `**/*.{yaml,yml}` | `resources:` includes `validatingwebhookconfigurations`\|`mutatingwebhookconfigurations` with verb `create`/`update`/`*` | CRITICAL | intercept/approve API requests |
| RBAC rules | `resources: ["serviceaccounts/token"]` verb `create`; or `nodes/proxy` any verb; or `pods/exec`\|`pods/ephemeralcontainers` create; or `persistentvolumes` create | HIGH | token-mint / kubelet exec / hostPath enable |
| RBAC rules | `resources: ["secrets"]` verbs `get`\|`list`\|`watch` at broad scope | HIGH | secret exfiltration |
| `**/*{validating,mutating}webhookconfiguration*.{yaml,yml}` | `failurePolicy:\s*Ignore`; `apiGroups:\s*\[?["']?\*`; missing `namespaceSelector` | HIGH | admission bypass |
| Kyverno policy YAML | `http\.(Get\|Post)\(` in CEL **and** chart `kyverno` version in `[1.16.0, 1.17.1]` | CRITICAL | **CVE-2026-4789** SSRF — new |
| Pod specs `**/*.{yaml,yml}` | `initContainers[].restartPolicy:\s*Always` with `privileged:true`/`capabilities.add`/hostPath | HIGH | **native sidecar** — apply container scrutiny (new parse case) |
| Pod specs | `privileged:\s*true`; `capabilities.add` of `SYS_ADMIN`\|`NET_ADMIN`\|`SYS_PTRACE`\|`BPF`; `hostPID`/`hostIPC`/`hostNetwork:\s*true`; `seccompProfile.type:\s*Unconfined`; `procMount:\s*Unmasked`; AppArmor `unconfined` | CRITICAL/HIGH | escape enablers (extends current cat-07 set) |
| Pod specs / SA | `automountServiceAccountToken` absent or `true` | MEDIUM | already partial in cat-07 |
| Namespace manifests | `pod-security.kubernetes.io/enforce: privileged` or label absent | MEDIUM | PSA posture |

### Container / Dockerfile / compose

| Glob | Key / pattern | Severity | Notes |
|---|---|---|---|
| `**/*.{yaml,yml}`, `docker-compose*.{yml,yaml}` | hostPath/volume mount of `/var/run/docker.sock` | CRITICAL | Docker-socket escape (extends cat-07) |
| `**/Dockerfile*` | `^ENV\s+.*LD_PRELOAD` / `LD_PRELOAD=` | HIGH | **CVE-2025-23266 (NVIDIAScape)** static signal — new |
| `**/Dockerfile*`, Helm `values.yaml` | image ref `:tag` without `@sha256:` digest | MEDIUM | supply-chain immutability |
| Helm `Chart.yaml` | `dependencies[].version` with range operator `^`\|`~`\|`*`\|`>=` | MEDIUM | unpinned chart deps |

### IaC (Terraform/OpenTofu/CloudFormation/Bicep)

| Glob | Key / pattern | Severity | Notes |
|---|---|---|---|
| `**/*.tf` | `aws_db_instance` … `publicly_accessible\s*=\s*true` | HIGH | RDS public (CKV_AWS_17/18) |
| `**/*.bicep`, ARM `**/*.json` | `publicNetworkAccess:\s*'?Enabled` or `networkAcls.defaultAction:\s*'?Allow` | HIGH | Azure storage public |
| `**/*.tf` | `azurerm_storage_account` … `shared_access_key_enabled\s*=\s*true` | MEDIUM | should be Entra-only |
| `**/*.tf` | `min_tls_version\s*=\s*"TLS1_[01]"` | MEDIUM | weak TLS policy |
| `**/*.tf` | `aws_eks_cluster` … `endpoint_public_access\s*=\s*true` + `public_access_cidrs.*0\.0\.0\.0/0` | HIGH | public control-plane |
| IAM JSON `**/*.{json,tf}` | `"Action":\s*"\*"` AND `"Resource":\s*"\*"`; `Principal.*"\*"`; `NotAction`/`NotResource` inversion; `iam:PassRole` with `"Resource":"*"` | HIGH | over-broad IAM (extends cat-07) |
| `**/*.bicep` | roleAssignment `roleDefinitionId` = Owner (`8e3af657…`) / Contributor (`b24988ac…`) at subscription scope | HIGH | Azure over-privilege |
| `**/*.tf` | `google_*_iam_*` member `roles/owner`\|`roles/editor`\|`allUsers`\|`allAuthenticatedUsers`; `uniform_bucket_level_access\s*=\s*false` | HIGH | GCP over-privilege / public |
| `**/*.tf` | `aws_kms_key` block missing `enable_key_rotation = true` | LOW | absence detection |
| repo-wide (absence) | no `aws_cloudtrail` / `aws_guardduty_detector` / `aws_flow_log` / `aws_s3_bucket_logging` while related resources exist | MEDIUM | logging-disabled (absence) |
| `**/*.bicep` | `module ... 'br:<non-allowlisted-registry>/'` | MEDIUM | BCP446 supply-chain |

### Serverless

| Glob | Key / pattern | Severity | Notes |
|---|---|---|---|
| `**/*.tf` | `aws_lambda_function_url` … `authorization_type\s*=\s*"NONE"` | CRITICAL | **HazyBeacon C2** — new, active |
| CFN `**/*.{yaml,yml,json}` | `Type:\s*AWS::Lambda::Url` + `AuthType:\s*NONE` | CRITICAL | same, CFN form (CKV_AWS_258) |
| `**/*.tf` | `aws_lambda_function.environment.variables` key matching `(?i)(password\|secret\|token\|api[_-]?key)` | HIGH | Lambda env-secret (CKV_AWS_45; FP-prone) |
| `**/*.tf` | `aws_lambda_permission.principal\s*=\s*"\*"` | HIGH | open resource policy |
| `**/wrangler.{toml,jsonc}` | sensitive key under `[vars]` (vs `secrets`/`secrets.required`) | HIGH | Cloudflare Workers plaintext secret (new `secrets` property, 2026-03-24) |

### NHI / workload identity / secrets

| Glob | Key / pattern | Severity | Notes |
|---|---|---|---|
| IAM trust `**/*.json`, `aws_iam_role.assume_role_policy` in `**/*.tf` | `token.actions.githubusercontent.com:sub` value containing `*` (esp. `repo:org/*`); OR **`sub` condition absent** while `aud` present | CRITICAL | OIDC wildcard/missing-sub trust — new |
| `**/*.tf` | `google_iam_workload_identity_pool_provider` with **no `attribute_condition`** / mapping not constraining `assertion.repository` | HIGH | GCP WIF broad trust |
| `**/*.tf` | resource `google_service_account_key` | HIGH | SA-key anti-pattern (prefer WIF) |
| `**/*.tf` | resource `aws_iam_access_key` | HIGH | long-lived key |
| `**/*.{json,yaml,env,tf,tfvars}` | AWS key `\b(AKIA\|ASIA\|ABIA\|ACCA)[A-Z2-7]{16}\b`; HCL `aws_access_key_id`/`aws_secret_access_key` literal | CRITICAL | hardcoded long-lived key |
| `**/*.json`, `**/*key*.json`, `**/credentials*.json` | `"type":\s*"service_account"` AND `"private_key":\s*"-----BEGIN` | CRITICAL | committed GCP SA key |
| `**/*.tfstate`, `**/*.tfstate.backup`, `**/*.tfvars`, `**/*.tfvars.json` | file tracked in git at all | HIGH/CRITICAL | already in cat-06; reinforce |
| `**/backend.tf`, `terraform { backend ... }` | S3 backend missing `encrypt = true` | MEDIUM | unencrypted state backend |
| `**/*.{yaml,yml}` (k8s) | `kind: Secret` + `type: kubernetes.io/service-account-token` + `kubernetes.io/service-account.name` annotation | MEDIUM-HIGH | manual long-lived SA token (anti-pattern since 1.22) |
| `**/*.tf` (`aws_instance`/`aws_launch_template`/`aws_launch_configuration`) | `metadata_options { http_tokens = "optional" }` | HIGH | **IMDSv1 allowed** — SSRF-to-cred (CKV_AWS_79) — new to skill |
| MCP config: `**/.mcp.json`, `**/mcp.json`, `**/*mcp*.{json,toml}`, `**/.cursor/mcp.json`, `**/claude_desktop_config.json` | literal-looking secret values in `env`/`headers`/`args` | HIGH | **new sweep** — MCP files are a 2026 leak hotspot (24,008 secrets) |

**Out of scope (live cloud needed — flag location, defer):** whether a found
key/token is *active/valid*; whether an OIDC role is *actually assumable*; runtime
IMDS reachability; CloudTrail/GuardDuty *actually receiving* events; runc/kernel
breakouts (CVE-2025-31133/-52565/-52881). For these, emit a finding at the *config
location* and note that live verification is deferred.

---

## Mapping to the skill

Named exactly against `skills/security-audit/steps/deepdive/`.

### cat-06 (`secret_sprawl`) — additions

- **New sweep: MCP config files.** Add `.mcp.json`, `mcp.json`, `.cursor/mcp.json`,
  `claude_desktop_config.json`, `*mcp*.{json,toml}` to the tracked-secret-file and
  literal-secret sweeps. *Strong 2026 justification* (GitGuardian: 24,008 secrets,
  8.8% valid). Currently absent.
- **New sweep: GCP service-account key JSON.** cat-06 already lists
  `gcp-*.json` / `service-account.json` as filenames; add the *content* signal
  `"type":"service_account"` + `"private_key":"-----BEGIN` so renamed files are caught.
- **Extend "Terraform / IaC" subsection** with the **unencrypted-state-backend**
  signal (`backend.tf` missing `encrypt = true`) — complements the existing
  `.tfstate`/`.tfvars` tracked-file checks.
- **Scanner cross-ref refresh.** The "Vendor-specific token regexes" subsection
  should note the **2026 detector additions** (GitGuardian v2.162, TruffleHog Mar
  2026) so CONFIRMED-confidence findings pick up GitLab fine-grained PATs, Cloudflare
  API v2, Consul ACL, JFrog ref-tokens, MuleSoft OAuth2. No new regex maintenance
  needed in-skill — just lean on the scanners.

### cat-07 (`deployment`) — additions

- **Kubernetes block:** add RBAC privesc-verb detection (`escalate`/`bind`/`impersonate`,
  write on webhook configs, `serviceaccounts/token` create, `nodes/proxy`,
  `pods/exec`, `pods/ephemeralcontainers`). Current cat-07 RBAC check is only the
  `*`-verb/`*`-resource wildcard — too narrow; these primitives are escalation even
  without wildcards.
- **Kubernetes block:** add admission-webhook-misconfig detection
  (`failurePolicy: Ignore`, broad `rules`, missing `namespaceSelector`) — **plus the
  Kyverno CEL-SSRF special case (CVE-2026-4789)**. Brand-new; not in cat-07.
- **Kubernetes block:** add **native-sidecar parsing** — walk
  `initContainers[].restartPolicy: Always` with the same securityContext checks as
  `containers[]`. The current cat-07 Pod-spec greps would miss a privileged sidecar.
- **Kubernetes block:** extend escape-enabler greps with `hostIPC`, `capabilities.add`
  (SYS_ADMIN/NET_ADMIN/SYS_PTRACE/BPF), `seccompProfile.type: Unconfined`,
  `procMount: Unmasked`, AppArmor `unconfined`. Current set has privileged/hostNetwork/
  hostPID/allowPrivilegeEscalation/runAsUser:0 but is missing these.
- **Docker/compose:** add **`/var/run/docker.sock` mount** detection (hostPath in k8s,
  `volumes:` in compose). Classic escape; not currently listed.
- **Dockerfile:** add **`LD_PRELOAD` ENV** signal (CVE-2025-23266) and **image-not-pinned-
  by-digest** (`:tag` without `@sha256:`).
- **Terraform block:** extend beyond the current S3/SG/IAM trio with: RDS
  `publicly_accessible`, EKS public endpoint + open CIDR, Azure storage
  `public_network_access`/`shared_access_key_enabled`/weak `min_tls_version`, GCP
  `roles/owner|editor`/`allUsers`/`uniform_bucket_level_access=false`, KMS rotation
  absence, and the **logging-absence** detections (CloudTrail/flow-logs/S3-logging/
  GuardDuty).
- **Serverless (new sub-area):** Lambda Function URL `AuthType=NONE` (**HazyBeacon**),
  Lambda env-secret, Lambda over-broad role, `aws_lambda_permission` `principal="*"`,
  Cloudflare `wrangler.toml [vars]` secrets. cat-07 has no serverless coverage today.
- **NHI / workload identity (new sub-area):** OIDC trust-policy misconfig
  (wildcard/missing `sub`), `google_service_account_key`/`aws_iam_access_key` long-lived
  resources, manual k8s SA-token Secrets, and **IMDSv1-allowed
  (`http_tokens="optional"`)**. These span cat-06 (the *secret*) and cat-07 (the *posture*)
  — see "new cross-cutting note" below.

### New / cross-cutting

- **NHI as an explicit cross-cutting theme.** The "secret-zero / workload-identity"
  problem straddles cat-06 (long-lived keys, SA-key files, state secrets) and cat-07
  (OIDC trust posture, IMDS, IAM). Rather than a 10th category, add a short shared
  **"NHI & workload identity" note** referenced from both files, with the OIDC-trust and
  IMDS signals living in cat-07 (posture) and the hardcoded-key/SA-key/MCP signals in
  cat-06 (sprawl). Keeps the 9-category fan-out intact.
- **No new mandatory tool.** trivy/checkov/kube-linter/hadolint already cover most of
  this; the gaps are *skill-side greps*. Optional: note Checkov's new GitHub-OIDC
  checks (CKV_AWS_393/358) and Trivy's CFN IMDSv2 propagation (v0.71.0) in the Phase-4
  cross-ref so those scanner hits map to the new cat-07 NHI signals.

---

## Prioritized recommendations

Priority (P0 highest) × effort (S/M/L).

| # | Rec | Pri | Effort | Rationale |
|---|---|---|---|---|
| 1 | cat-07: **Lambda Function URL `AuthType=NONE`** (TF + CFN) | P0 | S | Actively exploited (HazyBeacon, 2026-06); trivial regex; zero FP risk; no current serverless coverage. |
| 2 | cat-07: **Kyverno CEL-SSRF (CVE-2026-4789)** signal + admission-webhook-misconfig block | P0 | M | CVSS 9.8, version-bounded, statically detectable; admission webhooks are an unaddressed gap. |
| 3 | cat-07: **native-sidecar securityContext parsing** + missing escape-enablers (`hostIPC`, caps, seccomp Unconfined, docker.sock) | P0 | M | Sidecars GA in 1.33 means current container-only greps now *silently miss* privileged sidecars — a correctness gap, not just a coverage gap. |
| 4 | cat-07: **OIDC trust-policy misconfig** (wildcard/missing `sub`) + **IMDSv1-allowed** | P1 | M | Dominant 2026 NHI failure mode; GitHub enforcement 2026-07-15 makes this timely; IMDSv1 is a direct SSRF-to-cred enabler. |
| 5 | cat-06: **MCP-config-file secret sweep** | P1 | S | 24,008 secrets in MCP files (GitGuardian 2026); the skill ships *as* a Claude Code tool — dogfood-relevant; cheap to add globs. |
| 6 | cat-07: **RBAC privesc-verb detection** (escalate/bind/impersonate/webhook-write/token-create) | P1 | M | Current RBAC check only catches `*` wildcards; these primitives escalate without wildcards and are the canonical kubernetes.io list. |
| 7 | cat-07: **Terraform breadth** — RDS/EKS public, Azure storage, GCP over-privilege, logging-absence, KMS rotation | P1 | L | Brings IaC posture up to CIS v6/v7 (2026) baseline; absence-detections need a repo-wide pass (the L). |
| 8 | cat-06: GCP SA-key **content** signal + unencrypted-state-backend + 2026 scanner-detector cross-ref note | P2 | S | Closes rename-evasion gap and aligns CONFIRMED-confidence tagging with 2026 detectors. |
| 9 | cat-07: Dockerfile **`LD_PRELOAD`** (CVE-2025-23266) + **digest-pinning** | P2 | S | Niche but cheap; hadolint won't catch it (no 2026 release). |
| 10 | Cross-cutting **"NHI & workload identity" shared note** + Phase-4 cross-ref additions (CKV_AWS_393/358, Trivy v0.71.0) | P2 | S | Organizes the NHI theme without a 10th category; keeps fan-out at 9. |

**Explicitly NOT recommended:** chasing a "2026 Terraform AWS provider default-drift"
story (provider 6.0 was 2025; no 2026 security-default flips) — premise unsubstantiated.

---

## Sources

Primary sources verified during this research (✓ = fetched/verified directly by me;
others verified by research sub-agents and spot-checked).

- ✓ **NVD CVE-2026-4789** — https://nvd.nist.gov/vuln/detail/CVE-2026-4789 — Kyverno CEL SSRF, CVSS 9.8, 2026-03-30, vers 1.16.0–1.17.1 (supports the Kyverno static signal).
- ✓ **GitHub Changelog — immutable OIDC subject claims** — https://github.blog/changelog/2026-04-23-immutable-subject-claims-for-github-actions-oidc-tokens/ — new `sub` format + 2026-07-15 enforcement (supports OIDC-trust signal & timeliness).
- ✓ **GitGuardian State of Secrets Sprawl 2026** — https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/ — 28.65M secrets, 64% still-valid, +81% AI leaks, 24,008 MCP secrets, 3.2% AI-assisted leak rate (supports NHI narrative + MCP sweep priority).
- ✓ **Kubernetes v1.33 release blog** — https://kubernetes.io/blog/2025/04/23/kubernetes-v1-33-release/ — native sidecars GA (`initContainers[].restartPolicy: Always`) (supports sidecar parsing rec).
- ✓ **Qualys — HazyBeacon / Lambda Function URL C2** — https://blog.qualys.com/qualys-insights/2026/06/02/hazybeacon-aws-lambda-function-url-command-control-abuse — active `AuthType=NONE` abuse (supports P0 #1). Corroboration: https://gbhackers.com/hazybeacon-campaign-abuses-aws/ .
- ✓ **CIS Benchmarks May 2026 Update** — https://www.cisecurity.org/insights/blog/cis-benchmarks-may-2026-update — CIS Kubernetes v2.0.0 (k8s 1.34/1.35), Azure Foundations v6.0.0 (supports benchmark-refresh claims). *GCP v5.0.0 NOT in this page — unverified, deferred.*
- **kubernetes.io RBAC Good Practices** — https://kubernetes.io/docs/concepts/security/rbac-good-practices/ — canonical RBAC escalation primitives (supports RBAC privesc-verb detections).
- **kubernetes.io "Reconciling Unfixed Kubernetes CVEs" (2026-05-26)** — https://kubernetes.io/blog/2026/05/26/reconciling-unfixed-kubernetes-cves/ — CVE-2020-8561 record correction 2026-06-01 (supports webhook-redirect context).
- **Wiz — NVIDIAScape CVE-2025-23266** — https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape — Dockerfile `LD_PRELOAD` escape (supports cat-07 Dockerfile signal).
- **OWASP Non-Human Identities Top 10 (2025)** — https://owasp.org/www-project-non-human-identities-top-10/2025/top-10-2025/ — NHI6 cloud-misconfig, NHI7 long-lived secrets (supports NHI theme).
- **AWS STS Identity Provider Claims Validation (2026-02-09)** — https://sjramblings.io/aws-sts-identity-provider-claims-validation/ — per-claim trust conditions (supports missing-`sub` finding).
- **Datadog-sourced — Exploiting Org Wildcards in OIDC Trust (2026-02-16)** — https://medium.com/@sadi.zane/exploiting-organisation-wildcards-in-oidc-trust-policies-a98eda04fb46 — wildcard `sub` exploitation (supports OIDC signal).
- **GitGuardian Detection Engine v2.162 (2026-04-27)** — https://docs.gitguardian.com/releases/detection-engine — GitLab fine-grained PAT + 16 detectors (supports cat-06 scanner cross-ref refresh).
- **TruffleHog release notes (Mar 2026)** — https://docs.trufflesecurity.com/trufflehog-release-notes — JFrog ref-token, MuleSoft OAuth2 (supports cat-06 cross-ref).
- **Trivy CHANGELOG** — https://github.com/aquasecurity/trivy/blob/main/CHANGELOG.md — tfsec absorption, CFN IMDSv2 propagation v0.71.0 (supports Phase-4 note).
- **Checkov CHANGELOG** — https://github.com/bridgecrewio/checkov/blob/main/CHANGELOG.md — GitHub-OIDC checks CKV_AWS_393/358; Lambda URL CKV_AWS_258 (supports cat-07 cross-ref).
- **OpenTofu 1.10 CHANGELOG** — https://github.com/opentofu/opentofu/blob/v1.10/CHANGELOG.md — state-encryption; CVE-2025-58185/58187/58188 (supports state-secret reinforcement).
- **hadolint releases** — https://github.com/hadolint/hadolint/releases — latest v2.14.0 (Sep 2024), no 2026 release (supports "skill must add Dockerfile signals itself").
- **Cloudflare wrangler `secrets` config property (2026-03-24)** — https://developers.cloudflare.com/changelog/post/2026-03-24-secrets-config-property — `[vars]` plaintext risk (supports Workers serverless signal).
- **Kubernetes ServiceAccounts** — https://kubernetes.io/docs/concepts/security/service-accounts/ — manual long-lived token discouraged since 1.22 (supports k8s SA-token signal).
- **tfsec enforce-http-token-imds / Checkov CKV_AWS_79** — https://aquasecurity.github.io/tfsec/latest/checks/aws/ec2/enforce-http-token-imds/ — IMDSv1 (`http_tokens="optional"`) (supports IMDS signal).

**Unverified / deferred:** CIS GCP Foundations v5.0.0 (reported 2026-05-09, not on the
May CIS update page — verify the PDF before quoting). Bicep BCP446 trusted-registry
enforcement (single secondary source). GitHub/GitLab token regexes in detections are
the well-established public formats — verify against the current gitleaks/TruffleHog
config rather than treating as novel. No CVE/GHSA IDs were invented; all cited IDs were
confirmed on NVD or quoted verbatim from a vendor changelog.
