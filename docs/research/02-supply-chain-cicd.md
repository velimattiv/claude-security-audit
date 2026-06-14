# Software Supply Chain & CI/CD Security — Research Refresh (2026-06-14)

Research angle for the `/security-audit` skill (v2.0.6) refresh. Scope: STATIC
signals only (no DAST/runtime/CSPM). Covers the *gap* the skill admits to — it
has no dedicated software-supply-chain deep-dive; `osv-scanner` does dependency
CVE/SCA only. Window of interest: roughly 2026-01 → 2026-06, with key 2025
precedents that set the threat model. Last skill research round: 2026-04-24.

## TL;DR

- **Self-replicating npm worms are now the dominant supply-chain pattern.**
  Shai-Hulud (Sep 2025) and **Shai-Hulud 2.0** (21-24 Nov 2025) weaponise
  `preinstall`/`postinstall` lifecycle scripts to steal CI/CD + cloud creds,
  register the victim as a **self-hosted GitHub Actions runner** named
  `SHA1HULUD`, and republish to every package the stolen npm token can reach.
  Scale: ~700 packages, 25k+ malicious repos, ~14k secrets. (CONFIRMED)
- **The skill's own scanner was a victim.** On 19 Mar 2026 the **TeamPCP** group
  force-pushed malware to 76/77 tags of `aquasecurity/trivy-action` and all 7 of
  `setup-trivy` (CVE-2026-33634, CVSS 9.4), harvesting creds later used to clone
  **300+ Cisco repos**. `trivy` is in the Phase-4 bundle — pinning guidance for
  the skill's *own* recommended tooling is now load-bearing. (CONFIRMED)
- **CI/CD-credential theft is the unifying objective.** Every 2026 campaign
  (LiteLLM/TeamPCP, CanisterSprawl, TrapDoor, BufferZoneCorp) targets the same
  asset class: `GITHUB_TOKEN`, npm/PyPI publish tokens, AWS `AKIA*` keys, OIDC,
  kube service-account tokens — read at install-time inside CI runners.
- **Cross-ecosystem execution paths are well-mapped now**: npm `postinstall`,
  Python import-time / `.pth` startup hooks / `setup.py`, Rust `build.rs`, Ruby
  `extconf.rb`. A static check should cover all five, not just npm. (CONFIRMED)
- **Dependency confusion is back with better social engineering** — a May 2026
  npm campaign (45 pkgs, 9 corporate scopes) used **fabricated enterprise infra
  URLs** in `package.json` + inflated versions (`100.100.100`) to win resolution
  and pass code review. Statically detectable. (CONFIRMED)
- **The publishing trust model changed under our feet.** npm **revoked classic
  tokens 9 Dec 2025**; OIDC **trusted publishing** + auto-provenance is now the
  recommended path. GitHub shipped **SHA-pinning enforcement policy** (Aug 2025)
  and **immutable releases** (2026). The skill should reward provenance and flag
  long-lived token publishing.
- **`zizmor` covers ~39 GHA rules** (incl. new `typosquat-uses`, `cache-poisoning`,
  `template-injection`, `self-hosted-runner`) but does **not** cover: OIDC
  trust-policy *breadth*, dependency confusion, lockfile integrity, or non-GHA
  CI (GitLab/CircleCI). These are category-10 territory.
- **Recommendation: add Phase-5 category 10 "Supply Chain & CI/CD Integrity"**
  fed by `osv-scanner` (have), `zizmor` (have), `trivy` (have), plus new
  signals/tools: lockfile-lint, GuardDog, OpenSSF Scorecard, and bespoke
  manifest/lockfile/CI regex scans.

## What changed since 2026-01

Dated, cited to primary/vendor research. CONFIRMED = named by ≥1 vendor + a
primary advisory/CVE; SPECULATIVE flagged inline. Campaign names are taken
verbatim from the cited reporting — none invented.

### Incidents & campaigns

- **2025-09-15 — Shai-Hulud (wave 1).** First self-replicating npm worm; ~200
  packages incl. `@ctrl/tinycolor` and CrowdStrike-owned packages. `postinstall`
  harvests npm/GitHub/CI tokens, exfiltrates to attacker `Shai-Hulud` GitHub
  repos. CISA alert issued 2025-09-23. *Sets the threat model.* (CONFIRMED —
  Wiz, Unit42, Sysdig, CISA)
- **2025-11-21..24 — Shai-Hulud 2.0 ("Sha1-Hulud: The Second Coming").** Runs in
  **`preinstall`** (wider blast radius than v1). Drops `setup_bun.js` +
  `bun_environment.js`, runs payload under the **Bun** runtime. Registers victim
  as GHA self-hosted runner `SHA1HULUD`; installs `.github/workflows/discussion.yaml`
  (command exec via `${{ github.event.discussion.body }}`) and
  `formatter_<digits>.yml` (secrets→artifact exfil). Bundles **TruffleHog** to
  scan victim FS. ~700 pkgs, 25k+ repos (~1000 new/30 min), ~14k secrets / 487
  orgs. High-prevalence: `@postman/tunnel-agent`, `posthog-node`,
  `@asyncapi/specs`. (CONFIRMED — Wiz, Datadog, Endor, Red Canary, Zscaler)
- **2026-03-19 — Trivy / TeamPCP / Cisco.** `aquasecurity/trivy-action` (76/77
  tags) + `setup-trivy` (7/7) force-pushed with the "TeamPCP Cloud Stealer".
  Release binaries + Docker Hub images poisoned simultaneously. **CVE-2026-33634,
  CVSS 9.4.** Harvested creds → 300+ Cisco repos cloned + AWS lateral movement.
  (CONFIRMED — TheHackerNews, BleepingComputer, Legit, SOCRadar) **Direct
  relevance: `trivy` is in the skill's Phase-4 bundle.**
- **2026-03-24 — LiteLLM / Telnyx on PyPI (TeamPCP).** LiteLLM `1.82.7` (payload
  in `litellm/proxy/proxy_server.py`, import-time) and `1.82.8` (malicious
  **`.pth`** file → runs at interpreter startup). Steals env vars, SSH keys,
  cloud creds, **k8s data, Docker configs**, CI/CD secrets → `models.litellm[.]cloud`.
  systemd persistence; creates privileged k8s pods if SA tokens present. Same
  TeamPCP campaign as Trivy. IOCs: `litellm_init.pth`, `~/.config/sysmon/sysmon.py`.
  (CONFIRMED — Datadog, CSO, PyPI advisory)
- **2026-04-21..23 — CanisterSprawl.** Self-propagating npm worm (≥16 versions,
  Namastex Labs namespaces incl. `pgserve`). `postinstall` regex-sweeps ~40
  credential categories; exfiltrates to a **decentralized ICP (Internet Computer
  Protocol) canister** C2; re-injects into any package the found npm token can
  publish, and **jumps to PyPI** if a PyPI token is found. Part of "three
  campaigns in 48h" across npm/PyPI/Docker Hub. (CONFIRMED — Socket,
  StepSecurity, GitGuardian, CSA, SANS ISC)
- **2026-05-22 — TrapDoor.** Cross-ecosystem: >34 packages / >384 versions across
  **npm, PyPI, crates.io**. Per-ecosystem execution: **`build.rs`** (Rust),
  **`postinstall`** (npm), **import-time** (Python). Names tailored to crypto/AI/
  env-setup/security tooling. Steals secrets, wallets, SSH keys, cloud creds,
  browser data. (CONFIRMED — TheHackerNews 2026-05; corroborated CoreWin)
- **2026-05 — BufferZoneCorp (RubyGems + Go).** "Sleeper" gems abuse
  **`extconf.rb`** (auto-run during `gem install`/`bundle install`) to harvest CI
  creds; paired malicious Go modules (blocked by the Go checksum DB / proxy).
  (CONFIRMED — TheHackerNews 2026-05, GitLab precedent 2025-06)
- **2026-05-28..29 — npm dependency-confusion campaign.** 45 pkgs / 3 accounts /
  9 corporate scopes (e.g. `@cloudplatform-single-spa`, `@sber-ecom-core`).
  **Fabricated enterprise infra URLs** in `package.json` (`repository`,
  `bugs`, `homepage`) pointing at look-alike `.io` domains; **inflated versions
  (`100.100.100`, `99.x.x`)** to beat private-registry resolution; kill-switch
  env vars (`*_NO_TELEMETRY`). Shared C2 header `X-Secret: l95HdDaz3kQx...`.
  (CONFIRMED — Microsoft Security Blog 2026-05-29)
- **2025-05-25 — crates.io `faster_log` / `async_println`.** Working logging code
  that scans source for Solana/Ethereum private keys, exfil via HTTP POST; 8,424
  downloads. (CONFIRMED — TheHackerNews 2025-09) Shows crates payloads hide in
  *runtime* code, not only `build.rs`.

### Platform / ecosystem hardening (defender-relevant)

- **npm classic tokens revoked 2025-12-09** (creation disabled early Nov). Path
  forward: **OIDC trusted publishing** (short-lived, workflow-scoped, **auto
  provenance**) or granular tokens (90-day max, 2FA default). Local publish uses
  2-hour session tokens. (CONFIRMED — Socket, GitHub community discussions)
- **GitHub Actions SHA-pinning enforcement policy (2025-08).** Org/enterprise
  policy can now *fail* (not just warn) workflows using unpinned actions, and
  *block* specific actions via `!org/action`. (CONFIRMED — GitHub Changelog)
- **GitHub immutable releases (2026)** — once marked immutable, release assets +
  git tag cannot be changed/deleted; directly counters the force-pushed-tag
  vector used by tj-actions and Trivy. (CONFIRMED — GitHub roadmap; SPECULATIVE
  on exact GA date — verify before relying on enforcement.)
- **OpenTofu v1.10+ OCI registry support (2025-2026)** for modules/providers —
  enables digest-pinned, signed module distribution vs. tag-based registry
  trust. Terraform/OpenTofu registry **tag attacks** remain a live concern
  (BoostSecurity research). (CONFIRMED tooling; incident severity SPECULATIVE.)
- **`zizmor` v1.24-1.26 (2026)** added `typosquat-uses` (action-name squatting),
  `dependabot-cooldown`, persona-gated `secrets-inherit` findings, and
  `undocumented-permissions`. (CONFIRMED — zizmor docs)

### Precedent (pre-2026, threat-model anchors)

- **2025-03-12..14 — tj-actions/changed-files (CVE-2025-30066).** Compromised PAT
  → attacker force-pushed malicious code and **re-pointed all version tags** to
  it. Python script dumped runner-memory secrets into **public build logs**.
  ~23,000 repos. Cascaded to `reviewdog/action-setup` (CVE-2025-30154). The
  canonical "unpinned mutable action ref" disaster. (CONFIRMED — Wiz, CISA,
  Unit42, Semgrep)

## Concrete detections

Implementable static signals. Grouped by target file class. All regexes are
illustrative (PCRE-ish); tune for the scanner. Severity is a starting CVSS-ish
anchor for `properties.security-severity`.

### A. Lifecycle / install-hook scripts (all ecosystems) — CWE-829, CWE-506

- **npm manifest hooks.** In `package.json`, presence of `scripts.preinstall`,
  `scripts.postinstall`, `scripts.install`. Not malicious per se → flag, then
  escalate on the *body* of the referenced script:
  - `"(pre|post)install"\s*:` → INFO baseline; HIGH if the command contains any
    of: `curl|wget|Invoke-WebRequest`, `bun `/`setup_bun`, `node -e`, `eval(`,
    `child_process`, `base64 -d`, `atob(`, `https?://[^"']+` with a non-registry host.
  - **Shai-Hulud 2.0 signal:** `setup_bun\.js|bun_environment\.js` anywhere in
    repo or `package.json`; SHA-256 `a3894003ad1d293ba96d77881ccd2071446dc3f6...`
    (`setup_bun.js`) — pin as IOC, expect to age out.
- **Python build/startup hooks.** `setup.py` containing a custom
  `cmdclass`/`install`/`build_py` override that runs code; `pyproject.toml`
  `[build-system]` with a non-standard `build-backend`; **`.pth` files** shipped
  in a wheel (`*.pth` containing `import ` — runs at interpreter start; LiteLLM
  IOC `litellm_init.pth`); top-level `__init__.py` with network/exec at import.
  - Regex: `^\s*import\s+\w+;\s*\w*\.?(system|popen|exec|connect)` in a `.pth`.
- **Rust `build.rs`** present AND containing `std::process::Command`,
  `reqwest|ureq|curl`, `include_bytes!` decode-and-exec, or `std::net`. — HIGH.
- **Ruby native-extension hook.** Gem ships `ext/**/extconf.rb` that does more
  than `create_makefile` — e.g. `system(`, `Net::HTTP`, `Base64.decode64`,
  `eval`. (BufferZoneCorp vector.) — HIGH.
- **Go.** No install hooks, but flag `//go:generate` running network commands and
  `go.mod` `replace` directives pointing at non-canonical hosts.

### B. Lockfile integrity & dependency confusion — CWE-1357, CWE-494, CWE-829

- **Resolved-URL tampering.** In `package-lock.json` / `yarn.lock` /
  `pnpm-lock.yaml`, any `resolved`/`registry` URL whose host is **not** the
  expected registry (`registry.npmjs.org` or the org's private registry).
  - Regex: `"resolved"\s*:\s*"https?://(?!registry\.npmjs\.org)[^"]+"` → MEDIUM
    (HIGH if host is a raw IP, a URL shortener, or a look-alike domain).
  - This is exactly what **lockfile-lint** does (`--allowed-hosts`,
    `--validate-https`, `--validate-integrity`) — wrap it rather than reimplement.
- **Integrity-hash absence/mismatch.** Lockfile entries missing `integrity` (npm)
  or `hash`/`checksum` (other ecosystems) → MEDIUM. Mismatch vs. on-disk content
  → HIGH (requires fetch; mark as needs-network, out of pure-static scope —
  delegate to `osv-scanner`/`npm ci` integrity check).
- **Dependency-confusion signals (manifest):**
  - Scoped internal-looking package (`@<corp>/…`) with **no** matching
    `.npmrc`/`registry` scoping the scope to a private registry. → HIGH.
  - **Inflated version** in a dependency: `"\^?(\d{2,}\.\d{2,}\.\d{2,})"` where
    major ≥ 90 (e.g. `100.100.100`, `99.99.99`) — classic resolution-winning. → HIGH.
  - **Fabricated enterprise infra URL**: `repository`/`bugs`/`homepage` host is a
    look-alike of a known SaaS (`*.atlassian.net`, `github.com`) on a different
    TLD/subdomain, e.g. `jira.<corp>.io`, `github.<corp>.io`. → MEDIUM (needs
    human triage; surface as POSSIBLE).
  - `.npmrc` lacking explicit scope→registry mapping while internal scopes are in
    use → MEDIUM (missing scope-locking).
- **Typosquatting (heuristic, opt-in).** Levenshtein ≤ 2 against a top-N popular
  package list per ecosystem (npm/PyPI/crates/RubyGems/Maven/Go). High false-
  positive risk → emit POSSIBLE only, or **delegate to GuardDog** which already
  does this with metadata heuristics.

### C. CI/CD workflow files — CWE-94 (injection), CWE-829 (unpinned), CWE-668

GitHub Actions (`.github/workflows/*.yml`). `zizmor` covers most; the skill
should *run zizmor* and add only the gaps below.

- **Script injection** via untrusted `github.event.*` interpolated into `run:`:
  - Regex: `\$\{\{\s*github\.event\.(issue|pull_request|comment|discussion|review)[^}]*\}\}`
    inside a `run:`/`script:` block. (zizmor `template-injection` — confirm it
    fired; keep as a backstop.)
  - **Shai-Hulud 2.0 IOC:** `github\.event\.discussion\.body` in a `run:`. → CRITICAL.
- **Dangerous trigger + untrusted checkout** (the tj-actions / fork-PR class):
  `on: pull_request_target` (or `workflow_run`) **combined with**
  `actions/checkout` using `ref: ${{ github.event.pull_request.head.* }}`. →
  CRITICAL. (zizmor `dangerous-triggers`; the *combination with explicit head
  checkout* is the high-signal escalation.)
- **Unpinned / mutable action refs.** `uses:\s*[\w./-]+@(v?\d+(\.\d+)*|main|master|HEAD|latest)$`
  (i.e. not a 40-hex SHA). → MEDIUM (HIGH for third-party orgs). (zizmor
  `unpinned-uses` — but also flag the skill's *own* recommended actions/tools.)
- **Self-hosted runner usage.** `runs-on:` containing `self-hosted`. → MEDIUM
  (context for Shai-Hulud runner-registration risk). (zizmor `self-hosted-runner`.)
- **Over-broad permissions / secrets exposure.** `permissions: write-all`,
  missing top-level `permissions:`, `secrets: inherit` in reusable-workflow
  calls. (zizmor `excessive-permissions`, `secrets-inherit`.)
- **OIDC trust-policy over-breadth (zizmor GAP).** When a workflow uses
  `aws-actions/configure-aws-credentials` / `azure/login` / `google-github-actions/auth`
  with OIDC, there is no static check that the *cloud-side* trust policy is
  scoped to `repo:<org>/<repo>:ref:refs/heads/main` rather than `repo:<org>/*` or
  wildcard `sub`. The skill can only flag the *workflow side* (presence of OIDC
  role assumption) and recommend trust-policy review → MEDIUM, category 7/10 overlap.
- **Cache poisoning in release workflows.** `actions/cache` (or `save-cache`) in a
  job that also publishes/releases, on a privileged trigger. → MEDIUM. (zizmor
  `cache-poisoning`.)
- **Non-GHA CI (zizmor GAP).** Apply the script-injection + unpinned-image +
  plaintext-secret checks to `.gitlab-ci.yml`, `.circleci/config.yml`,
  `azure-pipelines.yml`, `Jenkinsfile`, `bitbucket-pipelines.yml`. zizmor is
  GitHub-only; these are uncovered today.

### D. Provenance / attestation / publishing posture — CWE-347, CWE-1357

- **Reward provenance (positive signal).** Detect `npm publish --provenance` or
  `id-token: write` + trusted-publishing in the publish workflow → downgrade
  severity / emit INFO "good posture".
- **Flag long-lived publish tokens.** `NPM_TOKEN`/`PYPI_TOKEN`/`CARGO_REGISTRY_TOKEN`
  referenced as a *secret* in a publish step where no OIDC `id-token: write` is
  present → MEDIUM (post-Dec-2025 classic-token revocation makes this both risky
  and likely-broken).
- **Missing SBOM / attestation in release.** No `actions/attest-build-provenance`,
  no `cosign`/`slsa-github-generator`, no SBOM emit step in a release workflow →
  INFO/LOW (maturity nudge, not a vuln).
- **Container base-image pinning.** In `Dockerfile`: `FROM <image>:<tag>` without
  `@sha256:` digest → MEDIUM (overlaps existing hadolint DL3006/DL3007; the
  *provenance* angle is the new framing). `FROM <image>:latest` → HIGH.
  Recommend `trivy image --attestation` / cosign verify in CI.
- **Terraform/OpenTofu module pinning.** `module "x" { source = "<registry>/..." }`
  without a pinned `version =`, or `source` pointing at a `git::` ref that is a
  branch/tag not a commit SHA → MEDIUM. Provider blocks without
  `required_providers { … version = "= x.y.z" }` (pinned, not `>=`) → MEDIUM.
  No `.terraform.lock.hcl` committed → MEDIUM (loses provider checksum pinning).

## Proposed category 10 spec

**Category 10 — Supply Chain & CI/CD Integrity.**

- **File:** `steps/deepdive/cat-10-supply-chain.md`.
- **Fan-out gate:** runs when the partition contains ANY of: a package manifest
  (`package.json`, `pyproject.toml`/`setup.py`, `Cargo.toml`, `*.gemspec`,
  `go.mod`, `pom.xml`/`build.gradle`), a lockfile, a CI workflow
  (`.github/workflows/`, `.gitlab-ci.yml`, `.circleci/`, `Jenkinsfile`,
  `azure-pipelines.yml`), a `Dockerfile`, or Terraform/OpenTofu (`*.tf`).
  Gate reason when absent: `"no package manifests, CI workflows, containers, or IaC in partition"`.
- **What it checks (sub-checks → detection set above):**
  1. Install/lifecycle-hook abuse (§A) — npm/Python/Rust/Ruby/Go.
  2. Lockfile integrity + dependency confusion + typosquatting (§B).
  3. CI/CD workflow injection, unpinned refs, dangerous triggers, OIDC breadth,
     cache poisoning, self-hosted runners, non-GHA CI (§C).
  4. Provenance/publishing posture + base-image & IaC-module pinning (§D).
- **Tools it orchestrates (feeds):**
  - `osv-scanner` — dependency CVEs (already in Phase 4; cross-reference only).
  - `zizmor` — GHA workflow audit (already conditional in Phase 4; consume its
    SARIF, don't duplicate its ~39 rules; add only the §C gaps).
  - `trivy` — image/IaC misconfig + (optional) attestation verify (already in
    bundle).
  - **NEW (recommend adding, all SARIF-or-wrappable):**
    - `lockfile-lint` — resolved-URL/host/HTTPS/integrity validation (§B). Small,
      npm-only, easy wrap.
    - `GuardDog` (DataDog) — Semgrep-rule + metadata heuristics for malicious
      npm/PyPI/Go/RubyGems/GHA packages (install-script, base64-exec, typosquat).
      Best single tool for §A + typosquat; runs offline on vendored deps.
    - `OpenSSF Scorecard` — repo-posture signals (Pinned-Dependencies,
      Dangerous-Workflow, Token-Permissions, Branch-Protection). Use for the
      *project's own* repo, not deps; needs a GitHub token (network — mark
      optional / out-of-pure-static).
    - *Optional/secondary:* `bomber` or `osv-scanner --experimental-licenses` for
      SBOM consumption; **Socket** (CLI/API, network) noted as commercial but the
      reference detector for many of these campaigns — cite, don't bundle.
- **Gates / confidence:** lifecycle-hook + obfuscation match from ≥2 sources
  (e.g. GuardDog rule + own regex) → CONFIRMED. Single regex on `postinstall`
  body → LIKELY. Typosquat-distance only → POSSIBLE.
- **Outputs:** `phase-05-supply_chain-<partition>.jsonl` conforming to
  `lib/finding-schema.json`. Every row carries `properties.category:
  "supply_chain"` (NEW enum value — see Mapping), `cwe` (CWE-829/506/494/1357/94/
  347 as appropriate), and ≥1 OWASP id (map to **ASVS V10 Malicious Code /
  V14 Config**, and **CI/CD-SEC** Top 10 for pipeline findings).
- **OWASP/standards tagging:** prefer OWASP **CI/CD Security Top-10**
  (`CICD-SEC-1` … `CICD-SEC-10`) for pipeline findings — e.g. `CICD-SEC-3`
  (Dependency Chain Abuse), `CICD-SEC-4` (Poisoned Pipeline Execution),
  `CICD-SEC-6` (Insufficient Credential Hygiene). Add these strings to
  `lib/cwe-map.json`/owasp mapping.

## Mapping to the skill

| Recommendation | Phase / file it touches |
|---|---|
| New category 10 (supply chain) | `phase-05-deepdives.md` §5.1 table; new `steps/deepdive/cat-10-supply-chain.md` |
| `supply_chain` category enum value | `lib/finding-schema.json`; SKILL.md artifact-contract note; `properties.category` list |
| CWE additions (829/506/494/1357/347) + CICD-SEC ids | `lib/cwe-map.json` + OWASP map |
| Add `lockfile-lint`, `GuardDog` to scanner bundle (conditional) | `phase-04-scanners.md` (consume SARIF in cat-10) |
| Add `OpenSSF Scorecard` (optional, network) | `phase-04-scanners.md` conditional + `docs/KNOWN-GAPS.md` (network caveat) |
| Consume existing `zizmor` SARIF + add non-GHA CI + OIDC-breadth gaps | `cat-10`, cross-ref `cat-07-deployment.md` (GHA already lives there) |
| Base-image digest pinning (provenance framing) | overlaps `cat-07-deployment.md` (hadolint) — cat-10 adds the provenance lens |
| Terraform/OpenTofu module + provider + lockfile pinning | `cat-07-deployment.md` (Terraform already there) + cat-10 supply-chain view |
| Pin the skill's *own* recommended actions/tools to SHAs | `docs/` + any CI examples in `docs/ci-examples/` (dogfooding after Trivy incident) |
| Provenance "good posture" positive signals | `cat-10`; report rendering in `phase-07-synthesis.md` |

Note: deployment posture (cat-07) already touches Dockerfile/k8s/Terraform/GHA.
Cat-10 should **own the supply-chain dimension** (provenance, pinning-as-integrity,
malicious-dependency) and *reference* cat-07 for the misconfig dimension, to
avoid double-reporting. Define the boundary explicitly in both files.

## Prioritized recommendations

Effort: S ≤ ½ day, M ≈ 1-2 days, L ≈ 3-5 days.

- **P0 / M — Add category 10 with the §A lifecycle-hook + §B lockfile/dep-
  confusion + §C CI-injection checks.** This is the admitted gap and the exact
  surface every 2026 campaign exploited. Even a regex-first MVP catches
  Shai-Hulud, CanisterSprawl, TrapDoor, and the dep-confusion class. Rationale:
  highest threat-coverage-per-effort; the skill is *static*, and these are
  static signals.
- **P0 / S — Pin the skill's own recommended/used GitHub Actions to commit
  SHAs and document base-image digest pinning.** The Trivy/Cisco incident (a
  skill-bundled scanner) makes "do as we say" indefensible if the skill's own
  CI is unpinned. Dogfood credibility + concrete supply-chain hardening.
- **P1 / S — Add the `supply_chain` category enum + CWE/CICD-SEC map entries.**
  Mechanical but required for SARIF rows, GitHub Security tab, and Phase-7
  aggregation to accept category-10 findings. Do alongside P0.
- **P1 / S — Wrap `lockfile-lint`** (npm resolved-URL/host/integrity). Tiny,
  high-precision, directly counters lockfile injection + dep-confusion resolution
  tampering. Network-free.
- **P1 / M — Integrate `GuardDog`** as a conditional Phase-4 scanner (npm/PyPI/
  Go/RubyGems/GHA). Best single off-the-shelf detector for §A install-script +
  base64-exec + typosquat heuristics; offline; Semgrep-backed (the skill already
  ships semgrep). Feeds cat-10 with second-source corroboration → CONFIRMED.
- **P1 / S — Add provenance/publishing-posture signals** (OIDC trusted publishing
  vs. long-lived `NPM_TOKEN`; `--provenance`; attestation steps). Cheap positive/
  negative signal; aligns with the Dec-2025 classic-token revocation reality.
- **P2 / S — OIDC trust-policy-breadth flag + non-GHA CI script-injection
  checks.** zizmor gaps. Trust-policy is workflow-side-only statically (can't see
  cloud IAM) → emit as POSSIBLE + recommend review. Non-GHA CI extends coverage
  to GitLab/CircleCI/Jenkins shops.
- **P2 / M — Optional `OpenSSF Scorecard` integration** for the audited repo's
  own posture. Defer because it needs a GitHub token (network) — conflicts with
  the pure-static promise; gate behind an explicit opt-in flag and document in
  `KNOWN-GAPS.md`.
- **P2 / S — Typosquatting heuristic (Levenshtein vs. top-N).** High FP; ship as
  POSSIBLE-only or lean on GuardDog. Low urgency given GuardDog covers it.

## Sources

- Wiz — Shai-Hulud 2.0 ongoing attack (payloads `setup_bun.js`/`bun_environment.js`,
  preinstall, `SHA1HULUD` runner, scale, IOCs): https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
- Datadog Security Labs — Shai-Hulud 2.0 analysis (hashes, `discussion.yaml`,
  TruffleHog abuse): https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/
- Endor Labs — Shai-Hulud 2 / Bun runtime: https://www.endorlabs.com/learn/shai-hulud-2-malware-campaign-targets-github-and-cloud-credentials-using-bun-runtime
- Unit42 — original Shai-Hulud + Nov 26 update: https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
- CISA — npm ecosystem supply-chain alert (Shai-Hulud wave 1): https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
- TheHackerNews — Trivy GitHub Action breach / TeamPCP / CVE-2026-33634: https://thehackernews.com/2026/03/trivy-security-scanner-github-actions.html
- BleepingComputer — Cisco source code stolen via Trivy-linked breach (300+ repos): https://www.bleepingcomputer.com/news/security/cisco-source-code-stolen-in-trivy-linked-dev-environment-breach/
- Legit Security — Trivy compromise playbooks: https://www.legitsecurity.com/blog/the-trivy-supply-chain-compromise-what-happened-and-playbooks-to-respond
- Datadog Security Labs — LiteLLM/Telnyx PyPI (TeamPCP), `.pth` startup hook, IOCs: https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
- StepSecurity — CanisterSprawl / `pgserve` / ICP-canister C2: https://www.stepsecurity.io/blog/pgserve-compromised-on-npm-malicious-versions-harvest-credentials
- GitGuardian — three campaigns in 48h (npm/PyPI/Docker, CanisterSprawl naming): https://blog.gitguardian.com/three-supply-chain-campaigns-hit-npm-pypi-and-docker-hub-in-48-hours/
- TheHackerNews — TrapDoor cross-ecosystem (`build.rs`/postinstall/import-time): https://thehackernews.com/2026/05/trapdoor-supply-chain-attack-spreads.html
- TheHackerNews — Poisoned Ruby gems + Go modules (BufferZoneCorp, `extconf.rb`): https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html
- Microsoft Security Blog — npm dependency-confusion campaign (fake infra URLs, inflated versions, `X-Secret` header): https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/
- TheHackerNews — malicious Rust crates `faster_log`/`async_println`: https://thehackernews.com/2025/09/malicious-rust-crates-steal-solana-and.html
- Wiz — tj-actions/changed-files (CVE-2025-30066), mutable-tag re-point: https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066
- GitHub Advisory GHSA-mrrh-fwg8-r2c3 (CVE-2025-30066): https://github.com/advisories/ghsa-mrrh-fwg8-r2c3
- CISA — tj-actions + reviewdog/action-setup advisory: https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction
- zizmor — audit rules reference (full ~39-rule list, gaps): https://docs.zizmor.sh/audits/
- GitHub Changelog — Actions SHA-pinning enforcement policy (Aug 2025): https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/
- Socket — npm revokes classic tokens / OIDC trusted publishing migration: https://socket.dev/blog/npm-revokes-classic-tokens
- npm Docs — trusted publishing (OIDC, auto-provenance): https://docs.npmjs.com/trusted-publishers/
- Sigstore Blog — cosign verification of npm provenance / GitHub attestations: https://blog.sigstore.dev/cosign-verify-bundles/
- DataDog GuardDog — README / heuristics (install-script, base64-exec, typosquat): https://github.com/DataDog/guarddog/blob/main/README.md
- DataDog GuardDog 1.0 release (npm support, CI integration): https://securitylabs.datadoghq.com/articles/guarddog-1-0-release/
- lirantal/lockfile-lint — resolved-URL/host/integrity validation: https://github.com/lirantal/npm-security-best-practices
- OpenSSF Scorecard — checks (Pinned-Dependencies, Dangerous-Workflow, Token-Permissions): https://openssf.org/projects/scorecard/
- BoostSecurity — Terraform Registry tag-attack supply-chain risks: https://boostsecurity.io/blog/erosion-of-trust-unmasking-supply-chain-vulnerabilities-in-the-terraform-registry
- OpenTofu issue #1545 — registry module verification / supply chain: https://github.com/opentofu/opentofu/issues/1545
- StepSecurity — SHA-pinning complete guide: https://www.stepsecurity.io/blog/pinning-github-actions-for-enhanced-security-a-complete-guide
- buildmvpfast — GitHub Actions supply-chain hardening guide 2026 (immutable releases, lock files): https://www.buildmvpfast.com/blog/github-actions-supply-chain-security-hardening-guide-2026
