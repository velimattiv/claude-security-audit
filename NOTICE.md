# Third-Party Notices

This project includes work from third parties. Their copyright notices and
license terms are reproduced below and in the referenced files.

## Adversarial Review Prompt

Location: `skills/security-audit/vendored/adversarial-review/`

Derived from the `bmad-review-adversarial-general` skill in
[bmad-method](https://github.com/bmad-code-org/BMAD-METHOD) (v6.3.0),
authored by BMad Code, LLC and released under the MIT License.

The vendored copy reproduces the upstream prompt unmodified. See
`skills/security-audit/vendored/adversarial-review/LICENSE` for the
full MIT license text applicable to that file.

## CWE IDs and Names

Location: `skills/security-audit/lib/cwe-map.json`

Common Weakness Enumeration identifiers and names are reproduced from
the Common Weakness Enumeration (CWE™) maintained by The MITRE
Corporation. CWE is licensed under CC BY 4.0 (Creative Commons
Attribution 4.0 International); see
https://cwe.mitre.org/about/termsofuse.html. The `cwe-map.json` file
reproduces a curated subset of CWE IDs and names relevant to
application-security audits; the canonical definitions live at
https://cwe.mitre.org/.

## Scanner Bundle (reference only — not vendored)

The following security scanners are invoked via `scripts/install-scanners.sh`
and `steps/phase-04-scanners.md`. Their binaries are **not** bundled
with this skill; users install them locally. Listed here for license
transparency:

- **semgrep** — Semgrep Community Edition, LGPL-2.1 CLI + community
  rulesets under various permissive licenses.
- **osv-scanner** — Apache-2.0, Google.
- **gitleaks** — MIT, Zachary Rice.
- **trufflehog** — AGPL-3.0, Truffle Security Co.
- **trivy** — Apache-2.0, Aqua Security.
- **hadolint** — GPL-3.0, Lukas Martinelli.
- **brakeman** — MIT, Justin Collins (conditional).
- **checkov** — Apache-2.0, Bridgecrew (conditional).
- **kube-linter** — Apache-2.0, StackRox (conditional).
- **govulncheck** — BSD-3-Clause, Go team (conditional).
- **psalm** — MIT, Vimeo (conditional).
- **zizmor** — MIT, William Woodruff (conditional).

Each tool's license terms apply to the installed binary; this skill's
MIT license covers only the wrapper code and instructions.

## ASVS Category List

Location: `skills/security-audit/lib/asvs-l2.md`

The OWASP Application Security Verification Standard (ASVS) categories
are published by the OWASP Foundation under CC BY-SA 4.0. See
https://github.com/OWASP/ASVS. `asvs-l2.md` restates category topics
for sub-agent prompt seeding; canonical sub-item text lives at the
OWASP repository linked above.
