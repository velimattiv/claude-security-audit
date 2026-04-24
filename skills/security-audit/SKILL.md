---
name: security-audit
description: "Comprehensive polyglot security audit. Discovers the attack surface across 60+ frameworks, runs a SARIF scanner bundle, executes 9 parallel deep-dive categories, and produces an OWASP-methodology-tagged report. Invoke when the user asks to 'run security audit', 'security audit', 'audit security', or passes args like 'mode: delta' / 'scope: services/api' / 'categories: crypto,mitm,secrets'. Typical run 15-60 minutes (full) or 2-5 minutes (delta)."
---

Follow the instructions in [workflow.md](workflow.md).

The skill version is in [VERSION](VERSION). Always stamp it into every artifact
you emit so the user can reason about cross-run comparability.
