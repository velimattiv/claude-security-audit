# Research round — 2026-06-14

Source material for the v2.x capability refresh. Seven parallel research
agents, each scoped to one angle, run on 2026-06-14 to surface what is new
or changed in the security-audit threat/tooling/methodology landscape since
the last research round (2026-04-24, the basis for `docs/V2-SCOPE.md`).

This directory closes the provenance gap noted at `docs/V2-SCOPE.md` ("Full
research reports will be committed to `docs/research/` during M1") — the
v2.0.0 source reports were never committed; these are.

| # | Report | Angle | Skill surface |
|---|--------|-------|---------------|
| 01 | [modern-exploits-2026](01-modern-exploits-2026.md) | Exploit classes & notable CVEs since 2026-01 | cat-01/02/04/08 |
| 02 | [supply-chain-cicd](02-supply-chain-cicd.md) | Software supply chain & CI/CD integrity | **new category** |
| 03 | [ai-agentic-mcp](03-ai-agentic-mcp.md) | AI / agentic / MCP security | cat-09 + **new category** |
| 04 | [scanner-tooling-landscape](04-scanner-tooling-landscape.md) | Scanner bundle refresh (opengrep, pins, new entrants) | Phase 4 |
| 05 | [methodology-standards](05-methodology-standards.md) | Standards refresh (OWASP Top 10:2025, CWE Top 25, SSDF) | Phase 6/7 spine |
| 06 | [cloud-iac-container-nhi](06-cloud-iac-container-nhi.md) | Cloud-native / IaC / container / NHI secrets | cat-06/07 |
| 07 | [benchmarks-cyber-gyms](07-benchmarks-cyber-gyms.md) | Benchmarks & cyber gyms to measure capability | E2E / precision harness |

The synthesized, severity-ranked backlog drawn from these reports lives in
[`../ROADMAP.md`](../ROADMAP.md) under "Research round — 2026-06-14".

## Caveat for implementers

Several 2026 CVE IDs cited across these reports are flagged by their authoring
agent as "verify on NVD before shipping," and report 01 self-flagged one ID
(`CVE-2026-23993`) as **fabricated**. **Verify every CVE identifier against
NVD/primary advisory before encoding it into a detection pattern, fixture, or
user-facing doc.** The *bug classes* are well-sourced; individual identifiers
are not all confirmed.
