# CyberGym-E2E — read + applicable lessons (2026-06-14)

Source: **CyberGym-E2E: Scalable Real-World Benchmark for AI Agents' End-to-End
Cybersecurity Capabilities** — Shi, Rheem, Jiang, … Wenbo Guo, Dawn Song
(UC Berkeley). arXiv **2606.04460v1**. Successor to CyberGym (arXiv 2506.02548,
2025), which `docs/research/07-benchmarks-cyber-gyms.md` cited.

> **Correction to report 07.** Report 07 classed CyberGym as "offensive-leaning,
> wrong instrument, none-as-scored." That holds for *scoring a static auditor* —
> CyberGym-E2E does not benchmark static analysis. But the E2E paper explicitly
> covers the **defensive** half (patch generation + functional-test validation),
> and it benchmarks the **same harnesses we run on** (Claude Code, Codex, Gemini
> CLI, OpenHands). Its method + failure-analysis are directly transferable to
> our Phase-5 deep-dive sub-agents. Report 07 under-rated it.

## What it is

- **Task:** an agent gets a vulnerable repo + build env and must produce a
  crashing PoC **and** a patch, scored by a 4-stage oracle: **S1** PoC crashes
  the unpatched binary → **S2** patch kills that crash → **S3** the repo's own
  unit tests still pass → **S4** the patch fixes the *intended* bug (matches the
  ground-truth PoC), not a different one.
- **Scale:** 920 verified vuln/fix tasks across 139 OSS-Fuzz projects, mostly
  **C/C++ memory-safety**. Built by binary-searching OSS-Fuzz for the fix
  commit, validating the PoC reproduces pre-patch and fails post-patch,
  extracting developer unit tests, and expert-validating coverage.
- **Verification oracle:** AddressSanitizer/MemorySanitizer crash + dev tests.
  Reward-hacking guards: test files are read-only to the agent; S4 detects
  "patched a different bug"; memorization analysis showed no pre/post-cutoff
  difference (p > 0.1).
- **Not a static-auditor benchmark:** detection is implicit via exploitation;
  there is no metric for vulnerability *localization* or *classification*.

## Key empirical findings (the useful part for us)

- **Vulnerability *discovery* is the bottleneck**, not patching. End-to-end S1
  (find + PoC) ≈ 25–30% across frontier models; patch-only S3 ≈ 82% (Opus 4.5)
  when the PoC + stack trace are handed over.
- **Agent failure taxonomy** (from ~200 sampled trajectories):
  1. **Context-flooding → premature abandonment** — verbose tool output / large
     files fill the window; agents quit after 2–3 failed hypotheses. Mitigated
     by *targeted grep/ripgrep + active task-tracking*. **Claude Code's
     targeted-file strategy beat OpenHands' full-file loading** (OpenHands
     burned 2000+ tokens per file read).
  2. **Analysis failures** — incomplete data-flow tracing; domain-expertise
     gaps.
  3. **Ineffective exploration** — random input attempts instead of systematic.
- **Success pattern:** keyword parse → targeted grep → code-path analysis →
  minimal PoC → iterative refine.
- **S3↔S4 gap** (Opus 4.5: 19.2% vs 7.6%): agents routinely fix a *different*
  real bug than intended — "found A bug here" ≠ "found THE bug."
- **Budget:** ~$10 / 90-min per task; diminishing returns after 60 min
  (30→60 big gains, 60→90 small).

## What we take into v2.2 (and what we don't)

| Lesson | Our application | Story |
|---|---|---|
| Context-flooding kills agents; targeted grep + task-tracking wins | Harden Phase-5 sub-agent prompts: grep-to-the-surface-row, read handler ±N lines, never whole files | A1 |
| Analysis failures = incomplete data-flow tracing | Taint categories (cat-02, cat-08) must demand an explicit source→sink trace; `confidence: POSSIBLE` when incomplete | A1 |
| Pre-patch code = labeled TP; post-patch code = labeled TN | Document the patched-commit-as-decoy method to mint precision fixture pairs (the v3 decoy mechanism already shipped in v2.1) | A2 |
| S3↔S4: "found A bug" ≠ "found THE bug" | Add a semantic-correctness check to the scorecard (mechanism vs fixture, not just file+cwe) — addresses KNOWN-GAPS #1 | A3 |
| $10 / 90-min, diminishing returns after 60 min | Budget anchor for any future live/GHA E2E (doc note) | A4 |

**Not taken:** adopting CyberGym-E2E as a scored benchmark (it's exploit/patch,
not static detection); its C/C++ memory-safety corpus wholesale (off our
web/app-sec axis — we borrow the *method*, seed with web-framework CVE pairs);
auto-patch-with-functional-tests as a skill feature (future).

Plan: `docs/EPIC-v2.2-cybergym.md`.
