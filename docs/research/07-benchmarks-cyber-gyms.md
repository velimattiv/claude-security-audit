# Benchmarks & "Cyber Gyms" for Measuring Audit Capability

> Research note for the `/security-audit` skill refresh (repo `claude-security-audit`, v2.0.6). Authored 2026-06-14.
> **Scope:** how to measure this skill's *capability and quality objectively* — closing the documented measurement gap that the current E2E checks **coverage** (did we find the 12 fixtured Juice Shop bugs?) but never **precision** (false-positive rate, precision/recall/F1). Verified against primary repos/papers; see **Sources**.

## TL;DR

- **The gap is real and the fix is well-trodden.** The E2E today is a coverage gate (12 fixtures, "did we find them?"). Every credible SAST evaluation adds a **labeled negative set** so you can count false positives and compute precision/recall/F1. The reference methodology is **OWASP Benchmark's** TP/FP scoring (Youden Index → 0–100 score). Adopt the *method*, not necessarily the *corpus*.
- **The single biggest constraint is polyglot.** This skill audits JS/TS/Python/Go/PHP/Java/etc. Almost every labeled detection corpus is **single-language** (OWASP Benchmark = Java + new Python; Juliet = C/C++/Java; Big-Vul/Devign/D2A/DiverseVul = C/C++; SecurityEval = Python). The **only genuinely multi-language labeled corpus is CVEfixes** (CC-BY-4.0) — and even it labels only fix-touched functions.
- **OWASP Benchmark is the right precision yardstick to *start* with** — it's purpose-built for scoring detectors (TP **and** FP cases), now has a Python v0.1 (1,230 cases) alongside Java v1.2 (2,740 cases, 11 categories), GPL-2.0. But it's synthetic and the skill is LLM-driven, so treat its score as a *calibration signal*, not the headline metric.
- **Best near-term ROI is a precision-aware E2E**, not a new external corpus: add **decoy/"should-NOT-flag" expectations** to the existing fixture mechanism so a run that flags safe code is penalised. This converts the coverage gate into a precision/recall scorecard with no new infrastructure.
- **For new E2E targets, the standout is OWASP crAPI** — it is polyglot (Java/Spring + Go + Python + TS), microservices-in-Docker, and is built around **BOLA/JWT/token** flaws plus a weak container/k8s posture. It hits *three* currently-untested categories at once (`token_scope`, `deployment`, partially `mitm`) and adds Java + Go. **DVWA** (PHP, GPL-3.0) is the cheapest polyglot win the repo already planned.
- **Agentic "cyber gyms" are mostly the wrong instrument.** Cybench, NYU CTF Bench, AutoPenBench, InterCode-CTF, and (effectively) CyberGym measure **offensive** capability — CTF solving, live pentest, PoC synthesis. None of that scores a static, defensive, SARIF-emitting auditor. **Only Meta CyberSecEval** has a defensively-relevant piece, and even there the reusable artifact is its **Insecure Code Detector** (weggli + semgrep + regex, ~189 patterns / 50 CWEs / 8 languages) — not its headline instruct/autocomplete *generation* scores.
- **Recommended stack:** (P0) precision-aware E2E with decoys + a CVEfixes-derived polyglot micro-benchmark for precision/recall; (P1) add crAPI and DVWA as E2E targets to cover untested categories/languages; (P2) optional OWASP Benchmark Java/Python run as an external calibration check and mine CyberSecEval's ICD rule corpus.

---

## Three families

### Family 1 — Labeled benchmarks & datasets for precision/recall

These give you **ground-truth labels** (a location is vulnerable or not) so you can count TP/FP/FN. Two sub-types: **synthetic scored suites** (OWASP Benchmark, Juliet) built to evaluate detectors, and **real-world labeled corpora** (CVEfixes, Big-Vul, Devign, D2A, SecurityEval, DiverseVul) mined from CVE fixes.

| Name | What it measures | Languages / scope | License | Last updated | Fit for this skill |
|---|---|---|---|---|---|
| **OWASP Benchmark** | Detector accuracy with explicit TP **and** FP cases; scores via TPR/FPR → **Youden Index** → 0–100 | Java v1.2 = **2,740** cases, **11** vuln categories; **Python v0.1 = 1,230** cases (v1.0 planned early 2026) | GPL-2.0 | Java v1.2 since 2016 (still current); Python v0.1 new, 2025–26 | **High (as a method); medium (as a corpus).** The canonical precision/recall methodology; synthetic so it overstates real-world precision, and only Java+Python today |
| **NIST SARD / Juliet** | Per-CWE labeled flaw corpus (good + bad variants) | Juliet **C/C++ 1.3** (~118 CWEs) and **Java 1.3** (~112 CWEs); SARD is a broader case DB | NIST public-domain (US Gov work) | Juliet 1.3 (2017); SARD platform actively maintained | **Medium.** Per-CWE granularity is great; C/C++/Java only, very synthetic, no JS/TS/Go/PHP |
| **CVEfixes** | Real CVE fix commits, before/after at file & method granularity | **Multi-language** (inherits real OSS: Python, JS, Java, Go, PHP, C, …) | code **MIT**, data **CC-BY-4.0** | **v1.0.8, 2024-07-30** (CVEs to Jul 2024) | **Highest of the real-world sets** — the only true multi-language corpus; labels only fix-touched functions (FN/FP risk if used naively) |
| **Big-Vul** | Function-level vuln/non-vuln from CVE fixes | **C/C++ only** (188,636 functions; 3,754 CVEs) | MIT | repo 2021 (paper MSR 2020) | **Low** for this skill — clean license, widely cited, but C/C++ only |
| **Devign** | Manually-labeled function vuln/non-vuln (high-quality labels) | **C only** (4 projects; public subset = FFmpeg+QEMU) | **unverified** (no SPDX; subset via CodeXGLUE) | paper 2019 | **Low** — best label quality, but C-only and partial release |
| **D2A** | Static-analyzer (Infer) issues confirmed by differential analysis | **C/C++ only** (millions of samples) | code Apache-2.0; data **CDLA** (variant unverified) | repo archived 2024-07-22 | **Low** — labels are analyzer-derived (noisy oracle), C/C++ only |
| **SecurityEval** | Whether an LLM **generates** insecure code (CWE-mapped prompts) | **Python only** (130 samples, 75 CWEs) | **unverified** (no license tag) | paper 2022 | **Not fit for detection** — it's a *generation* eval, the inverse of this skill's job |
| **DiverseVul** *(bonus)* | Largest project-diverse function-level vuln corpus | **C/C++ only** (18,945 vuln + 330,492 non-vuln; 150 CWEs) | **none declared** (Google-Drive distribution) | repo 2024-10-23 (paper RAID 2023) | **Low** — C/C++ only and no license = redistribution-ambiguous |

**Read-through.** For a polyglot LLM auditor, the field collapses fast: synthetic scored suites (OWASP Benchmark, Juliet) give you a clean TP/FP methodology but in only Java/C/C++/Python; the real-world corpora are overwhelmingly C/C++ except **CVEfixes**. SecurityEval is a different instrument entirely (it measures secure-code *generation*). So the practical play is: **borrow OWASP Benchmark's scoring math**, and **build a small multi-language precision/recall set from CVEfixes** (and the skill's own decoys), rather than adopting any single corpus wholesale.

### Family 2 — Vulnerable-by-design apps as E2E targets

These fit the existing `--target` fixture mechanism (clone at a pinned tag, run `/security-audit`, assert against a per-target `tests/e2e/<target>-fixture.json`). Chosen to cover **languages beyond JS/TS** and the skill's **currently-untested categories** (`deployment`, `mitm`, `token_scope`).

| Name | What it exercises | Languages / scope | License | Last updated | Fit for this skill |
|---|---|---|---|---|---|
| **OWASP crAPI** | **BOLA / broken auth / JWT / mass-assignment** + microservice & container misconfig | **Java/Spring + Go + Python + TypeScript**; Docker-Compose / k8s microservices | Apache-2.0 | **v1.1.6, 2025-09-30** | **Best single new target.** Hits `token_scope`, `deployment`, partial `mitm`; adds Java + Go in one repo |
| **DVWA** | SQLi, XSS, command injection, LFI/RFI, CSRF, file upload (graded low/med/high/impossible) | **PHP** + MariaDB/MySQL | GPL-3.0 | release "Vulnerable APIs", **2025-01-29** | **High & cheapest.** The repo already names DVWA for PHP; "impossible" level gives ready-made FP decoys |
| **OWASP NodeGoat** | OWASP Top-10 in Express/Node | **JavaScript / Node** | Apache-2.0 | maintained | **Low** — same JS/TS surface as Juice Shop; little new coverage |
| **OWASP RailsGoat** | OWASP Top-10 in Rails (mass assignment, etc.) | **Ruby on Rails** | unverified (OWASP) | Rails 8 (2024+) | **Medium** — adds Ruby, a language the skill otherwise never sees in E2E |
| **OWASP DVGA** | GraphQL-specific flaws (injection, DoS, introspection abuse) | **Python (Flask + Graphene)** | MIT | maintained | **Medium** — only if GraphQL is a stated audit target; niche |
| **OWASP WebGoat** | Guided OWASP lessons (injection, auth, XXE, deserialization) | **Java / Spring Boot** | GPL-2.0 | **v2025.3** (2025) | **Medium** — adds Java, but lessons are runtime-interactive; static ground truth is fiddlier than crAPI |
| **OWASP crAPI ⟂ VAmPI** | API flaws with a **vuln on/off switch** (SQLi, BOLA, JWT, mass assignment) | **Python / Flask** | unverified | maintained (`erev0s/VAmPI`) | **Medium** — the on/off switch is *ideal for FP testing*, but Python-only and overlaps crAPI's API focus |
| **Vulhub** | Real-CVE reproductions (one dir per CVE) | **200+ CVEs**, many stacks (Django, Laravel, Spring, GitLab, …) | MIT | active (CVEs to 2026) | **Low for THIS skill.** It reproduces *running-service* CVEs for exploitation, not source-with-known-source-bugs; poor fit for a static auditor's fixture model |

**Read-through.** Vulhub is the famous name but the **wrong shape** here — it's a dynamic-exploitation gym, not a labeled-source corpus, so there's no clean static ground truth to assert against. The targets that move the needle are the ones that (a) add languages and (b) hit untested categories: **crAPI** is the unique multi-hit (Java+Go+Python+TS, token/deployment/mitm), and **DVWA** is the low-effort PHP win the roadmap already committed to. RailsGoat (Ruby) and WebGoat (Java) are good *second-wave* additions if language breadth is the goal.

### Family 3 — Agentic "cyber gyms"

Built to measure **agents acting in environments**. The honest finding: these measure **offensive** capability and are largely **irrelevant** to a static, defensive auditor.

| Name | What it measures | Tasks | Offensive vs defensive | License | Last updated | Fit for this skill |
|---|---|---|---|---|---|---|
| **Cybench** (Stanford) | Agentic CTF solving in a live shell (capture the flag) | 40 CTF tasks, 6 categories | **Offensive** | Apache-2.0 | 2024–25 | **None** — exploitation, not code-reading |
| **NYU CTF Bench** | Automated CTF solving (function-calling agents) | 200 CSAW challenges | **Offensive** | GPL-2.0 | release 2025-02-06 | **None** — same shape, larger |
| **CyberGym** (UC Berkeley) | Real-CVE **reproduction** — agent produces a crashing PoC | 1,507 vulns / 188 projects | **Offensive-leaning** | Apache-2.0 | paper 2025; v3 2026 | **None as scored** (it gives pre-patch C/C++ source, so the *corpus* could seed a C/C++ detection set — but the task is PoC synthesis, not detection) |
| **AutoPenBench** | Automated pentest vs live Docker containers | 36 tasks (24 in-vitro + 12 CVE) | **Offensive** | MIT | 2024 | **None** — furthest from static analysis |
| **Meta CyberSecEval** (PurpleLlama) | Mixed: insecure-code **generation** (instruct/autocomplete) + MITRE assist + prompt injection + exploitation CTFs (+ v4 AutoPatch) | many; insecure-code built from ~189 patterns / 50 CWEs / 8 langs | **Mixed** — most offensive; insecure-code is defensive-*adjacent* | MIT | v3 2024; v4 2025 | **Partial — the only relevant one.** Reusable artifact = its **Insecure Code Detector** (weggli+semgrep+regex, CWE-mapped, multi-language) and v4 **AutoPatch**; the instruct/autocomplete *scores* measure generation, not detection |
| **InterCode-CTF** (Princeton) | Agentic CTF solving in a Bash/Python shell | 100 picoCTF tasks | **Offensive** | MIT | 2023 | **None** — easiest-level CTF, precursor to Cybench |

**Read-through.** Scoring a defensive static auditor on an offensive CTF gym is a category error: those benchmarks reward recon → exploit → flag-capture, a loop this skill doesn't run. The one defensible touch-point is **CyberSecEval's Insecure Code Detector** — it is conceptually a sibling of this skill (static, rule-based, CWE-mapped, 8 languages), so its **rule corpus and CWE taxonomy are mine-able** to seed/expand the skill's grep-pattern catalog and to cross-check CWE tagging. v4's **AutoPatch** is also defensive and worth watching. Everything else in this family should be cited as "out of scope — measures offensive agentic capability."

---

## Recommended scoring harness

**Goal:** turn the E2E from a coverage gate into a **precision/recall scorecard**, with the least new infrastructure. The blocker is not tooling — `assertions.py` already matches findings by `(file_pattern, cwe, category)`. The missing ingredient is a **labeled negative set** so false positives become countable.

### 1. Add a labeled negative ("should-NOT-flag") set — the core change
Today every expectation is a positive (a bug that must be found). Add a parallel block of **decoys**: locations in the target that are *safe* and must **not** be flagged with a given category/CWE.

- Extend `tests/e2e/expected-findings.json` (or per-target fixtures) with a sibling array, e.g. `negative_expectations[]`, each `{id, file_pattern, forbidden_cwe | forbidden_category, rationale}`. Reuse the existing schema-versioning convention (this is `schema_version: 3`).
- Source decoys from three places: (a) the **"impossible"/secure-level** code in DVWA and the **vuln-off switch** in VAmPI — these are *designed* to be the safe twin of a vuln; (b) hardened code in the target (e.g. Juice Shop v19.2.1's distroless Dockerfile — flagging it as a deployment HIGH is a FP); (c) hand-picked safe handlers adjacent to the fixtured bugs.

### 2. Define TP / FP / FN against those labels
In `assertions.py`, after `collect_all_findings`, classify every emitted SARIF result:
- **TP** = matches a positive expectation `(file_pattern, cwe∈{cwe}∪alternate_cwes, category∈{category}∪alternate_categories)`.
- **FN** = a positive expectation with no matching finding (today's failure mode).
- **FP** = a finding that (a) matches a `negative_expectation`'s forbidden tuple, **or** (b) lands in a target region declared "clean" with a severity ≥ MEDIUM and matches no positive. Keep an **`unscored`** bucket for findings outside labeled regions so you don't over-penalise legitimate extra finds — precision is computed only over labeled territory.

### 3. Compute and gate on the metrics
- **Precision** = TP / (TP + FP); **Recall** = TP / (TP + FN); **F1** = 2·P·R / (P+R).
- Optionally emit the **OWASP-Benchmark-style score** per category: TPR − FPR (Youden), so results are comparable to the SAST literature.
- Write a `tests/e2e/scorecard.json` artifact per run (per-category and overall P/R/F1 + TP/FP/FN counts) and a human `scorecard.md`. Gate the E2E on **floors** (e.g. recall ≥ 0.9 on hard fixtures, precision ≥ 0.8 on labeled regions) rather than "all 12 found" — the floors are the new contract.

### 4. Add an external calibration run (optional, decoupled from the gate)
A `scripts/run-precision-bench.sh` that runs the skill's deep-dives over **OWASP Benchmark (Java v1.2 / Python v0.1)** and/or a **CVEfixes-derived polyglot slice**, then scores with the same TP/FP code. This is a *calibration* signal (synthetic-precision number, comparable to published SAST tools) — keep it out of the blocking E2E because it's slow and synthetic, but track it across skill versions to catch precision drift the Juice Shop fixtures can't see (closes Known-Gap #4).

**What lands in `tests/e2e/`:** `negative_expectations[]` in the fixtures (schema v3); a `score_findings()` + metrics block in `assertions.py`; `scorecard.json` / `scorecard.md` emitters; and (decoupled) `scripts/run-precision-bench.sh` + a CVEfixes-slice loader.

---

## Recommended next E2E targets

Ranked. Each adds languages and/or untested categories the Juice Shop fixture cannot reach (`deployment`, `mitm`, `token_scope`).

1. **OWASP crAPI** — *highest value.* One repo covers **three untested categories** (`token_scope` via JWT/BOLA, `deployment` via its intentionally weak Docker/k8s setup, partial `mitm` via inter-service calls) and adds **Java/Spring + Go + Python**. Apache-2.0, actively maintained (v1.1.6, 2025-09-30), pin-able tag. Effort to build a fixture is **M** (microservices = more files to map), but the category/language payoff is unmatched. *This is the target that retires the most roadmap debt.*
2. **DVWA** — *lowest-effort, already planned.* Adds **PHP**, the repo's own roadmap names it, GPL-3.0, recent release (2025-01-29). Its **graded levels** are a built-in precision testbed: "impossible" code is the safe twin of "low" code, so a single file yields both a positive and a decoy. Effort **S**.
3. **OWASP RailsGoat** — *language-breadth pick.* Adds **Ruby/Rails**, which no current or above target covers. Good OWASP-Top-10 ground truth (mass assignment, etc.). Effort **S–M**. Choose this third if the priority is *language* coverage over *category* coverage.
4. **VAmPI** *(or WebGoat)* — *precision-specialist alt.* VAmPI's **vuln on/off switch** is the cleanest decoy generator of any target (run twice; off-mode findings are FPs). Python/Flask, so it overlaps crAPI's API focus — pick it only if you want a dedicated FP-rate target. WebGoat (Java/Spring, GPL-2.0, v2025.3) is the alternative if you'd rather double down on Java. Effort **M**.

**Explicitly *not* recommended:** **NodeGoat** (no new coverage vs Juice Shop) and **Vulhub** (dynamic-exploitation gym; wrong shape for a static fixture).

---

## Prioritized recommendations

| Pri | Recommendation | Effort | Rationale |
|---|---|---|---|
| **P0** | Add `negative_expectations[]` (decoys) to the fixture schema (v3) and a TP/FP/FN + precision/recall/F1 scorer to `assertions.py`; emit `scorecard.json`/`.md`; gate on precision/recall **floors** | **M** | Directly closes the documented precision gap with **no new external corpus or infra** — reuses the existing matcher. Highest value-to-effort in the whole plan |
| **P0** | Seed initial decoys from **Juice Shop's hardened Dockerfile** + a handful of safe handlers, so the very first scored run has a non-trivial FP denominator | **S** | Without decoys, precision is undefined; this is the minimum to make the scorer meaningful on day one |
| **P1** | Add **DVWA** (PHP) as the second E2E target with its own fixture + decoys from "impossible" level | **S** | Cheapest polyglot win; already on the roadmap; graded levels give free positive/negative pairs |
| **P1** | Add **OWASP crAPI** as the third target | **M** | Retires the most roadmap debt: `token_scope` + `deployment` + partial `mitm`, plus Java + Go, in one repo |
| **P2** | Build a **CVEfixes-derived polyglot micro-benchmark** (a curated few-hundred-function slice across JS/TS/Python/Go/PHP/Java) + `scripts/run-precision-bench.sh`, scored with the P0 code; track across versions | **L** | The only path to a *real-world, multi-language* precision/recall number; calibration signal, kept out of the blocking gate (slow); closes Known-Gap #4 |
| **P2** | Add an **OWASP Benchmark (Java v1.2 / Python v0.1)** calibration run for literature-comparable Youden scores | **M** | Lets the skill report a number directly comparable to published SAST tools; synthetic, so calibration-only |
| **P2** | Mine **CyberSecEval's Insecure Code Detector** rule corpus + CWE taxonomy to cross-check the skill's grep-pattern catalog and CWE tagging; track v4 **AutoPatch** | **S** | The one genuinely reusable artifact from the agentic-gym literature; defensive-relevant, multi-language, CWE-mapped |
| **P2** | Add **RailsGoat** (Ruby) as a fourth target for language breadth | **S–M** | Only if language coverage beyond JS/TS/PHP/Java/Go/Python is a goal; Ruby is otherwise unrepresented |

**Deliberately deprioritised / rejected:** scoring against any **offensive CTF gym** (Cybench, NYU CTF Bench, AutoPenBench, InterCode-CTF, CyberGym) — wrong instrument for a static defensive auditor; and adopting **Big-Vul / Devign / D2A / DiverseVul / SecurityEval** as primary corpora — all single-language (C/C++ or Python) and, for SecurityEval, a generation eval rather than a detection one.

---

## Sources

Each URL is followed by what it supports. All verified against the linked primary source on 2026-06-14 unless marked *unverified*.

**Family 1 — labeled benchmarks/datasets**
- https://owasp.org/www-project-benchmark/ — OWASP Benchmark: **2,740** Java test cases, **11** categories; **Python v0.1 = 1,230** cases (v1.0 planned early 2026); Youden-Index scoring ((sensitivity+specificity)−1 → 0–100). Confirms it is *not* Java-only anymore.
- https://github.com/OWASP-Benchmark/BenchmarkJava — OWASP Benchmark Java repo: **GPL-2.0**, v1.2 current (since 2016), Java/Maven; scoring utilities in separate BenchmarkUtils repo.
- https://samate.nist.gov/SARD/test-suites — NIST SARD test-suite index (platform actively maintained).
- https://samate.nist.gov/SARD/test-suites/112 and https://samate.nist.gov/SARD/test-suites/111 — **Juliet C/C++ 1.3** and **Juliet Java 1.3** (per-CWE labeled, ~118 / ~112 CWEs); NIST work = public domain.
- https://www.nist.gov/publications/juliet-11-cc-and-java-test-suite — Juliet origin (81,000+ synthetic C/C++/Java programs with known flaws).
- https://github.com/secureIT-project/CVEfixes — **CVEfixes** v1.0.8 (2024-07-30): 11,873 CVEs / 138,974 functions; **code MIT + data CC-BY-4.0**; multi-language (inherits real OSS). Paper: https://arxiv.org/abs/2107.08760.
- https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset — **Big-Vul** (C/C++, 188,636 functions; **MIT**; repo 2021). Paper: https://doi.org/10.1145/3379597.3387501 (MSR 2020).
- https://proceedings.neurips.cc/paper/2019/hash/49265d2447bc3bbfe9e76306ce40a31f-Abstract.html — **Devign** (C-only, manual labels, NeurIPS 2019; dataset license *unverified*, public subset via CodeXGLUE). Paper: https://arxiv.org/abs/1909.03496.
- https://github.com/IBM/D2A — **D2A** (C/C++, Infer-derived labels; code Apache-2.0, data **CDLA** variant *unverified*; repo archived 2024-07-22). Paper: https://arxiv.org/abs/2102.07995 (ICSE-SEIP 2021).
- https://huggingface.co/datasets/s2e-lab/SecurityEval — **SecurityEval** (Python; **code-generation** eval, 130 samples / 75 CWEs; license *unverified*). Paper: https://doi.org/10.1145/3549035.3561184 (MSR4P&S 2022). *Detection-unfit — measures secure-code generation.*
- https://github.com/wagner-group/diversevul — **DiverseVul** (C/C++; 18,945 vuln + 330,492 non-vuln; 150 CWEs; **no declared license**). Paper: https://arxiv.org/abs/2304.00409 (RAID 2023).

**Family 2 — vulnerable-by-design apps**
- https://github.com/OWASP/crAPI — **crAPI**: tech stack Java 28.9% / TypeScript 25.9% / Python 22.6% / Go 4.6%; Docker-Compose / k8s microservices; BOLA/JWT/API-Top-10 focus; **Apache-2.0**; latest **v1.1.6, 2025-09-30**.
- https://github.com/digininja/DVWA — **DVWA**: PHP + MariaDB/MySQL; SQLi/XSS/cmd-injection/LFI/CSRF/file-upload at graded levels; **GPL-3.0**; latest release "Vulnerable APIs", **2025-01-29**.
- https://github.com/OWASP/NodeGoat — **NodeGoat**: Node.js, **Apache-2.0** (low marginal coverage vs Juice Shop).
- https://github.com/OWASP/railsgoat — **RailsGoat**: Ruby on Rails (through Rails 8); OWASP-Top-10 (license file at /blob/master/LICENSE.md).
- https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application — **DVGA**: Python/Flask GraphQL; **MIT**.
- https://github.com/WebGoat/WebGoat — **WebGoat**: Java / Spring Boot 3.5.6; **GPL-2.0**; latest **v2025.3**.
- https://github.com/erev0s/VAmPI — **VAmPI**: Python/Flask + Connexion; API Top-10 with a **vuln on/off switch** (ideal for FP testing); license *unverified*.
- https://github.com/vulhub/vulhub — **Vulhub**: 200+ docker-compose real-CVE reproductions (CVEs to 2026); **MIT**. *Dynamic-exploitation gym — wrong shape for a static fixture.*

**Family 3 — agentic cyber gyms**
- https://github.com/andyzorigin/cybench + https://arxiv.org/abs/2408.08926 — **Cybench** (Stanford): 40 offensive CTF tasks; Apache-2.0.
- https://github.com/NYU-LLM-CTF/NYU_CTF_Bench + https://arxiv.org/abs/2406.05590 — **NYU CTF Bench**: 200 offensive CSAW challenges; **GPL-2.0**; release 2025-02-06.
- https://github.com/sunblaze-ucb/cybergym + https://arxiv.org/abs/2506.02548 — **CyberGym** (Berkeley): 1,507 real-CVE **PoC-reproduction** tasks / 188 projects; Apache-2.0. *Offensive-leaning; corpus is C/C++ pre-patch source.*
- https://github.com/lucagioacchini/auto-pen-bench + https://arxiv.org/abs/2410.03225 — **AutoPenBench**: 36 live-container pentest tasks; **MIT**.
- https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks + https://arxiv.org/abs/2312.04724 (v1) + https://arxiv.org/abs/2408.01605 (v3) — **CyberSecEval**: MIT; **Insecure Code Detector** = weggli + semgrep + regex, ~189 patterns / 50 CWEs / 8 languages (the one defensively-relevant artifact). v1 instruct/autocomplete measure insecure-code *generation*, not detection.
- https://github.com/princeton-nlp/intercode + https://arxiv.org/abs/2306.14898 — **InterCode-CTF**: 100 picoCTF offensive tasks; **MIT**.

**In-repo context grounding this note**
- `/workspace/tests/e2e/expected-findings.json` — current 12-fixture coverage gate + `gated_categories` (token_scope, mitm, deployment, llm) confirming the untested categories.
- `/workspace/tests/e2e/README.md` — confirms coverage-only assertion ("treat PASS as structurally valid + 12 fixture hits, not semantically correct").
- `/workspace/docs/ROADMAP.md` & `/workspace/docs/KNOWN-GAPS.md` — confirm the precision gap, the `--target` flag, and the planned DVWA (PHP) + Go second target.
