# Test Runs

Per-milestone and per-remediation dogfood evidence. Each file captures:
a specific run of the skill (or a sub-agent of it) against a real
target, the artifacts produced, and observations filed for later.

These are **evidence, not specification.** If behavior changes, the
historical runs still read correctly even if the skill evolves — they
document what was true at a point in time.

**Superseded content — read with care.** The M6 writeup references a
Phase 2 `surface.file` lookup that no longer exists (v2.0.1 replaced
it with `registration_file` + `handler_file`). The M5 dogfood
used the old `sha1(file:line:title)` fingerprint formula (v2.0.1 uses
`sha1(handler_file:line:cwe:category)`). These runs still demonstrate
the phase *behavior* validly, but if you re-run the same target with
v2.0.1 the numeric fingerprints and the surface field names will
differ. No historical file has been silently edited — the superseded
sections are left as-written for provenance integrity.

## Milestone dogfoods (v2.0.0 → v2.0.0 release)

| File | Scope |
|---|---|
| `m1-2026-04-24T110600Z.md` | Phase 0 Discovery + Phase 1 Partition on Juice Shop |
| `m2-2026-04-24T112200Z.md` | Phase 2 Surface + Phase 3 Keystone on Juice Shop |
| `m3-2026-04-24T114100Z.md` | Phase 4 Scanner Bundle on Juice Shop (4/6 scanners initially) |
| `m4-2026-04-24T115000Z.md` | Phase 5 Deep Dives cat-01 + cat-08 on Juice Shop |
| `m5-2026-04-24T120500Z.md` | Phase 6 + Phase 7 synthesis on Juice Shop (214 findings, SARIF validated) |
| `m6-2026-04-24T121500Z.md` | Phase 8 Baseline emission + delta-mode dry-run |
| `m7-2026-04-24T122500Z.md` | Clean-host install test + v2.0.0 completion check |

## Polyglot validation (v2.0.1 remediation)

| File | Scope |
|---|---|
| `polyglot-go-2026-04-24T191700Z.md` | cat-04 MITM on gosec (Go; 20 findings, patterns validated) |
| `polyglot-php-2026-04-24T191700Z.md` | cat-08 Injection on DVWA (PHP; 40 findings, impossible.php sanity check passed) |

## Runtime verification

| File | Scope |
|---|---|
| `1m-context-check-2026-04-24T193000Z.md` | Claude Code harness self-reports model ID for sub-agents (Opus 4.7, [1m] suffix) |

## How to add a new test-run writeup

1. Name: `<descriptor>-<UTC-iso-timestamp>.md` (e.g., `rails-cat-01-2026-06-15T100000Z.md`).
2. Start with target + skill version + scope.
3. Show the command/sub-agent prompt used.
4. Paste the findings summary (by severity, by category, patterns that fired).
5. Cross-reference to any validator output (`scripts/validate-findings.py`).
6. End with **Observations** — anything that wasn't in the spec.
7. Commit as part of the PR that introduces the change being validated.

See `CONTRIBUTING.md §Testing` for the wider contribution flow.
