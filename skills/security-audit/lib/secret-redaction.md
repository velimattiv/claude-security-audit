# Secret Redaction

How this skill avoids writing credentials into the repository it is auditing.

Two enforcers, one shared detector table, one invariant:

> **No deliverable this skill writes may contain credential material — including
> material the audited repository had correctly kept out of git.**

---

## The defect this closes (v2.6.0 and earlier)

Four links, each behaving exactly as specified:

1. `steps/phase-04-scanners.md` runs `gitleaks detect --no-git`. The flag makes
   gitleaks ignore `.gitignore`, which is correct — uncommitted secrets are the
   ones worth finding. Its SARIF carries the match verbatim in
   `region.snippet.text`. `trufflehog --results=verified` carries it in `Raw` /
   `RawV2` / `Redacted`, and `verified` means the scanner authenticated the
   credential against the live provider.
2. `steps/phase-07-synthesis.md §7.8.1` builds `findings.sarif` as one run per
   scanner plus one synthetic run, instructing that scanner runs be "copied
   through *verbatim*". That instruction was about metadata; it moved snippets.
3. `§7.10` copies the result to `<output_dir>`.
4. `lib/output-routing.md` defaults `<output_dir>` to
   `docs/security-audit-output/` and calls it "tracked".

Result: a live token sitting in a gitignored scratch directory was read by the
audit and committed by the audit. No source file, no `.env`, no config ever
carried it into git — the audit was the sole reason it entered version history.

Two aggravating details worth keeping in view, because both are about how the
defect *stayed*:

- **`workflow.md §1` gitignored `.claude-audit/` and never `<output_dir>`.** The
  protection was on the scratch directory and absent from the one whose entire
  purpose is to be committed.
- **The skill had no concept that its own output was secret-bearing.** A later
  run's gitleaks flagged its predecessor's `findings.sarif`, and the hits were
  triaged away as prior-artifact noise — a security report is *expected* to look
  full of secrets, so the dismissal confirmed itself. That happened twice.

---

## Layer 1 — structural strip at ingest

`lib/redact-scanner-output.py`, invoked at `phase-04-scanners.md §4.4b`,
immediately after the scanners write and before anything reads them.

It removes SARIF `snippet`, `contents` and `insertedContent` from **every**
scanner run — not only the secret scanners, and not by matching credential
patterns. This is a whitelist: the field is gone, so nothing in it survives,
whatever format the credential was in and whether or not this skill has ever
heard of it.

The strip is free because no consumer reads those fields:

| Consumer | What it reads |
|---|---|
| `lib/sarif-postprocess.md` slim schema | rule, level, file, line, message |
| Phases 5-7 | the slim form |
| `tests/e2e/assertions.py:_sarif_result_to_finding` | `ruleId`, `properties.cwe`, `properties.cwes`, `tags` |
| GitHub Security tab | file + line region |

Each result keeps everything triage needs and gains
`properties.secret_fingerprint`. A pattern pass then covers the free text the
strip cannot reach — `message.text`, invocation command lines, trufflehog
`ExtraData`.

**Ordering matters.** The strip runs before `§4.5` normalization and `§4.6`
slimming. Redacting later would still leave raw values on disk in
`phase-04-scanners/`, in every deep-dive sub-agent's context, and in
`.claude-audit/history/<ts>/` after rotation.

## Layer 2 — fail-closed gate at every write

`lib/verify-deliverable.py`, invoked at `phase-07-synthesis.md §7.10` and
`phase-08-baseline.md §8.4`, before each `cp` into `<output_dir>`.

This one *is* a pattern blocklist, and it is deliberately the last line rather
than the first. It exists for the source Layer 1 structurally cannot reach:
**prose an analyst wrote.** `cat-06-secret-sprawl.md` sends a sub-agent looking
for literal credentials, and `report-template.md` renders `{{description}}` into
a tracked markdown file. Free text is meant to be read; there is no field to
delete.

It gates the **blackboard** copies, then the `cp` happens — so blackboard and
deliverable stay byte-identical and no raw value is left behind in
`.claude-audit/`.

On a hit it scrubs, writes, and returns exit 3, which obliges Phase 7 to emit a
CRITICAL finding naming *this skill* as defective (`§7.10a`). It does not abort:
a user 45 minutes into an audit will find whatever flag silences an abort, and
that flag becomes the hole.

**A firing gate means Layer 1 did not hold.** Treat it as a bug report.

## Layer 3 — gitignore hygiene

`workflow.md §3.5b` applies the `<output_dir>/*.sarif` and `*.cyclonedx.json`
ignore recipe when `<output_dir>` is inside a git work tree and not already
ignored.

Defence in depth only. It covers two globs and does nothing for
`security-audit-report.md`, which stays tracked by design so `mode: delta` works
on a fresh clone. Layers 1 and 2 are what make the tracked files safe.

---

## The shared detector table

`lib/secret-detectors.py` is the single source both enforcers import, by
absolute path, from the directory they ship in.

Two copies would drift, and the day they drift the gate stops matching the
redactor: a control whose enforcer no longer covers it — the exact defect class
this skill exists to detect, committed by the skill.
`tests/test-secret-redaction.sh` asserts both resolve the same module.

### What the fingerprint is not

`properties.secret_fingerprint` is `sha256(domain ‖ context ‖ value)`, truncated
to 16 hex characters. It is stable across runs for the same secret in the same
detector context, which is what lets a secret finding dedupe in Phase 7 and
carry forward in the Phase 8 baseline now that the value is gone.

It is **not** a security boundary:

- It is domain-separated and salted with the rule id, so a *generic* rainbow
  table is useless — an attacker needs one per rule id.
- It is **not** resistant to a targeted guess against a known-weak secret. If
  the credential was `hunter2`, the fingerprint confirms `hunter2` to anyone who
  tries it. That is acceptable because such a secret is already lost the moment
  its file and line are published, and publishing file and line is the whole
  point of the finding.
- Do not treat a fingerprint as safe to publish *outside* the audited repo's
  trust boundary. Inside it, the reader already has the source file.

### Adding a detector

Add to `_RAW_DETECTORS` in `secret-detectors.py` only. Prefix-anchored patterns
(`ghp_`, `AKIA`, `xox…`) take `value_group=0` and skip the entropy gate — the
prefix is the evidence. Patterns needing surrounding context (an assignment, a
header) capture the value in a group and set `entropy_gated=True`, so
documentation placeholders and low-entropy filler do not fire.

Then extend `tests/test-secret-redaction.sh` with a positive case and a
placeholder negative case. A detector with no negative case is how a scrubber
starts eating prose.
