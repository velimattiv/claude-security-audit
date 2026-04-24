# Contributing

Thanks for wanting to improve `/security-audit`. This document is brief;
if anything is unclear, open a discussion issue first.

## Branch convention

- Trunk-based: branch from `main` for feature / fix work.
- Branch name: `feat/<short-slug>`, `fix/<short-slug>`,
  `docs/<short-slug>`.
- For milestone-scoped work (e.g., future v2.1 milestones), use
  `m<N>-<slug>` as the v2.0.0 bootstrap did.

## Commits

- **Conventional "why-first" style.** One logical unit per commit.
  Commit message body explains *why*, not *what* (`git diff` shows
  what).
- **Commits must be signed.** Use `git commit -S` (GPG) or SSH signing
  (`git config commit.gpgsign true` + `gpg.format ssh`).
- Every AI-assisted commit SHOULD include a
  `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`
  trailer. This is an honesty / provenance convention, not a legal
  requirement.

## Testing

Before opening a PR:

1. Run the validation suite:
   ```bash
   scripts/validate-schemas.sh
   ```
   Every JSON Schema must parse; every CWE referenced in a `cat-*.md`
   file must exist in `lib/cwe-map.json`; every installer shell script
   must pass `bash -n`.

2. If you added or modified a deep-dive category, dogfood it against a
   real target. For auth/IDOR/crypto/deployment changes, use OWASP
   Juice Shop (`git clone https://github.com/juice-shop/juice-shop`).
   For PHP, DVWA. For Go, gosec. Commit the test-run writeup under
   `docs/test-runs/` with a descriptive filename.

3. Validate any new JSONL findings against the schema:
   ```bash
   python3 scripts/validate-findings.py \
       --schema skills/security-audit/lib/finding-schema.json \
       <your-findings.jsonl>
   ```

4. GitHub Actions will re-run the validation suite on your PR. CI must
   be green before merge.

## What counts as a good PR

- **Correctness-only:** prefer surgical changes. A 3-line fix + 1-line
  regression test is better than a 200-line refactor.
- **Spec + code together:** if you change a `phase-*.md` procedure,
  update the matching `lib/*-schema.json` or `lib/*.md` reference in
  the same commit.
- **Test-run evidence:** new categories / new language grep patterns
  MUST include a `docs/test-runs/<descriptor>.md` writeup showing the
  pattern fires on a real target.

## What we will not merge

- New categories without polyglot dogfood evidence.
- Changes that weaken the installer's checksum verification.
- Changes that expose `ANTHROPIC_API_KEY` or user secrets in logs /
  reports.
- Changes that enable telemetry without opt-in.

## Questions

File a discussion issue. For security-bug reports, see `SECURITY.md`.
