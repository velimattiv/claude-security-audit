---
name: Bug report
about: Something in the skill is incorrect or crashes
labels: bug
---

## Summary

<!-- One-sentence description. -->

## What happened

<!-- Paste the skill output, sub-agent RETURN SHAPE, or validator error. -->

## Expected

<!-- What should have happened. Reference the spec file or phase doc if helpful. -->

## Environment

- Skill version (`cat skills/security-audit/VERSION`): <!-- e.g., 2.0.1 -->
- Claude Code version: <!-- e.g., v0.6.x -->
- Host OS + arch: <!-- macOS 14.x arm64 / Debian 12 amd64 / ... -->
- Install path: <!-- Path A (host install) or Path B (container) -->
- Scanner versions (`scripts/install-scanners.sh --check`):
  ```
  [paste output]
  ```

## Repro target

<!-- If possible, a public repo the bug reproduces on.
     Juice Shop, DVWA, gosec, or your own test fixture. -->

## Artifact snippet

<!-- First 10-20 lines of the failing phase's JSONL / JSON,
     or the offending sub-agent prompt. -->

## Security-sensitive?

<!-- If this report touches a vulnerability in the skill itself
     (not a finding about someone else's code), STOP and follow
     SECURITY.md. Do not file a public bug report. -->
