## Summary

<!--
One or two sentences on what this PR does and why. If it fixes a
specific adversarial-review finding or a documented v2.1 roadmap item,
link to it.
-->

## Type

- [ ] Bug fix (correctness in the skill's instructions / schemas / scripts)
- [ ] New feature (category, framework support, mode, phase behavior)
- [ ] Docs-only
- [ ] CI / tooling
- [ ] Breaking schema change

## Changes

<!-- What files changed and why. -->

## Test plan

- [ ] `scripts/validate-schemas.sh` passes locally.
- [ ] If a `cat-*.md` regex was added or changed: `python3 scripts/validate-patterns.py` compiles clean.
- [ ] If a new category / new framework / new language was added:
      **dogfood evidence under `docs/test-runs/<descriptor>-<ISO-ts>.md`**
      showing the patterns fire on a real target (don't just assert —
      *demonstrate*).
- [ ] If finding schema or baseline schema was changed: `tests/fixtures/`
      updated accordingly and the fixture validates.
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]`.

## Related

<!-- Issue #, adversarial finding #, ROADMAP §. -->
