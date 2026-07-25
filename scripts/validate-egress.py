#!/usr/bin/env python3
"""Compatibility shim — the canonical implementation lives in
`skills/security-audit/lib/validate-egress.py`.

WHY THE MOVE (v2.5). Installation copies `skills/security-audit/` to
`~/.claude/skills/security-audit` and nothing else. `phase-06-config.md §6.19`
invoked `$SKILL_DIR/scripts/validate-egress.py` — a path that exists only in a
git checkout of this repo, never in a real install. v2.4's flagship control was
therefore unreachable at audit time: a control with no enforcer, which is the
exact bug class it was written to detect.

Every audit-time validator now lives under `skills/security-audit/lib/` (the
directory that actually ships). This shim keeps repo-local invocations
(`python3 scripts/validate-egress.py ...`), CI, and docs working, and makes
divergence between the two copies structurally impossible.
"""
import os
import runpy
import sys

_TARGET = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    os.pardir, "skills", "security-audit", "lib", "validate-egress.py",
)

if __name__ == "__main__":
    # Guarded: importing this shim as a module must NOT execute the validator.
    # Without the guard, `importlib` loading it (as the test suite does to reach
    # `extract_candidates`) would run main() and exit the interpreter.
    if not os.path.exists(_TARGET):
        sys.stderr.write(f"ERROR: canonical validator missing at {_TARGET}\n")
        sys.exit(2)
    sys.argv[0] = _TARGET
    runpy.run_path(_TARGET, run_name="__main__")
