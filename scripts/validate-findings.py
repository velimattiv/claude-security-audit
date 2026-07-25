#!/usr/bin/env python3
"""Compatibility shim — the canonical implementation lives in
`skills/security-audit/lib/validate-findings.py`.

Two byte-divergent copies of this validator existed until v2.5 (repo-root
`scripts/` and the shipped `skills/security-audit/lib/`). Only the latter is
installed, so only the latter can run during an audit. This shim keeps
repo-local invocations, CI, and docs working while guaranteeing there is exactly
one implementation.
"""
import os
import runpy
import sys

_TARGET = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    os.pardir, "skills", "security-audit", "lib", "validate-findings.py",
)

if __name__ == "__main__":
    # Guarded so importing this shim as a module does not execute the validator.
    if not os.path.exists(_TARGET):
        sys.stderr.write(f"ERROR: canonical validator missing at {_TARGET}\n")
        sys.exit(2)
    sys.argv[0] = _TARGET
    runpy.run_path(_TARGET, run_name="__main__")
