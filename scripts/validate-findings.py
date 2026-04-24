#!/usr/bin/env python3
"""
validate-findings.py — validate JSONL findings against a JSON Schema.

Every Phase 5 deep-dive sub-agent and Phase 6 methodology sub-agent
MUST run this before emitting its RETURN SHAPE. Usage:

    python3 scripts/validate-findings.py \
        --schema skills/security-audit/lib/finding-schema.json \
        <path-to-jsonl>

Exit codes:
  0  all rows valid
  1  at least one row failed validation (stderr prints which)
  2  argparse / I/O error

Dependencies:
  - jsonschema (pip install jsonschema). Falls back to a permissive
    manual check if jsonschema is missing (so the skill still runs in
    minimal environments; CI MUST have jsonschema installed).
"""
import argparse
import json
import sys
from pathlib import Path


def load_schema(schema_path: Path) -> dict:
    with open(schema_path) as f:
        return json.load(f)


def iter_findings(jsonl_path: Path):
    with open(jsonl_path) as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield lineno, json.loads(line)
            except json.JSONDecodeError as e:
                yield lineno, {"__parse_error__": str(e), "__raw__": line[:200]}


def load_cwe_map(cwe_map_path: Path | None) -> set[str] | None:
    """Load the set of CWE IDs from cwe-map.json. Returns None if path
    is None (meaning: skip the semantic CWE-in-map check).

    Fails loudly if the file lacks a `mappings` object or the object
    is empty — this defends against a silent no-op semantic check
    caused by a schema refactor that renames the top-level key."""
    if cwe_map_path is None:
        return None
    with open(cwe_map_path) as f:
        doc = json.load(f)
    if "mappings" not in doc:
        raise ValueError(
            f"{cwe_map_path}: missing top-level `mappings` object. "
            "If you refactored the schema, update validate-findings.py "
            "too — the silent empty-set fallback has been removed."
        )
    mappings = doc["mappings"]
    if not isinstance(mappings, dict) or not mappings:
        raise ValueError(
            f"{cwe_map_path}: `mappings` must be a non-empty object. "
            "An empty map would pass every finding through the semantic "
            "check trivially — failing loudly instead."
        )
    return set(mappings.keys())


def validate_with_jsonschema(schema: dict, findings, cwe_ids: set[str] | None):
    import jsonschema  # type: ignore
    validator = jsonschema.Draft202012Validator(schema)
    errors = []
    for lineno, finding in findings:
        if "__parse_error__" in finding:
            errors.append(f"line {lineno}: JSON parse error — {finding['__parse_error__']}")
            continue
        for err in sorted(validator.iter_errors(finding), key=lambda e: e.path):
            path = ".".join(str(p) for p in err.path) or "<root>"
            errors.append(f"line {lineno}: {path}: {err.message}")
        if cwe_ids is not None:
            cwe = finding.get("cwe")
            if cwe and cwe not in cwe_ids:
                errors.append(
                    f"line {lineno}: cwe `{cwe}` not in cwe-map.json "
                    f"(schema pattern allows any CWE-\\d+; semantic check requires map entry)"
                )
    return errors


def validate_manual(schema: dict, findings, cwe_ids: set[str] | None):
    """Minimal manual validator used when jsonschema is unavailable.
    Checks only the top-level `required` list + CWE-in-map when
    provided. Not a substitute for jsonschema — CI must install it."""
    required = schema.get("required", [])
    errors = []
    for lineno, finding in findings:
        if "__parse_error__" in finding:
            errors.append(f"line {lineno}: JSON parse error — {finding['__parse_error__']}")
            continue
        for field in required:
            if field not in finding:
                errors.append(f"line {lineno}: missing required field `{field}`")
        if cwe_ids is not None:
            cwe = finding.get("cwe")
            if cwe and cwe not in cwe_ids:
                errors.append(f"line {lineno}: cwe `{cwe}` not in cwe-map.json")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument(
        "--cwe-map",
        type=Path,
        default=None,
        help="Optional path to cwe-map.json. If provided, every finding's `cwe` must exist in the map (semantic check beyond the schema's regex).",
    )
    parser.add_argument("jsonl", type=Path, help="Path to a findings JSONL file")
    parser.add_argument("--quiet", action="store_true", help="Only emit non-zero exit; no stderr")
    args = parser.parse_args()

    if not args.schema.exists():
        print(f"ERROR: schema not found: {args.schema}", file=sys.stderr)
        sys.exit(2)
    if not args.jsonl.exists():
        print(f"ERROR: findings file not found: {args.jsonl}", file=sys.stderr)
        sys.exit(2)
    if args.cwe_map is not None and not args.cwe_map.exists():
        print(f"ERROR: cwe-map not found: {args.cwe_map}", file=sys.stderr)
        sys.exit(2)

    schema = load_schema(args.schema)
    findings = list(iter_findings(args.jsonl))
    cwe_ids = load_cwe_map(args.cwe_map)

    try:
        errors = validate_with_jsonschema(schema, findings, cwe_ids)
        backend = "jsonschema"
    except ImportError:
        errors = validate_manual(schema, findings, cwe_ids)
        backend = "manual-fallback"
        if not args.quiet:
            print(
                "WARNING: jsonschema not installed — using minimal manual validator. "
                "CI must `pip install jsonschema` for full coverage.",
                file=sys.stderr,
            )

    if errors:
        if not args.quiet:
            print(f"FAIL ({backend}): {len(errors)} issue(s) in {args.jsonl}", file=sys.stderr)
            for e in errors[:50]:
                print(f"  - {e}", file=sys.stderr)
            if len(errors) > 50:
                print(f"  ... and {len(errors) - 50} more.", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        n_findings = sum(1 for _, f in findings if "__parse_error__" not in f)
        print(f"OK ({backend}): {n_findings} findings validated against {args.schema.name}")


if __name__ == "__main__":
    main()
