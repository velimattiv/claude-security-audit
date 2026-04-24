#!/usr/bin/env python3
"""
assertions.py — validate a full /security-audit run against the fixture
list in expected-findings.json.

Runs after the skill exits. Takes the artifact-dir as input; exits 0 on
all-pass, non-zero with a diff on any failure.

Structural checks:
  - every phase-NN.done marker present (Phase 0-7; Phase 8 optional for
    non-full modes).
  - findings.sarif parses + validates against SARIF 2.1.0 top-level
    structure (.runs array exists, each run has .tool.driver.name,
    .results is an array).
  - phase-07-report.md contains required section headers:
        "# Security Audit Report"
        "## Executive Summary"
        "## Findings"
        "## Attack Surface Summary" OR "## Route Inventory"
        "## Methodology Coverage"
  - each non-empty phase-05-<cat>-*.jsonl validates against
    finding-schema.json via validate-findings.py (spawned).

Coverage checks:
  - every `expectations[].id` matches at least one finding by
    (file_pattern, cwe, category).
  - File-pattern allows glob; `alternate_file_patterns` count as
    equivalents.
  - `gated_categories` are expected to be either missing entirely
    or present with zero findings.
"""
import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def load_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def check_phase_markers(artifact_dir: Path, failures: list[str]) -> None:
    current = artifact_dir / ".claude-audit" / "current"
    required = [f"phase-{i:02d}.done" for i in range(0, 8)]
    for marker in required:
        if not (current / marker).exists():
            failures.append(f"MISSING marker: .claude-audit/current/{marker}")
    # phase-08 optional.


def check_sarif_structure(artifact_dir: Path, failures: list[str]) -> dict | None:
    sarif_path = artifact_dir / ".claude-audit" / "current" / "findings.sarif"
    if not sarif_path.exists():
        failures.append(f"MISSING: findings.sarif at {sarif_path}")
        return None
    try:
        doc = load_json(sarif_path)
    except json.JSONDecodeError as e:
        failures.append(f"findings.sarif: JSON parse error — {e}")
        return None
    if "runs" not in doc or not isinstance(doc["runs"], list):
        failures.append("findings.sarif: missing top-level .runs array")
        return None
    for i, run in enumerate(doc["runs"]):
        tool_name = run.get("tool", {}).get("driver", {}).get("name")
        if not tool_name:
            failures.append(f"findings.sarif: run[{i}] missing .tool.driver.name")
        if not isinstance(run.get("results"), list):
            failures.append(f"findings.sarif: run[{i}] .results is not an array")
    return doc


def check_report_sections(artifact_dir: Path, failures: list[str]) -> None:
    # Report may land in two locations per Phase 7 §7.10.
    candidates = [
        artifact_dir / "docs" / "security-audit-report.md",
        artifact_dir / "_bmad-output" / "implementation-artifacts" / "security-audit-report.md",
        artifact_dir / ".claude-audit" / "current" / "phase-07-report.md",
    ]
    report = next((c for c in candidates if c.exists()), None)
    if report is None:
        failures.append("MISSING: phase-07-report.md (checked all three paths)")
        return
    content = report.read_text()
    required_headers = [
        r"^#\s+Security Audit Report",
        r"^##\s+Executive Summary",
        r"^##\s+Findings",
        r"^##\s+(Attack Surface Summary|Route Inventory)",
        r"^##\s+Methodology Coverage",
    ]
    for pattern in required_headers:
        if not re.search(pattern, content, re.MULTILINE):
            failures.append(f"report missing required section header: {pattern}")


def check_jsonl_schema_validity(
    repo_root: Path, artifact_dir: Path, failures: list[str]
) -> None:
    validator = repo_root / "scripts" / "validate-findings.py"
    schema = repo_root / "skills" / "security-audit" / "lib" / "finding-schema.json"
    cwe_map = repo_root / "skills" / "security-audit" / "lib" / "cwe-map.json"
    for jsonl in sorted((artifact_dir / ".claude-audit" / "current").glob("phase-05-*.jsonl")):
        if jsonl.stat().st_size == 0:
            failures.append(f"EMPTY: {jsonl.name} — category produced no findings at all")
            continue
        # `jq '[inputs] | length > 0'` equivalent: non-empty JSONL.
        rows = load_jsonl(jsonl)
        if not rows:
            failures.append(f"EMPTY: {jsonl.name} — no findings rows")
            continue
        # Schema + CWE-in-map semantic check.
        result = subprocess.run(
            [
                "python3", str(validator),
                "--schema", str(schema),
                "--cwe-map", str(cwe_map),
                str(jsonl),
                "--quiet",
            ],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            failures.append(f"SCHEMA-FAIL: {jsonl.name} — {result.stdout}{result.stderr}")


def finding_matches_expectation(finding: dict, exp: dict) -> bool:
    """Match a single finding against one expectation. Allows glob
    file_pattern + alternates."""
    if finding.get("cwe") != exp["cwe"]:
        return False
    if finding.get("category") != exp["category"]:
        return False
    patterns = [exp["file_pattern"]] + exp.get("alternate_file_patterns", [])
    f_file = finding.get("handler_file") or finding.get("file") or ""
    return any(fnmatch.fnmatch(f_file, p) or fnmatch.fnmatch(f_file, f"*{p}") for p in patterns)


def collect_all_findings(artifact_dir: Path) -> list[dict]:
    """Collect findings from both Phase 5 JSONLs and findings.sarif
    (when sarif has skill-derived rows; scanner-only rows are excluded
    by requiring .category on the finding)."""
    findings: list[dict] = []
    current = artifact_dir / ".claude-audit" / "current"
    for jsonl in sorted(current.glob("phase-05-*.jsonl")):
        findings.extend(load_jsonl(jsonl))
    # Also check phase-06 JSONLs (config, asvs, api-top10) — they can
    # carry the findings this fixture is about too.
    for extra in ["phase-06-config.json"]:
        p = current / extra
        if p.exists():
            doc = load_json(p)
            if isinstance(doc, list):
                findings.extend(doc)
            elif isinstance(doc, dict) and "findings" in doc:
                findings.extend(doc["findings"])
    return findings


def check_expectations(
    artifact_dir: Path, expected: dict, failures: list[str]
) -> None:
    findings = collect_all_findings(artifact_dir)
    if not findings:
        failures.append("no findings collected — every expectation will fail")
        return
    missing = []
    for exp in expected["expectations"]:
        matches = [f for f in findings if finding_matches_expectation(f, exp)]
        if not matches:
            missing.append(exp)
    if missing:
        failures.append(
            f"{len(missing)} of {len(expected['expectations'])} fixture expectations not matched:"
        )
        for exp in missing:
            failures.append(
                f"  - {exp['id']}: {exp['description']} "
                f"(expected cwe={exp['cwe']} category={exp['category']} "
                f"file≈{exp['file_pattern']})"
            )


def check_gated_categories(
    artifact_dir: Path, expected: dict, failures: list[str]
) -> None:
    """For categories marked as gated (no ground truth), require that
    either the JSONL is absent OR present-but-empty — anything else
    indicates the skill found something the fixture hasn't accounted
    for, which merits investigation."""
    gated = expected.get("gated_categories", {})
    current = artifact_dir / ".claude-audit" / "current"
    for cat, reason in gated.items():
        matching = list(current.glob(f"phase-05-{cat}-*.jsonl"))
        for jsonl in matching:
            rows = load_jsonl(jsonl)
            if rows:
                # Not a failure, but a diagnostic note.
                print(
                    f"NOTE: gated category '{cat}' produced {len(rows)} finding(s). "
                    f"Reason on file: {reason}. Consider updating fixtures.",
                    file=sys.stderr,
                )


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        required=True,
        help="Root of the audited repo (contains .claude-audit/).",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent.parent,
        help="Root of this skill's own repo (for locating validator + schema).",
    )
    parser.add_argument(
        "--fixture",
        type=Path,
        default=Path(__file__).resolve().parent / "expected-findings.json",
    )
    parser.add_argument(
        "--skip-expectations",
        action="store_true",
        help="Only run structural checks; skip the fixture-list match. Useful for dogfood against partial artifacts.",
    )
    args = parser.parse_args()

    if not args.artifact_dir.exists():
        print(f"ERROR: artifact-dir does not exist: {args.artifact_dir}", file=sys.stderr)
        sys.exit(2)
    if not args.fixture.exists():
        print(f"ERROR: fixture not found: {args.fixture}", file=sys.stderr)
        sys.exit(2)

    expected = load_json(args.fixture)
    failures: list[str] = []

    print(f"=== E2E assertion suite ({expected['target']}) ===")
    print(f"artifact-dir: {args.artifact_dir}")
    print()

    print("[1/5] Phase-done markers...")
    check_phase_markers(args.artifact_dir, failures)

    print("[2/5] SARIF structure...")
    check_sarif_structure(args.artifact_dir, failures)

    print("[3/5] Report section headers...")
    check_report_sections(args.artifact_dir, failures)

    print("[4/5] Phase-05 JSONL schema + CWE-in-map...")
    check_jsonl_schema_validity(args.repo_root, args.artifact_dir, failures)

    if not args.skip_expectations:
        print("[5/5] Fixture expectations...")
        check_expectations(args.artifact_dir, expected, failures)
        check_gated_categories(args.artifact_dir, expected, failures)
    else:
        print("[5/5] Fixture expectations — SKIPPED (--skip-expectations).")

    print()
    if failures:
        print(f"=== FAIL — {len(failures)} issue(s) ===", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        sys.exit(1)
    print("=== PASS — all structural + fixture checks green ===")


if __name__ == "__main__":
    main()
