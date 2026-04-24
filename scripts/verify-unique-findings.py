#!/usr/bin/env python3
"""
verify-unique-findings.py — independently recompute the "unique-to-skill"
finding count from Phase 5 JSONL + Phase 4 slim SARIFs.

The Phase 7 synthesis sub-agent self-reports a `unique_to_skill` count
in its return shape. That number is the skill's headline value claim
("found things scanners miss"). Reviewer-grade integrity requires an
independent recount from the raw artifacts.

Definition of "unique-to-skill":
    A Phase 5 finding whose (handler_file, line, cwe) tuple does NOT
    appear in any Phase 4 slim SARIF AND whose `sources[]` contains
    no entry of kind == "scanner".

Usage:
    python3 scripts/verify-unique-findings.py \
        --phase5-glob '.claude-audit/current/phase-05-*.jsonl' \
        --slim-glob   '.claude-audit/current/phase-04-scanners/*.slim.json' \
        [--report-json]

Output:
    Plain text summary by default. --report-json emits a machine-
    readable struct that the Phase 7 report can consume.

Exit codes:
    0 — verification complete; prints count
    1 — missing inputs or parse error
"""
import argparse
import glob
import json
import sys


def load_phase5(pattern: str) -> list[dict]:
    findings = []
    for path in glob.glob(pattern):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        print(f"WARN: skipping malformed line in {path}: {e}", file=sys.stderr)
    return findings


def load_slim(pattern: str) -> list[dict]:
    all_results = []
    for path in glob.glob(pattern):
        with open(path) as f:
            doc = json.load(f)
        for r in doc.get("results", []):
            all_results.append({
                "file": r.get("file"),
                "start_line": r.get("start_line"),
                "rule_id": r.get("rule_id"),
                "tool": doc.get("tool"),
            })
    return all_results


def cwe_of(rule_id: str | None) -> str | None:
    """Attempt to derive a CWE string from a scanner rule_id.
    Heuristic only — scanner rule ids rarely include the CWE, so this
    conservatively returns None unless the rule id is itself CWE-NNN."""
    if rule_id and rule_id.startswith("CWE-"):
        return rule_id
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase5-glob", required=True)
    parser.add_argument("--slim-glob", required=True)
    parser.add_argument("--report-json", action="store_true")
    args = parser.parse_args()

    findings = load_phase5(args.phase5_glob)
    scanner_results = load_slim(args.slim_glob)

    if not findings:
        print("ERROR: no Phase 5 findings loaded — check --phase5-glob", file=sys.stderr)
        sys.exit(1)

    # Build overlap index: set of (file, line) tuples that any scanner touched.
    scanner_locations = {(r["file"], r["start_line"]) for r in scanner_results if r["file"]}

    unique = []
    overlap_file_line = []
    scanner_sourced = []

    for f in findings:
        # Take handler_file if present (new schema); fall back to file.
        file_key = f.get("handler_file") or f.get("file")
        line_key = f.get("line")
        sources_kinds = {s.get("kind") for s in f.get("sources", []) if isinstance(s, dict)}

        has_scanner_source = "scanner" in sources_kinds
        has_file_line_overlap = (file_key, line_key) in scanner_locations

        if has_scanner_source:
            scanner_sourced.append(f)
        elif has_file_line_overlap:
            overlap_file_line.append(f)
        else:
            unique.append(f)

    if args.report_json:
        print(json.dumps({
            "total_phase5_findings": len(findings),
            "scanner_sourced": len(scanner_sourced),
            "overlap_file_line": len(overlap_file_line),
            "unique_to_skill": len(unique),
            "scanner_results_inspected": len(scanner_results),
        }, indent=2))
    else:
        print(f"Phase 5 findings loaded:           {len(findings)}")
        print(f"Scanner slim SARIF results loaded: {len(scanner_results)}")
        print()
        print(f"  With `scanner` source in sources[]:  {len(scanner_sourced)}")
        print(f"  (file, line) overlaps scanner hit:    {len(overlap_file_line)}")
        print(f"  UNIQUE TO SKILL:                      {len(unique)}")
        print()
        if unique:
            print("First 5 unique-to-skill findings:")
            for f in unique[:5]:
                print(f"  - {f.get('id')}: {f.get('title')} ({f.get('file')}:{f.get('line')}, {f.get('cwe')})")


if __name__ == "__main__":
    main()
