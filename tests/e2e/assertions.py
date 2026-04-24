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
    .results is an array, at least some results carry
    properties.security-severity).
  - phase-07-report.md contains required section headers (tolerant of
    format drift: accepts `## Findings` with `### CRITICAL` subsections
    OR `## CRITICAL` directly).
  - each non-empty phase-05-<cat>-*.jsonl validates against
    finding-schema.json via validate-findings.py (spawned).
  - Gated categories (from expected-findings.json) are permitted to have
    either an absent JSONL or a present-but-empty one.

Coverage checks:
  - every `expectations[].id` matches at least one finding by
    (file_pattern, cwe, category). Supports `alternate_file_patterns`,
    `alternate_cwes`, and `alternate_categories` for tolerating
    pre-existing dogfood evidence + Phase 6 cross-category hits.
"""
import argparse
import fnmatch
import json
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
    # GHA CI gating depends on `properties.security-severity`. Sample
    # the first results and fail if absent.
    severity_present = False
    for run in doc["runs"]:
        for r in run.get("results", [])[:10]:
            if r.get("properties", {}).get("security-severity") is not None:
                severity_present = True
                break
        if severity_present:
            break
    if not severity_present:
        failures.append(
            "SARIF: no result carries properties.security-severity — "
            "GHA CI gates that filter on '9.0'/'7.0' break on this SARIF. "
            "Phase 7 synthesis must stamp security-severity per §7.8."
        )
    return doc


def check_report_sections(artifact_dir: Path, failures: list[str]) -> None:
    """Tolerant format check. Hard-fails on:
        - report file missing entirely
        - title header missing
        - no findings section at all
    Emits warnings (non-fatal) for missing template-recommended sections
    so the orchestrator's free-form report shape doesn't block the E2E.
    """
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

    # Hard-fail headers.
    hard_required = [
        (r"^#\s+(Security|Audit)", "report title (e.g., `# Security Audit Report`)"),
    ]
    for pattern, description in hard_required:
        if not re.search(pattern, content, re.MULTILINE):
            failures.append(f"report missing: {description}")

    # Soft-recommended headers — print as warnings, do not fail.
    soft_recommended = [
        (r"^##\s+Executive Summary", "Executive Summary section"),
        (r"^##\s+(Attack Surface Summary|Route Inventory|Routes)", "surface/route section"),
        (r"^##\s+Methodology Coverage", "Methodology Coverage section"),
    ]
    for pattern, description in soft_recommended:
        if not re.search(pattern, content, re.MULTILINE):
            print(
                f"WARN: report doesn't contain a `{description}` "
                f"(pattern: {pattern}). Orchestrator may have improvised "
                "the shape — non-fatal.",
                file=sys.stderr,
            )

    # Hard-fail: must have SOME findings block, in any of the legitimate shapes.
    findings_patterns = [
        r"^##\s+Findings",
        r"^##\s+(Top|Top\s+Risks|Risks|Critical|High|Medium)",
        r"^##\s+(CRITICAL|HIGH|MEDIUM)",
        r"^###\s+(CRITICAL|HIGH|MEDIUM)",
        r"^##\s+Top\s+\d+",
    ]
    if not any(re.search(p, content, re.MULTILINE | re.IGNORECASE) for p in findings_patterns):
        failures.append(
            "report missing findings section (accepted: `## Findings`, "
            "`## Top Risks`, `## CRITICAL/HIGH/MEDIUM`, or similar)"
        )


def check_jsonl_schema_validity(
    repo_root: Path,
    artifact_dir: Path,
    gated_categories: set[str],
    require_jsonschema_backend: bool,
    failures: list[str],
) -> None:
    validator = repo_root / "scripts" / "validate-findings.py"
    schema = repo_root / "skills" / "security-audit" / "lib" / "finding-schema.json"
    cwe_map = repo_root / "skills" / "security-audit" / "lib" / "cwe-map.json"

    if require_jsonschema_backend:
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            failures.append(
                "Python `jsonschema` not installed. Assertion suite requires the "
                "full validator backend. Run: `pip install -r requirements-ci.txt` "
                "(or `pip install jsonschema`). Aborting before false passes."
            )
            return

    for jsonl in sorted((artifact_dir / ".claude-audit" / "current").glob("phase-05-*.jsonl")):
        # Filename: phase-05-<cat>-<partition>.jsonl → extract <cat>.
        name = jsonl.name.replace("phase-05-", "").rsplit(".jsonl", 1)[0]
        parts = name.rsplit("-", 1)
        cat = parts[0] if len(parts) == 2 else name

        if jsonl.stat().st_size == 0:
            if cat in gated_categories:
                continue
            failures.append(
                f"EMPTY: {jsonl.name} — category '{cat}' produced no findings "
                "(not listed in gated_categories)"
            )
            continue
        rows = load_jsonl(jsonl)
        if not rows:
            if cat in gated_categories:
                continue
            failures.append(
                f"EMPTY: {jsonl.name} — no findings rows "
                "(not listed in gated_categories)"
            )
            continue

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


def normalize_path(p: str | None) -> str:
    """Normalize a finding's file field for glob matching. Strips
    absolute-path prefixes from known repo roots + leading `./`."""
    if not p:
        return ""
    p = p.strip()
    if p.startswith("/"):
        for marker in ("/juice-shop/", "/DVWA/", "/gosec/", "/e2e-target/"):
            if marker in p:
                p = p.split(marker, 1)[1]
                break
        else:
            p = p.lstrip("/")
    if p.startswith("./"):
        p = p[2:]
    return p


def finding_matches_expectation(finding: dict, exp: dict) -> bool:
    """Match a single finding against one expectation. Supports
    cwe/category/file alternates. Findings sourced from SARIF
    (`_source == "sarif"`) skip the category check — SARIF doesn't
    carry our skill's category vocab natively, so requiring it would
    miss valid matches. Cross-source matches still require cwe + file."""
    valid_cwes = [exp["cwe"]] + exp.get("alternate_cwes", [])
    if finding.get("cwe") not in valid_cwes:
        return False

    if finding.get("_source") != "sarif":
        valid_cats = [exp["category"]] + exp.get("alternate_categories", [])
        if finding.get("category") not in valid_cats:
            return False

    patterns = [exp["file_pattern"]] + exp.get("alternate_file_patterns", [])
    f_file = normalize_path(finding.get("handler_file") or finding.get("file"))
    return any(
        fnmatch.fnmatch(f_file, p)
        or fnmatch.fnmatch(f_file, f"*/{p}")
        or f_file.endswith(p)
        for p in patterns
    )


def collect_all_findings(artifact_dir: Path) -> list[dict]:
    """Collect findings from every machine-readable surface the skill
    might produce: Phase 5 JSONLs (v2 canonical), Phase 5 single-JSONs
    (v1-style), Phase 6 methodology files, Phase 7 synthesis, and
    findings.sarif. Merges all into one list so fixture matching works
    regardless of where the orchestrator actually wrote findings."""
    findings: list[dict] = []
    current = artifact_dir / ".claude-audit" / "current"

    for jsonl in sorted(current.glob("phase-05-*.jsonl")):
        findings.extend(load_jsonl(jsonl))
    for js in sorted(current.glob("phase-05-*.json")):
        try:
            doc = load_json(js)
            if isinstance(doc, list):
                findings.extend(doc)
            elif isinstance(doc, dict):
                if isinstance(doc.get("findings"), list):
                    findings.extend(doc["findings"])
                elif isinstance(doc.get("results"), list):
                    findings.extend(doc["results"])
        except (json.JSONDecodeError, OSError):
            pass

    config_path = current / "phase-06-config.json"
    if config_path.exists():
        try:
            doc = load_json(config_path)
            if isinstance(doc, list):
                findings.extend(doc)
            elif isinstance(doc, dict) and isinstance(doc.get("findings"), list):
                findings.extend(doc["findings"])
        except (json.JSONDecodeError, OSError):
            pass

    for extra in ["phase-06-api-top10.jsonl", "phase-06-asvs.jsonl", "phase-06-linddun.jsonl"]:
        p = current / extra
        if p.exists():
            try:
                findings.extend(load_jsonl(p))
            except (json.JSONDecodeError, OSError):
                pass

    syn_path = current / "phase-07-synthesis.json"
    if syn_path.exists():
        try:
            doc = load_json(syn_path)
            if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
                findings.extend(doc["findings"])
        except (json.JSONDecodeError, OSError):
            pass

    # SARIF — the canonical machine-readable export. Always include.
    sarif_path = current / "findings.sarif"
    if sarif_path.exists():
        try:
            doc = load_json(sarif_path)
            for run in doc.get("runs", []):
                for r in run.get("results", []):
                    findings.append(_sarif_result_to_finding(r))
        except (json.JSONDecodeError, OSError):
            pass

    return findings


def _sarif_result_to_finding(r: dict) -> dict:
    """Normalize a SARIF result into the JSONL finding shape used by
    finding_matches_expectation. Best-effort CWE extraction; absent
    category (SARIF doesn't carry our skill's category vocab)."""
    rule_id = r.get("ruleId") or ""
    props = r.get("properties") or {}
    cwe = None
    if rule_id.startswith("CWE-"):
        cwe = rule_id
    elif isinstance(props.get("cwe"), str):
        cwe = props["cwe"]
    elif isinstance(props.get("cwes"), list) and props["cwes"]:
        cwe = props["cwes"][0]
    else:
        for tag in props.get("tags", []) or []:
            if isinstance(tag, str) and tag.startswith("CWE-"):
                cwe = tag
                break
    locs = r.get("locations") or []
    f_uri = ""
    line = None
    if locs:
        loc = locs[0].get("physicalLocation") or {}
        f_uri = (loc.get("artifactLocation") or {}).get("uri") or ""
        line = (loc.get("region") or {}).get("startLine")
    return {
        "cwe": cwe,
        "category": props.get("category") or props.get("kind"),
        "file": f_uri,
        "handler_file": f_uri,
        "line": line,
        "title": (r.get("message") or {}).get("text"),
        "_source": "sarif",
    }


def check_expectations(
    artifact_dir: Path, expected: dict, failures: list[str]
) -> None:
    findings = collect_all_findings(artifact_dir)
    if not findings:
        failures.append("no findings collected — every hard expectation will fail")
        return

    # Split fixtures into hard (must_match=true; default) and soft.
    hard_missing: list[dict] = []
    soft_missing: list[dict] = []
    for exp in expected["expectations"]:
        matches = [f for f in findings if finding_matches_expectation(f, exp)]
        if not matches:
            if exp.get("must_match", True) is False:
                soft_missing.append(exp)
            else:
                hard_missing.append(exp)

    n_total = len(expected["expectations"])
    n_hard = sum(1 for e in expected["expectations"] if e.get("must_match", True))
    n_soft = n_total - n_hard

    print(
        f"  fixture summary: {n_total} total ({n_hard} must-match, {n_soft} soft); "
        f"matched {n_total - len(hard_missing) - len(soft_missing)}, "
        f"hard misses {len(hard_missing)}, soft misses {len(soft_missing)}",
        flush=True,
    )

    if soft_missing:
        for exp in soft_missing:
            print(
                f"WARN: soft fixture {exp['id']} not matched — "
                f"{exp['description']} (cwe={exp['cwe']} file≈{exp['file_pattern']}). "
                "Likely needs deeper cat-* fan-out; single-shot orchestrators often miss.",
                file=sys.stderr,
            )

    if hard_missing:
        failures.append(
            f"{len(hard_missing)} of {n_hard} hard fixture expectations not matched:"
        )
        for exp in hard_missing:
            failures.append(
                f"  - {exp['id']}: {exp['description']} "
                f"(expected cwe={exp['cwe']} category={exp['category']} "
                f"file≈{exp['file_pattern']})"
            )


def check_gated_categories_diagnostic(
    artifact_dir: Path, expected: dict
) -> None:
    gated = expected.get("gated_categories", {})
    current = artifact_dir / ".claude-audit" / "current"
    for cat, reason in gated.items():
        for jsonl in current.glob(f"phase-05-{cat}-*.jsonl"):
            try:
                rows = load_jsonl(jsonl)
            except (json.JSONDecodeError, OSError):
                continue
            if rows:
                print(
                    f"NOTE: gated category '{cat}' produced {len(rows)} finding(s). "
                    f"Reason on file: {reason[:80]}... "
                    "Consider updating fixtures.",
                    file=sys.stderr,
                )


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--artifact-dir", type=Path, required=True,
                        help="Root of the audited repo (contains .claude-audit/).")
    parser.add_argument("--repo-root", type=Path,
                        default=Path(__file__).resolve().parent.parent.parent,
                        help="Root of this skill's own repo.")
    parser.add_argument("--fixture", type=Path,
                        default=Path(__file__).resolve().parent / "expected-findings.json")
    parser.add_argument("--skip-expectations", action="store_true",
                        help="Only run structural checks; skip fixture match.")
    parser.add_argument("--require-jsonschema-backend", action="store_true",
                        help="Hard-fail if Python `jsonschema` is not installed.")
    args = parser.parse_args()

    if not args.artifact_dir.exists():
        print(f"ERROR: artifact-dir does not exist: {args.artifact_dir}", file=sys.stderr)
        sys.exit(2)
    if not args.fixture.exists():
        print(f"ERROR: fixture not found: {args.fixture}", file=sys.stderr)
        sys.exit(2)

    expected = load_json(args.fixture)
    gated_cats = set(expected.get("gated_categories", {}).keys())
    failures: list[str] = []

    print(f"=== E2E assertion suite ({expected['target']}) ===")
    print(f"artifact-dir: {args.artifact_dir}")
    print()

    print("[1/5] Phase-done markers...", flush=True)
    check_phase_markers(args.artifact_dir, failures)

    print("[2/5] SARIF structure...", flush=True)
    check_sarif_structure(args.artifact_dir, failures)

    print("[3/5] Report section headers (tolerant)...", flush=True)
    check_report_sections(args.artifact_dir, failures)

    print("[4/5] Phase-05 JSONL schema + CWE-in-map (gated-aware)...", flush=True)
    check_jsonl_schema_validity(
        args.repo_root, args.artifact_dir, gated_cats,
        args.require_jsonschema_backend, failures,
    )

    if not args.skip_expectations:
        print("[5/5] Fixture expectations...", flush=True)
        check_expectations(args.artifact_dir, expected, failures)
        check_gated_categories_diagnostic(args.artifact_dir, expected)
    else:
        print("[5/5] Fixture expectations — SKIPPED (--skip-expectations).", flush=True)

    sys.stdout.flush()
    print()
    if failures:
        print(f"=== FAIL — {len(failures)} issue(s) ===", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        sys.exit(1)
    print("=== PASS — all structural + fixture checks green ===")


if __name__ == "__main__":
    main()
