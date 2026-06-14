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


def check_manifest_required_outputs(repo_root: Path, artifact_dir: Path,
                                    failures: list[str]) -> None:
    """Walk skills/security-audit/manifest.yaml and validate the contract:
      - every required_outputs.path exists,
      - every required_outputs.path_glob with at_least_one matches at
        least one file,
      - no file matching forbidden_pattern exists,
      - empty_if_gated is documented but not enforced (we don't replay
        the gate condition here; that lives in the audit's own logic).

    Soft-skip with a note if PyYAML is missing — manifest cross-check
    is supplementary; the rest of the suite still validates the run.
    Phase 8 is also skipped because its skip_if rules require replaying
    audit-time conditions; v2.0.3 candidate."""
    manifest_path = repo_root / "skills" / "security-audit" / "manifest.yaml"
    if not manifest_path.exists():
        return  # Pre-2.0.2 layout — existing checks cover.

    try:
        import yaml  # noqa: F401
    except ImportError:
        print("  NOTE: PyYAML not installed; skipping manifest cross-check.",
              file=sys.stderr)
        return

    try:
        with open(manifest_path) as f:
            manifest = yaml.safe_load(f)
    except yaml.YAMLError as e:
        failures.append(f"manifest.yaml: parse error — {e}")
        return

    for phase in manifest.get("phases", []):
        pid = phase.get("id")
        if pid == 8:
            # Phase 8's skip_if conditions need audit.log replay; defer.
            continue
        for req in phase.get("required_outputs", []):
            if "path" in req:
                target = artifact_dir / req["path"]
                if not target.exists():
                    failures.append(
                        f"manifest phase-{pid:02d}: missing required output {req['path']}"
                    )
            elif "path_glob" in req and req.get("at_least_one"):
                pattern = req["path_glob"]
                matches = list(artifact_dir.glob(pattern))
                if not matches:
                    failures.append(
                        f"manifest phase-{pid:02d}: zero matches for required glob {pattern}"
                    )
        # forbidden_outputs is a phase-level sibling of required_outputs.
        # Each entry has {path, reason}; the reason is surfaced in the
        # failure message so a user can act on it.
        for forbidden in phase.get("forbidden_outputs", []):
            target = artifact_dir / forbidden["path"]
            if target.exists():
                reason = forbidden.get("reason", "no reason given in manifest")
                failures.append(
                    f"manifest phase-{pid:02d}: forbidden output {forbidden['path']} is present — {reason}"
                )

    # Phase 5 specifically: validate phase-05-skipped.json shape if present.
    skipped_path = artifact_dir / ".claude-audit" / "current" / "phase-05-skipped.json"
    if skipped_path.exists():
        try:
            with open(skipped_path) as f:
                skipped_doc = json.load(f)
            if not (isinstance(skipped_doc, dict) and "skipped" in skipped_doc and isinstance(skipped_doc["skipped"], list)):
                failures.append(
                    f"manifest phase-05: phase-05-skipped.json must be {{'skipped': [...]}}; got {type(skipped_doc).__name__}"
                )
        except json.JSONDecodeError as e:
            failures.append(f"manifest phase-05: phase-05-skipped.json parse error — {e}")


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
    # Resolve the output dir the run actually used (lib/output-routing.md):
    # persisted in .claude-audit/config.json, default docs/security-audit-output/.
    out_dir = "docs/security-audit-output"
    cfg = artifact_dir / ".claude-audit" / "config.json"
    if cfg.exists():
        try:
            out_dir = json.loads(cfg.read_text()).get("output_dir", out_dir)
        except (ValueError, OSError):
            pass
    candidates = [
        artifact_dir / out_dir / "security-audit-report.md",
        artifact_dir / "docs" / "security-audit-output" / "security-audit-report.md",
        artifact_dir / "docs" / "security-audit-report.md",  # pre-v2.1 legacy
        artifact_dir / ".claude-audit" / "current" / "phase-07-report.md",
    ]
    report = next((c for c in candidates if c.exists()), None)
    if report is None:
        failures.append("MISSING: phase-07-report.md (checked all three paths)")
        return
    content = report.read_text()

    # Hard-fail headers. Title check accepts any leading-`# ` line that
    # mentions "security" + "audit" (e.g. `# Security Audit Report` or
    # `# OWASP Juice Shop — Security Audit Report` — the orchestrator
    # often prefixes the project name).
    hard_required = [
        (r"^#\s+.*[Ss]ecurity.*[Aa]udit", "report title containing 'Security Audit'"),
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

        # An empty JSONL is VALID if the matching .done marker exists —
        # that means the sub-agent ran and legitimately found zero
        # findings on this (category, partition) pair. The .done marker
        # is the source of truth for "did the sub-agent execute"; the
        # JSONL contents reflect what it found. Only flag empty JSONLs
        # that ALSO lack a .done (genuinely missing fan-out output).
        done_marker = jsonl.with_suffix(".done")
        if jsonl.stat().st_size == 0:
            if done_marker.exists():
                continue  # legitimate "checked, nothing here"
            if cat in gated_categories:
                continue
            failures.append(
                f"EMPTY: {jsonl.name} — category '{cat}' produced no findings AND no .done marker"
            )
            continue
        rows = load_jsonl(jsonl)
        if not rows:
            if done_marker.exists():
                continue
            if cat in gated_categories:
                continue
            failures.append(
                f"EMPTY: {jsonl.name} — no rows AND no .done marker"
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


# --- Precision/recall scorecard (schema v3) ---------------------------------
#
# The coverage gate (check_expectations) answers "did we find the bugs?".
# The scorecard adds "did we ALSO avoid flagging safe code?" by scoring
# every finding against the fixture's positive expectations AND its
# negative_expectations[] decoys:
#
#   TP = a positive expectation matched by >=1 finding.
#   FN = a positive expectation with no matching finding.
#   FP = a finding that matches a negative_expectation's forbidden tuple
#        (file + forbidden_cwe/forbidden_category) at >= the decoy's
#        min_severity, AND is not itself a true positive (a finding that
#        legitimately satisfies a positive expectation is never counted
#        as an FP, even if it also lands on a decoy file — TP precedes FP;
#        see neg-03 in expected-findings.json).
#
#   precision = TP / (TP + FP)   recall = TP / (TP + FN)   F1 = 2PR/(P+R)
#
# Findings that land outside any labeled region (neither a positive nor a
# decoy) are "unscored" — precision is computed only over labeled
# territory so legitimate extra finds are not penalised (research note
# §2). Default gate floors are 0.0 (no-op) so the scorecard is purely
# additive and never regresses the existing coverage gate.

SEVERITY_RANK = {
    "INFO": 0, "INFORMATIONAL": 0, "NONE": 0, "NOTE": 0,
    "LOW": 1, "WARNING": 1, "WARN": 1,
    "MEDIUM": 2, "MODERATE": 2, "MED": 2,
    "HIGH": 3, "ERROR": 3,
    "CRITICAL": 4, "CRIT": 4,
}


def finding_severity_rank(finding: dict) -> int:
    """Best-effort severity → ordinal rank. Accepts a textual `severity`
    (LOW/MEDIUM/HIGH/CRITICAL or SARIF level/INFO synonyms) or a numeric
    SARIF `security-severity` (CVSS 0-10). Unknown/absent severity is
    treated as MEDIUM (rank 2) — the conservative default so a finding
    with no severity still counts against a MEDIUM-floor decoy."""
    # Prefer the numeric CVSS-style score (SARIF properties.security-severity)
    # — it is finer-grained than the coarse SARIF `level` (error/warning/note),
    # so when both are present the numeric value wins.
    score = finding.get("security_severity")
    if score is None:
        props = finding.get("properties")
        if isinstance(props, dict):
            score = props.get("security-severity")
    if score is not None:
        try:
            v = float(score)
        except (TypeError, ValueError):
            v = None
        if v is not None:
            if v >= 9.0:
                return 4
            if v >= 7.0:
                return 3
            if v >= 4.0:
                return 2
            if v > 0.0:
                return 1
            return 0
    # No numeric score → fall back to a textual severity / SARIF level.
    sev = finding.get("severity")
    if isinstance(sev, str) and sev.strip():
        return SEVERITY_RANK.get(sev.strip().upper(), 2)
    return 2  # no severity info → conservative MEDIUM


def finding_matches_negative(finding: dict, neg: dict) -> bool:
    """True if `finding` lands on a negative_expectation decoy AND matches
    its forbidden tuple at >= the decoy's min_severity. A decoy may forbid
    by cwe (forbidden_cwe / forbidden_cwes), by category
    (forbidden_category / forbidden_categories), or both — when both are
    given, EITHER matching is enough to count as an FP (a naive auditor
    flagging the safe file under the wrong cwe OR the wrong category is
    still a false positive)."""
    # File must match first — a decoy is location-scoped.
    patterns = [neg["file_pattern"]] + neg.get("alternate_file_patterns", [])
    f_file = normalize_path(finding.get("handler_file") or finding.get("file"))
    if not any(
        fnmatch.fnmatch(f_file, p)
        or fnmatch.fnmatch(f_file, f"*/{p}")
        or f_file.endswith(p)
        for p in patterns
    ):
        return False

    # Severity floor (default MEDIUM if the decoy omits one).
    floor = neg.get("min_severity", "MEDIUM")
    floor_rank = SEVERITY_RANK.get(str(floor).upper(), 2)
    if finding_severity_rank(finding) < floor_rank:
        return False

    forbidden_cwes = neg.get("forbidden_cwes", [])
    if "forbidden_cwe" in neg:
        forbidden_cwes = [neg["forbidden_cwe"]] + forbidden_cwes
    forbidden_cats = neg.get("forbidden_categories", [])
    if "forbidden_category" in neg:
        forbidden_cats = [neg["forbidden_category"]] + forbidden_cats

    if not forbidden_cwes and not forbidden_cats:
        # Decoy with no forbidden tuple = "nothing of MEDIUM+ here".
        return True

    cwe_hit = bool(forbidden_cwes) and finding.get("cwe") in forbidden_cwes
    # SARIF findings carry no native category; only score category-FP on
    # non-SARIF findings (mirrors finding_matches_expectation's policy).
    cat_hit = (
        bool(forbidden_cats)
        and finding.get("_source") != "sarif"
        and finding.get("category") in forbidden_cats
    )
    return cwe_hit or cat_hit


def score_findings(findings: list[dict], expected: dict) -> dict:
    """Compute the precision/recall scorecard. Returns a dict with overall
    and per-category P/R/F1 + TP/FP/FN counts and the labeled detail.

    TP/FN are computed over HARD positive expectations (must_match!=false)
    — the gated contract. Soft expectations are reported separately and do
    NOT drag recall down (they are orchestrator-depth-dependent, see the
    existing check_expectations rationale). FP is computed over decoys."""
    positives = expected.get("expectations", [])
    negatives = expected.get("negative_expectations", [])

    # First pass: which findings are true positives (so TP can pre-empt FP).
    tp_finding_ids: set[int] = set()
    tp_exps: list[dict] = []
    fn_hard: list[dict] = []
    soft_missed: list[dict] = []
    per_cat: dict[str, dict] = {}

    def _cat_bucket(cat: str) -> dict:
        return per_cat.setdefault(
            cat, {"tp": 0, "fp": 0, "fn": 0}
        )

    for exp in positives:
        is_hard = exp.get("must_match", True)
        matches = [f for f in findings if finding_matches_expectation(f, exp)]
        cat = exp.get("category", "uncategorized")
        if matches:
            for f in matches:
                tp_finding_ids.add(id(f))
            if is_hard:
                tp_exps.append(exp)
                _cat_bucket(cat)["tp"] += 1
        else:
            if is_hard:
                fn_hard.append(exp)
                _cat_bucket(cat)["fn"] += 1
            else:
                soft_missed.append(exp)

    # Second pass: false positives = findings on a decoy's forbidden tuple
    # that are not already counted as a true positive.
    fp_detail: list[dict] = []
    for neg in negatives:
        for f in findings:
            if id(f) in tp_finding_ids:
                continue  # TP precedes FP
            if finding_matches_negative(f, neg):
                cat = (
                    neg.get("forbidden_category")
                    or f.get("category")
                    or "uncategorized"
                )
                _cat_bucket(cat)["fp"] += 1
                fp_detail.append({
                    "decoy_id": neg.get("id"),
                    "file": f.get("handler_file") or f.get("file"),
                    "cwe": f.get("cwe"),
                    "category": f.get("category"),
                    "source": f.get("_source", "jsonl"),
                    "title": f.get("title"),
                })

    tp = len(tp_exps)
    fn = len(fn_hard)
    fp = len(fp_detail)

    def _metrics(tp_: int, fp_: int, fn_: int) -> dict:
        precision = tp_ / (tp_ + fp_) if (tp_ + fp_) else 1.0
        recall = tp_ / (tp_ + fn_) if (tp_ + fn_) else 1.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        # OWASP-Benchmark-style Youden index (TPR - FPR) is not computable
        # without a labeled-negative count per category; we expose F1 as
        # the headline and leave Youden to the optional external bench.
        return {
            "tp": tp_, "fp": fp_, "fn": fn_,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    overall = _metrics(tp, fp, fn)
    per_category = {
        cat: _metrics(b["tp"], b["fp"], b["fn"]) for cat, b in sorted(per_cat.items())
    }

    return {
        "target": expected.get("target"),
        "schema_version": expected.get("schema_version"),
        "has_decoys": bool(negatives),
        "n_positives_hard": sum(1 for e in positives if e.get("must_match", True)),
        "n_positives_soft": sum(1 for e in positives if not e.get("must_match", True)),
        "n_decoys": len(negatives),
        "overall": overall,
        "per_category": per_category,
        "soft_missed": [
            {"id": e.get("id"), "cwe": e.get("cwe"), "category": e.get("category"),
             "file_pattern": e.get("file_pattern")}
            for e in soft_missed
        ],
        "false_positives": fp_detail,
        "false_negatives": [
            {"id": e.get("id"), "cwe": e.get("cwe"), "category": e.get("category"),
             "file_pattern": e.get("file_pattern"), "description": e.get("description")}
            for e in fn_hard
        ],
    }


def write_scorecard(scorecard: dict, scorecard_dir: Path) -> tuple[Path, Path]:
    """Emit scorecard.json + scorecard.md into scorecard_dir. Returns the
    two paths. Stdlib-only; no templating dependency."""
    scorecard_dir.mkdir(parents=True, exist_ok=True)
    json_path = scorecard_dir / "scorecard.json"
    md_path = scorecard_dir / "scorecard.md"

    with open(json_path, "w") as f:
        json.dump(scorecard, f, indent=2, sort_keys=False)
        f.write("\n")

    o = scorecard["overall"]
    lines = [
        f"# Precision/Recall Scorecard — {scorecard.get('target')}",
        "",
        f"- Fixture schema: v{scorecard.get('schema_version')}",
        f"- Decoys present: {'yes' if scorecard.get('has_decoys') else 'no (precision = 1.0 by convention — no FP denominator)'}",
        f"- Hard positives: {scorecard.get('n_positives_hard')} | "
        f"Soft positives: {scorecard.get('n_positives_soft')} | "
        f"Decoys: {scorecard.get('n_decoys')}",
        "",
        "## Overall",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| True Positives (TP) | {o['tp']} |",
        f"| False Positives (FP) | {o['fp']} |",
        f"| False Negatives (FN) | {o['fn']} |",
        f"| **Precision** | **{o['precision']:.3f}** |",
        f"| **Recall** | **{o['recall']:.3f}** |",
        f"| **F1** | **{o['f1']:.3f}** |",
        "",
        "> Recall is computed over HARD fixtures only (the gated contract). "
        "Soft fixtures are orchestrator-depth-dependent and reported "
        "separately; they do not lower recall. Precision is computed only "
        "over labeled territory (positives + decoys); unlabeled extra "
        "finds are neither rewarded nor penalised.",
        "",
        "## Per-category",
        "",
        "| Category | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|---|",
    ]
    for cat, m in scorecard["per_category"].items():
        lines.append(
            f"| {cat} | {m['tp']} | {m['fp']} | {m['fn']} | "
            f"{m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} |"
        )
    if not scorecard["per_category"]:
        lines.append("| _(none)_ | | | | | | |")

    if scorecard["false_positives"]:
        lines += ["", "## False positives (findings on safe decoys)", ""]
        for fp in scorecard["false_positives"]:
            lines.append(
                f"- decoy `{fp['decoy_id']}` — finding {fp.get('cwe')}"
                f"/{fp.get('category')} on `{fp.get('file')}` "
                f"(source={fp.get('source')}): {fp.get('title')}"
            )

    if scorecard["false_negatives"]:
        lines += ["", "## False negatives (missed hard fixtures)", ""]
        for fn in scorecard["false_negatives"]:
            lines.append(
                f"- `{fn['id']}` — {fn.get('description')} "
                f"(expected {fn.get('cwe')}/{fn.get('category')} "
                f"file≈{fn.get('file_pattern')})"
            )

    if scorecard["soft_missed"]:
        lines += ["", "## Soft fixtures not matched (non-fatal)", ""]
        for s in scorecard["soft_missed"]:
            lines.append(
                f"- `{s['id']}` — {s.get('cwe')}/{s.get('category')} "
                f"file≈{s.get('file_pattern')}"
            )

    lines.append("")
    with open(md_path, "w") as f:
        f.write("\n".join(lines))

    return json_path, md_path


def normalize_path(p: str | None) -> str:
    """Normalize a finding's file field for glob matching. Strips
    absolute-path prefixes from known repo roots + leading `./`."""
    if not p:
        return ""
    p = p.strip()
    if p.startswith("/"):
        for marker in ("/juice-shop/", "/DVWA/", "/crapi/", "/crAPI/", "/gosec/", "/e2e-target/"):
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
            # Phase-05 is one of several finding sources; a malformed or
            # unreadable per-category JSON shouldn't abort ingestion of
            # the rest. Missing-artifact + structural checks elsewhere
            # surface the underlying skill failure.
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
            # Same rationale as phase-05: best-effort ingestion across
            # multiple optional sources.
            pass

    for extra in ["phase-06-api-top10.jsonl", "phase-06-asvs.jsonl", "phase-06-linddun.jsonl"]:
        p = current / extra
        if p.exists():
            try:
                findings.extend(load_jsonl(p))
            except (json.JSONDecodeError, OSError):
                # Optional methodology JSONLs — skip silently when malformed
                # so one bad file doesn't mask the others.
                pass

    syn_path = current / "phase-07-synthesis.json"
    if syn_path.exists():
        try:
            doc = load_json(syn_path)
            if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
                findings.extend(doc["findings"])
        except (json.JSONDecodeError, OSError):
            # phase-07-synthesis.json is optional alongside the canonical
            # phase-07-report.md + findings.sarif; absence here doesn't
            # affect the SARIF-driven matching path below.
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
            # SARIF parse failure is a separately-asserted condition
            # (see check_sarif_validity); here we just skip ingestion so
            # JSONL-derived findings still flow through.
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
        # Carry severity so the scorecard's decoy min_severity floor works on
        # SARIF-sourced findings (the canonical export). Prefer the numeric
        # CVSS-style security-severity; fall back to the SARIF `level`
        # (error/warning/note) which finding_severity_rank also understands.
        "security_severity": props.get("security-severity"),
        "severity": r.get("level"),
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


def run_scorecard(args, expected: dict, failures: list[str]) -> None:
    """Collect findings, compute the precision/recall scorecard, emit
    scorecard.{json,md}, print a summary, and apply optional floor gates.

    Additive by design: with default floors (0.0) this never appends to
    `failures`, so the existing exit-code behavior is preserved. A run
    against a fixture with no negative_expectations[] yields precision=1.0
    (no FP denominator) — also non-failing."""
    findings = collect_all_findings(args.artifact_dir)
    scorecard = score_findings(findings, expected)

    scorecard_dir = args.scorecard_dir or args.fixture.resolve().parent
    try:
        json_path, md_path = write_scorecard(scorecard, scorecard_dir)
        wrote = f"{json_path} + {md_path.name}"
    except OSError as e:
        # Emitting the scorecard is best-effort; a write failure must not
        # mask the structural/coverage verdict. Report and continue.
        print(f"  WARN: could not write scorecard to {scorecard_dir}: {e}",
              file=sys.stderr)
        wrote = "(write failed)"

    o = scorecard["overall"]
    print(
        f"  scorecard: TP={o['tp']} FP={o['fp']} FN={o['fn']} | "
        f"precision={o['precision']:.3f} recall={o['recall']:.3f} "
        f"f1={o['f1']:.3f} | decoys={scorecard['n_decoys']} "
        f"({'with FP denominator' if scorecard['has_decoys'] else 'no FP denominator'})",
        flush=True,
    )
    print(f"  wrote: {wrote}", flush=True)

    # Optional floor gates. Default floors are 0.0 → never fire.
    if args.min_recall > 0.0 and o["recall"] < args.min_recall:
        failures.append(
            f"scorecard recall {o['recall']:.3f} < floor {args.min_recall:.3f} "
            f"(--min-recall): {o['fn']} hard fixture(s) missed."
        )
    if args.min_precision > 0.0:
        if not scorecard["has_decoys"]:
            print(
                "  NOTE: --min-precision set but fixture has no "
                "negative_expectations[] decoys; precision is 1.0 by "
                "convention (no FP denominator). Gate is a no-op until "
                "decoys exist.",
                file=sys.stderr,
            )
        elif o["precision"] < args.min_precision:
            failures.append(
                f"scorecard precision {o['precision']:.3f} < floor "
                f"{args.min_precision:.3f} (--min-precision): {o['fp']} "
                f"false positive(s) on safe decoys."
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
    parser.add_argument("--skip-manifest-check", action="store_true",
                        help="Skip the manifest.yaml required_outputs / forbidden_outputs cross-check. Use when a known false-positive exists and the rest of the suite is sufficient.")
    parser.add_argument("--scorecard-dir", type=Path, default=None,
                        help="Directory to write scorecard.json + scorecard.md "
                             "(default: the fixture's directory, e.g. tests/e2e/). "
                             "run-e2e-test.sh points this at the artifact dir so "
                             "live runs don't dirty the repo.")
    parser.add_argument("--no-scorecard", action="store_true",
                        help="Do not compute/emit the precision/recall scorecard "
                             "(scorecard is additive; this restores pre-v3 behavior).")
    parser.add_argument("--min-precision", type=float, default=0.0,
                        help="Fail the suite if scorecard precision < this floor "
                             "(default 0.0 = no-op; only meaningful when decoys "
                             "exist). Opt-in gate; does not affect existing runs.")
    parser.add_argument("--min-recall", type=float, default=0.0,
                        help="Fail the suite if scorecard recall (over HARD "
                             "fixtures) < this floor (default 0.0 = no-op; the "
                             "existing hard-fixture coverage gate already enforces "
                             "recall=1.0). Opt-in tightening.")
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

    n_steps = 6 if args.no_scorecard else 7

    print(f"[1/{n_steps}] Phase-done markers...", flush=True)
    check_phase_markers(args.artifact_dir, failures)

    if args.skip_manifest_check:
        print(f"[2/{n_steps}] Manifest cross-check — SKIPPED (--skip-manifest-check).", flush=True)
    else:
        print(f"[2/{n_steps}] Manifest required_outputs cross-check...", flush=True)
        check_manifest_required_outputs(args.repo_root, args.artifact_dir, failures)

    print(f"[3/{n_steps}] SARIF structure...", flush=True)
    check_sarif_structure(args.artifact_dir, failures)

    print(f"[4/{n_steps}] Report section headers (tolerant)...", flush=True)
    check_report_sections(args.artifact_dir, failures)

    print(f"[5/{n_steps}] Phase-05 JSONL schema + CWE-in-map (gated-aware)...", flush=True)
    check_jsonl_schema_validity(
        args.repo_root, args.artifact_dir, gated_cats,
        args.require_jsonschema_backend, failures,
    )

    if not args.skip_expectations:
        print(f"[6/{n_steps}] Fixture expectations...", flush=True)
        check_expectations(args.artifact_dir, expected, failures)
        check_gated_categories_diagnostic(args.artifact_dir, expected)
    else:
        print(f"[6/{n_steps}] Fixture expectations — SKIPPED (--skip-expectations).", flush=True)

    if not args.no_scorecard:
        print(f"[7/{n_steps}] Precision/recall scorecard (schema v3)...", flush=True)
        run_scorecard(args, expected, failures)

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
