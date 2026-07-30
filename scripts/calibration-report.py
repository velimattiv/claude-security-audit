#!/usr/bin/env python3
"""
calibration-report.py — measure the audit's own precision.

Joins a run's `phase-07-findings-computed.jsonl` to a human verdict file
and emits per-`rule_family`, per-`evidence_class` and per-`attacked`
true-positive rates. This is the instrument behind the standing
calibration control recorded in
`skills/security-audit/manifest.yaml` (`calibration:`).

WHY THIS EXISTS
    Audit tools are almost never measured. The v2.5.0 numbers in
    `docs/EPIC-v2.6-calibrated-severity.md` §1.2 exist only because eight
    security engineers triaged 255 HIGH-or-above findings by hand. That
    is not repeatable. This script turns the *next* calibration into a
    command, so a rule-family regression is caught by the tool rather
    than by eight engineers.

DEFINITIONS
    true            := the verdict is REAL or ACCEPTED_RISK.
    rate            := true / n, where n counts every finding carrying a
                       usable verdict. Unresolvable duplicates count as
                       NOT true, so `rate` is an honest LOWER BOUND.
    rate_excl       := the same ratio with unresolvable duplicates
                       dropped from both numerator and denominator.
                       Always >= rate. Report both — on the v2.5.0 run
                       the gap was 43.1% vs 53.9%, which is large enough
                       that quoting only one of them misleads.

    Both columns are printed. The standing control in manifest.yaml
    gates on `rate` (the lower bound) by deliberate choice: using the
    flattering number to pass your own quality gate is the exact failure
    mode this release exists to correct.

VERDICT FILE FORMAT
    Either a JSON array or JSONL (one object per line). Blank lines and
    `#`-prefixed lines are ignored so a file can be annotated by hand.

        {"id": "F-0001", "verdict": "REAL"}
        {"id": "F-0002", "verdict": "FALSE_POSITIVE", "notes": "gate is two frames up"}
        {"id": "F-0003", "verdict": "DUPLICATE", "duplicate_of": "F-0001"}
        {"id": "F-0004", "verdict": "ACCEPTED_RISK", "notes": "provisional emit-only cred"}

    Required keys: `id` (must match a finding's `id`), `verdict`.
    Optional keys: `duplicate_of` (required in practice for DUPLICATE to
    resolve), `notes` (free text, never interpreted), plus any other
    key you like — unknown keys are preserved and ignored.

    Verdicts:
        REAL            — a real defect.                   [counts true]
        ACCEPTED_RISK   — real, and the project accepts it. [counts true]
        FALSE_POSITIVE  — not a defect.                    [counts false]
        UNCERTAIN       — triaged, could not be decided.   [counts false;
                          reported separately so it is never silent]
        DUPLICATE       — folds into `duplicate_of`; resolves transitively.
        NOT_TRIAGED     — explicitly not looked at. EXCLUDED from every
                          denominator, reported as coverage.

    A finding with no verdict row at all is `untriaged`: excluded from
    every denominator and reported, so partial triage cannot silently
    inflate a rate.

    A DUPLICATE with no `duplicate_of`, one pointing at an id that does
    not exist, or one in a reference cycle, is UNRESOLVABLE. Those are
    counted and reported as their own line.

RULE FAMILY
    Keys on the finding's `rule_family` field (added in v2.6 Wave 0,
    `lib/finding-schema.json`). Values look like `deepdive:cat-02`,
    `validate-egress:R5`, `validate-collection-scoping:C1`,
    `scanner:semgrep`, `asvs`, `linddun`, `config`, `governance:R4`.

    Runs predating v2.6 have no `rule_family`. For those, the family is
    inferred from `sources[].detail` (e.g. `validate-egress.py:R5`); the
    count of inferred rows is always printed. Rows that resist both are
    bucketed as `(unlabelled)` rather than dropped.

    The headline table rolls fine-grained families up into the groups
    used in the epic's §1.2 table; `--by-rule` prints the fine-grained
    table instead.

MODES
    (default)         emit the precision tables.
    --check-manifest  recompute and compare against the rates recorded
                      in manifest.yaml; non-zero on drift. This is what
                      keeps the recorded numbers from rotting.
    --gate FINDINGS   apply the manifest's headline-band policy to a
                      findings file. Non-zero when a family that is BARRED
                      (measured below threshold over >= min_sample_size)
                      or UNRECORDED (no calibration entry at all) has a
                      finding in the headline severity band. A family
                      recorded as unmeasured is reported PROVISIONAL and
                      does NOT fail the gate — see manifest.yaml for why
                      those two states are treated differently.

USAGE
    # measure a run
    python3 scripts/calibration-report.py \
        --findings .claude-audit/current/phase-07-findings-computed.jsonl \
        --verdicts triage/verdicts.jsonl

    # fine-grained, machine-readable
    python3 scripts/calibration-report.py \
        --findings run.jsonl --verdicts verdicts.jsonl --by-rule --json

    # fail CI when a family drops below 50% measured precision
    python3 scripts/calibration-report.py \
        --findings run.jsonl --verdicts verdicts.jsonl --fail-below 0.50

    # has the manifest's recorded calibration rotted?
    python3 scripts/calibration-report.py \
        --findings run.jsonl --verdicts verdicts.jsonl --check-manifest

    # would this run put a barred family in the headline band?
    python3 scripts/calibration-report.py --gate run.jsonl

    # self-test against tests/fixtures/calibration/
    python3 scripts/calibration-report.py --self-test

EXIT CODES
    0 — report emitted (or check/gate/self-test passed)
    1 — missing or unparseable input
    2 — verdict file references unknown ids, or uses an unknown verdict
    3 — a threshold/gate/check failed (--fail-below, --check-manifest,
        --gate, --self-test)
"""
import argparse
import io
import json
import re
import sys
from contextlib import redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "skills" / "security-audit" / "manifest.yaml"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "calibration"

TRUE_VERDICTS = {"REAL", "ACCEPTED_RISK"}
FALSE_VERDICTS = {"FALSE_POSITIVE", "UNCERTAIN"}
EXCLUDED_VERDICTS = {"NOT_TRIAGED"}
KNOWN_VERDICTS = TRUE_VERDICTS | FALSE_VERDICTS | EXCLUDED_VERDICTS | {"DUPLICATE"}

# Fine-grained rule_family -> headline group. Ordered; first match wins.
# The right-hand labels are the ones used in EPIC-v2.6 §1.2 so the two
# tables can be compared row-for-row.
FAMILY_GROUPS = [
    (re.compile(r"^deepdive(:|$)"), "Category deep-dive agent"),
    (re.compile(r"^asvs(:|$)"), "ASVS checklist"),
    (re.compile(r"^linddun(:|$)"), "LINDDUN"),
    (re.compile(r"^config(:|$)"), "config (methodology)"),
    (re.compile(r"^validate-egress(:|$)"), "R-rules (validate-egress.py)"),
    (re.compile(r"^validate-collection-scoping(:|$)"), "C-rules (validate-collection-scoping.py)"),
    (re.compile(r"^scanner(:|$)"), "External scanner"),
    (re.compile(r"^governance(:|$)"), "Governance (composer)"),
]

# Fallback for pre-v2.6 runs with no rule_family: sources[].detail often
# carries "validate-egress.py:R5" / "validate-collection-scoping.py:C1".
_INFER_DETAIL = re.compile(r"\b(validate-egress|validate-collection-scoping)\.py:([A-Z]\d+[a-z]?)")

UNLABELLED = "(unlabelled)"


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------

def _iter_json_records(path: Path, what: str) -> list[dict]:
    """Read a file that is either a JSON array or JSONL. Tolerates blank
    lines and #-comments so a verdict file stays hand-editable."""
    try:
        raw = path.read_text()
    except OSError as e:
        die(f"cannot read {what} file {path}: {e}", 1)

    stripped = raw.lstrip()
    if stripped.startswith("["):
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as e:
            die(f"{what} file {path} is not valid JSON: {e}", 1)
        if not isinstance(doc, list):
            die(f"{what} file {path} must be a JSON array or JSONL", 1)
        return [r for r in doc if isinstance(r, dict)]

    out = []
    for lineno, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            die(f"{what} file {path}:{lineno} is not valid JSON: {e}", 1)
        if isinstance(rec, dict):
            out.append(rec)
    return out


def load_findings(path: Path) -> list[dict]:
    findings = _iter_json_records(path, "findings")
    if not findings:
        die(f"no findings loaded from {path}", 1)
    missing_id = sum(1 for f in findings if not f.get("id"))
    if missing_id:
        die(f"{missing_id} finding(s) in {path} have no `id` — cannot join to verdicts", 1)
    return findings


def load_verdicts(path: Path) -> dict[str, dict]:
    records = _iter_json_records(path, "verdicts")
    verdicts: dict[str, dict] = {}
    bad_verdicts: list[str] = []
    dupes: list[str] = []
    for rec in records:
        fid = rec.get("id")
        if not fid:
            die(f"verdict row without `id` in {path}: {json.dumps(rec)[:120]}", 2)
        verdict = str(rec.get("verdict", "")).strip().upper()
        if verdict not in KNOWN_VERDICTS:
            bad_verdicts.append(f"{fid}: {rec.get('verdict')!r}")
            continue
        if fid in verdicts:
            dupes.append(fid)
        verdicts[fid] = {
            "verdict": verdict,
            "duplicate_of": rec.get("duplicate_of"),
            "notes": rec.get("notes"),
        }
    if bad_verdicts:
        sys.stderr.write(
            "ERROR: unknown verdict value(s) — expected one of "
            + ", ".join(sorted(KNOWN_VERDICTS))
            + "\n"
        )
        for b in bad_verdicts[:20]:
            sys.stderr.write(f"  {b}\n")
        sys.exit(2)
    if dupes:
        sys.stderr.write(
            f"WARN: {len(dupes)} id(s) carry more than one verdict row; last wins: "
            + ", ".join(sorted(set(dupes))[:10])
            + "\n"
        )
    return verdicts


# --------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------

def family_of(finding: dict) -> tuple[str, bool]:
    """Return (rule_family, inferred). Never returns empty."""
    fam = finding.get("rule_family")
    if isinstance(fam, str) and fam.strip():
        return fam.strip(), False
    for src in finding.get("sources", []) or []:
        if not isinstance(src, dict):
            continue
        m = _INFER_DETAIL.search(str(src.get("detail", "")))
        if m:
            return f"{m.group(1)}:{m.group(2)}", True
    return UNLABELLED, False


def group_of(family: str) -> str:
    for pattern, label in FAMILY_GROUPS:
        if pattern.match(family):
            return label
    return family


def resolve_verdict(fid: str, verdicts: dict[str, dict]) -> tuple[str, str | None]:
    """Follow DUPLICATE -> duplicate_of to a terminal verdict.

    Returns (state, terminal_verdict).
      state == "resolved"     -> terminal_verdict is a non-DUPLICATE verdict
      state == "unresolvable" -> terminal_verdict is None; the chain has no
                                 `duplicate_of`, points at an unknown id, or
                                 forms a cycle. Counted as NOT true in the
                                 lower-bound column and dropped from the
                                 excl-cycles column.
      state == "missing"      -> no verdict row for this id at all
    """
    rec = verdicts.get(fid)
    if rec is None:
        return "missing", None
    seen = {fid}
    cur = rec
    while cur["verdict"] == "DUPLICATE":
        target = cur.get("duplicate_of")
        if not target or target in seen:
            return "unresolvable", None
        nxt = verdicts.get(target)
        if nxt is None:
            return "unresolvable", None
        seen.add(target)
        cur = nxt
    return "resolved", cur["verdict"]


class Bucket:
    __slots__ = ("n", "true", "unresolvable", "uncertain", "not_triaged", "untriaged")

    def __init__(self):
        self.n = 0             # denominator: usable verdicts, incl. unresolvable
        self.true = 0
        self.unresolvable = 0
        self.uncertain = 0
        self.not_triaged = 0   # explicitly NOT_TRIAGED — outside n
        self.untriaged = 0     # no verdict row at all — outside n

    @property
    def rate(self):
        return (self.true / self.n) if self.n else None

    @property
    def n_excl(self):
        return self.n - self.unresolvable

    @property
    def rate_excl(self):
        return (self.true / self.n_excl) if self.n_excl else None

    def as_dict(self):
        return {
            "n": self.n,
            "true": self.true,
            "rate": self.rate,
            "n_excl_cycles": self.n_excl,
            "rate_excl_cycles": self.rate_excl,
            "unresolvable_duplicates": self.unresolvable,
            "uncertain": self.uncertain,
            "not_triaged": self.not_triaged,
            "untriaged": self.untriaged,
        }


def calibrate(findings: list[dict], verdicts: dict[str, dict], by_rule: bool = False) -> dict:
    by_family: dict[str, Bucket] = {}
    by_evidence: dict[str, Bucket] = {}
    by_attacked: dict[str, Bucket] = {}
    total = Bucket()
    inferred = 0
    seen_ids = set()

    for f in findings:
        fid = f["id"]
        seen_ids.add(fid)
        fam, was_inferred = family_of(f)
        if was_inferred:
            inferred += 1
        key = fam if by_rule else group_of(fam)
        ev = f.get("evidence_class") or "(unset)"
        at = f.get("attacked") or "not_attempted"

        buckets = [
            by_family.setdefault(key, Bucket()),
            by_evidence.setdefault(ev, Bucket()),
            by_attacked.setdefault(at, Bucket()),
            total,
        ]

        state, verdict = resolve_verdict(fid, verdicts)
        for b in buckets:
            if state == "missing":
                b.untriaged += 1
            elif state == "unresolvable":
                b.n += 1
                b.unresolvable += 1
            elif verdict in EXCLUDED_VERDICTS:
                b.not_triaged += 1
            else:
                b.n += 1
                if verdict in TRUE_VERDICTS:
                    b.true += 1
                elif verdict == "UNCERTAIN":
                    b.uncertain += 1

    orphan_verdicts = sorted(set(verdicts) - seen_ids)

    return {
        "keyed_by": "rule_family" if by_rule else "rule_family_group",
        "findings_total": len(findings),
        "families_inferred_from_sources": inferred,
        "verdicts_total": len(verdicts),
        "verdicts_with_no_matching_finding": orphan_verdicts,
        "by_rule_family": {k: v.as_dict() for k, v in sorted(by_family.items())},
        "by_evidence_class": {k: v.as_dict() for k, v in sorted(by_evidence.items())},
        "by_attacked": {k: v.as_dict() for k, v in sorted(by_attacked.items())},
        "total": total.as_dict(),
    }


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def pct(x):
    return "  —  " if x is None else f"{x * 100:5.1f}%"


def render_table(title: str, rows: dict, note: str | None = None) -> str:
    width = max([len(k) for k in rows] + [len(title), 20])
    out = [f"\n{title}", "-" * (width + 40)]
    out.append(f"{'':{width}}  {'n':>5} {'true':>5} {'rate':>7} {'rate*':>7} {'dup?':>5}")
    for k, v in rows.items():
        out.append(
            f"{k:{width}}  {v['n']:>5} {v['true']:>5} "
            f"{pct(v['rate']):>7} {pct(v['rate_excl_cycles']):>7} "
            f"{v['unresolvable_duplicates']:>5}"
        )
    if note:
        out.append(note)
    return "\n".join(out)


def render(result: dict) -> str:
    out = ["=== /security-audit calibration report ==="]
    out.append(f"findings loaded:            {result['findings_total']}")
    out.append(f"verdict rows loaded:        {result['verdicts_total']}")
    if result["families_inferred_from_sources"]:
        out.append(
            f"rule_family inferred:       {result['families_inferred_from_sources']} "
            "(pre-v2.6 run — no rule_family field; derived from sources[].detail)"
        )
    if result["verdicts_with_no_matching_finding"]:
        orphans = result["verdicts_with_no_matching_finding"]
        out.append(f"verdicts with no finding:   {len(orphans)}  e.g. {', '.join(orphans[:5])}")

    t = result["total"]
    out.append("")
    out.append(f"triage coverage:            {t['n']} of {result['findings_total']} findings carry a usable verdict")
    if t["untriaged"]:
        out.append(f"  untriaged (no verdict):   {t['untriaged']}  — excluded from every denominator")
    if t["not_triaged"]:
        out.append(f"  NOT_TRIAGED (explicit):   {t['not_triaged']}  — excluded from every denominator")
    if t["uncertain"]:
        out.append(f"  UNCERTAIN:                {t['uncertain']}  — counted as NOT true")
    if t["unresolvable_duplicates"]:
        out.append(
            f"  unresolvable duplicates:  {t['unresolvable_duplicates']}  — counted as NOT true "
            "in `rate`, dropped from `rate*`"
        )

    out.append(render_table(f"By {result['keyed_by']}", result["by_rule_family"]))
    out.append(render_table("By evidence_class", result["by_evidence_class"]))
    out.append(render_table("By attacked", result["by_attacked"]))

    out.append("")
    out.append("-" * 60)
    out.append(
        f"TOTAL   n={t['n']}  true={t['true']}  "
        f"rate={pct(t['rate']).strip()}  rate*={pct(t['rate_excl_cycles']).strip()}  "
        f"unresolvable_duplicates={t['unresolvable_duplicates']}"
    )
    out.append("")
    out.append("rate  = true / n, unresolvable duplicates counted as NOT true (LOWER BOUND).")
    out.append("rate* = the same ratio with unresolvable duplicates dropped from both sides.")
    out.append("The standing control in manifest.yaml gates on `rate`, not `rate*`.")
    return "\n".join(out)


# --------------------------------------------------------------------------
# manifest interop
# --------------------------------------------------------------------------

def load_manifest_calibration(path: Path = MANIFEST, force_fallback: bool = False) -> dict:
    """Read the `calibration:` block from manifest.yaml.

    Uses PyYAML when it is installed. When it is not, falls back to a
    deliberately small hand-rolled reader so this script keeps working in
    the offline/minimal environments the skill is meant to run in — the
    rest of scripts/ treats PyYAML as a soft dependency too. The fallback
    understands exactly the shape this repo writes: a top-level
    `calibration:` mapping of scalars plus a `rule_family_precision:` list
    of flat `- key: value` records. `--self-test` asserts the two readers
    agree, so the fallback cannot silently drift away from the real file.
    """
    if not force_fallback:
        try:
            import yaml  # noqa: PLC0415
        except ImportError:
            pass
        else:
            try:
                doc = yaml.safe_load(path.read_text()) or {}
            except (OSError, yaml.YAMLError) as e:
                die(f"cannot parse manifest {path}: {e}", 1)
            block = dict(doc.get("calibration") or {})
            block["rule_family_precision"] = list(block.get("rule_family_precision") or [])
            return block

    try:
        lines = path.read_text().splitlines()
    except OSError as e:
        die(f"cannot read manifest {path}: {e}", 1)

    def scalar(tok: str):
        tok = tok.split("#", 1)[0].strip() if not tok.strip().startswith("#") else ""
        tok = tok.strip().strip('"').strip("'")
        if tok in ("true", "false"):
            return tok == "true"
        if tok in ("null", "~", ""):
            return None
        try:
            return int(tok)
        except ValueError:
            pass
        try:
            return float(tok)
        except ValueError:
            return tok

    block: dict = {}
    families: list[dict] = []
    in_block = False
    in_list = False
    cur: dict | None = None

    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if indent == 0:
            in_block = stripped.startswith("calibration:")
            in_list = False
            cur = None
            continue
        if not in_block:
            continue

        if indent == 2 and stripped.endswith(":") and ":" in stripped:
            key = stripped[:-1].strip()
            in_list = key == "rule_family_precision"
            cur = None
            if not in_list:
                block[key] = {}
            continue
        if indent == 2 and ":" in stripped:
            k, _, v = stripped.partition(":")
            block[k.strip()] = scalar(v)
            in_list = False
            continue
        if in_list and stripped.startswith("- "):
            cur = {}
            families.append(cur)
            k, _, v = stripped[2:].partition(":")
            cur[k.strip()] = scalar(v)
            continue
        if in_list and cur is not None and ":" in stripped:
            k, _, v = stripped.partition(":")
            cur[k.strip()] = scalar(v)
            continue

    block["rule_family_precision"] = families
    return block


def family_status(rec: dict, threshold: float, min_sample: int) -> str:
    n = rec.get("n")
    rate = rec.get("rate")
    if not isinstance(n, int) or rate is None or not isinstance(rate, (int, float)):
        return "unmeasured"
    if n < min_sample:
        return "insufficient_sample"
    return "measured_pass" if rate >= threshold else "measured_fail"


def cmd_check_manifest(result: dict, tolerance: float) -> int:
    """Compare freshly-measured rates against the manifest's record."""
    cal = load_manifest_calibration()
    threshold = cal.get("headline_band_min_precision")
    min_sample = cal.get("min_sample_size")
    if threshold is None or min_sample is None:
        sys.stderr.write(
            "ERROR: manifest.yaml has no calibration.headline_band_min_precision "
            "/ min_sample_size — the standing control is not configured\n"
        )
        return 3

    recorded = {r.get("family"): r for r in cal["rule_family_precision"] if r.get("family")}
    measured = result["by_rule_family"]
    problems = []

    print("=== manifest calibration check ===")
    print(f"threshold: {threshold:.2f}   min_sample: {min_sample}\n")
    print(f"{'family':44} {'recorded':>9} {'measured':>9} {'n':>5}  {'recorded status':<20}")
    for fam in sorted(set(recorded) | set(measured)):
        rec = recorded.get(fam)
        got = measured.get(fam)
        rec_rate = rec.get("rate") if rec else None
        got_rate = got.get("rate") if got else None
        got_n = got.get("n", 0) if got else 0
        status = family_status(rec or {}, threshold, min_sample) if rec else "NOT RECORDED"
        print(f"{fam:44} {pct(rec_rate):>9} {pct(got_rate):>9} {got_n:>5}  {status:<20}")

        if rec is None:
            problems.append(
                f"{fam}: emitted by this run but absent from manifest "
                "calibration.rule_family_precision — add it, with rate: null if unmeasured"
            )
            continue

        # A rate over a handful of verdicts is an anecdote. Calling it drift
        # would reproduce, inside the control itself, the small-n error the
        # control exists to prevent.
        if got_n < min_sample:
            if got_n:
                print(f"{'':44} {'':>9} {'':>9} {'':>5}  (n < {min_sample} — not checked)")
            continue

        if rec_rate is None:
            problems.append(
                f"{fam}: manifest records NO rate, but this run measured "
                f"{got_rate:.3f} over {got_n} verdicts — record it"
            )
        elif abs(rec_rate - got_rate) > tolerance:
            problems.append(
                f"{fam}: manifest records {rec_rate:.3f}, this run measures {got_rate:.3f} "
                f"over {got_n} verdicts (drift {abs(rec_rate - got_rate):.3f} > tolerance "
                f"{tolerance:.3f}) — update the manifest"
            )

        new_status = family_status({"n": got_n, "rate": got_rate}, threshold, min_sample)
        if new_status == "measured_fail" and status != "measured_fail":
            problems.append(
                f"{fam}: NEWLY BELOW THRESHOLD ({got_rate:.3f} < {threshold:.2f} over "
                f"{got_n} verdicts) — this family must be barred from the headline band"
            )

    print()
    if problems:
        print("DRIFT:")
        for p in problems:
            print(f"  - {p}")
        return 3
    print("manifest calibration is current.")
    return 0


def cmd_gate(findings_path: Path) -> int:
    """Apply the manifest's headline-band policy to a findings file."""
    cal = load_manifest_calibration()
    threshold = cal.get("headline_band_min_precision")
    min_sample = cal.get("min_sample_size")
    band = [
        s.strip().strip("\"'").upper()
        for s in str(cal.get("headline_band", "CRITICAL,HIGH")).strip("[]").split(",")
        if s.strip()
    ]
    cap = str(cal.get("barred_family_severity_cap", "MEDIUM")).upper()
    if threshold is None or min_sample is None:
        sys.stderr.write("ERROR: manifest.yaml calibration block is not configured\n")
        return 3

    recorded = {r.get("family"): r for r in cal["rule_family_precision"] if r.get("family")}
    barred = {f for f, r in recorded.items() if family_status(r, threshold, min_sample) == "measured_fail"}
    provisional = {
        f for f, r in recorded.items()
        if family_status(r, threshold, min_sample) in ("unmeasured", "insufficient_sample")
    }

    findings = load_findings(findings_path)
    violations = []
    provisional_hits = []
    unknown_families = {}
    for f in findings:
        fam, _ = family_of(f)
        group = group_of(fam)
        sev = str(f.get("severity", "")).upper()
        if sev not in band:
            continue
        if group in barred:
            violations.append((f.get("id"), group, sev))
        elif group in provisional:
            provisional_hits.append((f.get("id"), group, sev))
        elif group not in recorded:
            unknown_families.setdefault(group, 0)
            unknown_families[group] += 1

    print("=== headline-band calibration gate ===")
    print(f"policy: a rule family measured below {threshold:.0%} over >= {min_sample} verdicts")
    print(f"        may not carry severity in {band}; cap is {cap}.\n")

    if provisional_hits:
        print(f"PROVISIONAL ({len(provisional_hits)} finding(s)) — family precision is NOT measured;")
        print("  admitted to the headline band but must be labelled, never silent:")
        for fid, group, sev in provisional_hits[:15]:
            print(f"    {sev:<8} {group:<44} {fid}")
        if len(provisional_hits) > 15:
            print(f"    … and {len(provisional_hits) - 15} more")
        print()

    rc = 0

    if unknown_families:
        # An UNRECORDED family is a different state from an unmeasured one and
        # is treated harder. "Unmeasured" means someone enumerated the family
        # and wrote down that we do not know its precision — an explicit,
        # reviewable claim. "Unrecorded" means nobody has looked at all, and
        # the remedy is one line of YAML rather than a triage round. A family
        # nobody has an opinion about must not reach the headline band
        # silently; that is the exact state this control exists to end.
        print("UNRECORDED FAMILIES in the headline band — no calibration entry exists at all:")
        for group, count in sorted(unknown_families.items()):
            print(f"    {count:>4}  {group}")
        print("  Add each to manifest.yaml calibration.rule_family_precision, with")
        print("  rate: null if it has never been measured, so the state is explicit.")
        print()
        rc = 3

    if violations:
        print(f"BARRED ({len(violations)} violation(s)) — measured below threshold:")
        for fid, group, sev in violations:
            print(f"    {sev:<8} -> {cap:<8} {group:<40} {fid}")
        print()
        rc = 3

    if rc == 0:
        print("gate clean: no barred or unrecorded family in the headline band.")
    return rc


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------

def _dig(node, path: str):
    """Resolve a dotted path into nested dicts, longest-key-first.

    Family names legitimately contain dots ("R-rules (validate-egress.py)"),
    so a naive split() would silently resolve to None and turn every
    assertion about the two families that matter most into a vacuous pass.
    """
    while path:
        if not isinstance(node, dict):
            return None
        parts = path.split(".")
        for i in range(len(parts), 0, -1):
            candidate = ".".join(parts[:i])
            if candidate in node:
                node = node[candidate]
                path = ".".join(parts[i:])
                break
        else:
            return None
    return node


def cmd_self_test() -> int:
    """Fixture-backed self-test.

    tests/fixtures/calibration/ encodes, in miniature, every arithmetic
    case the v2.5.0 triage hit: a true finding, an accepted risk, a plain
    false positive, an UNCERTAIN, a resolvable duplicate chain, a
    two-node duplicate CYCLE, a DUPLICATE with no target, a dangling
    DUPLICATE, an explicit NOT_TRIAGED, and a finding with no verdict at
    all. If the with-cycles and excl-cycles columns ever collapse into
    each other, this is what notices.
    """
    findings_path = FIXTURES / "findings-computed.jsonl"
    verdicts_path = FIXTURES / "verdicts.jsonl"
    expected_path = FIXTURES / "expected.json"
    for p in (findings_path, verdicts_path, expected_path):
        if not p.exists():
            sys.stderr.write(f"ERROR: self-test fixture missing: {p}\n")
            return 1

    expected = json.loads(expected_path.read_text())
    findings = load_findings(findings_path)
    verdicts = load_verdicts(verdicts_path)

    fails = []
    for keyed_by, exp in expected.items():
        if keyed_by.startswith("_"):
            continue  # fixture commentary
        result = calibrate(findings, verdicts, by_rule=(keyed_by == "by_rule"))
        for path, want in exp.items():
            if path.startswith("_"):
                continue
            got = _dig(result, path)
            if isinstance(want, float) and isinstance(got, float):
                same = abs(want - got) < 1e-9
            else:
                same = want == got
            if same:
                print(f"  ok: [{keyed_by}] {path} == {want}")
            else:
                fails.append(f"[{keyed_by}] {path}: got {got!r}, want {want!r}")

    # The gate and the manifest reader must survive a real manifest.
    cal = load_manifest_calibration()
    if not isinstance(cal.get("headline_band_min_precision"), float):
        fails.append("manifest calibration.headline_band_min_precision is not a float")
    else:
        print("  ok: manifest calibration block parses")
    if not cal.get("rule_family_precision"):
        fails.append("manifest calibration.rule_family_precision is empty")
    else:
        print(f"  ok: manifest records {len(cal['rule_family_precision'])} rule families")

    # The no-PyYAML fallback reader must agree with PyYAML, or an offline
    # operator silently gets a different policy from a CI runner.
    try:
        import yaml  # noqa: F401,PLC0415
    except ImportError:
        print("  note: PyYAML absent — fallback-reader cross-check skipped")
    else:
        fb = load_manifest_calibration(force_fallback=True)
        for key in ("headline_band_min_precision", "min_sample_size",
                    "barred_family_severity_cap", "gate_on"):
            if str(fb.get(key)) != str(cal.get(key)):
                fails.append(
                    f"manifest readers disagree on {key}: "
                    f"pyyaml={cal.get(key)!r} fallback={fb.get(key)!r}"
                )
        fb_rates = {r.get("family"): r.get("rate") for r in fb["rule_family_precision"]}
        yaml_rates = {r.get("family"): r.get("rate") for r in cal["rule_family_precision"]}
        if fb_rates != yaml_rates:
            fails.append(f"manifest readers disagree on rates: {fb_rates} vs {yaml_rates}")
        else:
            print("  ok: PyYAML and fallback manifest readers agree")

    # Every recorded family must resolve to a known status, and at least
    # one family must be barred — a control with nothing to bar on the
    # data that motivated it is not a control.
    threshold = cal.get("headline_band_min_precision") or 0.0
    min_sample = cal.get("min_sample_size") or 0
    statuses = {r.get("family"): family_status(r, threshold, min_sample) for r in cal["rule_family_precision"]}
    if "measured_fail" not in statuses.values():
        fails.append("no recorded family is measured_fail — the seeded calibration lost its teeth")
    else:
        barred = sorted(f for f, s in statuses.items() if s == "measured_fail")
        print(f"  ok: barred families: {', '.join(barred)}")

    # --gate must actually bar something on this fixture, and must not bar
    # the deep-dive rows. A gate that passes everything is not a gate.
    buf = io.StringIO()
    with redirect_stdout(buf):
        gate_rc = cmd_gate(findings_path)
    gate_out = buf.getvalue()
    if gate_rc != 3:
        fails.append(f"--gate returned {gate_rc}, want 3 (barred families are in the band)")
    elif "CAL-005" not in gate_out or "CAL-009" not in gate_out:
        fails.append("--gate did not bar the R-rule/C-rule findings in the headline band")
    elif "CAL-001" in gate_out.split("BARRED")[-1]:
        fails.append("--gate barred a deep-dive finding (measured_pass must not be barred)")
    else:
        print("  ok: --gate bars the two measured_fail families and nothing else")
    if "PROVISIONAL" not in gate_out:
        fails.append("--gate did not report provisional (unmeasured) families — "
                     "absence of data must never be silent")
    else:
        print("  ok: --gate reports unmeasured families as PROVISIONAL, not as pass")

    # --check-manifest must not call drift on an n-of-1 sample.
    buf = io.StringIO()
    with redirect_stdout(buf):
        check_rc = cmd_check_manifest(calibrate(findings, verdicts), 0.05)
    if check_rc != 0:
        fails.append(f"--check-manifest returned {check_rc} on a small-n fixture; it must "
                     "decline to judge below min_sample_size rather than report drift")
    else:
        print("  ok: --check-manifest declines to judge samples below min_sample_size")

    print()
    if fails:
        for f in fails:
            sys.stderr.write(f"  FAIL: {f}\n")
        print(f"self-test FAILED ({len(fails)} assertion(s))")
        return 3
    print("self-test PASSED")
    return 0


# --------------------------------------------------------------------------

def die(msg: str, code: int):
    sys.stderr.write(f"ERROR: {msg}\n")
    sys.exit(code)


def main():
    parser = argparse.ArgumentParser(
        prog="calibration-report.py",
        description=(
            "Join a run's phase-07-findings-computed.jsonl to a triage verdict "
            "file and emit measured true-positive rates by rule_family, "
            "evidence_class and attacked. Backs the standing calibration "
            "control in skills/security-audit/manifest.yaml."
        ),
        epilog=(
            "verdict file (JSON array or JSONL):\n"
            '  {"id": "F-0001", "verdict": "REAL"}\n'
            '  {"id": "F-0002", "verdict": "FALSE_POSITIVE", "notes": "gate is two frames up"}\n'
            '  {"id": "F-0003", "verdict": "DUPLICATE", "duplicate_of": "F-0001"}\n'
            "\n"
            "verdicts: REAL | ACCEPTED_RISK | FALSE_POSITIVE | UNCERTAIN | DUPLICATE | NOT_TRIAGED\n"
            "  true := REAL or ACCEPTED_RISK.\n"
            "  Unresolvable duplicate cycles count as NOT true, so `rate` is a lower bound;\n"
            "  `rate*` drops them. Both are always printed.\n"
            "\n"
            "examples:\n"
            "  python3 scripts/calibration-report.py \\\n"
            "      --findings .claude-audit/current/phase-07-findings-computed.jsonl \\\n"
            "      --verdicts triage/verdicts.jsonl\n"
            "\n"
            "  python3 scripts/calibration-report.py --findings run.jsonl \\\n"
            "      --verdicts v.jsonl --by-rule --json\n"
            "\n"
            "  python3 scripts/calibration-report.py --findings run.jsonl \\\n"
            "      --verdicts v.jsonl --fail-below 0.50\n"
            "\n"
            "  python3 scripts/calibration-report.py --findings run.jsonl \\\n"
            "      --verdicts v.jsonl --check-manifest\n"
            "\n"
            "  python3 scripts/calibration-report.py --gate run.jsonl\n"
            "  python3 scripts/calibration-report.py --self-test\n"
            "\n"
            "exit codes: 0 ok | 1 bad input | 2 bad verdict file | 3 threshold/gate/check failed\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--findings", type=Path,
                        help="phase-07-findings-computed.jsonl (JSONL or JSON array)")
    parser.add_argument("--verdicts", type=Path,
                        help="triage verdict file (JSONL or JSON array of {id, verdict})")
    parser.add_argument("--by-rule", action="store_true",
                        help="key on the raw rule_family instead of the §1.2 roll-up groups")
    parser.add_argument("--json", action="store_true",
                        help="emit the machine-readable struct instead of tables")
    parser.add_argument("--fail-below", type=float, metavar="RATE",
                        help="exit 3 if any family's measured `rate` (the lower bound) is "
                             "below RATE over at least --min-sample verdicts")
    parser.add_argument("--min-sample", type=int, default=30, metavar="N",
                        help="minimum verdicts before --fail-below judges a family (default 30)")
    parser.add_argument("--check-manifest", action="store_true",
                        help="compare measured rates against manifest.yaml's calibration block")
    parser.add_argument("--tolerance", type=float, default=0.05, metavar="D",
                        help="allowed drift for --check-manifest (default 0.05)")
    parser.add_argument("--gate", type=Path, metavar="FINDINGS",
                        help="apply the manifest headline-band policy to a findings file")
    parser.add_argument("--self-test", action="store_true",
                        help="run the fixture-backed self-test and exit")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(cmd_self_test())
    if args.gate:
        sys.exit(cmd_gate(args.gate))
    if not args.findings or not args.verdicts:
        parser.error("--findings and --verdicts are both required "
                     "(or use --gate / --self-test)")

    findings = load_findings(args.findings)
    verdicts = load_verdicts(args.verdicts)
    result = calibrate(findings, verdicts, by_rule=args.by_rule)

    if args.check_manifest:
        sys.exit(cmd_check_manifest(result, args.tolerance))

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render(result))

    if args.fail_below is not None:
        below = [
            (fam, v) for fam, v in result["by_rule_family"].items()
            if v["n"] >= args.min_sample and v["rate"] is not None and v["rate"] < args.fail_below
        ]
        if below:
            sys.stderr.write(
                f"\nFAIL: {len(below)} rule family/families below {args.fail_below:.0%} "
                f"over >= {args.min_sample} verdicts:\n"
            )
            for fam, v in below:
                sys.stderr.write(f"  {fam}: {v['true']}/{v['n']} = {v['rate'] * 100:.1f}%\n")
            sys.exit(3)

    sys.exit(0)


if __name__ == "__main__":
    main()
