#!/usr/bin/env python3
"""
redact-scanner-output.py — strip credential material from scanner output at
ingest, before anything else in the pipeline reads it.

WHERE THIS RUNS
---------------
`steps/phase-04-scanners.md §4.4b`, immediately after each scanner writes its
report and BEFORE §4.5 normalization, §4.6 slimming, or any sub-agent read.
Run it against the whole scanner directory:

    python3 "$SKILL_DIR/lib/redact-scanner-output.py" \
        .claude-audit/current/phase-04-scanners/

WHY AT INGEST AND NOT AT THE WRITE BOUNDARY
-------------------------------------------
The v2.6.0 leak was found late and the obvious patch is a scrubber in front of
the `cp` in `phase-07-synthesis.md §7.10`. That is the wrong primary layer for
two reasons:

  * Raw secrets would still be written to disk, still be handed to deep-dive
    sub-agents as context, and still sit in `.claude-audit/history/<ts>/` after
    the run. The blast radius would shrink, not close.
  * It makes a pattern blocklist the only control, and a blocklist racing
    gitleaks' ~170 detectors loses. Whatever gitleaks detects and this table
    does not is a secret that survives to the deliverable.

This script does not pattern-match for the primary strip. It removes SARIF
`snippet` / `contents` / `insertedContent` — the ArtifactContent objects that
carry raw file text — from EVERY scanner run unconditionally. That is a
whitelist: nothing survives because the field is gone, regardless of which
detector fired or whether this skill has ever heard of the credential format.

The strip is free because no consumer in this skill reads those fields:

  * `lib/sarif-postprocess.md` slim schema keeps rule/level/file/line/message
    and explicitly discards the rest.
  * Phases 5-7 read the slim form.
  * `tests/e2e/assertions.py:_sarif_result_to_finding` extracts from `ruleId`,
    `properties.cwe`, `properties.cwes` and `tags`.
  * GitHub's Security tab renders the region from file+line, not from snippet.

What triage actually loses is the ability to eyeball the matched string. It
gets `properties.secret_fingerprint` instead — stable across runs, so a secret
finding still dedupes in Phase 7 and still carries forward in the Phase 8
baseline, with nothing spendable in the file.

Pattern scrubbing (`lib/secret-detectors.py`) runs afterwards as a second pass
over free text — scanner `message.text`, invocation command lines, trufflehog
`ExtraData` — which is the residue the structural strip cannot reach.

EXIT CODES
----------
  0  file(s) processed (with or without redactions)
  1  `--check` only: credential material is present
  2  usage or I/O error
"""

import argparse
import importlib.util
import json
import os
import sys
from collections import Counter

_LIB = os.path.dirname(os.path.abspath(__file__))


def _load_detectors():
    """Load the shared detector table.

    Hyphenated filenames are not importable, and the canonical module must be
    the one that ships next to this file — never a same-named module that
    happens to be earlier on sys.path.
    """
    path = os.path.join(_LIB, "secret-detectors.py")
    if not os.path.exists(path):
        sys.stderr.write("ERROR: shared detector table missing at %s\n" % path)
        sys.exit(2)
    spec = importlib.util.spec_from_file_location("_audit_secret_detectors", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SD = _load_detectors()

# SARIF ArtifactContent lives under exactly these property names. Every one of
# them can carry raw file text, and none is read downstream.
_CONTENT_KEYS = ("snippet", "contents", "insertedContent")

_SCANNER_EXTS = (".sarif", ".json", ".jsonl")


# ---------------------------------------------------------------------------
# Structural strip
# ---------------------------------------------------------------------------

def _already_redacted(content):
    """True when this ArtifactContent is a marker we wrote on an earlier pass."""
    text = content.get("text")
    return (
        isinstance(text, str)
        and len(content) == 1
        and SD.MARKER_RE.fullmatch(text.strip()) is not None
    )


def _strip_content(node, context, stats):
    """Recursively replace every ArtifactContent object with a marker.

    Returns the list of fingerprints removed under `node`, so the caller can
    attach them to the owning result.
    """
    fps = []
    if isinstance(node, dict):
        for key in list(node.keys()):
            value = node[key]
            if key in _CONTENT_KEYS and isinstance(value, dict):
                if _already_redacted(value):
                    # Re-running the redactor must be a no-op, or `--check`
                    # reports a clean file as dirty and the Phase 7 write gate
                    # can never pass.
                    continue
                raw = value.get("text")
                if raw is None:
                    raw = value.get("binary")
                if raw is None:
                    raw = json.dumps(value, sort_keys=True)
                if not isinstance(raw, str):
                    raw = str(raw)
                fp = SD.fingerprint(raw, context)
                # Stay a valid ArtifactContent so the document still validates
                # as SARIF 2.1.0 — consumers that expect the shape keep working.
                node[key] = {
                    "text": "[REDACTED:artifact_content:%s:len%d]" % (fp, len(raw))
                }
                stats["artifact_content"] += 1
                fps.append(fp)
            else:
                fps.extend(_strip_content(value, context, stats))
    elif isinstance(node, list):
        for item in node:
            fps.extend(_strip_content(item, context, stats))
    return fps


def _scrub_strings(node, context, stats):
    """Second pass: pattern-scrub every remaining string in the subtree.

    Deliberately untyped by key. A secret in an unexpected field is exactly the
    case a key allowlist would miss, and scrubbing a string that was never a
    secret costs nothing — `secret-detectors.is_placeholder` already rejects
    documentation furniture and our own markers.
    """
    if isinstance(node, dict):
        for key, value in list(node.items()):
            if isinstance(value, str):
                new, fired = SD.scrub(value, context)
                if fired:
                    node[key] = new
                    stats.update(fired)
            else:
                _scrub_strings(value, context, stats)
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            if isinstance(item, str):
                new, fired = SD.scrub(item, context)
                if fired:
                    node[idx] = new
                    stats.update(fired)
            else:
                _scrub_strings(item, context, stats)


def redact_sarif(doc, stats):
    """Redact a SARIF 2.1.0 document in place."""
    runs = doc.get("runs")
    if not isinstance(runs, list):
        return
    for run in runs:
        if not isinstance(run, dict):
            continue
        driver = ""
        tool = run.get("tool")
        if isinstance(tool, dict) and isinstance(tool.get("driver"), dict):
            driver = tool["driver"].get("name") or ""

        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            context = "%s:%s" % (driver, result.get("ruleId") or "")
            fps = _strip_content(result, context, stats)
            _scrub_strings(result, context, stats)
            if fps:
                props = result.setdefault("properties", {})
                if isinstance(props, dict):
                    # First fingerprint is the primary location's match; the
                    # rest are context regions and related locations.
                    props["secret_fingerprint"] = fps[0]
                    props["redacted"] = "true"

        # Everything outside results[]: embedded artifact contents, invocation
        # command lines (a token passed as a CLI argument), rule help text.
        for key in ("artifacts", "invocations", "tool", "properties",
                    "originalUriBaseIds", "conversion", "logicalLocations"):
            if key in run:
                ctx = "%s:%s" % (driver, key)
                _strip_content(run[key], ctx, stats)
                _scrub_strings(run[key], ctx, stats)


# ---------------------------------------------------------------------------
# trufflehog JSONL
# ---------------------------------------------------------------------------

# trufflehog puts the credential in these fields. `Redacted` is trufflehog's own
# partial mask, and for several detectors it is the full secret — it is dropped
# rather than trusted.
_TRUFFLEHOG_SECRET_KEYS = ("Raw", "RawV2", "Redacted", "StructuredData")


def redact_trufflehog_entry(entry, stats):
    """Redact one trufflehog JSONL record in place."""
    if not isinstance(entry, dict):
        return
    detector = entry.get("DetectorName") or entry.get("detector_name") or ""
    context = "trufflehog:%s" % detector

    primary_fp = None
    for key in _TRUFFLEHOG_SECRET_KEYS:
        if key in entry and entry[key] not in (None, ""):
            raw = entry[key]
            if isinstance(raw, str) and SD.MARKER_RE.fullmatch(raw.strip()):
                # Already redacted on an earlier pass — see `_already_redacted`.
                primary_fp = primary_fp or entry.get("SecretFingerprint")
                continue
            if not isinstance(raw, str):
                raw = json.dumps(raw, sort_keys=True, default=str)
            fp = SD.fingerprint(raw, context)
            primary_fp = primary_fp or fp
            entry[key] = "[REDACTED:trufflehog_%s:%s:len%d]" % (key.lower(), fp, len(raw))
            stats["trufflehog_" + key.lower()] += 1

    # ExtraData is free-form per detector and routinely carries the account,
    # the scopes — and sometimes the credential itself.
    for key in ("ExtraData", "DetectorDescription", "SourceMetadata"):
        if key in entry:
            _scrub_strings(entry[key], context, stats)

    if primary_fp:
        entry["SecretFingerprint"] = primary_fp


# ---------------------------------------------------------------------------
# File handling
# ---------------------------------------------------------------------------

def _looks_like_sarif(obj):
    return isinstance(obj, dict) and isinstance(obj.get("runs"), list)


def _looks_like_trufflehog(obj):
    """Shape sniff, not a filename check.

    trufflehog emits JSONL, but a run with exactly ONE finding produces a file
    that is also valid single-document JSON. Dispatching on line count sent
    that file down the generic path and skipped the handler that knows about
    `Raw` / `RawV2` / `Redacted` — a one-secret repository is precisely the
    case that must not be handled worse than a ten-secret one.
    """
    return isinstance(obj, dict) and (
        "DetectorName" in obj or "detector_name" in obj
        or ("SourceMetadata" in obj and "Raw" in obj)
    )


def process_file(path, check_only, stats):
    """Redact one scanner output file. Returns True if it changed."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        sys.stderr.write("ERROR: cannot read %s: %s\n" % (path, exc))
        return False

    if not text.strip():
        return False

    before = Counter(stats)

    # Single JSON document (SARIF, or any scanner JSON).
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None

    if doc is not None:
        if _looks_like_sarif(doc):
            redact_sarif(doc, stats)
        elif _looks_like_trufflehog(doc):
            redact_trufflehog_entry(doc, stats)
            _strip_content(doc, "trufflehog:%s" % os.path.basename(path), stats)
            _scrub_strings(doc, "trufflehog:%s" % os.path.basename(path), stats)
        else:
            # Unknown JSON shape: fail closed and treat the whole document as
            # potentially secret-bearing rather than passing it through.
            _strip_content(doc, "unknown:%s" % os.path.basename(path), stats)
            _scrub_strings(doc, "unknown:%s" % os.path.basename(path), stats)
        changed = Counter(stats) != before
        if changed and not check_only:
            _atomic_write(path, json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
        return changed

    # JSONL (trufflehog).
    out_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            out_lines.append(line)
            continue
        try:
            entry = json.loads(stripped)
        except ValueError:
            # Not JSON — scrub as raw text rather than skipping it.
            new, fired = SD.scrub(line, "raw:%s" % os.path.basename(path))
            if fired:
                stats.update(fired)
            out_lines.append(new)
            continue
        redact_trufflehog_entry(entry, stats)
        # Then the generic passes. `redact_trufflehog_entry` only knows
        # trufflehog's field names; a JSONL file from any other tool would
        # otherwise cross this function untouched.
        ctx = "jsonl:%s" % os.path.basename(path)
        _strip_content(entry, ctx, stats)
        _scrub_strings(entry, ctx, stats)
        out_lines.append(json.dumps(entry, ensure_ascii=False))

    changed = Counter(stats) != before
    if changed and not check_only:
        _atomic_write(path, "\n".join(out_lines) + "\n")
    return changed


def _atomic_write(path, content):
    """Write via a temp file in the same directory, then rename.

    A half-written scanner report on a crash would be a JSON parse failure on
    the next read, and the failure mode of "redaction was interrupted" must
    never be "the unredacted original is still there".
    """
    tmp = path + ".redact.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _collect(paths):
    files = []
    for path in paths:
        if os.path.isdir(path):
            for root, _dirs, names in os.walk(path):
                for name in sorted(names):
                    if name.endswith(_SCANNER_EXTS) and not name.endswith(".redact.tmp"):
                        files.append(os.path.join(root, name))
        elif os.path.exists(path):
            files.append(path)
        else:
            sys.stderr.write("WARNING: no such path, skipping: %s\n" % path)
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="redact-scanner-output.py",
        description="Strip credential material from scanner output at ingest.",
    )
    parser.add_argument("paths", nargs="+",
                        help="scanner report files, or directories to walk")
    parser.add_argument("--check", action="store_true",
                        help="report without modifying; exit 1 if material is present")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the JSON summary on stdout")
    args = parser.parse_args(argv)

    files = _collect(args.paths)
    if not files:
        sys.stderr.write("ERROR: no scanner output found in: %s\n" % " ".join(args.paths))
        return 2

    stats = Counter()
    touched = []
    for path in files:
        if process_file(path, args.check, stats):
            touched.append(path)

    summary = {
        "files_scanned": len(files),
        "files_redacted": len(touched),
        "redactions": dict(sorted(stats.items())),
        "total_redactions": sum(stats.values()),
        "mode": "check" if args.check else "redact",
    }
    if not args.quiet:
        print(json.dumps(summary, indent=2))

    if args.check and touched:
        sys.stderr.write(
            "FAIL: credential material present in %d scanner file(s):\n%s\n"
            % (len(touched), "\n".join("  " + p for p in touched))
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
