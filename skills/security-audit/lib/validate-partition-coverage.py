#!/usr/bin/env python3
"""
validate-partition-coverage.py — Phase-1 partition coverage gate (v2.5).

WHY THIS EXISTS
---------------
In the 2026-07-25 audit that missed a CRITICAL authorization defect, one of the
three independent reasons it was missed was pure bookkeeping:

    server/api/content/  matched NO partition path-glob and fell through
    silently — "explicit partition membership: NONE". Its nearest partition
    ranked #9 against a default top_n of 8, so even that would have been
    inventory-only.

An entire directory of HTTP handlers left the audit without a word. Partition
coverage was ASSUMED; it was never ASSERTED.

This script asserts it. Every non-ignored source file must map to at least one
partition's `paths_included`. Unmatched files FAIL Phase 1 rather than landing in
a catch-all. It additionally reports:

  - CATCH-ALL partitions (a bare `**` alongside specific partitions) — the shape
    that turns "unmatched" into "silently swallowed";
  - the DEEP-DIVE CUT LINE — which partitions fell below top_n, how many source
    files they contain, and therefore what the run consciously chose not to
    deep-dive. A budget decision is fine; an invisible budget decision is not.

Usage:
  python3 validate-partition-coverage.py partitions.json \
      [--source-root .] [--ignore .claude-audit/ignore.txt] \
      [--out coverage.json] [--fail-on-multi] [--quiet]

Exit codes:
  0  every source file maps to a partition
  1  at least one unmatched file (or a multi-match with --fail-on-multi)
  2  argparse / I/O / shape error
"""
import argparse
import json
import re
import sys
from pathlib import Path

# Extensions that carry application logic. A file outside this set cannot hide a
# handler, so leaving it unpartitioned is not a coverage hole.
_SOURCE_EXT = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte",
    ".py", ".rb", ".php", ".java", ".kt", ".kts", ".scala", ".cs", ".go",
    ".rs", ".ex", ".exs", ".erl", ".swift", ".m", ".mm", ".c", ".cc", ".cpp",
    ".h", ".hpp", ".graphql", ".gql", ".proto", ".sql",
}
_DEFAULT_IGNORE_PARTS = {
    ".git", "node_modules", "dist", "build", "target", ".venv", "venv",
    "__pycache__", "vendor", ".next", ".nuxt", ".output", "coverage",
    ".pytest_cache", ".tox", ".gradle", ".idea", ".claude-audit",
}


def glob_to_re(pat):
    """Translate a path glob to a regex. Supports **, *, ?, and character
    classes. `**` crosses directory separators; `*` does not."""
    p = str(pat).strip().lstrip("./")
    out, i = [], 0
    while i < len(p):
        c = p[i]
        if c == "*":
            if p[i:i + 3] == "**/":
                out.append("(?:.*/)?")
                i += 3
                continue
            if p[i:i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
            continue
        if c == "?":
            out.append("[^/]")
            i += 1
            continue
        if c == "[":
            j = p.find("]", i)
            if j > i:
                out.append(p[i:j + 1])
                i = j + 1
                continue
        out.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def is_catch_all(pat):
    return str(pat).strip().lstrip("./") in ("**", "**/*", "*", "./**")


def load_ignore(path):
    pats = []
    if path and Path(path).exists():
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                pats.append(line)
    return pats


def ignored(rel, ignore_res):
    parts = set(Path(rel).parts)
    if parts & _DEFAULT_IGNORE_PARTS:
        return True
    for rx, raw in ignore_res:
        if rx.match(rel):
            return True
        # A bare directory pattern like `dist/` ignores the whole subtree.
        if raw.endswith("/") and (rel + "/").startswith(raw.lstrip("./")):
            return True
        if raw.rstrip("/") in parts:
            return True
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("partitions", type=Path)
    ap.add_argument("--source-root", type=Path, default=Path("."))
    ap.add_argument("--ignore", type=Path,
                    default=Path(".claude-audit/ignore.txt"))
    ap.add_argument("--out", type=Path)
    ap.add_argument("--fail-on-multi", action="store_true",
                    help="Also fail when a file matches more than one partition. "
                         "Off by default — workflow.md §1.6 resolves overlaps by "
                         "highest risk, but the overlap is always reported.")
    ap.add_argument("--max-report", type=int, default=40)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    try:
        doc = json.loads(args.partitions.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read {args.partitions}: {e}", file=sys.stderr)
        return 2

    parts = doc.get("partitions", doc if isinstance(doc, list) else [])
    if not parts:
        print("ERROR: partitions.json contains no partitions[].", file=sys.stderr)
        return 2

    compiled, catch_alls = [], []
    for p in parts:
        pid = p.get("id", "?")
        globs = p.get("paths_included") or ([p["path"] + "/**"] if p.get("path") else [])
        for g in globs:
            if is_catch_all(g):
                catch_alls.append((pid, g))
            compiled.append((pid, g, glob_to_re(g)))
        # A partition path with no trailing /** still owns its subtree.
        if p.get("path"):
            base = str(p["path"]).strip("/")
            if base and base != ".":
                compiled.append((pid, base + "/**", glob_to_re(base + "/**")))

    ignore_raw = load_ignore(args.ignore)
    ignore_res = [(glob_to_re(r), r) for r in ignore_raw]

    root = args.source_root
    if not root.is_dir():
        print(f"ERROR: --source-root not a directory: {root}", file=sys.stderr)
        return 2

    unmatched, multi, per_partition = [], [], {}
    total = 0
    for f in sorted(root.rglob("*")):
        if not f.is_file() or f.suffix not in _SOURCE_EXT:
            continue
        rel = str(f.relative_to(root)).replace("\\", "/")
        if ignored(rel, ignore_res):
            continue
        total += 1
        hits = sorted({pid for pid, _g, rx in compiled if rx.match(rel)})
        if not hits:
            unmatched.append(rel)
        else:
            if len(hits) > 1:
                multi.append({"file": rel, "partitions": hits})
            for h in hits:
                per_partition[h] = per_partition.get(h, 0) + 1

    depth = {p.get("id"): p.get("depth", "unknown") for p in parts}
    risk = {p.get("id"): (p.get("risk") or {}).get("score") for p in parts}
    cut = [{"partition": pid, "risk_score": risk.get(pid),
            "source_files": per_partition.get(pid, 0)}
           for pid, d in depth.items() if d == "inventory-only"]
    cut.sort(key=lambda x: -(x["source_files"] or 0))

    result = {
        "source_files_considered": total,
        "unmatched_count": len(unmatched),
        "unmatched": unmatched[:500],
        "multi_matched_count": len(multi),
        "multi_matched": multi[:200],
        "catch_all_partitions": [{"partition": pid, "glob": g}
                                 for pid, g in catch_alls],
        "files_per_partition": per_partition,
        "deep_dive_cut_line": cut,
    }

    if not args.quiet:
        print(f"partition coverage: {total} source file(s) considered across "
              f"{len(parts)} partition(s)")
        if catch_alls and len(parts) > 1:
            print("\nCATCH-ALL PARTITIONS (a bare glob next to specific partitions "
                  "turns 'unmatched' into 'silently swallowed'):")
            for pid, g in catch_alls:
                print(f"  ! {pid}: {g}")
        if multi:
            print(f"\n{len(multi)} file(s) match more than one partition "
                  "(workflow.md §1.6: highest-risk partition wins downstream):")
            for m in multi[:args.max_report]:
                print(f"  ~ {m['file']} -> {', '.join(m['partitions'])}")
            if len(multi) > args.max_report:
                print(f"  ... and {len(multi) - args.max_report} more.")
        if cut:
            print("\nDEEP-DIVE CUT LINE — inventory-only partitions (enumerated in "
                  "Phase 2, NOT deep-dived in Phase 5). Raise top_n or promote on "
                  "surface evidence (Phase 2 §2.13) if any of these hold handlers:")
            for c in cut[:args.max_report]:
                print(f"  - {c['partition']:<32} risk={c['risk_score']} "
                      f"files={c['source_files']}")
        if unmatched:
            print(f"\nUNMATCHED — {len(unmatched)} source file(s) belong to NO "
                  "partition. Phase 1 FAILS: an unpartitioned handler never gets a "
                  "deep dive, and nothing downstream will say so.")
            for u in unmatched[:args.max_report]:
                print(f"  ! {u}")
            if len(unmatched) > args.max_report:
                print(f"  ... and {len(unmatched) - args.max_report} more.")
        else:
            print("\nEvery source file maps to at least one partition.")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        if not args.quiet:
            print(f"\nwrote coverage report -> {args.out}")

    if unmatched or (args.fail_on_multi and multi):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
