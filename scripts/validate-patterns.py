#!/usr/bin/env python3
"""
validate-patterns.py — compile every regex in the deepdive category
files. Catches pattern drift introduced by edits to cat-*.md without
requiring a full polyglot sub-agent run.

Scope:
  - Walks steps/deepdive/cat-*.md.
  - Extracts every line inside fenced code blocks.
  - Lines that LOOK LIKE a regex (contain at least one regex-specific
    construct — backslash escape, anchor, character class, quantifier)
    are compiled with Python's `re` module.
  - Lines that look like code examples (contain `{`, `function`, `def`,
    `class`, assignment) are skipped.

Exits 0 if every regex-looking line compiles. Non-zero and lists
file+line of each broken pattern.

Not a behavioral test — doesn't verify patterns match anything real.
`docs/test-runs/polyglot-*.md` dogfoods handle behavior. This is a
syntax guard against typos.

KNOWN LIMITATIONS of the heuristic:
  - A short "simple" regex with no escapes / anchors / classes /
    quantifiers (e.g., `mysqli_query.*GET`) looks like prose to the
    REGEX_INDICATOR and is skipped. The trade-off is to avoid false
    positives on code examples; accept some false negatives.
  - Patterns mentioned inline in prose (outside fenced code blocks)
    are not extracted. The validator looks at fenced blocks only.
  - Cross-language regex dialect differences (ripgrep vs. Python re)
    can cause false FAILs on edge-case constructs. If that happens,
    re-test with `python3 -c "import re; re.compile(r'...')"` to
    confirm whether it's the pattern or the environment.
"""
import argparse
import re
import sys
from pathlib import Path


# A line is likely a regex if it contains at least one regex-y token.
REGEX_INDICATOR = re.compile(r"""
    (?:
        \\[a-zA-Z]       # \w, \s, \d, \b, \n etc.
      | \\\.|\\\(        # escaped dot / paren
      | \[[^\]]{2,}\]    # character class with content
      | \^|\$            # anchors
      | \\d|\\s|\\w
      | \{\d+,?\d*\}     # {n} or {n,m}
      | \(\?:[^)]+\)     # non-capturing group
    )
""", re.VERBOSE)

# A line is likely code (not regex) if it looks like function / assignment / JSON.
CODE_INDICATOR = re.compile(r"""
    (?:
        ^\s*(?:function|def|class|const|let|var|import|from|if|else|return|throw|new)\s
      | \{\s*$             # opening brace at EOL
      | =\s*function
      | =>\s*\{
      | \[SEVERITY\]       # finding template
      | ^\s*-\s            # markdown list
      | ^\s*\|             # markdown table
      | \{\{                # template placeholder
      | ^\s*\{              # JSON object start
    )
""", re.VERBOSE)


def is_likely_regex(line: str) -> bool:
    if not line.strip():
        return False
    if CODE_INDICATOR.search(line):
        return False
    return bool(REGEX_INDICATOR.search(line))


def extract_code_fence_lines(md_path: Path) -> list[tuple[int, str]]:
    """Return (line_number, content) for every line inside a fenced block."""
    lines = md_path.read_text().splitlines()
    out: list[tuple[int, str]] = []
    in_block = False
    for i, line in enumerate(lines, start=1):
        if line.lstrip().startswith("```"):
            in_block = not in_block
            continue
        if in_block:
            out.append((i, line))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("skills/security-audit/steps/deepdive"),
    )
    args = parser.parse_args()

    if not args.root.exists():
        print(f"ERROR: not a directory: {args.root}", file=sys.stderr)
        sys.exit(2)

    files = sorted(args.root.glob("cat-*.md"))
    if not files:
        print(f"WARNING: no cat-*.md files found under {args.root}", file=sys.stderr)
        sys.exit(0)

    broken: list[str] = []
    checked = 0
    skipped = 0

    for md in files:
        for lineno, raw in extract_code_fence_lines(md):
            line = raw.strip()
            if not is_likely_regex(line):
                skipped += 1
                continue
            checked += 1
            try:
                re.compile(line)
            except re.error as e:
                broken.append(f"{md}:{lineno}: {e} — {line[:120]}")

    if broken:
        print(f"FAIL: {len(broken)} regex(es) failed to compile:", file=sys.stderr)
        for b in broken:
            print(f"  - {b}", file=sys.stderr)
        sys.exit(1)

    print(f"OK: {checked} regex pattern(s) compiled across {len(files)} category files (skipped {skipped} code/prose lines).")


if __name__ == "__main__":
    main()
