#!/usr/bin/env python3
"""
validate-collection-scoping.py — the collection-scoping reconciliation (v2.5).

WHY THIS EXISTS
---------------
A 2026-07-25 full audit (v2.4.0, all six scanners present, no degraded mode)
returned a clean bill for this handler:

    export default defineEventHandler(async (event) => {
      const session = await requireRole(event, 'reader')        // gate EXISTS
      ...
      .where(and(eq(decks.scope, 'user'), isNull(decks.deletedAt)))  // no owner predicate
      ...
      const tree = applyCanWrite(rawTree, session)              // decorates, never filters
      return { data: tree }
    })

Any authenticated user received every other user's private resources. Three
mechanisms each passed it, for three independent reasons:

  1. The Phase-2 surface inventory records gate PRESENCE (`auth_required: true`,
     `roles_required: ['reader']`, `flags: []`). No field could express that
     *authentication was used where per-row authorization was required*.
  2. The Phase-6 egress reconciliation admits only BYTE-emitting sinks. This
     handler returns JSON, so it never entered the sink inventory. A JSON list of
     private identifiers is an egress.
  3. cat-02 (IDOR/BOLA) is OBJECT-centric: its candidate filter requires an
     id-shaped path/query param, so a collection route `/resources` — which has
     no id param — never became a candidate at all. Its own "list endpoints must
     filter by scope" invariant was therefore structurally unreachable.

This script is the mechanical answer to all three. It is COLLECTION-centric
(OWASP API1:2023 BOLA + API3:2023 at the collection level) and asks the question
the surface inventory cannot: **does the query bind rows to the caller?**

TWO RESPONSIBILITIES (same shape as validate-egress.py)
------------------------------------------------------
  (A) COVERAGE GATE (fail-closed). Re-extract collection-query candidates from
      the handler files. FAIL if any candidate is neither inventoried in
      phase-02-collections.json nor explicitly dismissed-with-reason, and FAIL on
      any row whose `coverage` is "incomplete". A silent omission must break the
      run, never pass quietly.

  (B) RECONCILIATION (C1-C5). Emit finding-schema JSONL:
      C1  unscoped collection of a sensitive entity (the primary rule)
      C2  authorization by decoration — permission computed per row, never used to filter
      C3  incomplete/caveat coverage (fail-closed deficit, surfaced not swallowed)
      C4  a TEST pins the insecure behaviour (asserts another principal's row is present)
      C5  claimed row-scoping with no caller-derived predicate (anti-laundering)

Findings carry `preconditions`/`postconditions` per lib/capability-lexicon.md so
compose-attack-paths.py can chain them. That wiring is the point: an unscoped
list endpoint grants `knows:any_<entity>_id`, which is precisely the capability
that "only exploitable if the attacker knows the UUID" mitigations assume nobody
has.

NOT A SOUNDNESS PROOF. This mechanically reconciles an agent-populated inventory
against a deterministic candidate set. Its value is (a) the class becomes
EXPRESSIBLE and checkable, (b) a missing collection is loud instead of silent,
and (c) C5 means the inventory cannot launder a false "it's scoped" claim.

Usage:
  python3 validate-collection-scoping.py <one-or-more .json inputs> \
      [--collections phase-02-collections.json] [--profile phase-00-profile.json] \
      [--surface phase-02-surface.json] \
      [--candidates candidates.json | --source-root DIR] \
      [--partition <id>] [--out findings.jsonl] [--quiet]

Exit codes:
  0  clean — coverage satisfied, no HIGH/CRITICAL deficit
  1  coverage gate failed OR >=1 HIGH/CRITICAL collection-scoping finding
  2  argparse / I/O / shape error
"""
import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

# --- Shared gate ranking (single source of truth: validate-egress.py) -------
# Both validators ship in this directory. Importing rather than re-implementing
# keeps the negation-aware ranker from drifting between the two controls.


def _load_sibling(filename, modname):
    path = Path(__file__).resolve().parent / filename
    if not path.exists():
        print(f"ERROR: required sibling module missing: {path}", file=sys.stderr)
        sys.exit(2)
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_ve = _load_sibling("validate-egress.py", "_ve")
gate_rank = _ve.gate_rank
GATE_NONE, GATE_AUTHN, GATE_AUTHZ, GATE_VERIFIED = (
    _ve.GATE_NONE, _ve.GATE_AUTHN, _ve.GATE_AUTHZ, _ve.GATE_VERIFIED)
_norm = _ve._norm
_split_site = _ve._split_site
_COVERAGE_LINE_TOLERANCE = _ve._COVERAGE_LINE_TOLERANCE

SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Roles that legitimately see every row. Anything else is NOT row scoping.
_ADMIN_ROLE_TOKENS = {"admin", "administrator", "superuser", "superadmin",
                      "root", "sysadmin", "staff", "owner", "platform"}

# Tokens that prove a predicate binds to the CALLER, not just to some constant.
# A "scoped" claim whose predicate contains none of these is not scoping — it is
# a filter on a literal (`scope = 'user'`, `deletedAt IS NULL`), which is exactly
# the shape the missed handler used.
# Single generic words that are caller-binding ONLY when adjacent to an identity
# token. camelCase splitting made these match `callerName`, `sessionType`,
# `callerPhoneNumber` — plausible column names with nothing to do with the
# authenticated caller, which would suppress real C1 findings.
_GENERIC_CALLER_WORDS = {"session", "caller", "me", "viewer", "principal",
                         "claims", "jwt", "acl"}
_IDENTITY_NEIGHBOURS = {"id", "uid", "sub", "user", "users", "email", "owner",
                        "tenant", "org", "organization", "account", "workspace",
                        "member", "membership"}

_CALLER_TOKENS = (
    "session", "current_user", "currentuser", "req.user", "request.user",
    "ctx.user", "context.user", "auth.uid", "authuser", "principal", "claims",
    "jwt", "me", "viewer", "caller",
    "userid", "user_id", "user.id", "ownerid", "owner_id", "createdby",
    "created_by", "tenantid", "tenant_id", "orgid", "org_id",
    "organizationid", "organization_id", "accountid", "account_id",
    "workspaceid", "workspace_id", "membership", "acl", "visible_to",
)

# Permission-shaped field names — the "authorization by decoration" signature.
_PERMISSION_FIELD_RE = re.compile(
    r"\b(can[A-Z]\w*|can_[a-z]\w*|is[A-Z]\w*(?:Allowed|Permitted|Editable|Writable|Visible)"
    r"|[a-zA-Z]\w*(?:Permitted|Allowed)|read_?only|readOnly)\b")


# --- Deterministic candidate extraction ------------------------------------
# Anchors are per-ecosystem list-query shapes. Precision matters more than
# breadth here: every candidate must be classified by an agent, so a noisy
# anchor is a tax on every future run. Scope is restricted to handler files
# (§_handler_files) — a route that Phase 2 never enumerated is caught by the
# partition-coverage gate, not this one.
_JS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
_ANCHORS = [
    # (kind, regex, flags, restrict-to-extensions | None)
    # TypeScript / JavaScript ORMs and query builders
    ("orm_list", r"\.findMany\s*\(", re.I, _JS),
    ("orm_list", r"\.findAll\s*\(", re.I, _JS),
    ("orm_list", r"\.select\s*\(", 0, _JS),
    # Drizzle/Kysely/Knex list queries wrap across lines
    # (`db\n  .select({...})\n  .from(decks)`), so anchor `.from(table)` too.
    ("orm_list", r"\.from\s*\(\s*[A-Za-z_$][\w$.]*\s*\)", 0, _JS),
    ("orm_list", r"\.query\.\w+\.findMany\b", 0, _JS),
    ("orm_list", r"\bprisma\.\w+\.findMany\b", 0, _JS),
    ("orm_list", r"getRepository\s*\([^)]*\)\s*\.find\s*\(", 0, _JS),
    # Mongoose / Mongo-style `Model.find({})` and `Model.findOne(...)`. The
    # capitalised receiver is what separates an ODM query from `array.find(`.
    # Without this, the whole Mongoose ecosystem produced ZERO candidates, so
    # nothing was ever UNACCOUNTED and the fail-closed gate was inert there.
    # `Model.find()` / `Model.find({...})` only. The `(?:\)|\{)` tail is what
    # separates an ODM query from an in-memory `Roles.find(r => r.id === x)` on a
    # capitalised constant array — those are everywhere in real TypeScript, and
    # matching them turned the fail-closed gate into noise that trains operators
    # to dismiss it. Trade-off: `Model.find(filterVar)` is missed; a variable
    # filter is indistinguishable from a predicate callback without type info.
    ("orm_list", r"\b[A-Z]\w*\.find(?:One)?\s*\(\s*(?:\)|\{)", 0, _JS),
    ("orm_list", r"\b[A-Z]\w*\.countDocuments\s*\(", 0, _JS),
    ("orm_list", r"\.createQueryBuilder\s*\(", 0, _JS),
    ("orm_list", r"\.aggregate\s*\(\s*\[", 0, _JS),
    ("orm_list", r"\bcollection\s*\(\s*[\"'][\w-]+[\"']\s*\)\s*\.\s*(?:get|find)\s*\(", 0, _JS),
    # Python
    ("orm_list", r"\.objects\.all\s*\(\s*\)", 0, {".py"}),
    ("orm_list", r"\.objects\.filter\s*\(", 0, {".py"}),
    ("orm_list", r"\.objects\.exclude\s*\(", 0, {".py"}),
    ("orm_list", r"\bsession\.query\s*\(", 0, {".py"}),
    ("orm_list", r"\.scalars\s*\(", 0, {".py"}),
    ("orm_list", r"\bselect\s*\(\s*[A-Z]\w*\s*\)", 0, {".py"}),
    # Ruby (ActiveRecord) — anchored on a constant receiver so we don't match
    # every `.all` in the file.
    ("orm_list", r"\b[A-Z]\w*\.(?:all|where|order|pluck)\b", 0, {".rb"}),
    # PHP (Eloquent / Doctrine)
    ("orm_list", r"::(?:all|where)\s*\(", 0, {".php"}),
    ("orm_list", r"->(?:get|getResult|findAll)\s*\(\s*\)", 0, {".php"}),
    # Java / Kotlin (Spring Data, JPA)
    ("orm_list", r"\bfindAll\s*\(", 0, {".java", ".kt"}),
    ("orm_list", r"\bcreateQuery\s*\(", 0, {".java", ".kt"}),
    # C#
    ("orm_list", r"\.ToListAsync\s*\(", 0, {".cs"}),
    ("orm_list", r"\.ToList\s*\(\s*\)", 0, {".cs"}),
    # Go
    ("orm_list", r"\.Find\s*\(\s*&", 0, {".go"}),
    ("orm_list", r"\bdb\.(?:Query|Select)\s*\(", 0, {".go"}),
    # Raw SQL returning rows. Case-SENSITIVE on purpose: lower-case `select(` /
    # `from(` in a JS query builder is already covered above, and matching it
    # here again would double-count every ORM call as raw SQL.
    ("raw_sql_list", r"\bSELECT\b[\s\S]{0,200}?\bFROM\b", 0, None),
    # GraphQL list fields — schema files only. In TS, `: [Foo]` is a tuple type,
    # not a list field, so restricting by extension is what keeps this precise.
    ("graphql_list", r":\s*\[\s*\w+!?\s*\]!?", 0, {".graphql", ".gql"}),
]
_ANCHORS_RE = [(kind, re.compile(rx, flags), exts)
               for kind, rx, flags, exts in _ANCHORS]

# Deliberately narrower than validate-partition-coverage.py's _SOURCE_EXT, which
# also carries .vue/.svelte: every anchor below is restricted to a server-side
# language, and single-file components hold template/client code. A SFC that DOES
# embed a server list-query is reached via the surface inventory's handler_file
# list (handler_files() unions both), not via this extension walk.
_SOURCE_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rb",
               ".php", ".java", ".kt", ".cs", ".go", ".graphql", ".gql", ".sql"}

_SKIP_DIR_PARTS = {".git", "node_modules", "dist", "build", "target", ".venv",
                   "venv", "__pycache__", "vendor", ".next", ".nuxt", ".output",
                   "coverage", ".pytest_cache", ".tox", "migrations", "migrate",
                   "seeds", "fixtures", "generated", "__generated__"}

_TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|spec|specs|__tests__)/|"
    r"\.(test|spec)\.[jt]sx?$|_test\.(py|go|rb|java)$|(^|/)test_[^/]+\.py$|"
    r"[A-Za-z0-9]Test\.(java|kt|cs)$|_spec\.rb$", re.IGNORECASE)

# Handler-ish directories, used when no surface inventory is supplied.
_HANDLER_PATH_RE = re.compile(
    r"(^|/)(server/api|server/routes|api|routes|controllers?|handlers?|"
    r"resolvers?|endpoints?|views|pages/api|app/api|graphql|rpc|"
    r"functions|lambdas?)(/|$)", re.IGNORECASE)
_HANDLER_FILE_RE = re.compile(
    r"(^|/)(views|urls|routes|schema|resolver|controller|handler)s?\.[a-z]+$|"
    r"[A-Za-z0-9](Controller|Resolver|Handler)\.[a-z]+$|"
    # NestJS / Angular dot-segment convention: `users.controller.ts`. The
    # alternatives above require the word to follow `/` or a PascalCase char,
    # so a dot-separated segment matched neither.
    r"[\w-]+\.(controller|resolver|handler|gateway|route)s?\.[a-z]+$",
    re.IGNORECASE)


def _is_skipped(rel: str) -> bool:
    """Skip-list applies to the path RELATIVE to the source root. Checking the
    absolute path would make the extractor silently blind to any repo that
    happens to live under a directory named `vendor`, `build`, `fixtures`, … —
    including this project's own test corpus."""
    return any(part in _SKIP_DIR_PARTS for part in Path(rel).parts)


def _looks_like_handler(rel: str) -> bool:
    return bool(_HANDLER_PATH_RE.search(rel) or _HANDLER_FILE_RE.search(rel))


def handler_files(root: Path, surface_doc):
    """The file set candidate extraction runs over.

    Union of (a) every `handler_file` in the Phase-2 surface inventory — the
    precise set — and (b) files under handler-ish paths, so a route Phase 2
    missed still yields candidates rather than silently contributing nothing."""
    files = {}
    for s in (surface_doc or {}).get("surfaces", []):
        hf = s.get("handler_file")
        if hf:
            p = (root / _norm(hf))
            if p.exists() and p.is_file():
                files[_norm(p.relative_to(root))] = p
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix not in _SOURCE_EXT:
            continue
        rel = _norm(p.relative_to(root))
        if _is_skipped(rel) or _TEST_PATH_RE.search(rel):
            continue
        if _looks_like_handler(rel):
            files[rel] = p
    return files


def extract_candidates(root, surface_doc=None):
    """Deterministic collection-query candidates. Returns [{file, line, kind, snippet}]."""
    root = Path(root)
    out = []
    seen = set()
    for rel, path in sorted(handler_files(root, surface_doc).items()):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        for kind, rx, exts in _ANCHORS_RE:
            if exts is not None and path.suffix not in exts:
                continue
            for m in rx.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                key = (rel, line)
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "file": rel,
                    "line": line,
                    "kind": kind,
                    "snippet": (lines[line - 1].strip()[:160] if line - 1 < len(lines) else ""),
                })
    return out


# --- Coverage gate (fail-closed) -------------------------------------------
def coverage_failures(collections_doc, candidates):
    """Hard coverage failures. Empty list == coverage OK.

    Line-scoped, matching validate-egress.py: an inventoried collection at one
    line cannot mask an un-inventoried collection elsewhere in the same file."""
    fails = []
    rows = (collections_doc or {}).get("collections", [])

    # 1. `coverage: incomplete` is itself a fail-closed deficit, independent of
    #    whether a candidate set was supplied. Emitting only a MEDIUM C3 finding
    #    would let a run whose inventory admits it could not read the handler
    #    still exit 0 — "we could not tell" is not "it is fine". (`caveat` is
    #    mechanically un-decidable and is reported, not failed.)
    for r in rows:
        if r.get("coverage") == "incomplete":
            fails.append(
                f"collection {r.get('id', r.get('handler_file'))}: "
                "coverage=incomplete — the query or a post-query transform could "
                "not be read end to end. Re-read the handler or split it; an "
                "unreadable collection is an open question, not a pass.")

    if candidates is None:
        return fails

    accounted = {}
    file_dismissed = set()

    def _add(f, ln):
        accounted.setdefault(_norm(f), []).append(ln)

    for r in rows:
        _add(r.get("handler_file", ""), r.get("line"))
        ev = r.get("scope_evidence") or {}
        if ev.get("file"):
            _add(ev["file"], ev.get("line"))
    for d in (collections_doc or {}).get("dismissed", []):
        f, ln = _split_site(d.get("candidate", ""))
        if ln is None:
            file_dismissed.add(f)
        else:
            _add(f, ln)

    def _is_accounted(cf, cl):
        if cf in file_dismissed:
            return True
        lines = accounted.get(cf)
        if not lines:
            return False
        if cl is None:
            return True
        return any(al is not None and abs(al - cl) <= _COVERAGE_LINE_TOLERANCE
                   for al in lines)

    for cand in candidates or []:
        cf = _norm(cand.get("file", ""))
        cl = cand.get("line")
        if _is_accounted(cf, cl):
            continue
        fails.append(
            f"UNACCOUNTED candidate {cand.get('kind', '?')} at {cf}"
            f"{':' + str(cl) if cl else ''} — no collections[] row or dismissal "
            f"within {_COVERAGE_LINE_TOLERANCE} lines. Every list-query candidate "
            "must be classified (silent omission is how the original bug survived)."
        )
    return fails


# --- Sensitivity / entity helpers ------------------------------------------
def entity_index(profile):
    """entity id -> {owner_cols, pii_cols}."""
    idx = {}
    dm = (profile or {}).get("data_model") or {}
    for e in dm.get("entities", []) or []:
        eid = e.get("id") or e.get("name")
        if not eid:
            continue
        idx[str(eid).lower()] = {
            "id": eid,
            "owner_cols": e.get("owner_cols") or [],
            "pii_cols": e.get("pii_cols") or [],
        }
    return idx


def is_public(entity, profile):
    allow = {str(x).lower() for x in (profile or {}).get("public_resources", []) or []}
    return str(entity).lower() in allow


def is_admin_role(roles, gate_text=None):
    """Is the endpoint restricted to a role that legitimately sees every row?

    Checks `roles_required` ONLY, on token boundaries. Deliberately NOT the free
    -text gate description: substring-matching prose fails OPEN (a gate described
    as "mounted on the root router" contains 'root'; "the operator dashboard
    calls this" contains 'operator'), and a false admin classification silently
    suppresses the C1 finding. `gate_text` is accepted and ignored so callers
    reading older signatures still work."""
    for r in (roles or []):
        for tok in re.split(r"[^a-z0-9]+", str(r).lower()):
            if tok in _ADMIN_ROLE_TOKENS:
                return True
    return False


# Lines either side of scope_evidence.line to read when checking whether a
# CLAIMED predicate string was fabricated. Generous on purpose: a wide window
# only makes us less likely to cry "fabricated".
_EVIDENCE_WINDOW = 3
# Max lines a cited statement may span when we SCORE it for caller-binding.
_STATEMENT_MAX = 8


def _statement_at(lines, idx):
    """The statement beginning at `lines[idx]`, extended FORWARD only until its
    brackets balance.

    Forward-only is the whole point. Scoring a +/-3 window around the cited line
    reintroduced the exact bug this file exists to catch: in

        const session = await requireRole(event, 'reader')   <- 2 lines above
        const rows = await db.select().from(decks)
          .where(and(eq(decks.scope, 'user'), isNull(decks.deletedAt)))

    the word `session` from the unrelated auth gate leaked into the window and
    scored the literal-only predicate as caller-bound. The gate is always ABOVE
    the query; the predicate is always AT or BELOW the citation."""
    if idx < 0 or idx >= len(lines):
        return ""
    out, depth = [], 0
    for i in range(idx, min(len(lines), idx + _STATEMENT_MAX)):
        ln = lines[i]
        out.append(ln)
        depth += ln.count("(") + ln.count("[") - ln.count(")") - ln.count("]")
        if depth > 0:
            continue
        # Brackets balance here, but a fluent query is written as a method chain
        # across lines, each of which balances on its own:
        #     const rows = await db.select().from(decks)
        #       .where(and(eq(decks.userId, session.user.id), ...))
        # Stopping at the cited line would drop the predicate entirely and flag a
        # correctly-scoped handler. Keep going while the NEXT line continues the
        # chain — still forward-only, so the auth gate above can never leak in.
        nxt = lines[i + 1].lstrip() if i + 1 < len(lines) else ""
        # NOT ",": with brackets already balanced, a leading comma introduces a
        # second declarator (`, unused = session.user.id`), and absorbing it
        # leaked a caller token from unrelated code into the score. Inside an
        # argument list depth is still > 0, so genuine multi-line arguments are
        # already handled above and never reach here.
        if nxt.startswith((".", "?.", ")")) or nxt.startswith("->"):
            continue
        break
    return "\n".join(out)


def _subseq(needle, hay):
    """Is `needle` a contiguous token subsequence of `hay`?"""
    if not needle:
        return False
    n = len(needle)
    return any(hay[i:i + n] == needle for i in range(len(hay) - n + 1))


_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _tokenize(text):
    """Split on non-alphanumerics AND camelCase boundaries, then lowercase.

    `session.user.id` -> ['session','user','id']
    `authUserId`      -> ['auth','user','id']

    The camelCase split matters: token-exact matching without it scored
    `authUserId`, `currentUserId`, `viewerId` and `callerId` as NOT caller-bound,
    which flags correctly-scoped handlers as unscoped. Splitting only on
    punctuation over-corrected the substring fail-open into a fresh false
    positive on equally common naming."""
    spaced = _CAMEL_BOUNDARY.sub(" ", str(text))
    return [t for t in re.split(r"[^a-z0-9]+", spaced.lower()) if t]


def _strip_literals(text):
    """Blank string literals and line comments, preserving length.

    A quoted value is data, never a caller reference: without this,
    `eq(decks.scope, 'session')` scores caller-bound because the component
    splitter discards the quotes and `session` becomes an ordinary token.

    Hand-scanned rather than regex-alternated, for two reasons a naive
    `'[^']*'` gets wrong:
      - escapes: `'it\'s'` must not terminate at the middle quote;
      - an UNTERMINATED quote (a prose apostrophe in a trailing comment) must be
        treated as an ordinary character, not paired with the next unrelated
        quote further along — which would blank everything between and erase a
        genuine caller reference.
    Residual ambiguity is documented in docs/KNOWN-GAPS.md #23."""
    t = str(text)
    n = len(t)
    out = []
    i = 0
    while i < n:
        c = t[i]
        if c in "'\"`":
            j = i + 1
            while j < n:
                if t[j] == "\\":
                    j += 2
                    continue
                if t[j] == c:
                    break
                j += 1
            if j < n:                       # properly closed literal
                out.append(" " * (j - i + 1))
                i = j + 1
                continue
            out.append(" ")                 # unterminated: a bare apostrophe
            i += 1
            continue
        if c == "#" or (c == "/" and i + 1 < n and t[i + 1] == "/"):
            # To end of LINE, not end of string: _statement_at returns multi-line
            # method chains, and blanking the whole remainder erased the
            # `.where(eq(..., session.user.id))` two lines below a trailing
            # comment — reporting a correctly-scoped collection as unscoped.
            eol = t.find("\n", i)
            stop = n if eol == -1 else eol
            out.append(" " * (stop - i))
            i = stop
            continue
        out.append(c)
        i += 1
    return "".join(out)


def predicate_binds_caller(text):
    """Does this predicate reference a value derived from the CALLER?

    Token-sequence containment, NOT substring containment. Plain substring
    matching fail-opens on ordinary identifiers: `scheme.name` contains "me.",
    `oracle.status` contains "acl", and both would be scored as caller-bound —
    silently suppressing C1 on a genuinely unscoped collection. False negatives
    are the expensive direction here, so the match is anchored to whole tokens."""
    if not text:
        return False
    text = _strip_literals(text)
    toks = _tokenize(text)
    if not toks:
        return False
    # Identifier components (split on punctuation only), each with its camelCase
    # parts. A bare generic word means the caller when it stands alone as a
    # component (`=== principal`, `session.user.id`); when it is only a camel
    # fragment of a longer name it is a modifier, and whether it means the caller
    # depends on what it modifies: `viewerId` yes, `callerName` no.
    components = [c for c in re.split(r"[^A-Za-z0-9_]+", str(text)) if c]
    standalone, camel_ctx = set(), []
    for comp in components:
        parts = _tokenize(comp)
        if len(parts) == 1:
            standalone.add(parts[0])
        else:
            camel_ctx.append(parts)

    for raw in _CALLER_TOKENS:
        want = _tokenize(raw)
        if not want:
            continue
        n = len(want)
        if n == 1 and want[0] in _GENERIC_CALLER_WORDS:
            w = want[0]
            if w in standalone:
                return True
            for parts in camel_ctx:
                for i, part in enumerate(parts):
                    if part != w:
                        continue
                    prev = parts[i - 1] if i > 0 else ""
                    nxt = parts[i + 1] if i + 1 < len(parts) else ""
                    if prev in _IDENTITY_NEIGHBOURS or nxt in _IDENTITY_NEIGHBOURS:
                        return True
            continue
        for i in range(len(toks) - n + 1):
            if toks[i:i + n] == want:
                return True
    return False


def preconditions_for(gate_text, roles):
    """Attacker capabilities required to reach this endpoint (lib/capability-lexicon.md)."""
    rank = gate_rank(gate_text)
    if rank == GATE_NONE:
        return []
    pre = ["authenticated"]
    if rank >= GATE_AUTHZ:
        for r in (roles or []):
            rl = str(r).strip().lower()
            if rl:
                pre.append(f"role:{rl}")
                break
    if rank == GATE_VERIFIED:
        pre.append("verified")
    return pre


def postconditions_for(entity, meta, returns):
    e = str(entity).lower().replace(" ", "_").replace("-", "_")
    post = [f"knows:any_{e}_id", f"reads:any_{e}_metadata"]
    if returns == "tree":
        post.append(f"knows:any_{e}_path")
    if (meta or {}).get("pii_cols"):
        post.append(f"reads:any_{e}_pii")
    return post


# --- Finding emission -------------------------------------------------------
def _finding(seq, partition, rule, severity, confidence, cwe, owasp, title,
             description, file, line, category="collection_scope", **extra):
    f = {
        "id": f"{partition}:{category}:{seq:04d}",
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "partition": partition,
        "file": file,
        "line": max(1, int(line or 1)),
        "cwe": cwe,
        "owasp_ids": owasp,
        "title": title[:120],
        "description": description[:800],
        "sources": [{"kind": "scanner",
                     "detail": f"validate-collection-scoping.py:{rule}"}],
    }
    f.update(extra)
    return f


def reconcile(collections_doc, profile, surface_doc, partition, source_root=None):
    """Rules C1-C5. Returns (findings, notes)."""
    findings, notes = [], []
    rows = (collections_doc or {}).get("collections", [])
    ents = entity_index(profile)
    surfaces = {s.get("id"): s for s in (surface_doc or {}).get("surfaces", [])}
    seq = 0

    for r in rows:
        entity = r.get("entity") or "unknown"
        meta = ents.get(str(entity).lower(), {"owner_cols": [], "pii_cols": []})
        returns = r.get("returns", "collection")
        scope = r.get("row_scope", "unknown")
        gate = r.get("endpoint_gate", "")
        roles = r.get("roles_required") or []
        hf, ln = r.get("handler_file", "?"), r.get("line", 1)
        rid = r.get("id", f"{hf}:{ln}")
        surf = surfaces.get(r.get("surface_id")) if r.get("surface_id") else None
        if not roles and surf:
            roles = surf.get("roles_required") or []
        pre = preconditions_for(gate, roles)
        post = postconditions_for(entity, meta, returns)
        sensitive = (not is_public(entity, profile)) and returns != "single"

        # --- C5: a scoping CLAIM with no caller-derived predicate is not scoping.
        claimed = scope in ("caller_bound", "visibility_filtered")
        if claimed:
            ev = r.get("scope_evidence") or {}
            pred = ev.get("predicate", "")
            fabricated = False
            # Read the cited location whenever we can, and judge on the SOURCE,
            # not on the claim. Only falling back to source when `predicate` was
            # empty meant any non-empty string was trusted outright — an agent
            # could write `eq(reports.authorId, session.user.id)` for a handler
            # whose real query is `eq(reports.status,'published')` and C5 would
            # wave it through. That would have falsified the release's own
            # "a wrong inventory cannot launder a gap into a pass" claim.
            actual = scored = ""
            if source_root and ev.get("file") and ev.get("line"):
                try:
                    src = (Path(source_root) / _norm(ev["file"])).read_text(
                        encoding="utf-8", errors="replace").splitlines()
                    i = int(ev["line"]) - 1
                    # Wide window: only used to decide "was this claim fabricated".
                    actual = "\n".join(src[max(0, i - _EVIDENCE_WINDOW):
                                           i + _EVIDENCE_WINDOW + 1])
                    # Narrow, forward-only statement: what we actually SCORE.
                    scored = _statement_at(src, i)
                except (OSError, ValueError, IndexError):
                    actual = scored = ""
            if actual:
                if pred and _tokenize(pred) and not _subseq(_tokenize(pred),
                                                            _tokenize(actual)):
                    fabricated = True
                # The source at the cited line is the authority either way.
                pred = scored
            if fabricated or not predicate_binds_caller(pred):
                seq += 1
                findings.append(_finding(
                    seq, partition, "C5", "MEDIUM", "LIKELY", "CWE-1220",
                    ["API1:2023", "A01:2025", "ASVS-V4.2.1"],
                    f"Row-scoping claimed for {entity} but no caller-derived predicate",
                    (f"Collection `{rid}` declares row_scope={scope} for entity "
                     f"`{entity}` citing a predicate that does NOT appear at "
                     f"{ev.get('file')}:{ev.get('line')}. The source there reads "
                     f"{actual.strip()[:120]!r}. A cited predicate that is not in "
                     "the cited file is not evidence."
                     if fabricated else
                     f"Collection `{rid}` declares row_scope={scope} for entity "
                     f"`{entity}`, but the predicate at its scope_evidence "
                     f"({str(pred).strip()[:160] or 'absent'!r}) references no "
                     "session/user/tenant/org value. A filter on a literal (e.g. "
                     "`scope = 'user'`, `deletedAt IS NULL`) constrains WHICH "
                     "rows, not WHOSE.") + " Treated as unscoped for the rules below.",
                    hf, ln,
                    surface_id=r.get("surface_id"),
                    preconditions=pre, postconditions=post,
                    suggested_fix="Add a WHERE predicate binding to the caller "
                                  "(session user id / org / tenant), or record "
                                  "row_scope=unscoped honestly.",
                    remediation_effort="small"))
                scope = "unscoped"   # fail-closed: the claim does not stand

        # --- role_restricted is only row scoping when the role is admin-tier.
        effective = scope
        if scope == "role_restricted" and not is_admin_role(roles, gate):
            effective = "unscoped"
            notes.append(f"{rid}: role_restricted with non-admin role(s) "
                         f"{roles or '[]'} — treated as unscoped")

        # --- C1: unscoped collection of a sensitive entity. THE primary rule.
        if sensitive and effective in ("unscoped", "unknown"):
            owned = bool(meta.get("owner_cols") or meta.get("pii_cols"))
            sev = "HIGH" if owned else "MEDIUM"
            conf = "LIKELY"
            if effective == "unknown":
                sev = {"HIGH": "MEDIUM", "MEDIUM": "LOW"}[sev]
                conf = "POSSIBLE"
            grank = gate_rank(gate)
            gate_note = (
                "The endpoint IS gated — that is the trap. `{}` authenticates the "
                "caller; it does not constrain which rows the caller may see. "
                "Authentication was used where per-row authorization was required."
                .format(str(gate)[:80]) if grank > GATE_NONE else
                "The endpoint is ungated AND unscoped.")
            seq += 1
            findings.append(_finding(
                seq, partition, "C1", sev, conf, "CWE-1220",
                ["API1:2023", "API3:2023", "A01:2025", "ASVS-V4.2.1"],
                f"Collection endpoint returns {entity} rows belonging to other principals",
                f"Handler `{rid}` returns a {returns} of `{entity}` with "
                f"row_scope={effective}: no WHERE predicate binds to the caller's "
                f"identity, no per-row visibility helper filters the result, and "
                f"`{entity}` is not on profile.public_resources. {gate_note} "
                f"Owner columns: {meta.get('owner_cols') or 'none recorded'}; "
                f"PII columns: {meta.get('pii_cols') or 'none recorded'}.",
                hf, ln,
                surface_id=r.get("surface_id"),
                preconditions=pre, postconditions=post,
                attack_scenario=(
                    f"Authenticate as the lowest-privilege principal that satisfies "
                    f"`{str(gate)[:60] or 'no gate'}`, call the endpoint, and read the "
                    f"identifiers and metadata of every other principal's `{entity}` "
                    f"rows. The identifiers are the enumeration half of a chain: any "
                    f"sibling endpoint that admits a known id now serves content."),
                verification_probe={
                    "request": f"Call {r.get('method') or 'GET'} "
                               f"{r.get('path') or hf} as a principal who owns NO "
                               f"{entity} rows.",
                    "expected": "An empty collection (or 403) — every returned row "
                                "must be owned by, or explicitly shared with, the caller.",
                    "actual": None,
                },
                suggested_fix=(
                    f"Add a caller-bound predicate to the {entity} query "
                    f"(e.g. `eq({entity.lower()}.{(meta.get('owner_cols') or ['ownerId'])[0]}, "
                    f"session.user.id)`), or filter the result set through the "
                    f"per-row visibility helper rather than decorating with it."),
                remediation_effort="small"))

        # --- C2b: the decoration counterpart to C5's anti-laundering check.
        # An inventory that says "no decoration here" while the handler is full
        # of canWrite/isEditable fields and contains no filter at all is making a
        # claim the source does not support. Bounded to POSSIBLE/MEDIUM because
        # the filter could live in a helper.
        if (source_root and not r.get("decorates_permission")
                and effective not in ("public_allowlisted",)):
            try:
                src = (Path(source_root) / _norm(hf)).read_text(
                    encoding="utf-8", errors="replace")
            except OSError:
                src = ""
            m = _PERMISSION_FIELD_RE.search(src)
            # Search for the filter only AFTER the permission is computed. A
            # whole-file scan let any unrelated `.filter(` elsewhere in the
            # handler suppress the finding — the false-negative direction.
            # Bound the search to the enclosing handler, not the whole file
            # tail: a router/controller file holds many endpoints, and a
            # `.filter(` in an unrelated later one would suppress this finding.
            after = ""
            if m:
                rest = src[m.end():]
                nxt = _NEXT_HANDLER_RE.search(rest)
                after = rest[:nxt.start()] if nxt else rest[:4000]
            if m and not re.search(r"\.filter\s*\(|filter\s*\(lambda|\bselect\s*\{", after):
                seq += 1
                findings.append(_finding(
                    seq, partition, "C2", "MEDIUM", "POSSIBLE", "CWE-863",
                    ["API1:2023", "A01:2025"],
                    f"Permission-shaped field in {entity} handler with no filter",
                    f"`{rid}` is inventoried as decorates_permission=false, but "
                    f"`{hf}` computes a permission-shaped field ({m.group(1)}) and "
                    "the file contains no filtering call. Either the inventory is "
                    "wrong or the permission is computed and discarded — both are "
                    "worth a look. If the filter lives in a helper, record it as "
                    "scope_evidence and this stops firing.",
                    hf, ln,
                    surface_id=r.get("surface_id"),
                    preconditions=pre, postconditions=post,
                    remediation_effort="trivial"))

        # --- C2: authorization by decoration.
        if r.get("decorates_permission") and not r.get("filters_after_decoration"):
            never_filtered = effective not in ("caller_bound", "visibility_filtered",
                                               "public_allowlisted")
            sev = "HIGH" if (never_filtered and sensitive) else "MEDIUM"
            fields = r.get("decoration_fields") or []
            seq += 1
            findings.append(_finding(
                seq, partition, "C2", sev, "LIKELY", "CWE-863",
                ["API1:2023", "API3:2023", "A01:2025", "ASVS-V4.2.1"],
                f"Authorization by decoration on {entity} collection",
                f"Handler `{rid}` computes a per-row permission "
                f"({', '.join(fields) or 'permission-shaped field'}) and attaches "
                f"it to the response instead of using it to filter. A row the "
                f"caller may not write is still a row the caller can now see. "
                + ("The collection was never read-filtered either "
                   f"(row_scope={effective}), so write-permission decoration is "
                   "standing in for read authorization that was never performed."
                   if never_filtered else
                   "The collection is read-filtered, so this is a hardening gap "
                   "rather than a disclosure."),
                hf, ln,
                surface_id=r.get("surface_id"),
                preconditions=pre, postconditions=post,
                suggested_fix="Filter the collection with the visibility decision "
                              "before decorating; decoration must describe rows the "
                              "caller may already see.",
                remediation_effort="small"))

        # --- C3: fail-closed coverage deficits are surfaced, never swallowed.
        if r.get("coverage") in ("incomplete", "caveat"):
            seq += 1
            findings.append(_finding(
                seq, partition, "C3",
                "LOW" if r.get("coverage") == "caveat" else "MEDIUM",
                "POSSIBLE", "CWE-1007", ["ASVS-V4.2.1"],
                f"Collection {rid} inventoried with coverage={r.get('coverage')}",
                f"The row-scoping of `{entity}` in `{rid}` could not be fully "
                f"determined ({r.get('coverage')}): {r.get('notes') or 'no reason recorded'}. "
                "Treated as an open question, not a pass — re-read the handler end "
                "to end or split it until the query and every post-query transform "
                "are legible.",
                hf, ln, surface_id=r.get("surface_id"),
                # A coverage deficit is a methodology finding: it records that
                # the question is OPEN, not that an attacker gained anything.
                category="methodology",
                preconditions=pre, postconditions=[],
                remediation_effort="small"))

    return findings, notes


# --- C4: does a test pin the insecure behaviour? ---------------------------
# Matches both the object-literal form (`canWrite: false`) and the assertion
# form (`expect(node.canWrite).toBe(false)`) — the `[)\].]*` hop is what lets the
# same pattern cover `).toBe(`.
_PERM_FALSE_RE = re.compile(
    r"(can[A-Z]\w*|can_[a-z]\w*|is\w*(?:Allowed|Permitted|Editable|Writable)"
    r"|[a-zA-Z]\w*Permitted|readOnly|read_only)"
    r"\s*[)\].]*\s*(?::|=|=>|,)?\s*"
    r"(?:to(?:Be|Equal|BeFalsy)\s*\(\s*)?(false|False|0)\b", re.MULTILINE)
_PRESENCE_RE = re.compile(
    r"toContain|toHaveLength\s*\(\s*[1-9]|toEqual\s*\(\s*\[|toMatchObject|"
    r"assertIn\b|assert_in\b|\bassert\s+\w+\s+in\b|toBeDefined|"
    r"\.length\s*\)\s*\.toBe\s*\(\s*[1-9]|expect\s*\(\s*\w+\s*\)\s*\.\s*to\s*\.\s*include",
    re.IGNORECASE)
_OTHER_PRINCIPAL_RE = re.compile(
    r"\b(other|another|second|foreign|different|not_?mine|someone_?else)"
    r"[_A-Za-z]*\b|\buser[_-]?(2|b|two|B)\b|\botherUser\b", re.IGNORECASE)


# Start of the NEXT handler in a multi-route file — the boundary C2b's filter
# search must not cross.
_NEXT_HANDLER_RE = re.compile(
    r"defineEventHandler\s*\(|export\s+default\b"
    r"|export\s+(?:async\s+)?function\b|^(?:async\s+)?function\s+\w+\s*\("
    r"|^exports\.\w+\s*=|^module\.exports\s*="
    # Column 0 ONLY. `^\s*` matched an indented local helper
    # (`  const formatDate = (d) => ...`) inside a handler body, truncating the
    # C2b search before the real `.filter(` and flagging a correctly-filtered
    # collection. A top-level declaration is the boundary; an indented one is
    # part of the handler we are still inside.
    r"|^(?:export\s+)?const\s+\w+\s*=\s*(?:async\s*)?\("
    r"|@(?:Get|Post|Put|Patch|Delete)\s*\(|router\.(?:get|post|put|patch|delete)\s*\("
    r"|app\.(?:get|post|put|patch|delete)\s*\("
    r"|^(?:async\s+)?def\s+\w+\s*\("
    r"|^\s+(?:async\s+)?def\s+\w+\s*\(\s*(?:self|cls)\b"
    # A decorated member of a view class is a handler even when it takes no
    # self. But `@\w+` matched @property / @cached_property / @Input() sitting
    # INSIDE the current handler and truncated the search window — the same bug
    # the column-0 rule fixed for `const`. Restrict to decorators that actually
    # register a handler, plus @staticmethod/@classmethod when a def follows.
    r"|^\s+@(?:action|api_view|route|get|post|put|patch|delete|head|options"
    r"|require_http_methods|require_GET|require_POST|csrf_exempt|login_required"
    r"|permission_classes|renderer_classes|authentication_classes)\b"
    r"|^\s+@(?:staticmethod|classmethod)\s*\n\s*(?:async\s+)?def\b"
    # Dotted route decorators: @app.route, @bp.route, @router.get/post/...
    # (Flask blueprints, FastAPI routers). Anchored to the verb so it can never
    # widen back into matching @property or @Input().
    r"|^\s*@\w+\.(?:route|get|post|put|patch|delete|head|options)\b",
    re.MULTILINE)

_COMMENT_LINE_RE = re.compile(r"^\s*(//|#|\*|/\*)")


def _blank_comment_lines(text):
    """Blank whole-line comments while preserving line count, so an anchor never
    reports a line that merely *describes* the pattern (including this repo's own
    fixture headers)."""
    return "\n".join("" if _COMMENT_LINE_RE.match(l) else l
                     for l in text.splitlines())


def _sibling_tests(root: Path, handler_file: str):
    """Test files that plausibly cover this handler: same-stem siblings, a
    __tests__ subdir, or a mirrored path under tests/. Scoped deliberately —
    grepping every test file in a repo would drown the signal."""
    rel = Path(_norm(handler_file))
    stem = rel.name.split(".")[0]
    if not stem:
        return []
    seen, out = set(), []
    globs = [
        rel.parent / f"{stem}*.test.*", rel.parent / f"{stem}*.spec.*",
        rel.parent / "__tests__" / f"{stem}*", rel.parent / f"{stem}_test.*",
        rel.parent / f"test_{stem}.*", rel.parent / f"{stem}_spec.*",
    ]
    for g in globs:
        for p in root.glob(str(g)):
            if p.is_file() and p not in seen:
                seen.add(p)
                out.append(p)
    for tdir in ("tests", "test", "spec", "__tests__"):
        base = root / tdir
        if base.is_dir():
            for p in base.rglob(f"{stem}*"):
                if p.is_file() and _TEST_PATH_RE.search(_norm(p)) and p not in seen:
                    seen.add(p)
                    out.append(p)
    return out


def test_pinned_findings(collections_doc, profile, partition, source_root, start_seq):
    """C4 — a test that asserts another principal's row is PRESENT (rather than
    absent/404) is high-signal precisely because somebody wrote it deliberately."""
    if not source_root:
        return []
    root = Path(source_root)
    out, seq = [], start_seq
    ents = entity_index(profile)
    for r in (collections_doc or {}).get("collections", []):
        hf = r.get("handler_file")
        entity = r.get("entity") or "unknown"
        if not hf or is_public(entity, profile):
            continue
        for tp in _sibling_tests(root, hf):
            try:
                text = _blank_comment_lines(
                    tp.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            perm = _PERM_FALSE_RE.search(text)
            presence = _PRESENCE_RE.search(text)
            other = _OTHER_PRINCIPAL_RE.search(text)
            triggers = []
            if perm and presence:
                triggers.append(
                    f"asserts a denied permission ({perm.group(1)}) on a row that "
                    "the same test asserts is PRESENT in the response")
            if other and presence:
                triggers.append(
                    f"names another principal ({other.group(0)}) alongside a "
                    "presence assertion")
            if not triggers:
                continue
            line = text.count("\n", 0, (perm or presence).start()) + 1
            seq += 1
            meta = ents.get(str(entity).lower(), {})
            out.append(_finding(
                seq, partition, "C4", "MEDIUM", "POSSIBLE", "CWE-1220",
                ["API1:2023", "A01:2025"],
                f"Test pins cross-principal visibility of {entity}",
                f"`{_norm(tp.relative_to(root))}` {'; '.join(triggers)}. The "
                f"insecure behaviour of `{hf}` is encoded as the expected "
                "behaviour, so a correct fix will look like a broken test. Confirm "
                "whether the assertion documents an intentional sharing model or a "
                "bug that was written down. If it is a bug, the regression test "
                "must assert the other principal's row is ABSENT.",
                _norm(tp.relative_to(root)), line,
                # `methodology`, not `collection_scope`: this finding is about
                # the TEST SUITE, and it grants an attacker nothing. Tagging it
                # as an access-control finding would force a fabricated
                # postcondition into the capability graph, and a fabricated
                # capability corrupts every chain it touches.
                category="methodology",
                preconditions=[], postconditions=[],
                suggested_fix="Invert the assertion: another principal's row must "
                              "be absent (or the response 403/404), not present-"
                              "with-a-false-permission.",
                remediation_effort="trivial",
                notes=f"entity={entity} owner_cols={meta.get('owner_cols') or []}"))
            break   # one C4 per collection is enough signal
    return out


# --- Input classification ---------------------------------------------------
def classify_inputs(paths):
    bag = {"collections": None, "profile": None, "surface": None, "candidates": None}
    for p in paths:
        try:
            with open(p) as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: cannot read {p}: {e}", file=sys.stderr)
            sys.exit(2)
        if not isinstance(doc, dict):
            continue
        if "collections" in doc:
            bag["collections"] = doc
        elif "surfaces" in doc:
            bag["surface"] = doc
        elif "candidates" in doc:
            bag["candidates"] = doc
        elif "data_model" in doc or "public_resources" in doc:
            bag["profile"] = doc
    return bag


def _read(path):
    if path is None:
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read {path}: {e}", file=sys.stderr)
        # `raise`, not sys.exit(): static analysis does not model sys.exit as
        # NoReturn, so the except branch appeared to fall off the end and return
        # an implicit None — a caller that ignored the exit would then get None
        # where it expected a document.
        raise SystemExit(2) from e


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("inputs", nargs="*", type=Path,
                    help="phase-02-collections.json / phase-00-profile.json / "
                         "phase-02-surface.json in any order (classified by shape)")
    ap.add_argument("--collections", type=Path)
    ap.add_argument("--profile", type=Path)
    ap.add_argument("--surface", type=Path)
    ap.add_argument("--candidates", type=Path,
                    help="Pre-extracted candidates {'candidates': [...]}, for tests.")
    ap.add_argument("--source-root", type=Path,
                    help="Run the deterministic extractor over this tree to build "
                         "the candidate set (enables the fail-closed coverage gate, "
                         "C4 test scanning, and C5 predicate verification).")
    ap.add_argument("--partition", default="global")
    ap.add_argument("--out", type=Path, help="Write findings JSONL here.")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    bag = classify_inputs(args.inputs)
    collections = _read(args.collections) or bag["collections"]
    profile = _read(args.profile) or bag["profile"] or {}
    surface = _read(args.surface) or bag["surface"]
    cand_doc = _read(args.candidates) or bag["candidates"]

    if collections is None:
        print("ERROR: no collections inventory supplied (phase-02-collections.json "
              "or --collections).", file=sys.stderr)
        return 2

    candidates = None
    if cand_doc is not None:
        candidates = cand_doc.get("candidates", [])
    elif args.source_root:
        if not args.source_root.is_dir():
            print(f"ERROR: --source-root not a directory: {args.source_root}",
                  file=sys.stderr)
            return 2
        candidates = extract_candidates(args.source_root, surface)

    exit_code = 0

    # (A) coverage gate — fail-closed. Runs even without a candidate set, because
    # a self-declared `coverage: incomplete` row is a deficit on its own.
    cov = coverage_failures(collections, candidates)
    if cov:
        exit_code = 1
        if not args.quiet:
            print("=" * 72)
            print("COLLECTION COVERAGE GATE (fail-closed) — FAILED")
            print("=" * 72)
            for c in cov[:60]:
                print(f"  ! {c}")
            if len(cov) > 60:
                print(f"  ... and {len(cov) - 60} more.")
            print()
    elif candidates is not None and not args.quiet:
        print(f"coverage gate: OK ({len(candidates)} candidate(s) all accounted for)")

    # (B) reconciliation.
    findings, notes = reconcile(collections, profile, surface, args.partition,
                                args.source_root)
    findings += test_pinned_findings(collections, profile, args.partition,
                                     args.source_root, len(findings))

    for n in notes:
        if not args.quiet:
            print(f"  note: {n}")

    if findings:
        worst = max(SEV_RANK[f["severity"]] for f in findings)
        if worst >= SEV_RANK["HIGH"]:
            exit_code = 1
        if not args.quiet:
            print(f"\n{len(findings)} collection-scoping finding(s):")
            for f in findings:
                print(f"  {f['severity']:<8} {f['sources'][0]['detail'].split(':')[-1]:<3} "
                      f"{f['file']}:{f['line']}  {f['title']}")
    elif not args.quiet:
        print("No collection-scoping deficits found.")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        # Stamp the gate outcome on every row. The `|| exit 1` shell guard stops
        # the documented workflow, but a consumer reading this file directly
        # (delta mode, a re-run against a stale .claude-audit/current/, a harness
        # that drops the exit code) would otherwise read an incomplete
        # reconciliation as a complete one.
        gate = "failed" if cov else "passed"
        for f in findings:
            f["coverage_gate"] = gate
        args.out.write_text(
            "".join(json.dumps(f, sort_keys=False) + "\n" for f in findings),
            encoding="utf-8")
        sidecar = args.out.with_suffix(args.out.suffix + ".incomplete")
        if cov:
            sidecar.write_text("\n".join(cov) + "\n", encoding="utf-8")
        else:
            # Remove a sidecar left by an earlier failing run, or a later clean
            # run looks incomplete forever.
            try:
                sidecar.unlink(missing_ok=True)
            except OSError:
                pass   # a stale sidecar is a reporting nit; never fail the gate on it
        if not args.quiet:
            print(f"\nwrote {len(findings)} finding(s) -> {args.out}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
