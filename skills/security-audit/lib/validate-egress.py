#!/usr/bin/env python3
"""
validate-egress.py — Authorized-Egress reconciliation (v2.4).

Deterministic core of the "catch any path to sensitive data without permission"
capability. Operates on the Phase-2 inventories:
  - phase-02-sinks.json        (egress sinks, path-sensitive guarded_paths)
  - phase-02-credentials.json  (credential mint/consume ledger)
optionally enriched by:
  - phase-02-surface.json      (interface catalogue — gates on resolve-layer surfaces)
  - phase-00-profile.json      (public_resources allowlist; default-deny otherwise)

Two responsibilities:

  (A) COVERAGE GATE (fail-closed). If a candidate set is supplied (--candidates or
      --source-root, which runs the lib/egress-detection.md extractor), FAIL if any
      candidate sink/credential site is neither inventoried nor explicitly
      dismissed-with-reason, and FAIL on any sink whose `coverage` is "incomplete".
      A silent omission must break the run, never pass quietly.

  (B) RECONCILIATION (R1-R5). Compute, per resource, the strongest INTENDED gate
      (across every path + every credential that protects it), then flag every
      byte-serving branch whose enforced gate is weaker, every credential that no
      byte-serving path consumes, and every capability-only branch on a sensitive
      resource. Emits finding-schema JSONL.

This is NOT a soundness proof. It mechanically reconciles an AGENT-POPULATED
inventory; its value is (a) it makes the cross-layer / conditional-bypass /
missing-enforcer class EXPRESSIBLE and checkable, and (b) the coverage gate makes a
*missing* sink loud instead of silent. A clean run = "every known egress path was
accounted for and gated", not "no unauthorized path exists".

Usage:
  python3 lib/validate-egress.py <one-or-more .json inputs> \
      [--surface phase-02-surface.json] [--profile phase-00-profile.json] \
      [--candidates candidates.json | --source-root DIR] \
      [--partition <id>] [--out findings.jsonl] [--quiet]

Inputs may be passed positionally (classified by their top-level keys, so
`tests/fixtures/egress/deck-bug/*.json` works) or via explicit flags.

Exit codes:
  0  clean — coverage satisfied, no HIGH/CRITICAL deficit
  1  coverage gate failed OR >=1 HIGH/CRITICAL Authorized-Egress finding
  2  argparse / I/O / shape error
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

# --- Gate strength ranking --------------------------------------------------
# enforced_gate / intended_gate are free-text descriptions of the gate that IS
# enforced on a path (or "none"). We rank by keyword. Ranks are deliberately
# coarse — the signal is the DELTA between paths to the same resource, not the
# absolute number. Keep this table in sync with lib/egress-detection.md.
GATE_NONE, GATE_AUTHN, GATE_AUTHZ, GATE_VERIFIED = 0, 1, 2, 3

_RANK_KEYWORDS = [
    # (rank, [keywords]) — checked high-to-low; first hit wins.
    (GATE_VERIFIED, ["2fa", "mfa", "otp", "verif", "step-up", "step up",
                     "__sv", "sv_", "email code", "email-code", "share gate",
                     "share-gate", "second factor"]),
    (GATE_AUTHZ, ["role", "rbac", "admin", "permission", "scope", "canaccess",
                  "can_access", "owner", "ownership", "tenant", "org", "acl",
                  "requirerole", "entra", "oidc", "policy", "authorize", "authz"]),
    (GATE_AUTHN, ["auth", "authenticated", "session", "login", "signin",
                  "sign-in", "requireauth", "bearer", "logged in", "logged-in",
                  "jwt", "token valid", "valid token"]),
]

# Credential kind -> the gate strength it IMPLIES for resources it protects.
_KIND_RANK = {
    "capability": GATE_VERIFIED,
    "signed_url": GATE_VERIFIED,
    "verification": GATE_VERIFIED,
    "session": GATE_AUTHN,
    "jwt": GATE_AUTHN,
    "cookie": GATE_AUTHN,
    "csrf": GATE_AUTHN,
    "api_key": GATE_AUTHZ,
    "pat": GATE_AUTHZ,
    "license": GATE_AUTHZ,
    "feature_flag": GATE_NONE,
}

# Keywords that mean "the only thing protecting this path is knowing an id".
_CAPABILITY_ONLY = ["none", "public", "open", "unauthenticated", "anonymous",
                    "identifier", "id known", "id-known", "knows id", "knows the id",
                    "link exists", "link-exists", "publishlink", "publish link",
                    "share link", "uuid", "guid", "slug", "secret url", "obscurity"]

# NEGATION / no-gate markers. A gate DESCRIPTION that says the control is absent
# must rank GATE_NONE even though it contains positive keywords ("no role check"
# contains "role"; "unauthenticated" contains "auth"). Negation dominates. The
# failure direction is deliberately conservative: an ambiguous/negated gate is
# treated as NO gate, so we over-flag (triaged) rather than miss (the deck bug).
# This makes the ranker robust to free text instead of depending on the agent
# writing the one magic value "none".  [v2.4 P0-1 fix]
_NEGATION = ["none", "no ", "no-", "not ", "without", "missing", "absent",
             "lacks", "lacking", "unauth", "unprotected", "unguarded",
             "anonymous", "public", "open to", "bypass", "skip", "disabled",
             "any caller", "anyone", "everyone", "n/a", "tbd", "unknown",
             "ungated", "no auth", "no gate", "no check", "no verification"]

def _has_negation(t):
    return any(n in t for n in _NEGATION)


def gate_rank(text):
    """Rank a free-text gate description. Empty / negated / 'none' => GATE_NONE.

    Negation is checked FIRST so a description of an ABSENT control (the way an
    analyst naturally writes it) does not get a positive rank from the keyword it
    happens to contain. Unrecognized text falls through to GATE_NONE — conservative
    by design (fail toward flagging)."""
    if not text:
        return GATE_NONE
    t = str(text).lower()
    if _has_negation(t):
        return GATE_NONE
    for rank, kws in _RANK_KEYWORDS:
        if any(k in t for k in kws):
            return rank
    return GATE_NONE


def is_capability_only(text):
    """True when the only thing 'protecting' the path is knowing an identifier
    (or nothing at all). Any GATE_NONE description on a sensitive resource is a
    candidate capability-URL / ungated path."""
    if not text:
        return True
    t = str(text).lower()
    if gate_rank(t) > GATE_NONE:
        return False
    # rank is NONE: it is capability-only if it names an id/link/none marker OR
    # is a negated/ungated description (which is, effectively, served on id alone).
    return (any(k in t for k in _CAPABILITY_ONLY)
            or _has_negation(t)
            or t.strip() in ("", "none"))


# --- Input loading / classification ----------------------------------------
def _load(path):
    with open(path) as f:
        return json.load(f)


def classify_inputs(paths):
    """Classify each positional json input by its top-level keys."""
    bag = {"sinks": None, "credentials": None, "surface": None,
           "profile": None, "candidates": None}
    for p in paths:
        try:
            doc = _load(p)
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: cannot read {p}: {e}", file=sys.stderr)
            sys.exit(2)
        if not isinstance(doc, dict):
            continue
        if "sinks" in doc:
            bag["sinks"] = doc
        elif "credentials" in doc:
            bag["credentials"] = doc
        elif "surfaces" in doc:
            bag["surface"] = doc
        elif "candidates" in doc:
            bag["candidates"] = doc
        elif "data_model" in doc or "public_resources" in doc or "access_mechanisms" in doc:
            bag["profile"] = doc
    return bag


# --- Coverage gate (fail-closed) -------------------------------------------
def _norm(p):
    return str(p).lstrip("./").replace("\\", "/")


# A candidate is "accounted for" by an inventory/dismissal entry in the SAME file
# whose line is within this many lines (absorbs the drift between the extractor's
# anchor line and the line the agent records for the sink/handler). Line-scoped —
# NOT file-scoped — so one inventoried sink cannot mask another un-inventoried
# sink elsewhere in the same multi-handler file.  [v2.4 P0-2 fix]
_COVERAGE_LINE_TOLERANCE = 15


def _split_site(s):
    """Parse 'file:line' (or 'file') into (file, line|None)."""
    s = _norm(s)
    if ":" in s:
        head, _, tail = s.rpartition(":")
        if tail.isdigit():
            return head, int(tail)
    return s, None


def coverage_failures(sinks_doc, creds_doc, candidates):
    """Return a list of hard coverage failures (strings). Empty == coverage OK.

    Coverage is LINE-SCOPED: a candidate (file, line) is accounted for only by an
    inventory/dismissal entry in the same file within _COVERAGE_LINE_TOLERANCE
    lines. A file-only dismissal (no line) is a deliberate whole-file dismissal
    (e.g. a generated/vendored file) and covers the file — but a file-only SINK
    does not blanket-cover the file."""
    fails = []
    sinks = (sinks_doc or {}).get("sinks", [])

    # (file -> sorted list of accounted lines)  +  whole-file dismissals.
    accounted = {}       # file -> [lines]
    file_dismissed = set()  # files dismissed wholesale (bare 'file', no line)

    def _add(file, line):
        accounted.setdefault(_norm(file), []).append(line)

    for s in sinks:
        _add(s.get("sink_file", ""), s.get("line"))
    for c in (creds_doc or {}).get("credentials", []):
        for site in (c.get("writers", []) + c.get("readers", [])):
            _add(site.get("file", ""), site.get("line"))
    for doc in (sinks_doc, creds_doc):
        for d in (doc or {}).get("dismissed", []):
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
            return True  # candidate carries no line; file presence suffices
        return any(al is not None and abs(al - cl) <= _COVERAGE_LINE_TOLERANCE
                   for al in lines)

    # 1. coverage: incomplete is itself a fail-closed deficit.
    for s in sinks:
        if s.get("coverage") == "incomplete":
            fails.append(
                f"sink {s.get('id', s.get('sink_file'))}: coverage=incomplete "
                "(handler has more emitting branches than guarded_paths records — "
                "fail-closed; enumerate every branch or split the handler)"
            )

    # 2. every deterministic candidate must be accounted for or dismissed,
    #    line-scoped.
    for cand in candidates or []:
        cf = _norm(cand.get("file", ""))
        cl = cand.get("line")
        if _is_accounted(cf, cl):
            continue
        fails.append(
            f"UNACCOUNTED candidate {cand.get('kind', '?')} at {cf}"
            f"{':' + str(cl) if cl else ''} — no sink/credential/dismissal within "
            f"{_COVERAGE_LINE_TOLERANCE} lines. The agent must classify every "
            "candidate (silent omission is how the original bug survived)."
        )
    return fails


# --- Deterministic candidate extractor (when --source-root is given) -------
# A compact, language-agnostic subset of lib/egress-detection.md. Pure-python
# (no ripgrep dependency) so CI needs nothing extra.
# Order matters: the first matching pattern wins per line. More specific kinds
# (presigned_url, sse, graphql_field) are listed before the broad db_entity
# serializer. Keep in sync with lib/egress-detection.md; this compiled subset is
# intentionally broad (recall over precision — the agent prunes to dismissed[]).
_EXTRACT_PATTERNS = [
    ("presigned_url", re.compile(r"getSignedUrl\(|\.presign|createPresignedPost\(|"
                                 r"generateSignedUrl\(|generate_presigned_url\(")),
    ("sse", re.compile(r"text/event-stream|res\.write\(\s*['\"]?data:|"
                       r"EventSourceResponse\(|ActionController::Live")),
    ("websocket", re.compile(r"socket\.emit\(|ws\.send\(|\.broadcast\.emit\(")),
    ("graphql_field", re.compile(r"@ResolveField|@FieldResolver|fieldResolver|"
                                 r"def\s+resolve_\w+")),
    ("file", re.compile(r"\bres\.(sendFile|download)\b|\bcreateReadStream\b|"
                        r"\.pipe\(\s*res\b|send_file\b|send_data\b|ServeFile\(|"
                        r"PhysicalFile\(|return\s+File\(|InputStreamResource\(|"
                        r"FileResponse\(")),
    ("stream", re.compile(r"\bsendStream\b|StreamingHttpResponse\(|StreamingResponse\(|"
                          r"StreamingResponseBody|io\.Copy\(\s*w|response\.stream|"
                          r"http\.ServeContent\(")),
    ("static", re.compile(r"express\.static\(|serveStatic\(|ServeContent\(")),
    ("proxy", re.compile(r"createProxyMiddleware\(|http-proxy|\bproxy\(")),
    ("template", re.compile(r"res\.render\(|reply\.view\(|renderToString\(|"
                            r"render\s+(json|plain|html|xml):|\.render\(|render_template\(")),
    ("redirect", re.compile(r"res\.redirect\([^)]*(token|key|data|payload|=)|"
                            r"redirect_to\b|RedirectResponse\(|c\.Redirect\(")),
    ("async_job", re.compile(r"@(KafkaListener|RabbitListener|SqsListener)|"
                             r"\.perform_async\b|@app\.task|@shared_task|"
                             r"exportToCsv\(|generateReport\(|putObject\([^)]*public")),
    ("grpc", re.compile(r"stream\.Send\(|return\s+&pb\.|responseObserver\.onNext\(")),
    ("db_entity", re.compile(r"\bres\.(json|send)\(|reply\.send\(|JsonResponse\(|"
                             r"HttpResponse\(|c\.JSON\(|json\.NewEncoder\(|w\.Write\(|"
                             r"@ResponseBody|ResponseBodyAdvice|ResponseEntity\.(ok|of)\(|"
                             r"Results\.(Json|Ok)\(|return\s+Ok\(")),
]
_CRED_PATTERNS = re.compile(
    r"set-?cookie|cookies\.set\(|res\.cookie\(|jwt\.sign\(|createToken\(|"
    r"getSignedUrl\(|createHmac\(|x-api-key|personal.?access", re.I)
_SOURCE_EXT = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".py", ".rb",
               ".go", ".java", ".kt", ".cs", ".php"}
_SKIP_DIRS = {"node_modules", ".git", "dist", "build", "vendor", "__pycache__",
              ".venv", "venv", "test", "tests", "__tests__", "spec"}


def extract_candidates(root):
    cands = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if Path(fn).suffix not in _SOURCE_EXT:
                continue
            fpath = Path(dirpath) / fn
            try:
                lines = fpath.read_text(errors="ignore").splitlines()
            except OSError:
                continue
            rel = _norm(os.path.relpath(fpath, root))
            for i, line in enumerate(lines, 1):
                for kind, pat in _EXTRACT_PATTERNS:
                    if pat.search(line):
                        cands.append({"file": rel, "line": i, "kind": kind})
                        break
                if _CRED_PATTERNS.search(line):
                    cands.append({"file": rel, "line": i, "kind": "credential"})
    return cands


# --- Reconciliation (R1-R5) -------------------------------------------------
def _byte_branches(sink):
    return [b for b in sink.get("guarded_paths", []) if b.get("serves_bytes")]


def reconcile(sinks_doc, creds_doc, surface_doc, profile_doc, partition):
    sinks = (sinks_doc or {}).get("sinks", [])
    creds = (creds_doc or {}).get("credentials", [])
    surfaces = (surface_doc or {}).get("surfaces", []) if surface_doc else []
    public = set((profile_doc or {}).get("public_resources", []) or [])

    # Resource universe.
    resources = set()
    for s in sinks:
        if s.get("serves_resource"):
            resources.add(s["serves_resource"])
    for c in creds:
        for r in c.get("protects_resources", []):
            resources.add(r)

    findings = []
    seq = 0

    def mk(rule, resource, sev, cwe, file, line, title, desc, probe=None):
        nonlocal seq
        seq += 1
        cat = "idor" if cwe in ("CWE-639", "CWE-441") else "auth"
        owasp = ["A01:2025"]
        owasp += ["API1:2023"] if cat == "idor" else ["API5:2023"]
        f = {
            "id": f"{partition}:egress:{seq:04d}",
            "severity": sev,
            "confidence": "CONFIRMED",
            "category": cat,
            "partition": partition,
            "file": file or "<unknown>",
            "line": int(line) if line else 1,
            "cwe": cwe,
            "owasp_ids": owasp,
            "title": title[:120],
            "description": desc[:800],
            "sources": [{"kind": "scanner", "detail": f"validate-egress.py:{rule}"}],
            "remediation_effort": "small",
        }
        if probe:
            f["verification_probe"] = probe
        return f

    for r in sorted(resources):
        # gate_floor(R) = strongest gate observed anywhere for R.
        floor = GATE_NONE
        floor_src = "none"
        # ...from any sink intended_gate / strongest enforced branch
        sinks_for_r = [s for s in sinks if s.get("serves_resource") == r]
        for s in sinks_for_r:
            ig = gate_rank(s.get("intended_gate"))
            if ig > floor:
                floor, floor_src = ig, f"intended_gate of {s.get('id')}"
            for b in s.get("guarded_paths", []):
                br = gate_rank(b.get("enforced_gate"))
                if br > floor:
                    floor, floor_src = br, f"sibling branch {b.get('branch_id')} of {s.get('id')}"
        # ...from credentials protecting R
        creds_for_r = [c for c in creds if r in c.get("protects_resources", [])]
        for c in creds_for_r:
            cr = max(_KIND_RANK.get(c.get("kind", ""), GATE_NONE),
                     max([gate_rank(v) for v in c.get("validation_at_readers", [])] or [GATE_NONE]))
            if cr > floor:
                floor, floor_src = cr, f"credential {c.get('name')} ({c.get('kind')})"
        # ...from surfaces that serve R (incl. resolve-layer surfaces — R5 source).
        # Evaluated LAST so a resolve-layer gate wins ties: when the gate lives on a
        # non-byte-serving (resolve/identify) surface, the deficit is the cross-layer
        # class and is labelled R5.
        for sf in surfaces:
            if sf.get("serves_resource") == r:
                ig = gate_rank(sf.get("intended_gate"))
                for b in sf.get("guarded_paths", []) or []:
                    ig = max(ig, gate_rank(b.get("enforced_gate")))
                serves_bytes = any(o in ("read", "write", "delete", "exec")
                                   and sf.get("emits_bytes") for o in sf.get("data_ops", []))
                is_resolve_layer = not serves_bytes
                if ig >= floor and ig > GATE_NONE and is_resolve_layer:
                    floor, floor_src = ig, f"resolve-layer surface {sf.get('id')}"
                elif ig > floor:
                    floor, floor_src = ig, f"surface {sf.get('id')}"

        sensitive = r not in public  # default-deny
        if not sensitive and floor == GATE_NONE:
            continue  # explicitly public and nothing implies a gate

        # Per byte-serving branch: a deficit is a branch whose enforced gate is
        # weaker than the resource's floor. We do NOT infer credential
        # "consumption" from substring-in-gate-text (a credential consumed in
        # middleware is not named at the sink line — that produced false positives
        # on correctly-gated resources). Instead, the credential already RAISED the
        # floor; an ungated/under-gated byte path is therefore caught here as a
        # deficit (R5/R2), and a never-read credential is caught by R4 below.
        # [v2.4 P0-3 fix: removed substring-consumption R1]
        for s in sinks_for_r:
            for b in _byte_branches(s):
                br = gate_rank(b.get("enforced_gate"))
                gate_txt = (b.get("enforced_gate") or "none")
                probe = {
                    "request": f"curl -i '<base>{s.get('reachable_via', ['<path>'])[0]}' "
                               "   # attacker capability: knows the id, presents NO credential",
                    "expected": "401 or 404 (denied)",
                    "actual": None,
                }
                deficit = br < floor
                cap_only = sensitive and is_capability_only(gate_txt)
                if deficit:
                    # R5/R2: cross-layer / asymmetric gate deficit (CWE-862).
                    sev = "CRITICAL" if (br == GATE_NONE and floor >= GATE_AUTHZ) else "HIGH"
                    findings.append(mk(
                        "R5" if "resolve-layer" in floor_src else "R2",
                        r, sev, "CWE-862", s.get("sink_file"),
                        b.get("line") or s.get("line"),
                        f"Byte-serving path to {r} enforces a weaker gate than the resource requires",
                        f"Sink {s.get('id')} branch '{b.get('branch_id')}' emits {r} bytes with gate "
                        f"'{gate_txt}' (rank {br}), but {r}'s strongest declared gate is rank {floor} "
                        f"(from {floor_src}). A caller taking this branch retrieves {r} without the "
                        f"intended authorization — the control-with-no-enforcer / cross-layer class.",
                        probe,
                    ))
                if cap_only:
                    # R3: capability-only / ungated byte path on a sensitive
                    # resource (CWE-639 — distinct facet from R5's CWE-862, so it
                    # survives Phase-7 dedup and adds the id-is-not-secret framing).
                    findings.append(mk(
                        "R3", r, "HIGH", "CWE-639", s.get("sink_file"),
                        b.get("line") or s.get("line"),
                        f"Capability-only gate: {r} served on knowledge of an identifier alone",
                        f"Sink {s.get('id')} branch '{b.get('branch_id')}' serves {r} bytes gated only by "
                        f"'{gate_txt}'. If the identifier is handed to clients (DOM/URL/logs/Referer) the "
                        f"control collapses to id-secrecy. Treat the identifier as non-secret and enforce "
                        f"the resource's real gate.",
                        probe,
                    ))

        # R4 (pure theatre): a credential is minted (writers != []) but has NO
        # reader ANYWHERE (readers == []). An issued credential with zero consumers
        # is not a control. FP-safe: a credential read in middleware has readers !=
        # [] and is NOT flagged here.  [v2.4 P0-3 fix: was substring-based]
        for c in creds_for_r:
            if c.get("writers") and not c.get("readers"):
                findings.append(mk(
                    "R4", r, "HIGH", "CWE-862",
                    (c.get("writers") or [{}])[0].get("file"),
                    (c.get("writers") or [{}])[0].get("line"),
                    f"Credential '{c.get('name')}' minted but has zero consumers (theatre) for {r}",
                    f"Credential '{c.get('name')}' ({c.get('kind')}) is written "
                    f"({len(c.get('writers', []))} writer(s)) but read NOWHERE (0 readers) while it is "
                    f"declared to protect {r}. An issued credential with no consumer is not a control.",
                ))

    return findings


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("inputs", nargs="*", type=Path,
                    help="One or more json inputs (classified by top-level keys).")
    ap.add_argument("--sinks", type=Path)
    ap.add_argument("--credentials", type=Path)
    ap.add_argument("--surface", type=Path)
    ap.add_argument("--profile", type=Path)
    ap.add_argument("--candidates", type=Path,
                    help="JSON {candidates:[{file,line,kind}]} for the coverage gate.")
    ap.add_argument("--source-root", type=Path,
                    help="Run the deterministic extractor over this source tree for coverage.")
    ap.add_argument("--partition", default="global")
    ap.add_argument("--out", type=Path, help="Write findings JSONL here.")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    bag = classify_inputs(args.inputs)
    if args.sinks:
        bag["sinks"] = _load(args.sinks)
    if args.credentials:
        bag["credentials"] = _load(args.credentials)
    if args.surface:
        bag["surface"] = _load(args.surface)
    if args.profile:
        bag["profile"] = _load(args.profile)
    if args.candidates:
        bag["candidates"] = _load(args.candidates)

    if bag["sinks"] is None and bag["credentials"] is None:
        print("ERROR: no sinks or credentials inventory supplied.", file=sys.stderr)
        sys.exit(2)

    # Coverage candidates.
    candidates = None
    if bag["candidates"]:
        candidates = bag["candidates"].get("candidates", [])
    elif args.source_root:
        if not args.source_root.exists():
            print(f"ERROR: --source-root not found: {args.source_root}", file=sys.stderr)
            sys.exit(2)
        candidates = extract_candidates(args.source_root)

    cov_fails = coverage_failures(bag["sinks"], bag["credentials"], candidates) \
        if candidates is not None else []

    findings = reconcile(bag["sinks"], bag["credentials"], bag["surface"],
                         bag["profile"], args.partition)

    if args.out:
        with open(args.out, "w") as f:
            for row in findings:
                f.write(json.dumps(row) + "\n")

    high_crit = [f for f in findings if f["severity"] in ("HIGH", "CRITICAL")]

    if not args.quiet:
        print(f"Authorized-Egress reconciliation ({args.partition}):")
        print(f"  coverage candidates checked: "
              f"{len(candidates) if candidates is not None else 'n/a (no candidates supplied)'}")
        print(f"  coverage failures: {len(cov_fails)}")
        for cf in cov_fails[:30]:
            print(f"    ✗ {cf}", file=sys.stderr)
        print(f"  findings: {len(findings)} "
              f"({sum(1 for f in findings if f['severity']=='CRITICAL')} CRITICAL, "
              f"{sum(1 for f in findings if f['severity']=='HIGH')} HIGH)")
        for f in findings:
            print(f"    [{f['severity']}] {f['sources'][0]['detail']} {f['cwe']} — {f['title']}")
        # P1-7: default-deny visibility. If no public_resources allowlist was
        # supplied, EVERY served resource is treated as sensitive — say so, so a
        # triager knows R3 noise on genuinely-public resources is expected and the
        # fix is to curate the allowlist (not to weaken the rule).
        if not (bag["profile"] or {}).get("public_resources"):
            print("  NOTE: no public_resources allowlist supplied — default-deny is "
                  "in FULL effect (every served resource treated as sensitive). "
                  "Curate profile.public_resources to suppress findings on "
                  "intentionally-public data.")
        if args.out:
            print(f"  wrote: {args.out}")

    if cov_fails:
        if not args.quiet:
            print("=== FAIL — coverage gate (fail-closed): "
                  "unaccounted egress candidates ===", file=sys.stderr)
        sys.exit(1)
    if high_crit:
        if not args.quiet:
            print(f"=== FAIL — {len(high_crit)} HIGH/CRITICAL Authorized-Egress "
                  "finding(s) ===", file=sys.stderr)
        sys.exit(1)
    if not args.quiet:
        print("=== PASS — every known egress path accounted for and gated "
              "(NOT a proof of absence) ===")
    sys.exit(0)


if __name__ == "__main__":
    main()
