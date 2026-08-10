#!/usr/bin/env python3
"""
zp-tools-server.py — localhost bridge between the Tavus avatar page and ZeroPoint.

    cd ~/projects/zeropoint
    python3 zp-tools-server.py          # then open http://localhost:8080/

Serves the avatar page AND the tool endpoints from one origin, so there is no
CORS to configure and nothing is reachable from outside this machine.

Three tools, all read-only:

    corpus_search   ripgrep over docs/ and crates/
    chain_tail      audit.db, opened read-only, direct
    precedent_list  `zp precedent list --json`

Why chain_tail does not shell out to `zp chain story`: Chain and Audit are
absent from `is_session_token_only` in crates/zp-cli/src/main.rs, so those
verbs fall through to load_genesis_secret_composed() and prompt for a hardware
touch. An avatar that makes the Trezor blink because it got curious is not a
tool, it is a hazard. Precedent IS in that predicate, so it is safe to shell.

GET /health reports which database it actually opened and how many rows it
holds. Check it before believing an answer: a repo-root audit.db can be a stale
dev copy with a few dozen rows, and a confident answer drawn from the wrong
chain is worse than no answer.
"""

import http.server, socketserver, json, subprocess, sqlite3, os, sys, shutil, re
from pathlib import Path

PORT     = int(os.environ.get("ZP_TOOLS_PORT", "8080"))
REPO     = Path(os.environ.get("ZP_REPO", Path.cwd())).resolve()
PAGE     = Path(os.environ.get("ZP_PAGE", REPO / "tavus-avatar.html"))
TIMEOUT  = 20

# Two schemas ship under the same filename. The live substrate writes
# `audit_entries` (id/actor/action/policy_decision/signatures, append-only via
# triggers, no seq column). Older dev databases in the repo carry `audit_log`
# (seq/event_type/details). A probe written against only one of them silently
# rejects the other -- which is precisely how the first version of this file
# picked a 28-row February database over a 218MB live chain.
SCHEMAS = {
    "audit_entries": dict(order="timestamp", event="action", ts="timestamp"),
    "audit_log":     dict(order="seq",       event="event_type", ts="timestamp"),
}

def chain_table(p: Path) -> tuple[str | None, int]:
    """Return (table_name, row_count) for whichever known schema this file
    carries, or (None, 0). Existence is not enough -- an empty chain and a
    missing one answer questions equally badly."""
    try:
        c = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        names = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for t in SCHEMAS:
            if t in names:
                n = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                c.close()
                return (t, n) if n > 0 else (None, 0)
        c.close()
    except Exception:
        pass
    return (None, 0)

def has_chain(p: Path) -> bool:
    return chain_table(p)[0] is not None

def db_candidates() -> list[tuple[str, Path]]:
    """Mirror the substrate's own resolution order rather than inventing one.

    crates/zp-cli/src/main.rs:1767 promotes the clap default only when the
    resolved directory exists, and zp_core::paths::home() resolves ZP_HOME
    first, then ~/ZeroPoint. data_dir is that root plus "data".

    An earlier version of this function guessed "whichever audit.db is
    biggest", which picked a 28-row February database sitting at the repo
    root and would have had the avatar reporting on a dead chain with total
    confidence. Two mechanisms for one concern, and the second one drifted
    immediately -- which is P8, demonstrated at my own expense."""
    out: list[tuple[str, Path]] = []
    if os.environ.get("ZP_DATA_DIR"):
        out.append(("ZP_DATA_DIR", Path(os.environ["ZP_DATA_DIR"]).expanduser() / "audit.db"))
    if os.environ.get("ZP_HOME"):
        out.append(("$ZP_HOME/data", Path(os.environ["ZP_HOME"]).expanduser() / "data" / "audit.db"))
    out.append(("~/ZeroPoint/data", Path.home() / "ZeroPoint" / "data" / "audit.db"))
    out.append(("./data/zeropoint", REPO / "data" / "zeropoint" / "audit.db"))
    out.append(("repo root (legacy)", REPO / "audit.db"))
    return out

def find_db() -> Path | None:
    for _rule, p in db_candidates():
        if p.is_file() and has_chain(p):
            return p
    return None

def zp_candidates() -> list[Path]:
    c = [REPO / "target/release/zp", REPO / "target/debug/zp"]
    w = shutil.which("zp")
    if w:
        c.append(Path(w))
    return [p for p in c if p.is_file() and os.access(p, os.X_OK)]

def zp_supports(p: Path, verb: str) -> bool:
    """Ask the binary, do not assume. A release build can be weeks older than
    the source tree and simply not have the subcommand -- which is how
    precedent_list came back 'unrecognized subcommand' while a perfectly good
    debug build sat next to it."""
    try:
        r = subprocess.run([str(p), verb, "--help"], cwd=REPO,
                           capture_output=True, text=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False

def find_zp() -> str | None:
    # Newest first -- a stale release build is worse than a fresh debug one --
    # then confirm the verb actually exists before choosing it.
    cands = sorted(zp_candidates(), key=lambda p: p.stat().st_mtime, reverse=True)
    for p in cands:
        if zp_supports(p, "precedent"):
            return str(p)
    return str(cands[0]) if cands else None

DB = find_db()
ZP = find_zp()

# ---------------------------------------------------------------- tools

def corpus_search(query: str = "", max_results: int = 12, regex: bool = False):
    query = (query or "").strip()
    if not query:
        return {"error": "query is required"}
    max_results = max(1, min(int(max_results or 12), 40))
    # --max-columns-preview matters: without it rg *omits* an over-long line
    # entirely rather than truncating, so a match in a long paragraph reads as
    # no match at all. Silent absence is the worst failure mode here.
    # --max-count is PER FILE. Capping it at 3 silently truncated any entry
    # whose lines all live in one document -- the deliberation log's whole
    # grep-key format returned as a fragment with no sign it was clipped.
    # max_results already bounds the total, so per-file may equal it.
    argv = ["rg", "-n", "--no-heading", "--smart-case",
            "--max-columns", "240", "--max-columns-preview",
            "--max-count", str(max_results),
            "-g", "*.md", "-g", "*.rs", "-g", "*.toml"]
    if not regex:
        argv.append("--fixed-strings")
    argv += ["--", query, "docs", "crates"]
    try:
        r = subprocess.run(argv, cwd=REPO, capture_output=True,
                           text=True, timeout=TIMEOUT)
    except FileNotFoundError:
        return {"error": "ripgrep (rg) not installed"}
    except subprocess.TimeoutExpired:
        return {"error": f"search timed out after {TIMEOUT}s"}
    hits = []
    for line in r.stdout.splitlines()[:max_results]:
        m = re.match(r"^([^:]+):(\d+):(.*)$", line)
        if m:
            hits.append({"file": m.group(1), "line": int(m.group(2)),
                         "text": m.group(3).strip()[:240]})
    total = len(r.stdout.splitlines())
    return {"query": query, "hits": hits, "shown": len(hits), "total_matches": total,
            "truncated": total > len(hits)}

def _unwrap(v):
    """Chain fields are serde-tagged JSON: {"System":"regent"},
    {"SystemEvent":{"event":"..."}}, {"Allow":{"conditions":[]}}. A
    conversational model does not want the envelope, it wants the string."""
    if not isinstance(v, str):
        return v
    try:
        j = json.loads(v)
    except (json.JSONDecodeError, TypeError):
        return v
    while isinstance(j, dict) and len(j) == 1:
        k, inner = next(iter(j.items()))
        if isinstance(inner, str):
            return inner
        if isinstance(inner, dict) and "event" in inner:
            return inner["event"]
        if isinstance(inner, dict) and inner:
            return k
        return k
    return v if not isinstance(j, (dict, list)) else v

def chain_tail(limit: int = 5, event_type: str = "", include_archive: bool = False):
    # Default 5, ceiling 25. Twenty full entries is ~10KB of JSON, which is
    # both more than a data-channel app message will carry and far more than
    # a voice agent can do anything with. The counts are the answer to most
    # questions; the entries are texture.
    if not DB:
        return {"error": "no audit.db found; set ZP_DATA_DIR or ZP_HOME"}
    table, total = chain_table(DB)
    if not table:
        return {"error": f"{DB} has no recognised chain table"}
    s = SCHEMAS[table]
    limit = max(1, min(int(limit or 5), 25))
    try:
        c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
        cols = [d[1] for d in c.execute(f"PRAGMA table_info({table})")]
        sql = f"SELECT * FROM {table}"
        args: list = []
        if event_type:
            sql += f" WHERE {s['event']} LIKE ?"
            args.append(f"%{event_type}%")
        sql += f" ORDER BY {s['order']} DESC LIMIT ?"
        args.append(limit)
        rows = [dict(zip(cols, r)) for r in c.execute(sql, args)]
        archive = None
        if include_archive or True:
            try:
                archive = c.execute(
                    f"SELECT COUNT(*) FROM {table}_archive").fetchone()[0]
            except Exception:
                archive = None
        c.close()
    except Exception as e:
        return {"error": f"audit.db read failed: {e}"}

    out, signed_n = [], 0
    for r in rows:
        sigs = r.get("signatures")
        is_signed = sigs not in ("[]", "", None) if sigs is not None else None
        if is_signed:
            signed_n += 1
        e = {
            "at": str(r.get(s["ts"]))[11:19],          # HH:MM:SS; the date is today
            "event": str(_unwrap(r.get(s["event"])))[:140],
            "actor": _unwrap(r["actor"]) if "actor" in r else None,
            "signed": is_signed,
        }
        out.append({k: v for k, v in e.items() if v is not None})

    def envelope(entries):
        s2 = (f"{total:,} live entries, {archive:,} archived. "
              if archive is not None else f"{total:,} live entries. ")
        n_signed = sum(1 for e in entries if e.get("signed"))
        if entries and n_signed == len(entries):
            s2 += f"All {len(entries)} newest entries are signed."
        elif entries:
            s2 += f"{n_signed} of the {len(entries)} newest entries are signed."
        return {"summary": s2, "live_entries": total, "archived_entries": archive,
                "all_newest_signed": bool(entries) and n_signed == len(entries),
                "database": str(DB), "newest": entries}

    # A byte budget, not a count. The count ceiling is a proxy that fails as
    # soon as events get long -- 25 short entries fit and 25 long ones do not.
    # Trim to fit and say so, because a result that is quietly too big for the
    # data channel is dropped without an error and presents as a timeout.
    BUDGET = 2500
    res = envelope(out)
    while len(json.dumps(res)) > BUDGET and len(out) > 1:
        out = out[:-1]
        res = envelope(out)
    if len(out) < len(rows):
        res["trimmed_to_fit"] = (f"{len(out)} of {len(rows)} entries shown; the rest "
                                 "exceeded the message size limit")
    return res

def precedent_list():
    if not ZP:
        return {"error": "zp binary not found; build it or set PATH"}
    try:
        r = subprocess.run([ZP, "precedent", "list", "--json"], cwd=REPO,
                           capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"error": f"zp precedent list timed out after {TIMEOUT}s "
                         "(a hardware prompt may be waiting -- check the terminal)"}
    if r.returncode != 0:
        return {"error": f"zp exited {r.returncode}", "stderr": r.stderr[-600:]}
    try:
        return {"precedents": json.loads(r.stdout)}
    except json.JSONDecodeError:
        return {"raw": r.stdout[:2000]}

TOOLS = {"corpus_search": corpus_search,
         "chain_tail": chain_tail,
         "precedent_list": precedent_list}

# ---------------------------------------------------------------- http

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        sys.stderr.write("  %s\n" % (fmt % a))

    def _json(self, code, obj):
        b = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if self.path.startswith("/health"):
            db_table, db_rows = chain_table(DB) if DB else (None, None)
            # Report the whole ladder, not just the winner. Which candidates
            # existed and were rejected is the part that tells you whether the
            # selected chain is the one you meant.
            ladder = []
            for rule, p in db_candidates():
                e = {"rule": rule, "path": str(p), "exists": p.is_file()}
                if e["exists"]:
                    t, n = chain_table(p)
                    e["table"], e["rows"] = t, (n if t else "no usable chain table")
                e["selected"] = (DB is not None and p == DB)
                ladder.append(e)
            return self._json(200, {
                "repo": str(REPO),
                "page": str(PAGE), "page_exists": PAGE.is_file(),
                "audit_db": str(DB) if DB else None,
                "audit_table": db_table, "audit_entries": db_rows,
                "audit_db_resolution": ladder,
                "zp_binary": ZP,
                "zp_candidates": [{"path": str(p),
                                   "mtime": int(p.stat().st_mtime),
                                   "has_precedent": zp_supports(p, "precedent"),
                                   "selected": ZP is not None and str(p) == ZP}
                                  for p in zp_candidates()],
                "ripgrep": shutil.which("rg"),
                "tools": sorted(TOOLS),
            })
        if self.path in ("/", "/index.html", "/tavus-avatar.html"):
            if not PAGE.is_file():
                return self._json(404, {"error": f"page not found: {PAGE}"})
            b = PAGE.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self.path.startswith("/tool/"):
            return self._json(404, {"error": "not found"})
        name = self.path[len("/tool/"):].strip("/")
        fn = TOOLS.get(name)
        if not fn:
            return self._json(404, {"error": f"unknown tool: {name}",
                                    "known": sorted(TOOLS)})
        n = int(self.headers.get("Content-Length") or 0)
        try:
            args = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError as e:
            return self._json(400, {"error": f"bad JSON: {e}"})
        # Log the payload BEFORE validating it. The earlier version logged
        # after, so a rejected call printed a bare 400 and hid the one thing
        # worth seeing.
        sys.stderr.write(f"  tool {name}({json.dumps(args)[:300]})\n")
        if not isinstance(args, dict):
            return self._json(400, {"error": "arguments must be an object"})

        # Tavus injects its own fields into a tool call's arguments alongside
        # the model's. `response_to_user` is the filler line the PAL speaks
        # while the tool runs -- a product of on_call: generate_filler, present
        # on every call by design. It is protocol, not a mistake, so it is
        # dropped without comment; reporting it would put a spurious
        # "ignored_arguments" on every single response.
        PROTOCOL_FIELDS = {"response_to_user", "seq", "turn_idx",
                           "tool_call_id", "conversation_id"}
        args = {k: v for k, v in args.items() if k not in PROTOCOL_FIELDS}

        # Tolerant, not silent, for everything else. A conversational model
        # will occasionally invent a parameter; hard-failing the whole call
        # over it hands back nothing useful. Drop the unknown keys, run the
        # tool, and name what was dropped so the mismatch stays visible.
        allowed = set(fn.__code__.co_varnames[:fn.__code__.co_argcount])
        extra = sorted(set(args) - allowed)
        if extra:
            sys.stderr.write(f"    dropped unknown args {extra}; "
                             f"accepted are {sorted(allowed)}\n")
            args = {k: v for k, v in args.items() if k in allowed}
        try:
            out = fn(**args)
        except TypeError as e:
            return self._json(400, {"error": f"bad arguments: {e}",
                                    "accepted": sorted(allowed)})
        except Exception as e:
            return self._json(500, {"error": f"{type(e).__name__}: {e}"})
        if extra and isinstance(out, dict):
            out["ignored_arguments"] = extra
            out["accepted_arguments"] = sorted(allowed)
        return self._json(200, out)

def bind_server():
    """Bind, then report. The previous version announced a URL and only then
    discovered it could not have that port, which is a banner that lies.

    127.0.0.1, not 0.0.0.0: this runs reads against the repo and has no
    authentication. It must not be reachable from the network."""
    socketserver.TCPServer.allow_reuse_address = True
    tried, last = [], None
    for p in [PORT] + [PORT + i for i in range(1, 21)] + [0]:
        try:
            srv = socketserver.ThreadingTCPServer(("127.0.0.1", p), H)
            actual = srv.server_address[1]
            if tried:
                print(f"note        {', '.join(map(str, tried))} in use; "
                      f"bound {actual} instead")
            return srv, actual
        except OSError as e:
            if e.errno not in (48, 98):      # EADDRINUSE (BSD, Linux)
                raise
            tried.append(p if p else "ephemeral")
            last = e
    raise last

if __name__ == "__main__":
    server, port = bind_server()
    print(f"repo        {REPO}")
    print(f"page        {PAGE}{'' if PAGE.is_file() else '   << MISSING'}")
    for rule, p in db_candidates():
        mark = "  <== using" if (DB and p == DB) else ""
        if not p.is_file():
            state = "absent"
        else:
            t, n = chain_table(p)
            state = f"{t}, {n} rows" if t else "no usable chain table"
        print(f"audit.db    [{rule:<18}] {p}  ({state}){mark}")
    if not DB:
        print("audit.db    NONE USABLE -- set ZP_DATA_DIR or ZP_HOME")
    import datetime as _dt
    for p in sorted(zp_candidates(), key=lambda p: p.stat().st_mtime, reverse=True):
        age = _dt.datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        ok = "has `precedent`" if zp_supports(p, "precedent") else "NO `precedent` verb — stale build"
        mark = "  <== using" if ZP and str(p) == ZP else ""
        print(f"zp          {p}  ({age}, {ok}){mark}")
    if not ZP:
        print("zp          NOT FOUND")
    print(f"tools       {', '.join(sorted(TOOLS))}")
    print(f"\n  http://127.0.0.1:{port}/         avatar page   <== open this")
    print(f"  http://127.0.0.1:{port}/health   check this first\n")
    with server as s:
        try:
            s.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
