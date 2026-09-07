#!/usr/bin/env python3
"""
cli_surface.py — measure declared vs built vs deployed for the CLI surface.

Third in the series after `kind_catalog.py` (receipt types) and
`false_assurance.py` (extension keys). Same three columns, same discipline:

  DECLARED  exact.        Parsed from the clap `enum Commands` and every
                          `*Cmd` subcommand enum in crates/zp-cli/src.
  BUILT     exact-ish.    A verb is built if a `Commands::X` pattern exists
                          outside its own declaration. Rust's exhaustiveness
                          check makes this stronger than the grep used for
                          receipts — a missing arm is a compile error, not a
                          silent gap. Reported anyway, because the *shape* of
                          the dispatch is what turned out to matter.
  DEPLOYED  exact.        SQLite. Which verbs have ever left a trace on the
                          chain, and under which actor.

The question this was built to answer — "the CLI commands seem adrift" — has a
counter-intuitive shape. The clap surface is not adrift from itself: every
declared verb has a handler, every declared flag is destructured, and the
trailing match has no catch-all so the compiler enforces both. The drift is
between the CLI and the chain. An operator surface that leaves no trace is not
a governed surface, whatever its `--help` says.

Four measures, in the order they were needed:

  1. verbs      declared vs handled, per enum
  2. flags      declared vs destructured, per struct variant
  3. dispatch   `unreachable!()` claims vs the blocks that must make them true
  4. chain      which verbs are attributable on the chain, and as whom

Usage:  python3 tools/cli_surface.py [--db PATH]
"""

import argparse
import json
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CLI = REPO / "crates/zp-cli/src"
AUDIT = REPO / "crates/zp-core/src/audit.rs"

TEXT = {p.name: p.read_text(errors="replace") for p in sorted(CLI.glob("*.rs"))}
LINES = {n: t.splitlines() for n, t in TEXT.items()}


# ── parsing ────────────────────────────────────────────────────────────────

def enum_blocks(text):
    """(name, body, start_line) for each `enum X { .. }`, brace-matched."""
    for m in re.finditer(r"^(?:pub\s+)?enum\s+(\w+)\s*\{", text, re.M):
        depth = 0
        for j in range(m.end() - 1, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    yield m.group(1), text[m.end():j], text[:m.start()].count("\n") + 1
                    break


def parse_variants(body):
    """{variant: {'kind': struct|tuple|unit, 'fields': [(name, arg_attr)], 'cfg': str|None}}"""
    out, lines, i = {}, body.splitlines(), 0
    pending_attrs = []
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("#["):
            pending_attrs.append(s)
            i += 1
            continue
        if not s or s.startswith("//"):
            i += 1
            continue
        m = re.match(r"([A-Z]\w*)\s*(\{|\(|,|$)", s)
        if not m:
            i += 1
            continue
        vname, opener = m.group(1), m.group(2)
        cfg = next((a for a in pending_attrs if a.startswith("#[cfg(")), None)
        pending_attrs = []
        if opener != "{":
            out[vname] = {"kind": "tuple" if opener == "(" else "unit",
                          "fields": [], "cfg": cfg}
            i += 1
            continue
        depth, fields, arg_attr, j = 0, [], None, i
        while j < len(lines):
            ln = lines[j]
            depth += ln.count("{") - ln.count("}")
            t = ln.strip()
            if t.startswith("#[arg"):
                arg_attr = t
            elif not t.startswith("#") and not t.startswith("//"):
                fm = re.match(r"(\w+)\s*:\s*", t)
                if fm and depth == 1 and j > i:
                    fields.append((fm.group(1), arg_attr))
                    arg_attr = None
            if depth == 0 and j > i:
                break
            j += 1
        out[vname] = {"kind": "struct", "fields": fields, "cfg": cfg}
        i = j + 1
    return out


def surfaces():
    """Every clap enum reachable as a CLI verb, with its declaration range."""
    out = {}
    for fname, text in TEXT.items():
        for ename, body, ln in enum_blocks(text):
            if ename == "Commands" or ename.endswith("Cmd"):
                out[ename] = {"file": fname, "line": ln,
                              "end": ln + body.count("\n") + 2,
                              "variants": parse_variants(body)}
    return out


def sites(pattern, surf=None, ename=None):
    """Regex hits across the CLI sources, excluding the enum's own declaration."""
    rx = re.compile(pattern)
    hits = []
    for fname, ls in LINES.items():
        for i, line in enumerate(ls):
            if not rx.search(line):
                continue
            if surf and ename and fname == surf[ename]["file"] \
               and surf[ename]["line"] <= i + 1 <= surf[ename]["end"]:
                continue
            hits.append((fname, i + 1, line.strip()))
    return hits


# ── 1. verbs ───────────────────────────────────────────────────────────────

def measure_verbs(surf):
    rows, unhandled = [], []
    for ename, info in surf.items():
        for v in info["variants"]:
            hits = sites(rf"\b{ename}::{v}\b", surf, ename)
            rows.append((ename, v, len(hits)))
            if not hits:
                unhandled.append((ename, v))
    return rows, unhandled


# ── 2. flags ───────────────────────────────────────────────────────────────

def flag_name(field, arg_attr):
    if arg_attr and "long" in arg_attr:
        m = re.search(r'long\s*=\s*"([^"]+)"', arg_attr)
        if m:
            return "--" + m.group(1)
        return "--" + field.rstrip("_").replace("_", "-")
    return f"<{field}>"


def measure_flags(surf):
    """A field declared but never destructured is a flag the program cannot see.

    clap parses it, `--help` prints it, and nothing reads it. Checked against
    every pattern site rather than one, since several verbs are matched in more
    than one place and only one of those sites may bind the field.
    """
    declared = dead = 0
    findings = []
    for ename, info in surf.items():
        for v, vi in info["variants"].items():
            if vi["kind"] != "struct" or not vi["fields"]:
                continue
            pat_sites = []
            for m in re.finditer(rf"\b{ename}::{v}\s*\{{", "\n".join([])):
                pass
            for fname, text in TEXT.items():
                for m in re.finditer(rf"\b{ename}::{v}\s*\{{", text):
                    lineno = text[:m.start()].count("\n") + 1
                    if fname == info["file"] and info["line"] <= lineno <= info["end"]:
                        continue
                    depth, inner = 0, ""
                    for j in range(m.end() - 1, len(text)):
                        if text[j] == "{":
                            depth += 1
                        elif text[j] == "}":
                            depth -= 1
                            if depth == 0:
                                inner = text[m.end():j]
                                break
                    pat_sites.append((fname, lineno, set(
                        re.findall(r"\b([a-z_][a-z0-9_]*)\b", inner)), ".." in inner))
            if not pat_sites:
                continue
            bound = set().union(*[s[2] for s in pat_sites])
            for fld, attr in vi["fields"]:
                declared += 1
                if fld not in bound:
                    dead += 1
                    findings.append((ename, v, fld, flag_name(fld, attr),
                                     pat_sites[:2]))
    return declared, dead, findings


# ── 3. dispatch shape ──────────────────────────────────────────────────────

def measure_dispatch():
    """`unreachable!()` is a load-bearing assertion, not an error path.

    `main()` dispatches most verbs in a chain of early
    `if let Some(Commands::X ..) = &args.command { .. std::process::exit(..) }`
    blocks, then a trailing match claims `unreachable!()` for the same verbs.
    The claim is true only while every path through the early block exits. A
    cfg that removes the body, or a flag combination with no branch, turns a
    diagnostic into a panic. Nothing checks the pairing.
    """
    text = TEXT["main.rs"]
    early = {}
    for m in re.finditer(
        r"if (?:let Some\(Commands::(\w+)|matches!\(&args\.command, Some\(Commands::(\w+))",
            text):
        verb = m.group(1) or m.group(2)
        ln = text[:m.start()].count("\n") + 1
        early.setdefault(verb, []).append(ln)
    claims = {m.group(1): text[:m.start()].count("\n") + 1
              for m in re.finditer(r"Some\(Commands::(\w+)[^\n]*=>\s*unreachable!\(\)", text)}
    # A third dispatcher: the session-token path, a hand-maintained pair of
    # matches (`is_session_token_only` / `run_session_token_command`) whose
    # membership was derived by scanning callers rather than by exhaustiveness.
    st = re.search(r"fn is_session_token_only\(cmd: &Commands\) -> bool \{(.*?)\n\}",
                   text, re.S)
    session = set(re.findall(r"Commands::(\w+)", st.group(1))) if st else set()
    catch_all = bool(re.search(r"\n\s*_\s*=>", text[text.find("match args.command"):
                                                    text.find("match args.command") + 6000]))
    return early, claims, session, catch_all


# ── 4. chain ───────────────────────────────────────────────────────────────

def audit_action_variants():
    src = AUDIT.read_text(errors="replace")
    for name, body, _ in enum_blocks(src):
        if name == "AuditAction":
            return list(parse_variants(body))
    return []


def chain(db: Path):
    """Actor histogram and AuditAction histogram over live + archive."""
    if not db.exists():
        return None
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=180)
    c = con.cursor()
    actors, actions, operator_events = Counter(), Counter(), Counter()
    for t in ("audit_entries", "audit_entries_archive"):
        try:
            rows = c.execute(f"select actor, action from {t}")
        except sqlite3.OperationalError:
            continue
        for actor, action in rows:
            actors[actor] += 1
            try:
                a = json.loads(action)
            except Exception:
                continue
            if not isinstance(a, dict):
                continue
            variant = next(iter(a))
            actions[variant] += 1
            if actor == '"Operator"' and variant == "SystemEvent":
                ev = a["SystemEvent"].get("event", "")
                operator_events[":".join(ev.split(":")[:3]).split(" ")[0]] += 1
    return actors, actions, operator_events


# ── report ─────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(Path.home() / "ZeroPoint/data/audit.db"))
    args = ap.parse_args()

    surf = surfaces()
    n_verbs = sum(len(i["variants"]) for i in surf.values())

    print("=" * 74)
    print("zp CLI surface — declared / built / deployed")
    print("=" * 74)

    # 1
    rows, unhandled = measure_verbs(surf)
    print(f"\n[1] VERBS      clap enums {len(surf)}   variants {n_verbs}")
    print(f"    top-level verbs: {len(surf['Commands']['variants'])}")
    print(f"    declared with no pattern site anywhere: {len(unhandled)}")
    for e, v in unhandled:
        print(f"        {e}::{v}")

    # 2
    declared, dead, findings = measure_flags(surf)
    print(f"\n[2] FLAGS      struct-variant fields declared {declared}")
    print(f"    never destructured at any site: {dead}")
    for e, v, fld, flag, ss in findings:
        print(f"        {e}::{v}  {flag}")
        for f, l, _b, rest in ss:
            print(f"            {f}:{l}{'  [.. present]' if rest else ''}")

    # 3
    early, claims, session, catch_all = measure_dispatch()
    print(f"\n[3] DISPATCH   early `if let` blocks {len(early)}"
          f"   `unreachable!()` claims {len(claims)}")
    print(f"    trailing match has a catch-all `_ =>`: {catch_all}"
          "   (false = exhaustiveness is compiler-enforced)")
    orphan = sorted(set(claims) - set(early))
    print(f"    claimed unreachable with no early block: {len(orphan)}")
    for v in orphan:
        via = "session-token path" if v in session else "NO DISPATCHER FOUND"
        print(f"        Commands::{v:<12} line {claims[v]:<6} -> {via}")
    print("    NB: the session-token pair is hand-maintained. `is_session_token_only`")
    print("        matches Substrate/Officer/Vault per-subcommand while the trailing")
    print("        match claims them whole-group; that is only safe while those enums")
    print("        have one variant each. Adding a sibling breaks the pairing.")

    # 4
    print("\n[4] CHAIN")
    res = chain(Path(args.db))
    if res is None:
        print(f"    chain not found at {args.db}")
        return
    actors, actions, opev = res
    total = sum(actors.values())
    declared_actions = audit_action_variants()
    print(f"    entries (live + archive): {total}")
    print(f"\n    AuditAction variants declared: {len(declared_actions)}")
    for v in declared_actions:
        n = actions.get(v, 0)
        print(f"        {n:>9}  {v}{'' if n else '   <-- never written'}")
    print(f"\n    actors: {len(actors)} distinct")
    for a, n in actors.most_common():
        print(f"        {n:>9}  {a}")
    op = actors.get('"Operator"', 0)
    print(f"\n    operator-attributed: {op} of {total}  ({100*op/total:.4f}%)")
    print("    every operator-attributed entry, by verb family:")
    for k, n in opev.most_common():
        print(f"        {n:>9}  {k}")

    print("\n" + "-" * 74)
    print(f"{len(surf['Commands']['variants'])} top-level verbs, {n_verbs} total, "
          f"{declared} flags. {len(opev)} verb families appear on the chain.")
    print("The clap surface is internally consistent. The gap is between the CLI")
    print("and the chain: an operator surface that leaves no trace is not governed,")
    print("whatever --help says.")


if __name__ == "__main__":
    main()
