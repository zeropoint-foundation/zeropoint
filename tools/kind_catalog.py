#!/usr/bin/env python3
"""
kind_catalog.py — measure declared vs built vs deployed for the receipt surface.

This is a *measurement*, not a source of truth. It answers one question:

    Of everything the substrate declares it can emit, how much does it emit,
    and how much does anything read?

Three columns, three different kinds of evidence, three different confidence
levels — stated plainly rather than blended into one score:

  DECLARED  exact.        Parsed from the `ReceiptType` / `ClaimMetadata` enums
                          and from spec/receipt.schema.json.
  BUILT     approximate.  Grep. A "producer" is a construction site; a
                          "consumer" is a match arm or field read. Test code is
                          excluded best-effort by finding the first #[cfg(test)]
                          in each file and discarding hits below it. This will
                          miss producers built through generic helpers and will
                          over-count re-exports. Treat as a strong hint.
  DEPLOYED  exact.        SQLite count over the live chain + archive.

Usage:  python3 tools/kind_catalog.py [--db PATH] [--out PATH]
"""

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TYPES = REPO / "crates/zp-receipt/src/types.rs"
SCHEMA = REPO / "spec/receipt.schema.json"

# Crates excluded from the workspace build or explicitly pedagogical: a hit here
# is not evidence that the substrate produces anything.
NON_PRODUCTION = ("crates/course-examples/", "crates/trust-triangle/",
                  "crates/zp-hardening-tests/", "/tests/", "/benches/")


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def enum_variants(src: str, enum_name: str):
    """Top-level variant identifiers of a pub enum, in declaration order."""
    m = re.search(rf"pub enum {enum_name}\s*\{{", src)
    if not m:
        return []
    i, depth, start = m.end(), 1, m.end()
    while i < len(src) and depth:
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
        i += 1
    body = src[start:i - 1]
    # Variant heads sit at one indent level; skip attributes and doc comments.
    out, depth = [], 0
    for line in body.splitlines():
        s = line.strip()
        if depth == 0:
            v = re.match(r"^([A-Z]\w*)\s*(\{|\(|,|$)", s)
            if v:
                out.append(v.group(1))
        depth += line.count("{") + line.count("(") - line.count("}") - line.count(")")
        depth = max(depth, 0)
    return out


def rg(pattern: str):
    """ripgrep for a literal, returning (path, lineno) pairs across crates/."""
    try:
        r = subprocess.run(
            ["rg", "-n", "--no-heading", "--fixed-strings", "-g", "*.rs", "--", pattern, "crates"],
            cwd=REPO, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        sys.exit("ripgrep (rg) not found — required.")
    hits = []
    for line in r.stdout.splitlines():
        p = line.split(":", 2)
        if len(p) == 3 and p[1].isdigit():
            hits.append((p[0], int(p[1]), p[2]))
    return hits


_test_floor_cache = {}


def test_floor(path: str) -> int:
    """Line number of the first `#[cfg(test)]` in a file; hits below it are test
    code. Crude — a file with test helpers above production code would be
    misread — but it is the honest cheap approximation and it is stated."""
    if path not in _test_floor_cache:
        try:
            txt = (REPO / path).read_text(errors="replace")
        except OSError:
            _test_floor_cache[path] = 10**9
            return _test_floor_cache[path]
        m = re.search(r"^\s*#\[cfg\(test\)\]", txt, re.M)
        _test_floor_cache[path] = txt[:m.start()].count("\n") + 1 if m else 10**9
    return _test_floor_cache[path]


def production(hits):
    return [h for h in hits
            if not any(x in h[0] for x in NON_PRODUCTION) and h[1] < test_floor(h[0])]


def constructor_map(src: str):
    """`Receipt::<name>()` shorthand -> ReceiptType variant, parsed from types.rs.

    These matter because `Receipt::authorization(...)` constructs an
    `AuthorizationClaim` without the string `ReceiptType::AuthorizationClaim`
    appearing anywhere near it. A tool that greps only for the variant name
    misses every real producer and counts read-side match arms instead — which
    is exactly what the first version of this script did.
    """
    return {m[0]: m[1] for m in re.findall(
        r"pub fn (\w+)\([^)]*\)\s*->\s*crate::ReceiptBuilder\s*\{\s*"
        r"crate::ReceiptBuilder::new\(\s*ReceiptType::(\w+)", src)}


def doc_declared_families():
    """Receipt-family identifiers declared in the governed corpus.

    QUESTION-001 in the deliberation log records that "several hundred are
    declared in governed documents with no emitter behind them" — so the prose
    is a third declaration surface, independent of the `ReceiptType` enum. This
    finds backticked colon-delimited identifiers in docs/ and normalises them to
    the same two-segment key the chain is indexed by.

    Approximate, and biased toward over-collection: a backticked `foo:bar` in a
    sentence is not necessarily a declaration. Rust paths (`::`), URLs (`//`)
    and anything with whitespace or uppercase are dropped. Returns
    {two_segment_key: {full identifiers seen}}.
    """
    fams = defaultdict(set)
    docs = REPO / "docs"
    if not docs.is_dir():
        return fams
    pat = re.compile(r"`([a-z][a-z0-9_]*(?::[a-z0-9_*<>{}-]+){1,5})`")
    for p in docs.rglob("*.md"):
        try:
            txt = p.read_text(errors="replace")
        except OSError:
            continue
        for m in pat.finditer(txt):
            ident = m.group(1)
            if "::" in ident or "//" in ident:
                continue
            fams[":".join(ident.split(":")[:2])].add(ident)
    return fams


def chain_counts(db: Path):
    """receipt_type -> count, and kind -> count, over live + archive."""
    if not db.exists():
        return None, None, 0
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    tables = [t for (t,) in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
        "('audit_entries','audit_entries_archive')")]
    rtypes, kinds, total = Counter(), Counter(), 0
    for t in tables:
        for action, receipt in c.execute(f"SELECT action, receipt FROM {t}"):
            total += 1
            try:
                j = json.loads(action)
            except Exception:
                continue
            ev = j.get("SystemEvent", {}).get("event") if "SystemEvent" in j else None
            if ev:
                kinds[":".join(ev.split(":")[:2])] += 1
            if receipt:
                try:
                    rtypes[json.loads(receipt).get("receipt_type")] += 1
                except Exception:
                    pass
    c.close()
    return rtypes, kinds, total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(Path.home() / "ZeroPoint/data/audit.db"))
    ap.add_argument("--out", default=str(REPO / "target/conformance/kind-catalog.md"))
    args = ap.parse_args()

    src = TYPES.read_text()
    receipt_types = enum_variants(src, "ReceiptType")
    claim_variants = enum_variants(src, "ClaimMetadata")
    schema_enum = set(json.loads(SCHEMA.read_text())["properties"]["receipt_type"]["enum"])

    rtypes, kinds, total = chain_counts(Path(args.db))
    if rtypes is None:
        sys.exit(f"chain not found at {args.db}")

    ctors = constructor_map(src)

    rows = []
    for v in receipt_types:
        wire = snake(v)
        # PRODUCER: a construction site. Two spellings — the builder taken
        # directly, or one of the 26 `Receipt::<name>()` shorthands, which do
        # NOT contain the string `ReceiptType::<Variant>` and were invisible to
        # the first version of this tool.
        prod = production(rg(f"ReceiptBuilder::new(ReceiptType::{v}"))
        for name in [c for c, t in ctors.items() if t == v]:
            prod += production(rg(f"Receipt::{name}("))
        prod = [h for h in prod if "/zp-receipt/src/" not in h[0]]

        # CONSUMER: any other mention — match arms, comparisons, exhaustive
        # dispatch. Read-side. Counting these as producers was the original
        # defect: 4 of 5 spot-checked "producers" were verifier match arms.
        cons = [h for h in production(rg(f"ReceiptType::{v}"))
                if "/zp-receipt/src/" not in h[0]
                and not any(h[0] == p[0] and h[1] == p[1] for p in prod)]

        rows.append(dict(
            variant=v, wire=wire,
            in_schema=wire in schema_enum,
            producers=len({(h[0], h[1]) for h in prod}),
            consumers=len({(h[0], h[1]) for h in cons}),
            sites=sorted({h[0] for h in prod}),
            on_chain=rtypes.get(wire, 0),
        ))

    claim_rows = []
    for v in claim_variants:
        hits = production(rg(f"ClaimMetadata::{v}"))
        built = [h for h in hits if "types.rs" not in h[0] and "validation.rs" not in h[0]]
        claim_rows.append(dict(variant=v, refs=len(built)))

    # ---- summary -----------------------------------------------------------
    live = [r for r in rows if r["on_chain"] > 0]
    # These two used to be one bucket. Separating them is the point: an emitter
    # that exists but has never fired is an unexercised path; no emitter at all
    # is unbuilt work. Same symptom, different fix.
    wired = [r for r in rows if r["producers"] > 0 and r["on_chain"] == 0]
    inert = [r for r in rows if r["producers"] == 0 and r["on_chain"] == 0]
    read_only = [r for r in inert if r["consumers"] > 0]
    cm_inert = [r for r in claim_rows if r["refs"] == 0]

    declared_kinds = {snake(v) for v in receipt_types}
    docfams = doc_declared_families()
    doc_keys = set(docfams)
    chain_keys = set(kinds)

    print(f"chain entries                 {total:,}")
    print(f"receipt types declared        {len(receipt_types)}")
    print(f"  live      (emitted)         {len(live)}")
    print(f"  wired     (emitter, unfired){len(wired):>3}")
    print(f"  inert     (no emitter)      {len(inert)}")
    print(f"    of which read-only        {len(read_only)}  (consumed, never produced)")
    print(f"claim_metadata variants       {len(claim_variants)}")
    print(f"  never constructed           {len(cm_inert)}")
    print(f"event kinds seen on chain     {len(kinds)}")
    print(f"  matching a declared type    {len(chain_keys & declared_kinds)}")
    print()
    print("THIRD SURFACE — families declared in governed prose (docs/*.md)")
    print(f"doc-declared family keys      {len(doc_keys)}")
    print(f"  also emitted on chain       {len(doc_keys & chain_keys)}")
    print(f"  declared, never emitted     {len(doc_keys - chain_keys)}")
    print(f"emitted, undeclared anywhere  {len(chain_keys - doc_keys - declared_kinds)}")
    print(f"  (of {len(chain_keys)} emitted kinds)")
    print()
    print("LIVE:", ", ".join(f"{r['wire']}({r['on_chain']})" for r in live) or "none")
    print()
    print("INERT (declared, no production reference, never emitted):")
    for r in inert:
        print(f"  {r['wire']}")

    # ---- report ------------------------------------------------------------
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    L = ["# Kind catalog — declared vs built vs deployed", "",
         "Generated by `tools/kind_catalog.py`. Derived, not maintained — regenerate, do not edit.",
         "",
         f"- chain entries: **{total:,}** (live + archive)",
         f"- receipt types declared: **{len(receipt_types)}** · live **{len(live)}** · "
         f"wired-not-emitted **{len(wired)}** · inert **{len(inert)}**",
         f"- claim_metadata variants: **{len(claim_variants)}** · never constructed **{len(cm_inert)}**",
         f"- distinct event kinds on chain: **{len(kinds)}**, of which "
         f"**{len(set(kinds) & declared_kinds)}** correspond to a declared receipt type",
         "",
         "`producers` counts construction sites (`ReceiptBuilder::new(ReceiptType::X` "
         "plus the 26 `Receipt::<name>()` shorthands). `consumers` counts read-side "
         "mentions — match arms, comparisons. Grep-based, test code excluded "
         "best-effort, zp-receipt's own internals excluded. A hint, not proof.", "",
         "## Receipt types", "",
         "| kind | in schema | producers | consumers | on chain | status | emitted from |",
         "|---|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: (-r["on_chain"], -r["producers"], r["wire"])):
        st = ("live" if r["on_chain"] else
              "wired, unfired" if r["producers"] else
              "read-only" if r["consumers"] else "**inert**")
        where = ", ".join(p.split("/")[-1] for p in r["sites"][:2]) or "—"
        L.append(f"| `{r['wire']}` | {'yes' if r['in_schema'] else '**NO**'} | "
                 f"{r['producers']} | {r['consumers']} | {r['on_chain']} | {st} | {where} |")
    L += ["", "## claim_metadata variants", "", "| variant | refs | status |", "|---|---|---|"]
    for r in sorted(claim_rows, key=lambda r: (-r["refs"], r["variant"])):
        L.append(f"| `{r['variant']}` | {r['refs']} | {'built' if r['refs'] else '**inert**'} |")
    L += ["", "## Event kinds on the chain", "",
          "Top-level convention prefixes actually observed. A kind with no declared "
          "definition anywhere is the inverse gap: emitted, never specified.", "",
          "| kind | count | declared type? | in governed docs? |", "|---|---|---|---|"]
    for k, n in kinds.most_common():
        L.append(f"| `{k}` | {n} | {'yes' if k in declared_kinds else 'no'} | "
                 f"{'yes' if k in doc_keys else '**no**'} |")
    L += ["", "## Declared in governed prose but never emitted", "",
          "Families named in `docs/**.md` with no corresponding entry on the chain. "
          "Over-collected by design — a backticked identifier in a sentence is not "
          "necessarily a declaration — so read this as an upper bound.", ""]
    for k in sorted(doc_keys - chain_keys):
        ex = sorted(docfams[k])[:3]
        L.append(f"- `{k}` — seen as {', '.join('`'+e+'`' for e in ex)}")
    out.write_text("\n".join(L) + "\n")
    print(f"\nreport → {out}")


if __name__ == "__main__":
    main()
