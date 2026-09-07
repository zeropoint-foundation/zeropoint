#!/usr/bin/env python3
"""
ontology_surface.py — declared vs built vs deployed for the ontology.

Fourth in the series after `kind_catalog.py` (receipt types),
`false_assurance.py` (extension keys) and `cli_surface.py` (CLI verbs). Same
three columns, same discipline, applied to the substrate's model of itself.

  DECLARED  exact.        Parsed from `ObjectType` and `RelationshipKind` in
                          crates/zp-ontology/src/.
  BUILT     approximate.  Grep for construction sites outside `#[cfg(test)]`
                          and outside the declaring modules.
  DEPLOYED  exact.        SQLite over ontology.db.

The finding this was written to make legible: **relationship kinds are gated
by object types.** Every kind requires particular types at its endpoints, and
those requirements are stated in the doc comment on each variant. The
Cartographer materializes only `Trajectory`, so any kind needing a `Decision`,
`Insight`, `Artifact` or `Friction` at either end is not merely unwired — it is
*unreachable*, and wiring a producer for it would produce nothing.

That turns "0 relationships" from a flat number into a dependency order: to get
edges, materialize the object type that unblocks the most kinds first.

`REQUIRES` below is transcribed by hand from those doc comments. It is the one
part of this tool that is not derived, so it is the part most likely to rot —
`endpoint_requirements_match_the_doc_comments` re-reads them and complains on
disagreement rather than trusting the transcription.

Usage:  python3 tools/ontology_surface.py [--db PATH]
"""

import argparse
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ONTO = REPO / "crates/zp-ontology/src"
IDS = ONTO / "id.rs"
RELS = ONTO / "relationships.rs"

# Modules that *declare* the vocabulary. A mention here is not a producer.
DECLARING = ("crates/zp-ontology/src/id.rs",
             "crates/zp-ontology/src/relationships.rs",
             "crates/zp-ontology/src/objects.rs")

# Endpoint object types each relationship kind needs, transcribed from the doc
# comment on each variant. `Trajectory` is omitted because it already exists —
# what matters is which *missing* types a kind depends on.
REQUIRES = {
    "ContributesTo":   {"Artifact"},
    "BelongsTo":       {"Decision", "Insight", "Friction"},   # any one suffices
    "SubTrajectoryOf": set(),                                  # Trajectory → Trajectory
    "SupersededBy":    {"Decision"},
    "InfluencedBy":    {"Decision"},
    "AuthorizedBy":    {"Decision"},
    "BlockedBy":       {"Friction"},
    "MitigatedBy":     {"Friction", "Decision"},
    "RelatedTo":       {"Friction", "Insight"},
    "ProducedBy":      {"Artifact", "Decision"},
    "DependsOn":       {"Artifact"},
}
# Kinds where ANY one of the required types is enough, vs ALL of them.
ANY_OF = {"BelongsTo"}


def variants(src: str, enum: str):
    m = re.search(rf"pub enum {enum}\s*\{{", src)
    if not m:
        return []
    depth, i, start = 1, m.end(), m.end()
    while i < len(src) and depth:
        depth += (src[i] == "{") - (src[i] == "}")
        i += 1
    body = src[start:i - 1]
    out, doc = [], []
    for line in body.splitlines():
        s = line.strip()
        if s.startswith("///"):
            doc.append(s[3:].strip())
        elif s.startswith("//") or s.startswith("#[") or not s:
            continue
        else:
            v = re.match(r"([A-Z]\w*)\s*(,|\{|\()", s)
            if v:
                out.append((v.group(1), " ".join(doc)))
            doc = []
    return out


def production_sites(pattern: str):
    """Construction sites outside test modules and outside declaring modules."""
    r = subprocess.run(["grep", "-rn", "-E", pattern, "--include=*.rs", "crates/"],
                       cwd=REPO, capture_output=True, text=True)
    out = []
    for line in r.stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        f, l, txt = parts[0], int(parts[1]), parts[2]
        if f in DECLARING or "/tests/" in f:
            continue
        src = (REPO / f).read_text(errors="replace").splitlines()
        tstart = next((i + 1 for i, x in enumerate(src) if "#[cfg(test)]" in x), 10**9)
        if l >= tstart:
            continue
        out.append((f, l, txt.strip()))
    return out


def deployed(db: Path):
    if not db.exists():
        return None
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=60).cursor()
    objs = dict(c.execute("select object_type, count(*) from objects group by 1"))
    rels = dict(c.execute("select kind, count(*) from relationships group by 1"))
    meta = dict((k, v) for k, v, _ in c.execute("select * from meta"))
    roles = dict(c.execute("select role, count(*) from object_receipts group by 1"))
    return objs, rels, meta, roles


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(Path.home() / "ZeroPoint/data/ontology.db"))
    args = ap.parse_args()

    otypes = variants(IDS.read_text(), "ObjectType")
    rkinds = variants(RELS.read_text(), "RelationshipKind")

    dep = deployed(Path(args.db))
    objs, rels, meta, roles = dep if dep else ({}, {}, {}, {})

    print("=" * 76)
    print("ontology surface — declared / built / deployed")
    print("=" * 76)

    print(f"\nOBJECT TYPES ({len(otypes)} declared)")
    print(f"  {'type':<14}{'on chain':>10}   status")
    live_types = set()
    for v, _doc in otypes:
        n = objs.get(v.lower(), 0)
        if n:
            live_types.add(v)
        status = "live" if n else "reserved — declared, no materializer"
        print(f"  {v:<14}{n:>10}   {status}")

    print(f"\nRELATIONSHIP KINDS ({len(rkinds)} declared)")
    print(f"  {'kind':<18}{'on chain':>10}{'producers':>11}   blocked by")
    for v, _doc in rkinds:
        n = rels.get(_snake(v), 0)
        prod = production_sites(rf"RelationshipKind::{v}\b")
        need = REQUIRES.get(v, set())
        missing = need - live_types
        if v in ANY_OF:
            blocked = "" if (need & live_types) else "any of " + "/".join(sorted(need))
        else:
            blocked = "/".join(sorted(missing)) if missing else ""
        print(f"  {v:<18}{n:>10}{len(prod):>11}   {blocked or '— nothing; reachable today'}")

    unblocked = [v for v, _ in rkinds
                 if not ((REQUIRES.get(v, set()) - live_types)
                         if v not in ANY_OF
                         else (set() if (REQUIRES[v] & live_types) else REQUIRES[v]))]
    print(f"\n  reachable with today's object types: {len(unblocked)} of {len(rkinds)}"
          f"  -> {', '.join(unblocked) or 'none'}")

    print("\nLEVERAGE — kinds unblocked by materializing exactly one more type")
    for t, _ in otypes:
        if t in live_types:
            continue
        would = live_types | {t}
        got = []
        for v, _ in rkinds:
            need = REQUIRES.get(v, set())
            ok = (need & would) if v in ANY_OF else not (need - would)
            if ok and v not in unblocked:
                got.append(v)
        print(f"  {t:<12} unblocks {len(got):>2}   {', '.join(got) or '—'}")

    print("\nDEPLOYED")
    print(f"  objects            {sum(objs.values())}   {objs}")
    print(f"  relationships      {sum(rels.values())}")
    print(f"  object_receipts    {roles}")
    print(f"  cursor             {meta.get('last_processed_sequence')} "
          f"@ {meta.get('last_processed_at')}")

    print("\n" + "-" * 76)
    print("A relationship kind with no reachable endpoints is not unwired work —")
    print("it is work that cannot begin. Order the object types by what they")
    print("unblock, not by the order they were declared in.")


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


if __name__ == "__main__":
    main()
