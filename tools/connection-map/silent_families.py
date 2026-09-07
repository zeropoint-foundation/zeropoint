#!/usr/bin/env python3
"""Which declared receipt families have never fired.

Offline twin of `substrate_validate`'s receipt inventory. That runs in
the server and needs ZP up; this reads the audit DB directly, read-only,
so the number is available when the substrate is not running — including
before a first start, which is exactly when it is most interesting.

    python3 tools/connection-map/silent_families.py [~/ZeroPoint/data/audit.db]

Declared set is parsed from KNOWN_RECEIPT_PREFIXES in
crates/zp-server/src/substrate_validate.rs, so the two cannot drift:
there is one declaration and two readers.

Silence is not a fault. Most families are event-driven and legitimately
quiet. The output is the target list for an exercise sweep, per
docs/design/CONNECTION-INTEGRITY-PROGRAM-2026-07.md — whatever stays
silent after a sweep is either unreachable or wants a declared tie-off.
"""

import os
import re
import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "crates/zp-server/src/substrate_validate.rs"
DEFAULT_DB = Path(os.path.expanduser("~/ZeroPoint/data/audit.db"))


def declared_prefixes_from(src_text):
    """Parse KNOWN_RECEIPT_PREFIXES, ignoring comment text inside it.

    The naive `findall(r'"([^"]+)"')` over the array body also captures
    quoted words in `//` comments between entries — it read
    `reopen_watch — the two tiers` out of a doc comment as a declared
    receipt family. Entries are matched per line instead: a line whose
    only content is a quoted string and a comma.
    """
    import re as _re
    m = _re.search(r"KNOWN_RECEIPT_PREFIXES[^=]*=\s*&\[(.*?)\n\];", src_text, _re.S)
    if not m:
        return []
    out = []
    for line in m.group(1).split("\n"):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        entry = _re.fullmatch(r'"([^"]+)"\s*,?', stripped)
        if entry:
            out.append(entry.group(1))
    return sorted(set(out))


def declared_prefixes():
    out = declared_prefixes_from(SRC.read_text())
    if not out:
        sys.exit(f"could not parse KNOWN_RECEIPT_PREFIXES from {SRC}")
    return out


def events(db):
    """Every event string in the chain, however the table is shaped."""
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    tables = [r[0] for r in con.execute(
        "select name from sqlite_master where type='table'")]
    for t in tables:
        cols = [r[1] for r in con.execute(f"PRAGMA table_info({t})")]
        # The action/event column varies by schema generation; take any
        # text column whose name suggests it, rather than hardcoding one
        # and silently reading zero rows.
        cands = [c for c in cols if re.search(r"action|event|payload|detail", c, re.I)]
        for c in cands:
            for (val,) in con.execute(f"select {c} from {t} where {c} is not null"):
                if isinstance(val, str):
                    yield val


def main():
    db = Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else DEFAULT_DB
    if not db.exists():
        sys.exit(f"audit db not found: {db}")

    declared = declared_prefixes()
    seen = set()
    total = 0
    for ev in events(db):
        total += 1
        for p in declared:
            if p in ev:
                seen.add(p)

    silent = [p for p in declared if p not in seen]
    pct = (len(seen) / len(declared) * 100) if declared else 0.0

    print(f"chain: {db}")
    print(f"  rows scanned      {total}")
    print(f"  declared families {len(declared)}")
    print(f"  ever fired        {len(seen)}  ({pct:.1f}%)")
    print(f"  never fired       {len(silent)}")
    print()
    by_ns = {}
    for p in silent:
        by_ns.setdefault(p.split(":")[0], []).append(p)
    for ns in sorted(by_ns, key=lambda k: -len(by_ns[k])):
        print(f"  {ns}: {len(by_ns[ns])}")
        for p in by_ns[ns]:
            print(f"      {p}")


if __name__ == "__main__":
    main()
