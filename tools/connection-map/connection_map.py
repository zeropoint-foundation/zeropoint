#!/usr/bin/env python3
"""Connection map — P1 of CONNECTION-INTEGRITY-PROGRAM-2026-07.md.

Collates declared dependencies from the sources already in the tree and
assigns each one a status: live, tied_off, or defect.

Nobody authors the inventory. This tool derives it. If an edge is not
covered by a detector it lands as `defect` -- never as "unknown" -- per
the program's §4 rule that unclassified is the condition being
eliminated.

WHAT COUNTS AS A CONNECTION
---------------------------
A *declared* dependency, at its declaration site. Someone wrote it down;
the question is whether anything checks that the far end is honoured.

Derived edges are deliberately out of scope. `graphify-out/graph.json`
carries 126,231 nodes and 358,825 function-level links, none of which
anyone asserted -- so none of them can be an unhonoured assertion. That
also settles the §9 alternative "extend graphify instead": it answers a
different question. Call-graph reachability is not connection integrity.

STATUS
------
live      a detector exists that would fail if this edge broke
tied_off  a declared exception, carrying its reason at the site
defect    neither -- including every edge nobody has classified

There is deliberately no "works today" status.
"""

import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

EDGES = []
DROPPED = []          # no silent caps -- anything skipped is reported


def edge(kind, source, target, status, detector=None, note=None, site=None):
    EDGES.append({
        "kind": kind, "source": source, "target": target,
        "status": status, "detector": detector, "note": note, "site": site,
    })


def drop(reason, detail):
    DROPPED.append({"reason": reason, "detail": detail})


# ── 1. crate → crate (Cargo) ────────────────────────────────────────────
# Live by construction: a broken path dependency fails `cargo build`.
def collect_crate_deps(root):
    for manifest in sorted((root / "crates").glob("*/Cargo.toml")):
        crate = manifest.parent.name
        text = manifest.read_text(errors="replace")
        for m in re.finditer(r'^\s*([a-z0-9\-_]+)\s*=\s*\{[^}]*path\s*=\s*"([^"]+)"',
                             text, re.M):
            dep, path = m.group(1), m.group(2)
            target = (manifest.parent / path).resolve()
            exists = target.is_dir()
            edge("crate_dep", f"crates/{crate}", dep,
                 "live" if exists else "defect",
                 detector="cargo build --workspace" if exists else None,
                 note=None if exists else f"path dependency does not resolve: {path}",
                 site=str(manifest.relative_to(root)))


# ── 2. module → corpus doc (`//! Spec:` citations) ──────────────────────
# Live: corpus-lint check_spec_citations resolves these in both directions.
SPEC_RE = re.compile(r'^//!\s*Spec:\s*`?([^`\s]+\.md)', re.M)


def collect_spec_citations(root):
    for rs in sorted(root.glob("crates/*/src/**/*.rs")):
        if "/tests/" in str(rs):
            continue
        m = SPEC_RE.search(rs.read_text(errors="replace"))
        if not m:
            continue
        doc = m.group(1).lstrip("/")
        target = root / ("docs/" + doc) if not doc.startswith("docs/") else root / doc
        edge("code_to_corpus", str(rs.relative_to(root)), doc,
             "live" if target.exists() else "defect",
             detector="corpus-lint check_spec_citations" if target.exists() else None,
             note=None if target.exists() else "cited document does not exist",
             site=str(rs.relative_to(root)))


# ── 3. corpus doc → code (the reverse direction — C1's real surface) ────
# A governed doc naming an implementing path. NOTHING checks these.
# check_spec_citations only walks code→doc; a doc can claim any module it
# likes and no instrument disagrees.
PATH_CLAIM_RE = re.compile(r'`(crates/[A-Za-z0-9\-_]+/(?:src/)?[A-Za-z0-9\-_/]*\.rs)`')


def collect_doc_code_claims(root, governed_docs):
    for doc in governed_docs:
        text = doc.read_text(errors="replace")
        for claimed in sorted(set(PATH_CLAIM_RE.findall(text))):
            exists = (root / claimed).exists()
            edge("corpus_to_code", str(doc.relative_to(root)), claimed,
                 "defect",
                 detector=None,
                 note=("path exists but nothing verifies the claim "
                       "(check_spec_citations is code→doc only)")
                      if exists else "claimed implementing path does not exist",
                 site=str(doc.relative_to(root)))


# ── 4. doc → KEEL section ───────────────────────────────────────────────
# Live: corpus-lint check_keel_refs resolves declared sections.
ELAB_RE = re.compile(r'\*\*Elaborates:\*\*(.+)', re.M)
SECTION_RE = re.compile(r'§([IVXLC]+\.\d+)')


def collect_keel_refs(root, governed_docs):
    keel = root / "docs" / "KEEL-2026-07.md"
    keel_text = keel.read_text(errors="replace") if keel.exists() else ""
    for doc in governed_docs:
        m = ELAB_RE.search(doc.read_text(errors="replace"))
        if not m:
            continue
        for sec in sorted(set(SECTION_RE.findall(m.group(1)))):
            present = f"### {sec}" in keel_text or f"§{sec}" in keel_text
            edge("corpus_to_keel", str(doc.relative_to(root)), f"KEEL §{sec}",
                 "live" if present else "defect",
                 detector="corpus-lint check_keel_refs" if present else None,
                 note=None if present else "declared KEEL section not found",
                 site=str(doc.relative_to(root)))


# ── 5. receipt vocabulary: docs ↔ code registry ─────────────────────────
REGISTRY_RE = re.compile(r'KNOWN_RECEIPT_PREFIXES[^=]*=\s*&\[(.*?)\];', re.S)
RECEIPT_IN_DOC_RE = re.compile(r'`([a-z][a-z0-9_]*(?::[a-z0-9_*]+){1,3})`')


def collect_receipts(root, governed_docs):
    reg_file = root / "crates/zp-server/src/substrate_validate.rs"
    if not reg_file.exists():
        drop("registry missing", str(reg_file))
        return
    # Per-line parse: the array body contains `//` comments with quoted
    # words in them, and a blanket findall reads those as declared
    # prefixes. Found 2026-07-26 when `reopen_watch — the two tiers`
    # showed up in the declared set.
    body = REGISTRY_RE.search(reg_file.read_text(errors="replace"))
    if not body:
        drop("registry unparsed", "KNOWN_RECEIPT_PREFIXES not matched")
        return
    registry = set()
    for line in body.group(1).split("\n"):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        entry = re.fullmatch(r'"([^"]+)"\s*,?', stripped)
        if entry:
            registry.add(entry.group(1))

    documented = {}
    for doc in governed_docs:
        for r in set(RECEIPT_IN_DOC_RE.findall(doc.read_text(errors="replace"))):
            documented.setdefault(r, str(doc.relative_to(root)))

    for receipt, site in sorted(documented.items()):
        implemented = any(receipt.startswith(p) or p.startswith(receipt)
                          for p in registry)
        edge("corpus_to_chain", site, receipt,
             "live" if implemented else "defect",
             detector="corpus-lint check_receipt_vocabulary" if implemented else None,
             note=None if implemented else "documented with no family in the code registry",
             site=site)


# ── 6. code → runtime artifact ──────────────────────────────────────────
# include_str! embeds content at build time -- the artifact is in the
# binary, so the edge cannot break at runtime. Everything else resolves a
# path at runtime and is unchecked unless explicitly tied off.
#
# `create_dir_all` is excluded: it creates its own target, so there is no
# dependency on something already existing.
#
# LIMIT, owed to P2: this does not yet separate *operator data* reads
# (vault, config, session -- resolved through zp_core::paths, legitimately
# absent on first run, handled) from *substrate artifact* reads (dossiers,
# prompts, policies -- shipped with the substrate, and the actual C7
# surface). Both currently land as `defect`, which overstates the C7
# count. Partitioning needs the path's provenance, not its call shape.
OPEN_RE = re.compile(
    r'(include_str!|include_bytes!|read_to_string|File::open|read_dir)\s*\(')


def collect_artifact_reads(root):
    for rs in sorted(root.glob("crates/*/src/**/*.rs")):
        rel = str(rs.relative_to(root))
        for i, line in enumerate(rs.read_text(errors="replace").splitlines(), 1):
            m = OPEN_RE.search(line)
            if not m:
                continue
            call = m.group(1)
            if call in ("include_str!", "include_bytes!"):
                edge("code_to_artifact", rel, call, "live",
                     detector="rustc (compile-time embed)",
                     note="content embedded at build time; cannot break at runtime",
                     site=f"{rel}:{i}")
            elif "TIEOFF" in line or "-OK:" in line:
                edge("code_to_artifact", rel, call, "tied_off",
                     detector=None, note="declared exception at the site",
                     site=f"{rel}:{i}")
            else:
                edge("code_to_artifact", rel, call, "defect",
                     detector=None,
                     note="runtime path resolution; nothing verifies the artifact is present or versioned",
                     site=f"{rel}:{i}")


# ── 7. discipline pin allowlists → tie-offs ─────────────────────────────
ALLOW_RE = re.compile(r'\.allow_path\(\s*"([^"]+)"')
SKIP_RE = re.compile(r'\.skip_lines_containing\(\s*"([^"]+)"')


def collect_pin_tieoffs(root):
    pins = sorted((root / "crates/zp-discipline/tests").glob("*.rs"))
    if not pins:
        drop("no pins found", "crates/zp-discipline/tests")
    for pin in pins:
        name, text = pin.stem, pin.read_text(errors="replace")
        rel = str(pin.relative_to(root))
        edge("pin", name, "workspace", "live",
             detector="cargo test -p zp-discipline --no-fail-fast", site=rel)
        for allowed in sorted(set(ALLOW_RE.findall(text))):
            edge("pin_exception", name, allowed, "tied_off",
                 note="allowlisted path -- declared exception", site=rel)
        for marker in sorted(set(SKIP_RE.findall(text))):
            if marker in ("//", "///", "//!", "forbid_pattern"):
                continue  # comment/self-reference filters, not exceptions
            edge("pin_exception", name, f"marker:{marker}", "tied_off",
                 note="skip-line marker -- declared exception, annotated at each site",
                 site=rel)


# ── 8. derived artifact → the source state it was derived from ─────────
# C9 (derived, not refreshed). A generated artifact declares the state it
# came from; the connection is honoured only while that state still holds.
#
# Found 2026-07-26: graphify-out/graph.json declared
# built_at_commit=e29aef4 (2026-05-17) against a HEAD 106 commits and 184
# changed .rs files later -- while CLAUDE.md instructs every session to
# read it *before* any source file, as "your primary map of the
# codebase." The refresh instruction exists one line below and nothing
# enforces it.
#
# An artifact recording wall-clock time instead of a source commit cannot
# be checked against repo state at all. That is a weaker declaration, and
# it lands as a defect for that reason rather than for being old.
COMMIT_KEYS = ("built_at_commit", "generated_from_commit", "source_commit")
TIME_KEYS = ("generated_at", "built_at", "timestamp")
DERIVED_SCAN = ("graphify-out", "docs/lenses", "tools")


def collect_derived_artifacts(root):
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root,
                              capture_output=True, text=True).stdout.strip()
    except Exception:
        drop("git unavailable", "derived-artifact freshness unchecked")
        return

    for scan in DERIVED_SCAN:
        base = root / scan
        if not base.is_dir():
            continue
        # Prune during the walk, not after. rglob descends the whole
        # tree first, and docs/lenses/rust-ast-extractor/target/ is 116MB
        # of build output -- enough to blow a 45s budget on its own.
        candidates = []
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in (
                "target", "node_modules", ".git", "cache", ".venv", "venv",
                "site-packages", "dist", "build", "__pycache__")]
            candidates += [Path(dirpath) / f for f in filenames if f.endswith(".json")]
        for jf in sorted(candidates):
            try:
                data = json.loads(jf.read_text(errors="replace"))
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            rel = str(jf.relative_to(root))

            declared = next((str(data[k]) for k in COMMIT_KEYS if k in data), None)
            stamp = next((k for k in TIME_KEYS if k in data), None)
            if not declared and not stamp:
                continue    # not a derived artifact; it declares no provenance

            # Reference point is the commit that last *wrote* the
            # artifact, not the commit it declares. A self-regenerating
            # artifact always trails its own declared commit by one, and
            # judging on commit distance alone marks it stale the moment
            # anything lands after it -- caught on this detector's first
            # run against its own output. Staleness follows from inputs
            # changing, not from time passing.
            last = subprocess.run(
                ["git", "log", "-1", "--format=%H", "--", rel],
                cwd=root, capture_output=True, text=True).stdout.strip()
            if not last:
                edge("derived_artifact", rel, "untracked", "defect",
                     note="derived artifact is not tracked in git; drift is undiffable",
                     site=rel)
                continue

            changed = [f for f in subprocess.run(
                ["git", "diff", "--name-only", f"{last}..HEAD"],
                cwd=root, capture_output=True, text=True).stdout.split()
                if f.endswith((".rs", ".md", ".toml", ".py"))
                and not f.startswith(("graphify-out/", "tools/connection-map/"))]

            behind = subprocess.run(["git", "rev-list", "--count", f"{last}..HEAD"],
                                    cwd=root, capture_output=True, text=True).stdout.strip()

            if not changed:
                edge("derived_artifact", rel, declared or last[:12], "live",
                     detector="connection-map derived_artifact",
                     note=f"no relevant inputs changed since it was written ({behind} commits ago)",
                     site=rel)
            else:
                age = ""
                if declared:
                    d = subprocess.run(["git", "show", "-s", "--format=%cs", declared],
                                       cwd=root, capture_output=True, text=True)
                    if d.returncode == 0 and d.stdout.strip():
                        age = f", declared source {declared[:12]} dated {d.stdout.strip()}"
                edge("derived_artifact", rel, declared or last[:12], "defect",
                     note=(f"{len(changed)} relevant files changed since it was "
                           f"written ({behind} commits){age}"),
                     site=rel)
            continue

            if stamp:
                edge("derived_artifact", rel, f"{stamp}={data[stamp]}", "defect",
                     note=("records wall-clock time, not a source commit -- "
                           "freshness cannot be checked against repo state"),
                     site=rel)


# ── governed docs (mirrors corpus-lint's definition) ────────────────────
FROZEN = re.compile(r"Tier 3 historical|Status:\W{0,4}Historical|—\s*SUPERSEDED|"
                    r"This document is superseded|frozen at authoring frame",
                    re.M | re.I)


def frozen(path):
    """Tier 3 is frozen at authoring frame and never amended for corpus
    pivots. Counting its claims as defects reports the corpus's age as a
    defect -- the same error corpus-lint's frozen() exists to avoid.
    Mirrors that definition deliberately; the two must not drift."""
    try:
        return bool(FROZEN.search("\n".join(
            path.read_text(errors="replace").splitlines()[:25])))
    except Exception:
        return False


def governed_docs(root):
    idx = root / "docs" / "CANONICAL-CORPUS-INDEX-2026-07.md"
    if not idx.exists():
        drop("index missing", str(idx))
        return []
    listed = set(re.findall(r"\(((?:design/)?[A-Za-z0-9\-_.]+\.md)\)",
                            idx.read_text(errors="replace")))
    out, skipped = [], 0
    for rel in sorted(listed):
        p = root / "docs" / rel
        if not p.exists():
            continue
        if frozen(p):
            skipped += 1
            continue
        out.append(p)
    if skipped:
        drop("frozen (Tier 3 / superseded), excluded from claim checks",
             f"{skipped} indexed documents")
    keel = root / "docs" / "KEEL-2026-07.md"
    if keel.exists() and keel not in out:
        out.append(keel)
    return out


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    gov = governed_docs(root)

    collect_crate_deps(root)
    collect_spec_citations(root)
    collect_doc_code_claims(root, gov)
    collect_keel_refs(root, gov)
    collect_receipts(root, gov)
    collect_artifact_reads(root)
    collect_pin_tieoffs(root)
    collect_derived_artifacts(root)

    by_status = Counter(e["status"] for e in EDGES)
    by_kind = Counter((e["kind"], e["status"]) for e in EDGES)
    total = len(EDGES)
    classified = by_status["live"] + by_status["tied_off"]

    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=root,
                                capture_output=True, text=True).stdout.strip()
    except Exception:
        commit = "unknown"

    out = {
        "generated_from_commit": commit,
        "governed_docs": len(gov),
        "totals": {
            "connections": total,
            "live": by_status["live"],
            "tied_off": by_status["tied_off"],
            "defect": by_status["defect"],
            "maturity": round(classified / total, 4) if total else 0.0,
        },
        "by_kind": {f"{k}/{s}": n for (k, s), n in sorted(by_kind.items())},
        "dropped": DROPPED,
        "connections": EDGES,
    }

    (root / "tools/connection-map/connections.json").write_text(
        json.dumps(out, indent=2, sort_keys=False) + "\n")

    print(f"connection-map — {total} declared connections "
          f"({len(gov)} governed docs, commit {commit})")
    print(f"  live     {by_status['live']:>5}")
    print(f"  tied off {by_status['tied_off']:>5}")
    print(f"  defect   {by_status['defect']:>5}")
    print(f"  maturity {classified}/{total} = "
          f"{(classified / total * 100 if total else 0):.1f}%")
    print()
    for (k, s), n in sorted(by_kind.items()):
        print(f"  {k:<20} {s:<9} {n:>5}")
    if DROPPED:
        print("\n  dropped (not silently):")
        for d in DROPPED:
            print(f"    {d['reason']}: {d['detail']}")


if __name__ == "__main__":
    main()
