#!/usr/bin/env python3
"""corpus-lint — mechanical coherence checks over docs/ and crates/.

Instrumentation for the E1 and E2 edges of SUBSTRATE-LOOP-CLOSURE-2026-07.md.
Every check here is justified by a real defect found on 2026-07-25; none is
speculative. Reports by default, fails the build with --strict.

Spec: docs/design/SUBSTRATE-LOOP-CLOSURE-2026-07.md
"""
import re, sys, json, argparse
from pathlib import Path
from collections import defaultdict

FINDINGS = []

# Checks that measure rather than judge. They report and are never a build failure:
# the pre-convention stratum and the specified-not-shipped receipt surface are
# properties of a corpus mid-construction, not defects in it.
INFORMATIONAL = {"index-coverage", "receipt-coverage"}

# The corpus index declares its own establishment date in its opening
# line ("Established 2026-07-10"). Documents authored on or after it were
# written under the convention and are expected to be indexed.
INDEX_ESTABLISHED = "2026-07-10"

def finding(check, path, msg, line=None):
    FINDINGS.append({"check": check, "path": str(path), "line": line, "msg": msg,
                     "kind": "measurement" if check in INFORMATIONAL else "defect"})

# ── loaders ──────────────────────────────────────────────────────────────────
def load_docs(root):
    return sorted((root / "docs").rglob("*.md"))

def governed(root):
    """The corpus the conventions actually govern: what the index lists (Tier 1/2).

    Documents predating the tier / index / registry conventions are a separate
    stratum. Linting them uniformly reports the corpus's age as defect, and the
    corpus's own rule is that Tier 3 is frozen at authoring frame and is never
    amended for corpus pivots. They are counted, not flagged.
    """
    idx = root / "docs" / "CANONICAL-CORPUS-INDEX-2026-07.md"
    if not idx.exists():
        d = root / "docs"
        return sorted(list(d.glob("*.md")) + list((d / "design").glob("*.md")))
    listed = set(re.findall(r"\(((?:design/)?[A-Za-z0-9\-_.]+\.md)\)", idx.read_text(errors="replace")))
    out = [root / "docs" / rel for rel in sorted(listed)]
    return [p for p in out if p.exists() and not frozen(p)]

FROZEN = re.compile(r"Tier 3 historical|Status:\W{0,4}Historical|—\s*SUPERSEDED|"
                    r"This document is superseded|frozen at authoring frame", re.M | re.I)

def frozen(path):
    """Tier 3 and superseded documents are never amended for corpus pivots.
    Linting them for conformance to conventions that postdate them reports the
    corpus's age as defect. They are excluded from amendment-shaped checks."""
    try:
        return bool(FROZEN.search("\n".join(path.read_text(errors="replace").splitlines()[:25])))
    except Exception:
        return False

def keel_sections(root):
    """Every §-addressable id in KEEL: II.13, III.26, IV.3, V.3, Part IX…"""
    keel = root / "docs" / "KEEL-2026-07.md"
    if not keel.exists():
        return None
    text = keel.read_text(errors="replace")
    ids = set(re.findall(r"^#{2,4}\s+((?:[IVX]+)\.\d+)\s", text, re.M))
    ids |= {f"Part {p}" for p in re.findall(r"^##\s+Part\s+([IVX]+)\s", text, re.M)}
    return ids

def receipt_registry(root):
    """The de-facto receipt vocabulary: the prefix list in substrate_validate.rs."""
    f = root / "crates" / "zp-server" / "src" / "substrate_validate.rs"
    if not f.exists():
        return None
    text = f.read_text(errors="replace")
    return set(re.findall(r'"([a-z][a-z0-9_]*:[a-z0-9_:]*)"', text))

# ── checks ───────────────────────────────────────────────────────────────────
def check_tier_declaration(docs):
    """A1 — every governed doc declares its tier in the opening lines."""
    for d in docs:
        head = "\n".join(d.read_text(errors="replace").splitlines()[:12])
        if "Document type:" not in head and "Tier" not in head and "Status:" not in head:
            finding("tier-declaration", d, "no tier or document-type declaration in first 12 lines")

def check_keel_refs(docs, sections):
    """SC3 — a cited KEEL section must exist."""
    if sections is None:
        return finding("keel-refs", "docs/KEEL-2026-07.md", "KEEL not found; skipped")
    pat = re.compile(r"KEEL[^.\n]{0,40}?§((?:[IVX]+)\.\d+)")
    for d in docs:
        for i, line in enumerate(d.read_text(errors="replace").splitlines(), 1):
            for ref in pat.findall(line):
                if ref not in sections:
                    finding("keel-refs", d, f"cites KEEL §{ref}, which does not exist", i)

def check_duplicate_headings(docs):
    """SC4 — LENS-DISCIPLINE had two §7 and two §8."""
    for d in docs:
        seen = defaultdict(list)
        for i, line in enumerate(d.read_text(errors="replace").splitlines(), 1):
            m = re.match(r"^#{2,4}\s+((?:\d+(?:\.\d+)*)\.?\s+.+?)\s*$", line)
            if m:
                seen[m.group(1).strip()].append(i)
        for h, lines in seen.items():
            if len(lines) > 1:
                finding("duplicate-heading", d, f"heading {h!r} appears {len(lines)}x at lines {lines}")

def check_numbered_section_sequence(docs):
    """SC4 — '## 7.' followed by '## 7.' again, or numbering that resets."""
    for d in docs:
        nums = []
        for i, line in enumerate(d.read_text(errors="replace").splitlines(), 1):
            m = re.match(r"^##\s+(\d+)\.\s", line)
            if m:
                nums.append((int(m.group(1)), i))
        for (a, la), (b, lb) in zip(nums, nums[1:]):
            if b <= a:
                finding("section-sequence", d, f"section {b} at line {lb} follows section {a} at line {la}")

def check_doc_crossrefs(docs, root):
    """SC1/SC6 — a referenced .md must exist somewhere in the repo."""
    names = {p.name for p in root.rglob("*.md")}
    pat = re.compile(r"`([A-Za-z0-9][A-Za-z0-9\-_.]*\.md)`")
    unwritten = re.compile(r"not yet written|\(planned\)|to be written|does not exist yet|"
                           r"not yet authored|placeholder", re.I)
    for d in docs:
        for i, line in enumerate(d.read_text(errors="replace").splitlines(), 1):
            if unwritten.search(line):
                continue
            for ref in pat.findall(line):
                if ref not in names:
                    finding("crossref", d, f"references {ref}, which does not exist", i)

def check_stated_counts(docs):
    """CSA said 'fifteen' above 17 rows; CIP said 'six' above 7 classes."""
    words = {w: n for n, w in enumerate(
        "zero one two three four five six seven eight nine ten eleven twelve "
        "thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty".split())}
    pat = re.compile(r"\b(" + "|".join(words) + r")\b\s+(?:\w+\s+){0,3}?"
                     r"(features|classes|source classes|principles|heuristics|modes|primitives|"
                     r"outcomes|properties|dimensions|stages|layers|edges)\b", re.I)
    for d in docs:
        text = d.read_text(errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            m = pat.search(line)
            if not m:
                continue
            claimed, noun = words[m.group(1).lower()], m.group(2).lower()
            if claimed < 3:
                continue
            rows = len(re.findall(r"^\|\s+\*\*", text, re.M))
            heads = len(re.findall(r"^###\s+(?:Class|Stage|Layer)\s+\d", text, re.M))
            actual = max(rows, heads)
            if actual and abs(actual - claimed) >= 1 and actual not in (claimed,):
                finding("stated-count", d,
                        f"says {m.group(1)} {noun}; structural count is {actual}", i)

def check_spec_citations(root):
    """SC1 — every //! Spec: citation in crates/ resolves."""
    pat = re.compile(r"(docs/[A-Za-z0-9\-_/]*\.md)")
    for rs in (root / "crates").rglob("*.rs"):
        try:
            text = rs.read_text(errors="replace")
        except Exception:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if "//!" not in line and "///" not in line:
                continue
            for ref in pat.findall(line):
                if not (root / ref).exists():
                    finding("spec-citation", rs, f"cites {ref}, which does not exist", i)

def check_receipt_vocabulary(docs, registry):
    """SC2 — receipt vocabulary in docs vs the code registry.

    Absence is expected: most documented receipts are specified-not-shipped.
    The signal is (a) namespace coverage, reported as a summary, and
    (b) *drift* — a namespace live in code where a documented receipt in the
    same namespace has no counterpart. That is where a rename hides.
    """
    if registry is None:
        return finding("receipt-vocab", "crates/zp-server/src/substrate_validate.rs",
                       "registry not found; skipped")
    pat = re.compile(r"`([a-z][a-z0-9_]*:[a-z0-9_]+(?::[a-z0-9_*<>]+)*)`")
    marked = re.compile(r"specified,?\s*not\s*shipped|not yet (?:shipped|implemented)", re.I)
    drift = []
    doc_ns, exempt = defaultdict(set), set()
    for d in docs:
        text = d.read_text(errors="replace")
        for m in pat.finditer(text):
            r = m.group(1)
            doc_ns[r.split(":")[0]].add(r)
            # an A11 marker within the receipt's own neighbourhood declares status
            if marked.search(text[max(0, m.start() - 200): m.end() + 500]):
                exempt.add(r)
    code_ns = defaultdict(set)
    for r in registry:
        code_ns[r.split(":")[0]].add(r)

    # Compare at FAMILY level (first two segments). A namespace having one live
    # family does not make every other receipt in it drift — that is coverage.
    # Drift is: this family IS implemented, and this member of it is not.
    def fam(r):
        parts = r.split(":")
        return ":".join(parts[:2]) if len(parts) > 1 else r
    code_fam = defaultdict(set)
    for r in registry:
        code_fam[fam(r)].add(r.rstrip(":"))

    unshipped = []
    for ns in sorted(doc_ns):
        for r in sorted(doc_ns[ns]):
            f = fam(r)
            impl = code_fam.get(f)
            if not impl:
                unshipped.append((ns, r))
                continue
            if r in exempt:
                continue
            base = r.rstrip(":*").split("<")[0].rstrip(":")
            if not any(base.startswith(k) or k.startswith(base) for k in impl):
                drift.append((r, f, sorted(impl)[:3]))
    if unshipped:
        per_ns = defaultdict(int)
        for ns, _ in unshipped:
            per_ns[ns] += 1
        finding("receipt-coverage", "docs/",
                f"{len(unshipped)} receipt types across {len(per_ns)} namespaces are documented "
                f"with no implemented family in the code registry: " +
                ", ".join(f"{ns}:({n})" for ns, n in sorted(per_ns.items(), key=lambda x: -x[1])[:12]))
    for r, f, impl in drift:
        finding("receipt-drift", f"docs/ [{r}]",
                f"family {f}: is implemented but {r} is not a member — rename, or a "
                f"real gap. Implemented: {', '.join(impl)}")

def post_convention(root):
    """Indexed documents authored under the index convention.

    `governed()` excludes anything matching FROZEN, which is right for
    amendment-shaped checks and wrong here. Current investigations and
    programs describe themselves as "frozen at authoring frame" -- that
    phrase means *this document will not be retrofitted*, not *this
    document is historical*. Their reopen conditions are precisely the
    part meant to stay live, and the blunt filter was skipping them:
    SUBSTRATE-LOOP-CLOSURE's three tie-offs went unchecked because its
    own header tripped the regex.

    Date is the honest discriminator, as it is for index-coverage.
    """
    idx = root / "docs" / "CANONICAL-CORPUS-INDEX-2026-07.md"
    if not idx.exists():
        return []
    listed = set(re.findall(r"\(((?:design/)?[A-Za-z0-9\-_.]+\.md)\)",
                            idx.read_text(errors="replace")))
    out = []
    for rel in sorted(listed):
        p = root / "docs" / rel
        if not p.exists():
            continue
        m = re.search(r"^\*\*Date:\*\*\s*(\d{4}-\d{2}-\d{2})",
                      p.read_text(errors="replace"), re.M)
        if m and m.group(1) >= INDEX_ESTABLISHED:
            out.append(p)
    return out

def check_tieoff_reopen_conditions(docs, root):
    """Stage 1t — a deferred or open tie-off must declare a way back.

    IMPROVEMENT-LOOP-DISCIPLINE-2026-07.md §Stage 1t: `reopen_condition`
    is the load-bearing field. "Without it a tie-off is a prose bullet in
    a document nobody re-reads." The four dispositions differ precisely
    here -- `declined` and `limited` are terminal by design and need no
    condition; `deferred` and `open` are claims that the branch will be
    revisited, and a revisit claim with no stated trigger is a permanent
    absence wearing a temporary label.

    This is §III.19 applied to the corpus's own decisions: convert the
    absence into a record. It is also the declaration layer the
    CONNECTION-INTEGRITY-PROGRAM guardrail needs -- a tie-off cannot be
    watched before it can be read.

    Scoped to governed, non-frozen documents. Tier 3 is frozen at
    authoring frame and its prose predates the convention.
    """
    disp = re.compile(r'\*(declined|deferred|open|limited)\.?\*', re.I)
    for d in docs:
        for n, line in enumerate(d.read_text(errors="replace").split("\n"), 1):
            stripped = line.lstrip()
            if not stripped.startswith(("-", "*", "|")):
                continue
            m = disp.search(line)
            if not m or m.group(1).lower() not in ("deferred", "open"):
                continue
            disposition = m.group(1).capitalize()
            has_cond = bool(re.search(r"reopen[ _]condition", line, re.I))
            has_watch = bool(re.search(r"reopen[ _]watch", line, re.I))
            if has_cond and has_watch:
                continue
            missing = []
            if not has_cond:
                missing.append("reopen condition")
            if not has_watch:
                missing.append("reopen watch")
            finding("tie-off", d.relative_to(root) if str(d).startswith(str(root)) else d,
                    f"tie-off marked *{disposition}* is missing "
                    f"{' and '.join(missing)} — a revisit claim with no stated "
                    f"trigger, or no way of noticing the trigger, is a permanent "
                    f"absence wearing a temporary label "
                    f"(IMPROVEMENT-LOOP-DISCIPLINE Stage 1t)", line=n)

def check_index_coverage(docs, root):
    """SC6 — docs present but unindexed, and index entries pointing nowhere."""
    idx = root / "docs" / "CANONICAL-CORPUS-INDEX-2026-07.md"
    if not idx.exists():
        return finding("index", "docs/CANONICAL-CORPUS-INDEX-2026-07.md", "index not found; skipped")
    text = idx.read_text(errors="replace")
    listed = set(re.findall(r"\(((?:design/)?[A-Za-z0-9\-_.]+\.md)\)", text))
    for rel in listed:
        if not (root / "docs" / rel).exists():
            finding("index", idx, f"index lists {rel}, which does not exist")
    d = root / "docs"
    present = set(list(d.glob("*.md")) + list((d / "design").glob("*.md")))
    unlisted = [p for p in present if str(p.relative_to(d)) not in listed
                and p.name != "CANONICAL-CORPUS-INDEX-2026-07.md"]

    # Partition by declared date against the index's own establishment
    # date. Lumping the two together was itself a C4 defect per
    # docs/design/CONNECTION-INTEGRITY-PROGRAM-2026-07.md §3 — the check
    # ran, reported a number, and could not distinguish "deliberately
    # frozen" from "someone forgot." Four documents from the 2026-07-25/26
    # arc sat inside that number reading as pre-convention stratum.
    #
    # A document that declares a date on or after INDEX_ESTABLISHED was
    # authored under the convention and is a defect if unindexed. One
    # that predates it, or declares no date at all, stays a measurement —
    # Tier 3 is frozen at authoring frame and is not retro-indexed.
    post_convention, pre_convention = [], []
    for p in unlisted:
        m = re.search(r"^\*\*Date:\*\*\s*(\d{4}-\d{2}-\d{2})",
                      p.read_text(errors="replace"), re.M)
        (post_convention if m and m.group(1) >= INDEX_ESTABLISHED
         else pre_convention).append(p)

    for p in sorted(post_convention):
        finding("index-missing", str(p.relative_to(root)),
                f"authored {INDEX_ESTABLISHED} or later and not listed in the "
                f"corpus index — the index is the map; an unlisted document "
                f"is unreachable by anyone navigating it")

    if pre_convention:
        finding("index-coverage", "docs/",
                f"{len(pre_convention)} of {len(present)} documents in docs/ and "
                f"docs/design are not listed in the index (pre-convention stratum "
                f"or undated; not a defect by itself — Tier 3 is frozen at "
                f"authoring frame)")

# ── main ─────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any finding")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--only", help="comma-separated check names")
    args = ap.parse_args()
    root = Path(args.root).resolve()

    docs = load_docs(root)
    gov = governed(root)
    sections = keel_sections(root)
    registry = receipt_registry(root)

    check_tier_declaration(gov)
    check_keel_refs(gov, sections)
    check_duplicate_headings(gov)
    check_numbered_section_sequence(gov)
    check_doc_crossrefs(gov, root)
    check_spec_citations(root)
    check_receipt_vocabulary(gov, registry)
    check_tieoff_reopen_conditions(post_convention(root), root)
    check_index_coverage(gov, root)

    out = FINDINGS
    if args.only:
        keep = set(args.only.split(","))
        out = [f for f in out if f["check"] in keep]

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        by = defaultdict(list)
        for f in out:
            by[f["check"]].append(f)
        defects = [f for f in out if f["kind"] == "defect"]
        measures = [f for f in out if f["kind"] == "measurement"]
        print(f"corpus-lint — {len(docs)} documents ({len(gov)} governed)")
        print(f"  {len(defects)} defect(s), {len(measures)} measurement(s)\n")
        for check in sorted(by):
            print(f"── {check} ({len(by[check])})")
            for f in by[check][:40]:
                loc = f"{f['path']}:{f['line']}" if f["line"] else f["path"]
                print(f"   {loc}\n     {f['msg']}")
            if len(by[check]) > 40:
                print(f"   … {len(by[check]) - 40} more")
            print()
    sys.exit(1 if (args.strict and any(f["kind"] == "defect" for f in out)) else 0)

if __name__ == "__main__":
    main()
