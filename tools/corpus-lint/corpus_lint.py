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
ROOT = None

# Checks that measure rather than judge. They report and are never a build failure:
# the pre-convention stratum and the specified-not-shipped receipt surface are
# properties of a corpus mid-construction, not defects in it.
INFORMATIONAL = {"index-coverage", "receipt-coverage", "stated-count",
                 "doc-path-prospective", "doc-path-as-proposed", "pub-consumer"}

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
    """SC1/SC6 — a referenced .md must exist somewhere in the repo.

    Deliberately-untracked trees are excluded from the resolution set, not
    skipped. A bare-name citation of a `docs/handoffs/` file resolved on the
    author's machine -- where rglob finds it -- and failed in CI and in the
    temp worktree the pre-push hook builds, which made the verdict depend on
    which clone the check ran in. Excluding them here makes a bare handoff
    citation fail consistently everywhere, which is what pushes the author to
    the path form `docs/handoffs/x.md`. That form is the convention: it states
    in the citation itself that the target is a local note, and both this check
    and check_doc_paths honour it. Twenty citations were converted 2026-07-29.
    """
    IGNORED = ("docs/handoffs/", "graphify-out/", "target/", "node_modules/")
    names = {p.name for p in root.rglob("*.md")
             if not any(seg in p.as_posix() for seg in IGNORED)}
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
    """A stated count that disagrees with the structure right below it.

    CSA said "fifteen" above 17 rows; CIP said "six" above 7 classes.

    **Reported as a measurement, not a defect**, and the reason is in the
    check's own history. It was written, completed, and then never wired
    into `main()` -- so when it first ran on 2026-07-26 it had never been
    calibrated and produced 33 findings, nearly all false.

    Two rounds of calibration got it to 17: skip lines that cross-
    reference (a `§`, a `.md`, `KEEL`), and count the block immediately
    following the claim rather than the host document's global maximum,
    which had been comparing "Three properties frame the discipline:"
    against six table rows elsewhere in the file.

    The residual is not a tuning problem. Distinguishing *this document
    claims N about its own structure* from *this document mentions a
    count defined elsewhere* is a semantic judgment, and a regex cannot
    make it. Defect grade would mean blocking on a check that is wrong
    more often than right, which trains readers to ignore the suite --
    the alarm-fatigue harm named in SUBSTRATE-COORDINATION-DISCIPLINE.
    So it surfaces candidates and asserts nothing.
    """
    words = {w: n for n, w in enumerate(
        "zero one two three four five six seven eight nine ten eleven twelve "
        "thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty".split())}
    pat = re.compile(r"\b(" + "|".join(words) + r")\b\s+(?:\w+\s+){0,3}?"
                     r"(features|classes|source classes|principles|heuristics|modes|primitives|"
                     r"outcomes|properties|dimensions|stages|layers|edges)\b", re.I)
    xref = re.compile(r"§|\.md|KEEL")

    def following_block(lines, start):
        """Items in the first structured block after `start`, or None."""
        i, n = start, len(lines)
        while i < n and not lines[i].strip():
            i += 1
        prose = 0
        while i < n and lines[i].strip() and not re.match(r"^\s*(?:[-*]\s|\d+\.\s|\|)", lines[i]):
            prose += 1
            if prose > 2 or lines[i].startswith("#"):
                return None
            i += 1
        count, table_started = 0, False
        while i < n:
            l = lines[i]
            if not l.strip():
                if count:
                    break
                i += 1
                continue
            if re.match(r"^\s*[-*]\s|^\s*\d+\.\s", l):
                count += 1
            elif l.lstrip().startswith("|"):
                if re.match(r"^\s*\|[\s\-:|]+\|\s*$", l):
                    table_started = True
                elif table_started:
                    count += 1
            elif l.startswith("#"):
                break
            i += 1
        return count or None

    for d in docs:
        lines = d.read_text(errors="replace").splitlines()
        for i, line in enumerate(lines):
            m = pat.search(line)
            if not m:
                continue
            claimed = words[m.group(1).lower()]
            if claimed < 3 or xref.search(line):
                continue
            actual = following_block(lines, i + 1)
            if actual and actual != claimed:
                finding("stated-count", d.relative_to(ROOT) if ROOT and str(d).startswith(str(ROOT)) else d,
                        f"says {m.group(1)} {m.group(2).lower()}; the block below has "
                        f"{actual} — candidate, not a verdict: the check cannot tell a "
                        f"self-claim from a mention of a count defined elsewhere",
                        i + 1)

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
def check_doc_paths(docs, root):
    """SC3 — every backticked repo path in a governed doc resolves.

    Justified by two real defects, 2026-07-27: AGENT-TOOL-CONTRACT-2026-06.md
    cites `src/tools/wasm/capabilities.rs` for a runtime that was never in
    this repo, and EXTENSION-SURFACE-2026-07.md names
    `crates/zp-server/src/extensions/` as near-term implementation. Both read
    as descriptions of a tree that exists.

    File and directory misses are separated deliberately. A directory that
    does not exist is usually prospective -- "this will live here" -- which is
    C1 and the corpus is permitted to specify ahead of the code. A file path
    is far more often asserted as fact, so it is the defect and the directory
    is the measurement.

    docs/handoffs/* is skipped: handoffs are local notes by the convention
    recorded in CANONICAL-CORPUS-INDEX-2026-07.md, and their paths are not
    expected to resolve in any clone.
    """
    TOP = {"crates", "tools", "scripts", "docs", "policies", "models", "dashboard",
           "prompts", "src", "wasm-modules", "zeropoint.global", "migrations",
           "zeropointfoundation.org", "zeropoint-py", "graphify-out", "core", "INPUT"}
    EXT = (".rs", ".py", ".toml", ".json", ".md", ".sh", ".yml", ".yaml",
           ".jsonl", ".sql", ".html")
    pat = re.compile(r"`([A-Za-z0-9_][A-Za-z0-9_./-]*/[A-Za-z0-9_.-]+/?)`")

    def resolves(ref):
        # crate- and tool-relative citations are idiomatic in this corpus
        return ((root / ref).exists() or (root / "crates" / ref).exists()
                or (root / "tools" / ref).exists())

    for doc in docs:
        try:
            lines = doc.read_text(errors="replace").splitlines()
        except Exception:
            continue
        # A dated design record asserts its paths as *plan*, not as fact. The
        # check's premise -- "a file path is far more often asserted as fact" --
        # is right for current documents and wrong for a record of what was
        # proposed on a date. Declaring `**Paths as proposed**` in the header
        # downgrades this document's file misses to a measurement, so they stay
        # counted and visible but stop reading as present-tense claims.
        # Deliberately not silence: the count still appears under
        # doc-path-as-proposed, and a document that uses this to hide a genuine
        # stale claim is making that choice in public, in its own header.
        as_proposed = any("Paths as proposed" in l for l in lines[:25])
        kind = "doc-path-as-proposed" if as_proposed else "doc-path"
        for i, line in enumerate(lines, 1):
            for ref in pat.findall(line):
                if ref.startswith(("http", "/", "~")) or "*" in ref or "{" in ref:
                    continue
                if ref.split("/")[0] not in TOP and not ref.endswith(EXT):
                    continue
                # Deliberately-untracked trees. .gitignore excludes both, so a
                # citation into them cannot resolve in any clone -- including the
                # temp worktree the pre-push hook materializes. Flagging them made
                # the check's verdict depend on which clone it ran in, which is the
                # one thing a structural check must never do.
                if ref.startswith(("docs/handoffs/", "graphify-out/")):
                    continue
                if resolves(ref):
                    continue
                # A document reporting that a path dangles must not be flagged
                # for naming it. Both instances on first run (2026-07-27) were
                # of this shape: an investigation quoting the missing path from
                # the document that asserts it.
                if any(w in line.lower() for w in
                       ("does not exist", "no such", "never existed", "does not resolve",
                        "dangl", "absent from", "unbuilt", "not present")):
                    continue
                # A11 annotations, same convention check_doc_crossrefs honours:
                # `(not yet written)` declares prospective, `(external)` declares
                # a path in someone else's tree. Both are statements of status,
                # which is what the discipline asks an author for.
                low2 = line.lower()
                if ("not yet written" in low2 or "(external" in low2
                        or "external —" in low2 or "external --" in low2):
                    continue
                if ref.endswith("/"):
                    finding("doc-path-prospective", doc,
                            f"cites directory {ref}, which does not exist", i)
                else:
                    finding(kind, doc,
                            f"cites {ref}, which does not exist", i)


def check_doc_comment_symbols(root):
    """SC4 — a backticked symbol in a Rust doc comment exists in its own crate.

    Justified by a real defect, 2026-07-27: CapabilityGrant::delegate documented
    its scope check as "enforced by `narrow_capability`", a function that has
    never existed in the tree; enforcement is GrantedCapability::contains. The
    comment had been read by at least two surveys as evidence of a mechanism.

    Backticks in doc comments are invisible to rustdoc, so no compiler check
    reaches them. Writing them as intra-doc links would let
    `cargo doc -D rustdoc::broken_intra_doc_links` enforce this structurally,
    which is the better fix; until then this catches the phantom class.

    Deliberately narrow: only tokens shaped like identifiers (containing `::`
    or `_`, or CamelCase) and at least four characters, to avoid flagging
    prose. Expected to report zero -- it is a regression guard, not a
    discovery tool.
    """
    sym = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)`")
    crates = root / "crates"
    if not crates.exists():
        return
    sources = [p for p in crates.rglob("*.rs") if "/target/" not in str(p)]
    text_of = {}
    for path in sources:
        crate = crates / path.relative_to(crates).parts[0]
        if crate not in text_of:
            # token set, not a joined blob: membership is O(1) and the blob
            # form made this check the slowest in the suite by two orders
            text_of[crate] = set(re.findall(
                r"[A-Za-z_][A-Za-z0-9_]*",
                "\n".join(q.read_text(errors="replace") for q in crate.rglob("*.rs")
                           if "/target/" not in str(q))))
        for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            stripped = line.strip()
            if not (stripped.startswith("///") or stripped.startswith("//!")):
                continue
            for token in sym.findall(line):
                if ("::" not in token and "_" not in token
                        and not re.match(r"^[A-Z][a-zA-Z0-9]*$", token)):
                    continue
                leaf = token.split("::")[-1]
                if len(leaf) < 4:
                    continue
                if leaf not in text_of[crate]:
                    finding("doc-symbol", path,
                            f"doc comment cites `{token}`, absent from this crate", i)


def check_pub_type_consumers(root):
    """SC5 — public types with no consumer outside the file that defines them.

    C2 of CONNECTION-INTEGRITY-PROGRAM-2026-07.md at type granularity. That
    program's detector covers Regent tools; its own text records that nothing
    generalizes it. Justified by a real finding, 2026-07-27: MerkleProof,
    ProofStep and Direction in zp-receipt/src/epoch.rs are complete, tested
    and re-exported, and no path constructs or checks an inclusion proof --
    the capability the anchor tier's compact-commitment discipline wants,
    built and never called.

    Imports and re-exports are not consumers. Counting `pub use` as one is
    what hides exactly this case, since a type re-exported from lib.rs looks
    used from a naive grep.

    Informational by design: a public type with no internal consumer may be
    deliberate API surface. The number is the signal, and its movement more
    so than its level.
    """
    crates = root / "crates"
    if not crates.exists():
        return
    sources = [p for p in crates.rglob("*.rs") if "/target/" not in str(p)]
    decl = re.compile(r"^\s*pub\s+(?:struct|enum|trait)\s+([A-Z][A-Za-z0-9_]*)", re.M)

    def without_tests(text):
        cut = text.find("#[cfg(test)]")
        return text[:cut] if cut != -1 else text

    def without_imports(text):
        return "\n".join(l for l in text.splitlines()
                          if not re.match(r"\s*(pub\s+)?use\s", l))

    # Inverted index: token -> set of files mentioning it. Built in one pass,
    # because the naive form (regex per type per file) is ~10^6 searches and
    # made the suite unrunnable.
    token = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    declared_in, seen_in = {}, defaultdict(set)
    for path in sources:
        text = without_tests(path.read_text(errors="replace"))
        for name in decl.findall(text):
            declared_in.setdefault(name, path)
        for tok in set(token.findall(without_imports(text))):
            seen_in[tok].add(path)

    for name, path in sorted(declared_in.items()):
        if seen_in.get(name, set()) - {path}:
            continue
        finding("pub-consumer", path,
                f"pub type {name} has no non-test, non-import consumer")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any finding")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--only", help="comma-separated check names")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    global ROOT
    ROOT = root

    docs = load_docs(root)
    gov = governed(root)
    sections = keel_sections(root)
    registry = receipt_registry(root)

    # Every check is registered here, and registration is enforced below.
    #
    # This was a flat call list, and `check_stated_counts` sat in the file
    # for weeks without appearing in it — written in response to two real
    # defects (its docstring names both), complete, and never run. A check
    # that does not run is the C4 condition in
    # `docs/design/CONNECTION-INTEGRITY-PROGRAM-2026-07.md` §3, and it is
    # the class that reads as green: the suite passed, reported nine
    # checks, and the tenth was invisible.
    #
    # Same fix as REGENT_TOOLS in crates/zp-server/src/regent.rs — one
    # source of truth plus a structural assertion, so the omission cannot
    # recur by inattention.
    checks = {
        "tier_declaration": lambda: check_tier_declaration(gov),
        "keel_refs": lambda: check_keel_refs(gov, sections),
        "duplicate_headings": lambda: check_duplicate_headings(gov),
        "numbered_section_sequence": lambda: check_numbered_section_sequence(gov),
        "doc_crossrefs": lambda: check_doc_crossrefs(gov, root),
        "stated_counts": lambda: check_stated_counts(gov),
        "spec_citations": lambda: check_spec_citations(root),
        "receipt_vocabulary": lambda: check_receipt_vocabulary(gov, registry),
        "tieoff_reopen_conditions": lambda: check_tieoff_reopen_conditions(
            post_convention(root), root),
        "index_coverage": lambda: check_index_coverage(gov, root),
        "doc_paths": lambda: check_doc_paths(gov, root),
        "doc_comment_symbols": lambda: check_doc_comment_symbols(root),
        "pub_type_consumers": lambda: check_pub_type_consumers(root),
    }

    # Structural guard: a `check_*` defined in this module and absent from
    # the registry is a defect in the linter, not in the corpus, and fails
    # loudly rather than passing quietly.
    declared = {n[len("check_"):] for n in dir(sys.modules[__name__])
                if n.startswith("check_") and callable(getattr(sys.modules[__name__], n))}
    unregistered = declared - set(checks)
    if unregistered:
        print(f"corpus-lint: {len(unregistered)} check(s) defined but never run: "
              f"{', '.join(sorted(unregistered))}", file=sys.stderr)
        print("Every check_* must appear in the `checks` registry in main().",
              file=sys.stderr)
        raise SystemExit(2)

    for run in checks.values():
        run()

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
