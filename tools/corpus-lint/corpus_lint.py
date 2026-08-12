#!/usr/bin/env python3
"""corpus-lint — mechanical coherence checks over docs/ and crates/.

Instrumentation for the E1 and E2 edges of SUBSTRATE-LOOP-CLOSURE-2026-07.md.
Every check here is justified by a real defect found on 2026-07-25; none is
speculative. Reports by default, fails the build with --strict.

Spec: docs/design/SUBSTRATE-LOOP-CLOSURE-2026-07.md
"""
import re, sys, json, argparse, subprocess
from pathlib import Path
from collections import defaultdict

FINDINGS = []
ROOT = None

# Checks that measure rather than judge. They report and are never a build failure:
# the pre-convention stratum and the specified-not-shipped receipt surface are
# properties of a corpus mid-construction, not defects in it.
INFORMATIONAL = {"index-coverage", "receipt-coverage", "stated-count",
                 "doc-path-prospective", "doc-path-as-proposed", "pub-consumer",
                 "line-citation", "reservation-applied"}

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

def git_add_dates(root):
    """When each doc entered the tree, from git rather than from its own text.

    `check_index_coverage` partitions unlisted documents by a `**Date:**`
    field. On 2026-08-11 that field was present in 14 of 114 unlisted
    documents. The other 100 fell into the pre-convention bucket by default,
    and 15 of those had entered the tree *after* the convention was
    established -- including both W5 session briefs written two days earlier,
    which use `**Written:**`.

    So the check that exists to catch unindexed documents was silently
    exempting the newest ones, because it depended on an author remembering a
    field name. That is the hand-maintained-registry failure this whole tool
    exists to answer, reproduced one level up inside the tool.

    Git already knows. A file's first commit cannot be forgotten, misspelled,
    or written in a different vocabulary.
    """
    try:
        out = subprocess.run(
            ["git", "log", "--diff-filter=A", "--reverse", "--date=short",
             "--format=COMMIT:%ad", "--name-only", "--", "docs"],
            cwd=root, capture_output=True, text=True, timeout=60).stdout
    except subprocess.SubprocessError:
        # A git failure is a real answer -- no history -- and is reported as
        # such by the caller. A NameError or TypeError here is a bug in this
        # file and must not be laundered into "no dates found", which reads
        # as green.
        return {}
    dates, cur = {}, None
    for line in out.splitlines():
        if line.startswith("COMMIT:"):
            cur = line[len("COMMIT:"):].strip()
        elif line.strip() and cur:
            dates.setdefault(line.strip(), cur)
    return dates


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
    # Declared date first, git's add-date as the fallback. A document that
    # declares nothing is not thereby exempt -- see git_add_dates. Only a
    # document that both declares no date and predates the convention in git
    # is genuinely pre-convention stratum.
    added = git_add_dates(root)
    post_convention, pre_convention = [], []
    for p in unlisted:
        m = re.search(r"^\*\*Date:\*\*\s*(\d{4}-\d{2}-\d{2})",
                      p.read_text(errors="replace"), re.M)
        declared = m.group(1) if m else None
        # Untracked means authored now, which is after any past establishment
        # date -- absence of a git record is not absence of authorship.
        effective = declared or added.get(str(p.relative_to(root)), "9999-99-99")
        (post_convention if effective >= INDEX_ESTABLISHED
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

def check_line_citations(docs, root):
    """SC14 — `file.rs:NNN` citations, which drift on every edit above them.

    Justified by three real defects, 2026-08-12. HARNESS-SEAM-2026-08.md §6.1.1
    cited `zp-server/src/regent.rs:2481` for a struct that had moved to 2479,
    and `inference.rs:381` and `:611` for two constructs that had moved to 424
    and 654. All three were written on 2026-08-10 and were wrong on 2026-08-12.
    `check_doc_paths` did not see them: its pattern requires a slash and a
    closing backtick, and matches the path without the line suffix.

    A stale line number is cheap to work around individually -- the reader
    greps -- and expensive in aggregate, because the first one a reader finds
    costs them their trust in the surrounding paragraph, which is usually the
    part that was still true.

    Two dispositions, deliberately unequal:

      defect       the file resolves and has fewer lines than the citation.
                   Unambiguous: that line does not exist.
      measurement  every other surviving citation. The tool cannot know
                   whether line 707 still holds what the author meant, so it
                   reports the citation and what that line holds now, and
                   leaves the judgement where it belongs.

    The measurement is the point. Locations are the one class of claim in this
    corpus that cannot be kept true by care, so the convention adopted in
    §6.1.1 on 2026-08-12 is to name constructs instead and let `grep` locate
    them. This counts what has not converted yet.
    """
    EXT = r"(?:rs|py|toml|md|sh|json|jsonl|sql|yml|yaml)"
    pat = re.compile(rf"([A-Za-z0-9_][A-Za-z0-9_./-]*\.{EXT}):(\d+)\b")

    # Bare filenames ("inference.rs:391") need a name -> path index. Ask git
    # for it rather than walking: `rglob` over crates/ and tools/ visits
    # 122k entries and costs ~11s on a network filesystem, and it has to
    # filter out build output afterwards. git ls-files answers in one call
    # and excludes untracked detritus by construction -- a file git does not
    # track is not a file the corpus should be citing.
    by_name = {}
    try:
        tracked = subprocess.run(["git", "ls-files", "crates", "tools"],
                                 cwd=root, capture_output=True, text=True,
                                 timeout=30).stdout.splitlines()
    except subprocess.SubprocessError:
        tracked = []
    for rel in tracked:
        by_name.setdefault(rel.rsplit("/", 1)[-1], []).append(root / rel)

    cache = {}
    def lines_of(path):
        if path not in cache:
            cache[path] = path.read_text(errors="replace").splitlines()
        return cache[path]

    def resolve(ref):
        for cand in (root / ref, root / "crates" / ref, root / "tools" / ref):
            if cand.is_file():
                return cand
        if "/" not in ref:                      # bare filename — only if unique
            hits = by_name.get(ref, [])
            if len(hits) == 1:
                return hits[0]
        return None

    for doc in docs:
        try:
            text = doc.read_text(errors="replace")
        except Exception:
            continue
        seen = set()
        for m in pat.finditer(text):
            ref, num = m.group(1), int(m.group(2))
            if (ref, num) in seen:
                continue
            seen.add((ref, num))
            rel = str(doc.relative_to(root))
            target = resolve(ref)
            if target is None:
                finding("line-citation", rel,
                        f"cites {ref}:{num}; path does not resolve uniquely — "
                        f"the line cannot be checked")
                continue
            lines = lines_of(target)
            if num > len(lines):
                finding("line-citation-range", rel,
                        f"cites {ref}:{num}, but that file has {len(lines)} "
                        f"lines — the cited line does not exist")
            else:
                finding("line-citation", rel,
                        f"cites {ref}:{num}, which now reads: "
                        f"{lines[num - 1].strip()[:80]!r}")


def apply_reservations(root):
    """Reclassify findings that carry a declared reservation.

    Stage 1t's vocabulary at artifact granularity. IMPROVEMENT-LOOP-DISCIPLINE
    applies `declined / deferred / open / limited` to improvement arcs, and
    `tools/connection-map/tieoffs.toml` applies it to declared dependency
    edges. Neither reaches an individual receipt type, prospective path or
    unconsumed public type — which is why those three surfaces report raw
    counts today with no dispositions at all: 752 receipt types, 46 paths,
    360 types, none of them saying whether anyone decided.

    A reservation is not an allowlist entry. It names what it suppresses,
    carries a rationale, and — when it claims the thing will be revisited —
    states what would reopen it and what does the watching. All three are
    enforced here, because a reservation nobody can audit is the coverage
    story this tool exists to remove.

    Two failures are defects rather than measurements:

      reservation-incomplete  `deferred` or `open` with no way back. Stage 1t:
                              a revisit claim with no trigger is a permanent
                              absence wearing a temporary label.
      reservation-stale       matches no finding. It suppresses nothing and
                              goes on looking like coverage — the same class
                              as a check that never runs.

    Suppression counts are reported per reservation. A broad reservation is
    legible as broad; nothing is capped silently.
    """
    f = root / "tools/corpus-lint/reservations.toml"
    if not f.exists():
        return

    # Hand-parsed, for the reason tools/connection-map/connection_map.py gives
    # for the same choice: stdlib tomllib needs 3.11+, this tool targets
    # whatever python3 is present, and the format is small enough that
    # hand-parsing beats adding a version floor. The two parsers are
    # duplicated because there is no shared lib between the tools; that is a
    # real cost and is noted rather than hidden.
    rules, cur = [], None
    lines = f.read_text(errors="replace").split("\n")
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped == "[[reservation]]":
            if cur:
                rules.append(cur)
            cur = {}
        elif cur is not None and "=" in stripped and not stripped.startswith("#"):
            key, _, val = stripped.partition("=")
            key, val = key.strip(), val.strip()
            if val.startswith('"""'):
                body = [val[3:]]
                i += 1
                while i < len(lines) and '"""' not in lines[i]:
                    body.append(lines[i])
                    i += 1
                if i < len(lines):
                    body.append(lines[i].split('"""')[0])
                cur[key] = "\n".join(body).strip().replace("\\\n", "")
            else:
                cur[key] = val.strip('"')
        i += 1
    if cur:
        rules.append(cur)

    # An unknown disposition is not applied. Silently honouring it would let a
    # typo suppress findings under a word the vocabulary does not define.
    valid = {"declined", "deferred", "open", "limited"}
    for r in list(rules):
        d = (r.get("disposition") or "").lower()
        if d not in valid:
            finding("reservation-invalid", str(f.relative_to(root)),
                    f"{r.get('kind','?')} / {r.get('subject','?')} has unknown "
                    f"disposition '{d}' — not applied; expected one of "
                    f"{'|'.join(sorted(valid))}")
            rules.remove(r)

    counts = [0] * len(rules)
    for item in FINDINGS:
        if item["kind"] == "reserved":
            continue
        for n, r in enumerate(rules):
            if r.get("check") and r["check"] != item["check"]:
                continue
            subj = r.get("subject", "")
            if subj and subj not in item["msg"] and subj not in str(item["path"]):
                continue
            item["kind"] = "reserved"
            item["reservation"] = f"[{r.get('disposition')}] {r.get('rationale','').strip().splitlines()[0][:110]}"
            counts[n] += 1
            break

    for n, r in enumerate(rules):
        who = f"{r.get('kind','?')} / {r.get('subject','?')}"
        disp = (r.get("disposition") or "").lower()
        if disp in ("deferred", "open"):
            missing = [k for k in ("reopen_condition", "reopen_watch") if not r.get(k)]
            if missing:
                finding("reservation-incomplete", str(f.relative_to(root)),
                        f"{who} is *{disp}* and is missing {' and '.join(missing)} — "
                        f"a revisit claim with no stated trigger, or no way of "
                        f"noticing the trigger, is a permanent absence wearing a "
                        f"temporary label (IMPROVEMENT-LOOP-DISCIPLINE Stage 1t)")
        if counts[n] == 0:
            finding("reservation-stale", str(f.relative_to(root)),
                    f"{who} matches no finding — it suppresses nothing and will "
                    f"go on looking like coverage")
        else:
            finding("reservation-applied", str(f.relative_to(root)),
                    f"{who} [{disp}] reserves {counts[n]} finding(s)")


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
        "line_citations": lambda: check_line_citations(gov, root),
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

    # Last, so it sees every finding every check produced.
    apply_reservations(root)

    out = FINDINGS
    if args.only:
        keep = set(args.only.split(","))
        out = [f for f in out if f["check"] in keep]

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        defects = [f for f in out if f["kind"] == "defect"]
        measures = [f for f in out if f["kind"] == "measurement"]
        reserved = [f for f in out if f["kind"] == "reserved"]

        # Reserved findings print in their own section, never inline among the
        # defects. The first version of this printer grouped purely by check,
        # so a reserved finding still appeared under `doc-path` looking exactly
        # like a defect while the header counted it as neither: the list said
        # eight and the number said seven, with nothing to reconcile them.
        # That is the failure METACOGNITIVE-FIDELITY-HARNESS §1 names — a report
        # surface must declare the arithmetic over its own fields — reproduced
        # in the output of the tool built to remove it.
        by = defaultdict(list)
        for f in out:
            if f["kind"] != "reserved":
                by[f["check"]].append(f)

        print(f"corpus-lint — {len(docs)} documents ({len(gov)} governed)")
        print(f"  {len(defects)} defect(s), {len(measures)} measurement(s), "
              f"{len(reserved)} reserved")
        if len(defects) + len(measures) + len(reserved) != len(out):
            print(f"  !! reconciliation failed: {len(defects)}+{len(measures)}+"
                  f"{len(reserved)} != {len(out)} — a finding carries an "
                  f"unknown kind and is being reported in no category")
        print()

        for check in sorted(by):
            print(f"── {check} ({len(by[check])})")
            for f in by[check][:40]:
                loc = f"{f['path']}:{f['line']}" if f["line"] else f["path"]
                print(f"   {loc}\n     {f['msg']}")
            if len(by[check]) > 40:
                print(f"   … {len(by[check]) - 40} more")
            print()

        if reserved:
            print(f"── reserved ({len(reserved)}) — declared, not suppressed")
            for f in reserved:
                loc = f"{f['path']}:{f['line']}" if f["line"] else f["path"]
                print(f"   [{f['check']}] {loc}")
                print(f"     {f['msg']}")
                print(f"     {f.get('reservation', '(no rationale recorded)')}")
            print()
    sys.exit(1 if (args.strict and any(f["kind"] == "defect" for f in out)) else 0)

if __name__ == "__main__":
    main()
