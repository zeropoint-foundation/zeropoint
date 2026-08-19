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
# A governed doc naming an implementing path.
#
# Two-tier verification per 2026-07-27 handoff:
# - Structural: does the claimed path exist in the repo tree? If yes, the
#   doc's assertion "this file is an implementing site" is at least
#   structurally upheld — a file exists at the named location. We flip
#   these to `live` with the STRUCTURAL_ONLY_NOTE below.
# - Semantic: does the file's content actually implement what the doc says
#   it implements? That requires either a back-reference comment in the
#   code (already checked by `check_spec_citations` in the code→doc
#   direction), a per-doc assertion catalog, or full semantic analysis.
#   We do NOT attempt semantic verification here.
#
# Rationale for `live` rather than a new intermediate status: the
# structural check IS a real verification that either succeeds or fails.
# Consumers who need semantic verification can filter on the note. Keeping
# to the existing three-state model (live / tied_off / defect) avoids
# surface churn in the aggregate maturity number's meaning.
PATH_CLAIM_RE = re.compile(r'`(crates/[A-Za-z0-9\-_]+/(?:src/)?[A-Za-z0-9\-_/]*\.rs)`')

STRUCTURAL_ONLY_NOTE = (
    "structural verification only — path exists in repo tree; content "
    "not semantically checked against the doc's claim"
)


def collect_doc_code_claims(root, governed_docs):
    for doc in governed_docs:
        text = doc.read_text(errors="replace")
        for claimed in sorted(set(PATH_CLAIM_RE.findall(text))):
            exists = (root / claimed).exists()
            edge(
                "corpus_to_code",
                str(doc.relative_to(root)),
                claimed,
                "live" if exists else "defect",
                detector="connection-map check_doc_code_paths" if exists else None,
                note=STRUCTURAL_ONLY_NOTE
                if exists
                else "claimed implementing path does not exist",
                site=str(doc.relative_to(root)),
            )


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
RESERVED_RE = re.compile(r'RESERVED_RECEIPT_PREFIXES[^=]*=\s*&\[(.*?)\];', re.S)
RECEIPT_IN_DOC_RE = re.compile(r'`([a-z][a-z0-9_]*(?::[a-z0-9_*]+){1,3})`')

# Emission-site patterns for the reverse-direction check: what receipt
# names does the codebase actually emit? Restricted to identifiers with
# at least one colon so bare tokens like `capability` don't false-match.
# Three shapes cover 2026-08 emission conventions:
#   emit_receipt("regent:tool:completed", ...)  — the executor-side call
#   SystemEvent { event: "regent:intent:respond" }  — direct construction
#   format!("regent:tool:completed:{}", tool)  — dynamic-suffix pattern
# The format! variant captures the literal prefix before the {} so
# `regent:tool:completed:web_search` at runtime is recorded as the
# family `regent:tool:completed`.
EMIT_LITERAL_RE = re.compile(
    r'emit_receipt(?:_to_store)?\s*\(\s*(?:[^,]*,\s*)?"([a-z][a-z0-9_]*(?::[a-z0-9_*]+)+)"'
)
EMIT_SYSTEMEVENT_RE = re.compile(
    r'SystemEvent\s*\{\s*event\s*:\s*"([a-z][a-z0-9_]*(?::[a-z0-9_*]+)+)"'
)
EMIT_FORMAT_RE = re.compile(
    r'format!\s*\(\s*"([a-z][a-z0-9_]*(?::[a-z0-9_*]+)+)(?::\{|(?=[":,]))'
)


EMIT_CONTEXT_RE = re.compile(
    r'emit_receipt(?:_to_store)?\s*\(|\bemit\s*\(|SystemEvent\s*\{'
    r'|AuditAction::|append\s*\(')


def collect_emitted_receipts(root):
    """Scan crates/**/*.rs for receipt-emission sites.

    Returns a set of receipt names literally found in the source.
    Used to split corpus_to_chain defects into:
      - registry gap:  code emits it but KNOWN_RECEIPT_PREFIXES omits it.
                       Fix by adding to the registry.
      - aspirational:  doc mentions a receipt no code emits.
                       Fix by implementing OR reclassifying the doc.

    Not a complete emission audit — a receipt name synthesised entirely
    at runtime (e.g. constructed from a variable prefix) will be missed.
    Empirically covers the three patterns above, which handle
    ~all observed emit sites in 2026-08.
    """
    emitted = set()
    crates_dir = root / "crates"
    if not crates_dir.exists():
        return emitted
    for path in crates_dir.rglob("*.rs"):
        try:
            txt = path.read_text(errors="replace")
        except OSError:
            continue
        for pat in (EMIT_LITERAL_RE, EMIT_SYSTEMEVENT_RE):
            for m in pat.finditer(txt):
                emitted.add(m.group(1))
        # EMIT_FORMAT_RE matches any `format!("a:b:{}", ...)`, and that
        # shape also describes capability strings: zp-cli builds a role's
        # capability list with `format!("mail:read:{}", mb)`
        # (commands.rs:1405). Counting those made three illustrative
        # personal names in SAGE-WIZARD-SCRIPT read as "code emits this
        # receipt", which advertised a mechanical registry fix that did
        # not exist -- inspected and reported empty in
        # DYNAMICS-DISCIPLINE-2026-08 §"Corollary, same day". Adding them
        # would have registered a capability vocabulary as a receipt
        # vocabulary. Require an emit call in the preceding window, so the
        # forward direction agrees with collect_emitted_sites about what
        # an emission is.
        for m in EMIT_FORMAT_RE.finditer(txt):
            if EMIT_CONTEXT_RE.search(txt, max(0, m.start() - 160), m.start()):
                emitted.add(m.group(1))
    return emitted


def _is_test_path(rel):
    """True for paths whose emissions are fixtures rather than substrate."""
    s = str(rel)
    return ("/tests/" in s or s.startswith("tests/")
            or "-tests/" in s or "/benches/" in s)


def _test_module_lines(lines):
    """Line numbers (1-based) that fall inside a `#[cfg(test)] mod` block.

    Relies on this workspace's formatting: the attribute and `mod` sit at
    column zero and the block closes with a bare `}` at column zero. That
    holds throughout `crates/` and is far cheaper than parsing Rust.

    Worth stating the failure mode, because it decides the direction of
    error: an indented or unconventional test module is *not* detected, so
    its fixtures read as production emissions. That produces a noisy
    false positive, which someone fixes. The reverse — silently swallowing
    a real emission — is the failure this whole check exists to prevent.
    """
    inside = set()
    i = 0
    while i < len(lines):
        if lines[i].startswith("#[cfg(test)]"):
            j = i + 1
            while j < len(lines) and not lines[j].startswith("mod "):
                if lines[j].strip() and not lines[j].startswith("#["):
                    break
                j += 1
            if j < len(lines) and lines[j].startswith("mod "):
                k = j + 1
                while k < len(lines) and lines[k] != "}":
                    inside.add(k + 1)
                    k += 1
                i = k
        i += 1
    return inside


# Emission *contexts* for the reverse direction.
#
# `EMIT_FORMAT_RE` above matches any `format!` whose literal looks like a
# receipt name, wherever it appears. That is the right breadth for the
# doc-driven question ("does anything, anywhere, emit this documented
# receipt?"), and the wrong breadth for this one. Asking "is this emitted
# family declared?" of every colon-shaped string in the workspace produced
# a 40% false-positive rate on first run — `mail:read:{mailbox}` from a
# delegation capability list, `zp:issue:{id}` hashed to derive a
# conversation UUID. Neither is a receipt; both look exactly like one.
#
# A check people learn to skim is worse than no check, so this direction
# requires the literal to sit in a position that actually emits:
RECEIPT = r'([a-z][a-z0-9_]*(?::[a-z0-9_*]+)+)'
CTX_EVENT_BIND = re.compile(r'let\s+[a-z_]*event[a-z_]*\s*=\s*format!\s*\(\s*"' + RECEIPT)
CTX_EVENT_FIELD = re.compile(r'event\s*:\s*(?:format!\s*\(\s*)?"' + RECEIPT)
CTX_EMIT_CALL = re.compile(r'emit_(?:tool_)?receipt(?:_to_store)?\s*\(')
CTX_LITERAL_IN_CALL = re.compile(r'&?(?:format!\s*\(\s*)?"' + RECEIPT)
# Event-name constructor helpers: `fn foo(x: &str) -> String { format!("a:b:{}", x) }`.
# tool_chain.rs keeps a module of these, and their families reach the chain
# without any literal ever appearing at an emitter call site.
CTX_CONSTRUCTOR = re.compile(r'^\s*format!\s*\(\s*"' + RECEIPT)

EMIT_CALL_LOOKAHEAD = 4

# ── Why there is no registry → code direction here ──────────────────────
#
# `collect_undeclared_emissions` below answers "code emits this — is it
# declared?" The mirror question, "this is declared — can anything emit it?",
# would separate the two meanings of a silent family: *quiet* (an emitter
# exists, nothing triggered it) from *unreachable* (no code path produces it,
# so the declaration outlived its emitter or was aspirational).
#
# It was implemented on 2026-08-06 and removed the same day. Source scanning
# cannot answer it: of 72 declared families it reported 35 unreachable, and was
# wrong about nearly all of them. `cognitive:observer:verified` had fired 740
# times in the preceding window, `governance_request:` 2244.
#
# Two causes, neither incidental:
#
#   - **const-defined prefixes** — `EVENT_PREFIX_VERIFIED` and friends hold the
#     literal, and the emission site references the binding.
#   - **variable-segment prefixes** — `officer:{name}:heartbeat`,
#     `governance_request:{kind}`, `{domain}:canonicalized:{id}`. There is no
#     literal for a scan to find, by construction.
#
# Const resolution would recover roughly half and leave the rest. A check that
# is wrong a third of the time trains people to skim it.
#
# **The chain is the better oracle.** "Has this family ever appeared?" is a
# query against chain history, where const and variable prefixes are already
# resolved into the strings that actually landed. `substrate_validate`'s
# receipt inventory is where that belongs, and for any chain shorter than
# INVENTORY_WINDOW its `silent_prefixes` list already *is* the answer.
# Distinguishing "silent in window" from "never in chain history" only becomes
# a separate question once the chain outgrows the window.


def collect_emitted_sites(root):
    """Emission sites as (receipt, relpath, lineno), excluding test fixtures.

    The reverse-direction companion to `collect_emitted_receipts`, which
    returns a bare set for answering "does anything emit this documented
    receipt?" This one keeps provenance and drops fixtures, because the
    question it serves is the opposite: "code emits this — is it declared?"
    and the answer has to be actionable at a file and line.

    Known miss: a family whose name is assembled from a variable prefix —
    `format!("{}:canonicalized:{}", domain, id)` — has no literal to match,
    so its per-domain variants stay invisible here. `system:canonicalized:`
    is declared and `provider:` / `node:` were not, which is exactly that
    shape. Variable-prefix emitters need declaring by hand.
    """
    sites = []
    crates_dir = root / "crates"
    if not crates_dir.exists():
        return sites
    for path in sorted(crates_dir.rglob("*.rs")):
        rel = path.relative_to(root)
        if _is_test_path(rel):
            continue
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        skip = _test_module_lines(lines)
        for n, line in enumerate(lines, 1):
            if n in skip or line.lstrip().startswith("//"):
                continue
            hits = set()
            for pat in (EMIT_LITERAL_RE, EMIT_SYSTEMEVENT_RE,
                        CTX_EVENT_BIND, CTX_EVENT_FIELD):
                for m in pat.finditer(line):
                    hits.add(m.group(1))
            # A lone `format!` counts only as the body of a `-> String`
            # helper. Without that guard it also matches list elements —
            # `vec![format!("mail:read:{}", mb), …]` is a delegation
            # capability list, not three receipt families.
            if CTX_CONSTRUCTOR.match(line):
                back = "\n".join(lines[max(0, n - 3):n - 1])
                if "-> String" in back:
                    for m in CTX_CONSTRUCTOR.finditer(line):
                        hits.add(m.group(1))
            # `emit_tool_receipt(&store, &format!("policy:wasm:loaded:{}", h))`
            # routinely wraps, so the literal is a line or three below the call.
            if CTX_EMIT_CALL.search(line):
                for look in lines[n:n + EMIT_CALL_LOOKAHEAD]:
                    if look.lstrip().startswith("//"):
                        continue
                    for m in CTX_LITERAL_IN_CALL.finditer(look):
                        hits.add(m.group(1))
            for h in hits:
                sites.append((h, str(rel), n))
    return sites


def collect_undeclared_emissions(root):
    """Code → registry: every emitted family must be a declared family.

    # Why this direction exists

    `collect_receipts` walks *documented* receipts and asks whether code
    emits them. That covers three of the four quadrants:

        documented + declared              → live
        documented, not declared, emitted  → registry gap
        documented, not declared, no code  → aspirational

    The fourth — **emitted, undeclared, undocumented** — falls through
    every branch, because nothing in the corpus names it and so no
    iteration ever reaches it. It is invisible until the family first
    fires at runtime, at which point `substrate_validate` reports an
    unrecognized prefix and degrades posture for a receipt that was
    perfectly legitimate.

    Found 2026-08-06: a manual sweep of all 88 emission sites turned up
    ten production families in this quadrant — `artifact:signed`,
    `channel:slack:inbound:`, `cognition:model:routed:`, `emit:`,
    `foundation_relay:`, `model:registered`, `model:capability:updated`,
    `pricing:refresh:`, `request_blocked:`, `receipt_forwarded:`. All had
    been emittable for as long as their subsystems had existed. None had
    fired inside an inventory window, so nothing had ever flagged them.
    The registry comment at substrate_validate.rs pointed here for exactly
    this check, and this direction had never been implemented.
    """
    reg_file = root / "crates/zp-server/src/substrate_validate.rs"
    if not reg_file.exists():
        drop("registry missing", str(reg_file))
        return
    text = reg_file.read_text(errors="replace")
    reg_body = REGISTRY_RE.search(text)
    if not reg_body:
        drop("registry unparsed", "KNOWN_RECEIPT_PREFIXES not matched")
        return
    registry = _parse_prefix_list(reg_body.group(1))
    reserved_body = RESERVED_RE.search(text)
    reserved = _parse_prefix_list(reserved_body.group(1)) if reserved_body else set()
    declared = registry | reserved

    seen = {}
    for receipt, rel, line in collect_emitted_sites(root):
        seen.setdefault(receipt, f"{rel}:{line}")

    for receipt, site in sorted(seen.items()):
        covered = any(receipt.startswith(p) or p.startswith(receipt)
                      for p in declared)
        edge("chain_to_registry", site, receipt,
             "live" if covered else "defect",
             detector="connection-map collect_undeclared_emissions",
             note=None if covered else
                  ("undeclared emission: code emits this receipt family but "
                   "neither KNOWN_RECEIPT_PREFIXES nor "
                   "RESERVED_RECEIPT_PREFIXES declares it — the receipt-type "
                   "inventory will report it as an unrecognized prefix the "
                   "first time it fires. Fix by adding to the registry in "
                   "crates/zp-server/src/substrate_validate.rs"),
             site=site)


def _has_emitter(receipt, emitted):
    """Does any emit-site name match this documented receipt?

    A match either way:
      - emit `regent:tool:completed:foo` matches doc `regent:tool:completed:*`
      - emit `regent:tool:completed` matches doc `regent:tool:*`
      - emit `regent:tool:completed:foo` matches doc `regent:tool:completed:foo`
    Wildcards are stripped from either side before comparison.
    """
    r_norm = receipt.rstrip(':*')
    for name in emitted:
        n_norm = name.rstrip(':*')
        if r_norm == n_norm:
            return True
        if name.startswith(r_norm + ':'):
            return True
        if receipt.startswith(n_norm + ':'):
            return True
    return False


def collect_receipts(root, governed_docs, emitted):
    reg_file = root / "crates/zp-server/src/substrate_validate.rs"
    if not reg_file.exists():
        drop("registry missing", str(reg_file))
        return
    # Per-line parse: the array body contains `//` comments with quoted
    # words in them, and a blanket findall reads those as declared
    # prefixes. Found 2026-07-26 when `reopen_watch — the two tiers`
    # showed up in the declared set.
    reg_body = REGISTRY_RE.search(reg_file.read_text(errors="replace"))
    if not reg_body:
        drop("registry unparsed", "KNOWN_RECEIPT_PREFIXES not matched")
        return
    registry = _parse_prefix_list(reg_body.group(1))

    # Reserved vocabulary — receipt families declared in canon (KEEL /
    # Tier-2) but not yet emitted. Presence in this list is a formal
    # governance acknowledgement of outstanding implementation work, so
    # matched receipts read as `tied_off` rather than `defect`. Missing
    # RESERVED_RECEIPT_PREFIXES is not fatal — an older tree without
    # the const simply has no reservations, and every unregistered
    # receipt is still classified as gap or aspirational.
    reserved_body = RESERVED_RE.search(reg_file.read_text(errors="replace"))
    reserved = _parse_prefix_list(reserved_body.group(1)) if reserved_body else set()

    documented = {}
    for doc in governed_docs:
        for r in set(RECEIPT_IN_DOC_RE.findall(doc.read_text(errors="replace"))):
            documented.setdefault(r, str(doc.relative_to(root)))

    for receipt, site in sorted(documented.items()):
        implemented = any(receipt.startswith(p) or p.startswith(receipt)
                          for p in registry)
        if implemented:
            edge("corpus_to_chain", site, receipt,
                 "live",
                 detector="corpus-lint check_receipt_vocabulary",
                 note=None,
                 site=site)
            continue
        # Not in KNOWN_RECEIPT_PREFIXES. Check reservation next — a
        # reserved family is a declared deferral, not an unresolved gap.
        is_reserved = any(receipt.startswith(p) or p.startswith(receipt)
                          for p in reserved)
        if is_reserved:
            edge("corpus_to_chain", site, receipt,
                 "tied_off",
                 detector="connection-map RESERVED_RECEIPT_PREFIXES",
                 note=("reserved: vocabulary declared by canonical corpus; "
                       "substrate emission deferred — see "
                       "RESERVED_RECEIPT_PREFIXES in "
                       "crates/zp-server/src/substrate_validate.rs"),
                 site=site)
            continue
        # Registry doesn't cover it and it isn't reserved. Split by
        # whether code emits it anyway.
        if _has_emitter(receipt, emitted):
            # Registry gap — fixable by adding to KNOWN_RECEIPT_PREFIXES.
            edge("corpus_to_chain", site, receipt,
                 "defect",
                 detector="connection-map collect_emitted_receipts",
                 note=("registry gap: code emits this receipt but "
                       "KNOWN_RECEIPT_PREFIXES does not declare it — "
                       "fix by adding to the registry"),
                 site=site)
        else:
            # Aspirational — no emitter found anywhere in crates/.
            edge("corpus_to_chain", site, receipt,
                 "defect",
                 detector=None,
                 note=("aspirational: no code emitter found for this "
                       "receipt name — fix by implementing the emitter, "
                       "reserving via RESERVED_RECEIPT_PREFIXES, or "
                       "rewording the doc mention"),
                 site=site)


def _parse_prefix_list(body_text):
    """Extract quoted string entries from a Rust &[&str] literal body.

    Ignores `//` comment lines. Handles trailing comma on each entry.
    Tolerates trailing inline `// comment` on the entry line itself —
    strips it before matching so `"foo:",  // some note` still yields
    `foo:`. The Rust file's own convention prefers comments on their
    own lines, but a stray inline comment silently dropping an entry
    is worse than the parser tolerating both.
    """
    out = set()
    for raw in body_text.split("\n"):
        stripped = raw.strip()
        if stripped.startswith("//"):
            continue
        # Strip any trailing inline comment. The `//` must live outside
        # the quoted string — split on the first `//` after the string
        # closes. Simplest tolerant form: if we see `// ` after the
        # last `"` on the line, drop from there.
        last_quote = stripped.rfind('"')
        if last_quote >= 0:
            comment_at = stripped.find("//", last_quote)
            if comment_at >= 0:
                stripped = stripped[:comment_at].rstrip()
        entry = re.fullmatch(r'"([^"]+)"\s*,?', stripped)
        if entry:
            out.add(entry.group(1))
    return out


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
            # An artifact that records wall-clock time and no source
            # commit cannot have its freshness checked against repo state
            # at all -- the git-log proxy below answers a different
            # question ("has anything landed since you last committed
            # this file"), and answers it misleadingly: a manifest
            # regenerated thirty seconds ago still reports 165 commits of
            # drift because the regenerator never stamps what it read.
            # This branch was written for exactly that case and sat below
            # an unconditional `continue`, so it had never executed.
            if stamp and not declared:
                edge("derived_artifact", rel, f"{stamp}={data[stamp]}", "defect",
                     detector="connection-map derived_artifact",
                     note=("records wall-clock time, not a source commit -- "
                           "freshness cannot be checked against repo state. "
                           "Fix in the regenerator: stamp the commit it read."),
                     site=rel)
                continue

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


# ── declared tie-offs ───────────────────────────────────────────────────
# A tie-off moves an edge from `defect` to `tied_off`. Read from
# tools/connection-map/tieoffs.toml rather than hardcoded here: an
# allowlist in the tool is exactly the shape this program exists to
# catch, because it records the suppression without the reason.
TIEOFF_RULES = []


def load_tieoffs(root):
    """Parse tieoffs.toml without a TOML dependency.

    Deliberately minimal: [[tieoff]] blocks with key = "value" and
    key = \"\"\"triple quoted\"\"\" values. Stdlib tomllib exists on 3.11+
    but this tool targets whatever python3 is present, and the format is
    small enough that hand-parsing beats adding a version floor.
    """
    f = root / "tools/connection-map/tieoffs.toml"
    if not f.exists():
        return []
    text = f.read_text(errors="replace")
    rules, cur = [], None
    i, lines = 0, text.split("\n")
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped == "[[tieoff]]":
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

    # Stage 1t: deferred and open must declare a way back. A tie-off that
    # cannot be revisited is a permanent absence wearing a temporary label.
    for r in rules:
        d = r.get("disposition", "")
        if d in ("deferred", "open"):
            missing = [k for k in ("reopen_condition", "reopen_watch") if not r.get(k)]
            if missing:
                drop(f"tie-off '{r.get('source','?')}' is {d} without "
                     f"{' and '.join(missing)} — not applied",
                     "IMPROVEMENT-LOOP-DISCIPLINE Stage 1t")
                r["_invalid"] = True
        elif d not in ("declined", "limited"):
            drop(f"tie-off '{r.get('source','?')}' has unknown disposition "
                 f"'{d}' — not applied", "expected declined|deferred|open|limited")
            r["_invalid"] = True
    return [r for r in rules if not r.get("_invalid")]


def apply_tieoffs():
    """Reclassify defects that carry a declared tie-off."""
    applied = set()
    for e in EDGES:
        if e["status"] != "defect":
            continue
        for n, r in enumerate(TIEOFF_RULES):
            if r.get("kind") and r["kind"] != e["kind"]:
                continue
            if r.get("source") and r["source"] != e["source"]:
                continue
            if r.get("target") and r["target"] != e["target"]:
                continue
            e["status"] = "tied_off"
            e["note"] = f"[{r.get('disposition')}] {e['note']}"
            e["tieoff"] = r.get("rationale", "").split("\n")[0][:120]
            applied.add(n)
            break
    # A tie-off matching nothing is suppressing nothing, and will go on
    # looking like coverage. Same class as a check that does not run.
    for n, r in enumerate(TIEOFF_RULES):
        if n not in applied:
            drop("tie-off matches no edge (stale?)",
                 f"{r.get('kind','?')} / {r.get('source','?')}")


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

    emitted = collect_emitted_receipts(root)

    collect_crate_deps(root)
    collect_spec_citations(root)
    collect_doc_code_claims(root, gov)
    collect_keel_refs(root, gov)
    collect_receipts(root, gov, emitted)
    collect_undeclared_emissions(root)
    collect_artifact_reads(root)
    collect_pin_tieoffs(root)
    collect_derived_artifacts(root)

    global TIEOFF_RULES
    TIEOFF_RULES = load_tieoffs(root)
    apply_tieoffs()

    by_status = Counter(e["status"] for e in EDGES)
    by_kind = Counter((e["kind"], e["status"]) for e in EDGES)
    total = len(EDGES)
    classified = by_status["live"] + by_status["tied_off"]

    tieoff_provenance = {"declared_tieoff": 0, "pin_exception": 0,
                         "reserved_prefix": 0, "other": 0}
    for e in EDGES:
        if e.get("status") != "tied_off":
            continue
        if e.get("detector") == "connection-map RESERVED_RECEIPT_PREFIXES":
            tieoff_provenance["reserved_prefix"] += 1
        elif e.get("kind") == "pin_exception":
            tieoff_provenance["pin_exception"] += 1
        elif (e.get("note") or "").startswith("["):
            # tieoffs.toml stamps its disposition as a leading [tag].
            tieoff_provenance["declared_tieoff"] += 1
        else:
            tieoff_provenance["other"] += 1

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
            # Reported beside maturity, always. Maturity counts a tie-off
            # -- an honest acknowledgement that something is known-unbuilt
            # -- as classified, so it rises when the corpus writes down
            # what it has not built. Between 2026-07-26 and 2026-08-18
            # tie-offs grew 10.6x and live connections 2.05x, and roughly
            # 30 of the 44.8 headline points were tie-off growth. One
            # number is a coverage claim and the other is a documentation
            # claim; printing only the first is what made them
            # indistinguishable.
            "live_only": round(by_status["live"] / total, 4) if total else 0.0,
            "tied_off_share": round(by_status["tied_off"] / total, 4) if total else 0.0,
        },
        # Where the tie-offs come from, because they are not one mechanism.
        # tieoffs.toml's own header states the distinction it is built on:
        # "This file is NOT an allowlist. An allowlist says 'ignore this.' A
        # tie-off says 'this absence is deliberate, here is why, and here is
        # what would reopen it.'" Only entries in that file carry a
        # disposition, a declared date and (for deferred/open) a reopen
        # condition. Reserved receipt prefixes carry a source comment, which
        # is prose a reader can find and a tool cannot check. Pin exceptions
        # carry a reason at the site. All three suppress a defect and all
        # three count identically toward maturity; printing the split is what
        # keeps "433 tied off" from reading as 433 deliberations.
        "tieoff_provenance": tieoff_provenance,
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
          f"{(classified / total * 100 if total else 0):.1f}%"
          f"   (live+tied)")
    print(f"  live only {by_status['live']}/{total} = "
          f"{(by_status['live'] / total * 100 if total else 0):.1f}%"
          f"   <- coverage; the line above includes "
          f"{by_status['tied_off']} tie-offs")
    tp = tieoff_provenance
    print(f"\n  tie-offs by provenance — only the first carries a disposition,")
    print(f"  a declared date and a reopen condition:")
    print(f"    tieoffs.toml (full Stage-1t discipline)   {tp['declared_tieoff']:>5}")
    print(f"    pin exception (reason at the site)        {tp['pin_exception']:>5}")
    print(f"    reserved prefix (reason in a comment)     {tp['reserved_prefix']:>5}")
    if tp["other"]:
        print(f"    unclassified                              {tp['other']:>5}")
    print()
    for (k, s), n in sorted(by_kind.items()):
        print(f"  {k:<20} {s:<9} {n:>5}")

    # Split corpus_to_chain defects by fixability class so an operator
    # scanning the summary sees which slice is registry-hygiene work
    # (mechanical) vs which is aspirational-substrate work (per-doc
    # governance). Both are still `defect` in the aggregate — this is
    # extra visibility on top, not a status-model change.
    chain_defects = [e for e in EDGES
                     if e["kind"] == "corpus_to_chain" and e["status"] == "defect"]
    if chain_defects:
        registry_gap = sum(1 for e in chain_defects
                           if (e.get("note") or "").startswith("registry gap"))
        aspirational = sum(1 for e in chain_defects
                           if (e.get("note") or "").startswith("aspirational"))
        print("\n  corpus_to_chain defect breakdown:")
        print(f"    registry gap (code emits, registry omits) — mechanical fix: {registry_gap:>5}")
        print(f"    aspirational (no emitter found) — governance decision:      {aspirational:>5}")

    # Reserved receipt families — corpus commitments explicitly deferred
    # via RESERVED_RECEIPT_PREFIXES. Shown separately so the operator
    # sees how many defects were converted from unresolved to
    # governance-acknowledged. Not double-counted in tied_off totals
    # above — the aggregate already includes these; this is just a
    # readable slice.
    chain_reserved = [e for e in EDGES
                      if e["kind"] == "corpus_to_chain"
                      and e["status"] == "tied_off"
                      and (e.get("note") or "").startswith("reserved:")]
    if chain_reserved:
        print(f"\n  corpus_to_chain tied_off (reserved vocabulary):            {len(chain_reserved):>5}")

    if DROPPED:
        print("\n  dropped (not silently):")
        for d in DROPPED:
            print(f"    {d['reason']}: {d['detail']}")


if __name__ == "__main__":
    main()
