#!/usr/bin/env python3
"""
false_assurance.py — find code that reads what nothing writes.

Companion to `kind_catalog.py`, which counts *surfaces*. This one counts
*directions*, and only the dangerous one.

The asymmetry matters and is the whole reason this is a separate question:

  producer with no consumer  — usually FINE. A receipt chain is deliberately
      write-mostly; the reader may be a future auditor or a peer node. A rule
      demanding a live consumer per emitted kind would push toward emitting only
      what is currently consumed, which destroys an audit trail. (In *code*,
      rather than on the chain, an unread primitive is still dead weight — see
      `AuditStore::live_entry_count`, correct and documented with zero callers
      until 2026-08-08.)

  consumer with no producer  — ALWAYS a defect, and the dangerous direction,
      because it does not present as missing. It presents as a safety net.
      `reconstitute.rs` reads the receipt extension `zp.policy.version` and
      raises `PolicyDowngradeDetected`; nothing writes that key, so the alarm
      cannot fire. `recovery.rs` reads `zp.tool.completed_invocation_id` to
      close a pending tool invocation; no writer exists, so pending tools never
      close. These are not gaps in coverage — they are assurances the code
      offers a reader that it cannot honour.

Two detectable populations:

  1. Receipt `extensions` keys — the reverse-domain `zp.*` convention.
  2. `ClaimMetadata` variants — matched by validation logic, never constructed.

Both are grep-based and approximate. Read/write classification uses a small
window around each hit because the calls span lines; the heuristic is stated
inline and every ambiguous case is reported rather than silently bucketed.

Usage:  python3 tools/false_assurance.py
"""

import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kind_catalog import REPO, TYPES, enum_variants, production, rg  # noqa: E402

import subprocess  # noqa: E402

WINDOW = 2  # lines either side, since a builder call rarely fits on one line


def rgx(pattern: str):
    """ripgrep in regex mode. `kind_catalog.rg` is fixed-string only."""
    r = subprocess.run(
        ["rg", "-n", "--no-heading", "-g", "*.rs", "--", pattern, "crates"],
        cwd=REPO, capture_output=True, text=True, timeout=180)
    out = []
    for line in r.stdout.splitlines():
        p = line.split(":", 2)
        if len(p) == 3 and p[1].isdigit():
            out.append((p[0], int(p[1]), p[2]))
    return out


_lines = {}


def context(path: str, lineno: int) -> str:
    if path not in _lines:
        try:
            _lines[path] = (REPO / path).read_text(errors="replace").splitlines()
        except OSError:
            _lines[path] = []
    ls = _lines[path]
    lo, hi = max(0, lineno - 1 - WINDOW), min(len(ls), lineno + WINDOW)
    return "\n".join(ls[lo:hi])


READ = re.compile(r"\.get\(|contains_key\(|get_mut\(")
# WRITE must mean "writes this key onto a receipt", not "inserts into any map".
# A bare `\.insert\(` also matched `self.state.valid_operator_keys.insert(...)`
# in the *consumer*, so a read on one line and a state insert two lines below
# registered as separate read and write sites and the key was reported paired.
# That made three memory keys with no producer at all look wired, and the
# cross-check then recommended deleting them from the orphan list.
WRITE = re.compile(r"\.extension\(|with_extension\(|extensions\s*\.\s*insert\(|ext\s*\.\s*insert\(")


def extension_keys():
    """Classify every `zp.*` extension key as read / written / unclassified.

    Resolves constants as well as literals, and that is not a refinement — it is
    required for correctness. On 2026-08-09 the keys were centralised into
    `zp_core::receipt_extensions`, so consumers now write `ext::CAPABILITY_SCOPE`
    rather than `"zp.capability.scope"`. A literal-only search went instantly
    blind: it reported 0 reads, 0 writes, 0 paired, and 49 unclassified, and the
    cross-check below then declared all six known orphans "stale — now paired".

    Following that verdict would have deleted the record of six live defects.
    The tool that finds broken pairings had its own pairing broken by the fix it
    recommended, and said everything was fine. Resolve both spellings.
    """
    src = (REPO / EXT_MODULE).read_text()
    consts = dict(re.findall(r'pub const (\w+): &str = "([^"]+)";', src))

    keys = defaultdict(lambda: {"read": set(), "write": set(), "ambig": set()})

    def classify(key, path, lineno):
        # The definition module is neither a read nor a write of the key.
        if EXT_MODULE in path:
            return
        ctx = context(path, lineno)
        site = f"{path}:{lineno}"
        w, r = WRITE.search(ctx), READ.search(ctx)
        if w and not r:
            keys[key]["write"].add(site)
        elif r and not w:
            keys[key]["read"].add(site)
        else:
            keys[key]["ambig"].add(site)

    # 1. bare literals — producers/consumers that have not been centralised yet
    for path, lineno, text in production(rgx(r'"zp\.[a-z0-9_.]+"')):
        for k in re.findall(r'"(zp\.[a-z0-9_.]+)"', text):
            classify(k, path, lineno)

    # 2. constant references — `ext::NAME`, `receipt_extensions::NAME`
    for name, value in consts.items():
        for path, lineno, _ in production(rgx(rf"\b(?:ext|receipt_extensions)::{name}\b")):
            classify(value, path, lineno)
        keys[value]  # ensure declared keys appear even with zero sites

    return keys


def claim_variants():
    """Constructed vs matched, per ClaimMetadata variant.

    Heuristic: `ClaimMetadata::X { .. }` is a *pattern* (a consumer);
    `ClaimMetadata::X { field: ...` is a *construction*. Struct-update and
    multi-line constructions are read from the window. Stated because it is a
    heuristic and will occasionally be wrong in both directions.
    """
    src = TYPES.read_text()
    out = {}
    for v in enum_variants(src, "ClaimMetadata"):
        built, matched = set(), set()
        for path, lineno, text in production(rg(f"ClaimMetadata::{v}")):
            if "/zp-receipt/src/" in path:
                continue
            site = f"{path}:{lineno}"
            if re.search(r"\{\s*\.\.\s*\}", text) or re.search(r"=>\s*$|\bSome\(ClaimMetadata", text):
                matched.add(site)
            else:
                built.add(site)
        # zp-receipt's own validation.rs is the canonical consumer; count it
        # separately so "matched somewhere" is not confused with "used".
        val = production(rg(f"ClaimMetadata::{v}"))
        in_validation = any("validation.rs" in h[0] for h in val)
        out[v] = dict(built=built, matched=matched, in_validation=in_validation)
    return out


EXT_MODULE = "crates/zp-core/src/receipt_extensions.rs"


def declared_orphans():
    """Parse `KNOWN_ORPHAN_READS` out of the Rust module, resolved to strings.

    The Rust list is a *claim* about which keys have no producer. This tool
    measures the same thing. Claims and measurements that disagree are the whole
    subject of this exercise, so the two are compared rather than trusted —
    including when the claim is one we wrote ourselves. It rotted within an hour
    the first time: three keys were wired and left listed as unwired.
    """
    src = (REPO / EXT_MODULE).read_text()
    consts = dict(re.findall(r'pub const (\w+): &str = "([^"]+)";', src))
    m = re.search(r"KNOWN_ORPHAN_READS: &\[&str\] = &\[(.*?)\];", src, re.S)
    if not m:
        return None, consts
    names = [n.strip().rstrip(",") for n in m.group(1).strip().splitlines() if n.strip()]
    return {consts[n] for n in names if n in consts}, consts


def main():
    print("=" * 68)
    print("FALSE ASSURANCE — consumers with no producer")
    print("=" * 68)

    keys = extension_keys()
    orphan_reads = {k: v for k, v in keys.items() if v["read"] and not v["write"]}
    write_only = {k: v for k, v in keys.items() if v["write"] and not v["read"]}

    ambiguous = {k: v for k, v in keys.items() if v["ambig"] and not (v["read"] and v["write"])}
    paired = {k: v for k, v in keys.items() if v["read"] and v["write"]}

    print(f"\nreceipt extension keys seen        {len(keys)}")
    print(f"  read AND written (paired)        {len(paired)}")
    print(f"  read but never written           {len(orphan_reads)}   <-- defects")
    print(f"  written but never read           {len(write_only)}   (fine on a chain)")
    # This bucket used to be computed and never displayed, which is the same
    # silent-drop defect the tool exists to find. Keys land here when the
    # +/-2-line window cannot tell a read from a write — usually a call split
    # across more lines than the window sees. Unclassified is not zero-risk;
    # it is unknown risk, and it belongs on screen.
    print(f"  UNCLASSIFIED (window too narrow) {len(ambiguous)}   <-- verify by hand")
    for k in sorted(ambiguous):
        sites = sorted(ambiguous[k]["ambig"])[:2]
        print(f"      {k:<38} {', '.join(sites)}")
    for k, v in sorted(orphan_reads.items()):
        print(f"\n  {k}")
        for s in sorted(v["read"]):
            print(f"      read  {s}")

    # ── Cross-check the Rust module's own claim against measurement ────────
    declared, _consts = declared_orphans()
    if declared is not None:
        measured = set(orphan_reads)
        # STALE means *demonstrably paired now*, not merely absent from the
        # orphan set. A key that landed in the unclassified bucket is unknown,
        # not fixed, and the first version of this check conflated the two — it
        # reported three memory keys as "now paired" when they had simply fallen
        # into `ambig`. Acting on that would have deleted a true record on the
        # strength of a measurement that had not been made.
        stale = declared & set(paired)
        unknown = declared & set(ambiguous)
        missing = measured - declared        # measured orphaned, not declared
        print(f"\n\nKNOWN_ORPHAN_READS cross-check ({EXT_MODULE})")
        print(f"  declared orphans                 {len(declared)}")
        print(f"  measured orphans                 {len(measured)}")
        if stale:
            print(f"  STALE — listed but now paired    {len(stale)}   <-- remove from the list")
            for k in sorted(stale):
                print(f"      {k}")
        if missing:
            print(f"  UNDECLARED — orphaned, unlisted  {len(missing)}   <-- add, or wire a producer")
            for k in sorted(missing):
                print(f"      {k}")
        if unknown:
            print(f"  UNKNOWN — declared, unclassified {len(unknown)}   <-- not evidence either way")
            for k in sorted(unknown):
                print(f"      {k}")
        if not stale and not missing and not unknown:
            print("  the list agrees with reality")

    cv = claim_variants()
    never_built = {k: v for k, v in cv.items() if not v["built"]}
    consumed_not_built = {k: v for k, v in never_built.items()
                          if v["matched"] or v["in_validation"]}
    print(f"\n\nclaim_metadata variants            {len(cv)}")
    print(f"  never constructed                {len(never_built)}")
    print(f"  ...and validated anyway          {len(consumed_not_built)}   <-- unreachable branches")
    for k in sorted(consumed_not_built):
        print(f"      {k}")

    print("\n" + "-" * 68)
    print("Read-but-never-written keys are alarms that cannot fire.")
    print("Validated-but-never-constructed variants are branches that cannot run.")
    print("Neither shows up as an error; both read as coverage.")


if __name__ == "__main__":
    main()
