#!/usr/bin/env python3
"""discipline-pins — the pin registry, derived rather than authored.

WHY THIS IS GENERATED
---------------------
`docs/DISCIPLINE-PINS.md` was written 2026-05-14 as a hand-maintained registry.
It documents one pin and ends with the line "(future pins go here)". Nineteen
futures arrived. On 2026-07-29 the intersection between the registry and the
tree was **empty**: every pin the registry described lived somewhere the
registry did not look, and every pin on disk was undocumented.

That is the failure mode `tools/architecture-map` already predicted in its own
docstring -- a hand-maintained table goes stale the first week -- reproduced
exactly, in the document whose subject is mechanical enforcement. The registry
of the repo's structural rules was the least structurally maintained artifact
in it. So it is generated now, from the pins themselves, which are already
self-describing: each carries a `//!` rule, a `# Why`, and a builder call with
`cite_invariant` and `rationale`.

WHAT IT ANSWERS
---------------
For every pin: what it forbids, what invariant it cites, where it is allowed to
be violated, which governed document carries its rationale, and whether that
document is reachable by anyone but the author.

PIN LOCATIONS
-------------
Pins live in two places and a registry that assumes one misses the other:

  crates/zp-discipline/tests/*.rs   free-standing pin files (the bulk)
  crates/*/src/**.rs                inline `#[cfg(test)]` blocks in the crate
                                    they govern -- `singular_sovereign_root`
                                    is one, at zp-keys/src/sovereignty/mod.rs

Spec: docs/design/CONNECTION-INTEGRITY-PROGRAM-2026-07.md (derived-not-authored rule)
"""
import re, subprocess, sys
from pathlib import Path

BUILDER = re.compile(r'Discipline::new\(\s*"([^"]+)"')
CITE    = re.compile(r'\.cite_invariant\(\s*"([^"]*)"')
ALLOW   = re.compile(r'\.allow_path\(\s*"([^"]*)"')
FORBID  = re.compile(r'\.forbid_pattern\(')
DOCPATH = re.compile(r'docs/[A-Za-z0-9/_.\-]+\.md')

# Future-tense pin promises in shipped source. A comment saying a pin "will"
# exist is an A11 claim: it reads as enforcement to anyone skimming, and
# enforces nothing. Matched conservatively -- the phrase must contain both a
# pin reference and a future-tense verb.
PROMISE = re.compile(
    r'discipline[- ]pin[^.\n]{0,120}?\b(will|to be added|is added|planned|future)\b'
    r'|\b(will|planned|future)\b[^.\n]{0,120}?discipline[- ]pin',
    re.I)


def read(p):
    try: return p.read_text(errors="replace")
    except Exception: return ""


def header(text):
    """The `//!` block at the top of a pin file, as (rule, why, doc paths).

    rule = the first sentence-ish run of //! lines, which by convention states
    what the pin forbids. why  = the first paragraph after a `# Why` heading.
    """
    lines, doc = [], []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("//!"):
            lines.append(s[3:].strip())
        elif s and not s.startswith("//"):
            break
    body = "\n".join(lines)
    doc = sorted(set(DOCPATH.findall(body)))

    rule, why, in_why = [], [], False
    for l in lines:
        if l.startswith("#"):
            in_why = "why" in l.lower()
            continue
        if in_why:
            if not l and why: break
            if l: why.append(l)
        elif not rule or l:
            if not l and rule: in_why = False
            if l: rule.append(l)
        elif rule:
            break
    return " ".join(rule).strip(), " ".join(why).strip(), doc


def pins_in(path, text):
    """Every Discipline::new(...) in a file, with its metadata.

    A file may declare several. Five of the nineteen pin files on 2026-07-29
    declared none -- they assert by hand, which means a failure prints a bare
    assert rather than the cited invariant and rationale the builder emits.
    That is worth reporting, not silently normalising away.
    """
    rule, why, docs = header(text)
    names = BUILDER.findall(text)
    return {
        "file": path,
        "names": names,
        "builder": bool(names),
        "cites": sorted(set(CITE.findall(text))),
        "allows": sorted(set(ALLOW.findall(text))),
        "patterns": len(FORBID.findall(text)),
        "rule": rule,
        "why": why,
        "docs": docs,
        "loc": len(text.splitlines()),
    }


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    tests = sorted((root / "crates/zp-discipline/tests").glob("*.rs"))
    pins = [pins_in(f"crates/zp-discipline/tests/{f.name}", read(f)) for f in tests]

    # Inline pins and unlanded promises, both outside zp-discipline.
    inline, promised = [], []
    for f in (root / "crates").rglob("*.rs"):
        rel = f.relative_to(root).as_posix()
        if "/target/" in rel or rel.startswith("crates/zp-discipline/"):
            continue
        text = read(f)
        if "discipline" not in text.lower():
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r'discipline[- ]pin', line, re.I):
                if PROMISE.search(line):
                    promised.append((rel, i, line.strip().lstrip("/!* ")))
                elif re.search(r'#\[cfg\(test\)\]|─ .* discipline-pin tests', line) or \
                     re.search(r'discipline-pin tests', line, re.I):
                    inline.append((rel, i, line.strip().lstrip("/!* ")))

    # Rationale reachability. docs/handoffs/ is gitignored (.gitignore:160) and
    # the corpus convention adopted 2026-07-27 says handoffs are local notes,
    # not corpus. A pin whose rationale lives there is justified by a file that
    # does not exist in a fresh clone -- the check still runs, but nobody can
    # read why it exists.
    ignored_prefix = "docs/handoffs/"
    for p in pins:
        p["missing"] = [d for d in p["docs"] if not (root / d).exists()]
        p["unshared"] = [d for d in p["docs"] if d.startswith(ignored_prefix)]

    # Registry drift against the authored document this replaces.
    reg = read(root / "docs/DISCIPLINE-PINS.md")
    documented = [p for p in pins
                  if any(n in reg for n in p["names"]) or Path(p["file"]).stem in reg]

    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=root,
                                capture_output=True, text=True).stdout.strip() or "unknown"
    except Exception:
        commit = "unknown"

    total = sum(len(p["names"]) or 1 for p in pins)
    out = ["# Discipline Pins Map\n",
           "**Document type:** Derived registry — generated, not authored. "
           "**Status:** current as of the commit below.\n",
           f"**Generated** by `tools/discipline-pins/discipline_pins.py` from commit "
           f"`{commit}`. Derived, not authored — regenerate rather than edit.\n",
           f"{len(pins)} pin files · {total} assertions · "
           f"{sum(p['patterns'] for p in pins)} forbidden patterns · "
           f"{sum(p['loc'] for p in pins):,} lines\n",
           "\nThese run under `cargo test --workspace`, which `.github/workflows/ci.yml` "
           "invokes on every push. A violation fails the build.\n"]

    out.append("\n## Pins\n")
    out.append("| Pin | Forbids | Invariant cited | Allowlist | Rationale doc |")
    out.append("|---|---|---|---:|---|")
    for p in sorted(pins, key=lambda x: x["file"]):
        stem = Path(p["file"]).stem
        # Strip the conventional "Discipline[ pin][ (context)]:" opener — it is
        # on every header, so it carries no information in a column of pins.
        rule = re.sub(r'^Discipline(?:\s+pin)?(?:\s*\([^)]*\))?\s*:\s*', '',
                      p["rule"] or "—").replace("|", "\\|")
        rule = rule[:117] + "…" if len(rule) > 120 else rule
        cite = ", ".join(p["cites"]) or ("—" if p["builder"] else "**hand-rolled**")
        docs = ", ".join(f"`{d}`" for d in p["docs"]) or "—"
        out.append(f"| `{stem}` | {rule} | {cite} | {len(p['allows'])} | {docs} |")

    if inline:
        out.append("\n## Inline pins (outside `zp-discipline`)\n")
        for rel, i, txt in sorted(inline):
            out.append(f"- `{rel}:{i}` — {txt}")

    out.append("\n## Attention\n")

    hand = sorted(Path(p["file"]).stem for p in pins if not p["builder"])
    out.append(f"- **Hand-rolled, no `Discipline` builder** ({len(hand)}): "
               f"{', '.join(f'`{h}`' for h in hand) or 'none'} — these assert directly, "
               "so a failure prints a bare assertion rather than the cited invariant and "
               "rationale the builder emits. The pin still holds; the message does not "
               "explain itself.")

    nocite = sorted(Path(p["file"]).stem for p in pins if p["builder"] and not p["cites"])
    out.append(f"- **No `cite_invariant`** ({len(nocite)}): "
               f"{', '.join(f'`{h}`' for h in nocite) or 'none'} — uses the builder but "
               "names no invariant, so the rule is enforced without a stated source.")

    nodoc = sorted(Path(p["file"]).stem for p in pins if not p["docs"])
    out.append(f"- **No rationale document** ({len(nodoc)}): "
               f"{', '.join(f'`{h}`' for h in nodoc) or 'none'} — the `# Why` lives only "
               "in the pin's own header. Fine for a narrow rule; a gap for a broad one.")

    unshared = sorted({Path(p["file"]).stem for p in pins if p["unshared"]})
    out.append(f"- **Rationale in an untracked file** ({len(unshared)}): "
               f"{', '.join(f'`{h}`' for h in unshared) or 'none'} — cites `docs/handoffs/`, "
               "which `.gitignore` excludes and the corpus convention classifies as local "
               "notes rather than corpus. The pin ships; its justification does not.")

    # A rule with many exceptions is a rule under pressure. Not a defect --
    # `no_raw_peer_url_outside_zp_net` legitimately allows 17 paths -- but the
    # count is the cheapest available signal that a boundary is being widened
    # one call site at a time rather than held.
    wide = sorted(((len(p["allows"]), Path(p["file"]).stem) for p in pins
                   if len(p["allows"]) >= 5), reverse=True)
    out.append(f"- **Widest allowlists** ({len(wide)} with ≥5 exemptions): "
               + (", ".join(f"`{n}` ({c})" for c, n in wide) or "none")
               + " — each exemption is a place the rule does not hold. Worth re-reading "
                 "when the count grows, since exemptions are added one at a time and "
                 "never reviewed together.")

    missing = sorted({d for p in pins for d in p["missing"]})
    out.append(f"- **Cited document does not resolve** ({len(missing)}): "
               f"{', '.join(f'`{d}`' for d in missing) or 'none'}")

    out.append(f"- **Promised but not landed** ({len(promised)}): "
               + ("; ".join(f"`{rel}:{i}`" for rel, i, _ in sorted(promised)) or "none")
               + " — source comments announcing a pin that does not exist. These read as "
                 "enforcement and enforce nothing (A11).")

    doc_names = ", ".join(f"`{Path(p['file']).stem}`" for p in documented) or "**none**"
    out.append(f"- **Described by `docs/DISCIPLINE-PINS.md`** ({len(documented)} of "
               f"{len(pins)}): {doc_names}")

    (root / "docs" / "DISCIPLINE-PINS-MAP.md").write_text("\n".join(out) + "\n")
    print(f"wrote docs/DISCIPLINE-PINS-MAP.md — {len(pins)} pin files, "
          f"{total} assertions, commit {commit}")


if __name__ == "__main__":
    main()
