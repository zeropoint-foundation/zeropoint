#!/usr/bin/env python3
"""architecture-map — the crate-level baseline, derived rather than authored.

Nobody writes this inventory. The tree already knows what its crates are, what
they say they do, and what depends on what; this collates it so the answer does
not require a sweep. Same discipline as tools/connection-map: a hand-maintained
architecture table goes stale the first week, so it is generated.

WHAT IT ANSWERS
---------------
For every crate: its stated purpose, whether it is in the workspace, what it
depends on, what depends on it, how deep it sits in the dependency graph, and
whether any governed document describes it.

STATUS
------
member      in the root Cargo.toml workspace
standalone  declares its own [workspace] -- deliberately built alone
orphan      present under crates/ and in neither of the above

WIRING
------
consumed    at least one other crate depends on it
entrypoint  no dependents, but ships a binary (src/main.rs)
unwired     no dependents and no binary -- C2 territory per
            docs/design/CONNECTION-INTEGRITY-PROGRAM-2026-07.md

LAYER
-----
Dependency depth: 0 = depends on no sibling crate. A crate's layer is one more
than the deepest sibling it depends on. This is derived, not a judgement about
importance -- but it is the closest thing to an objective "base level," which is
what the map exists to expose.

Spec: docs/design/CONNECTION-INTEGRITY-PROGRAM-2026-07.md (derived-not-authored rule)
"""
import re, subprocess, sys
from pathlib import Path

def read(p):
    try: return p.read_text(errors="replace")
    except Exception: return ""

def toml_field(text, key):
    m = re.search(rf'^\s*{key}\s*=\s*"([^"]*)"', text, re.M)
    return m.group(1) if m else ""

def module_doc(crate):
    """First meaningful //! line from lib.rs or main.rs -- the crate's own words."""
    for entry in ("src/lib.rs", "src/main.rs"):
        text = read(crate / entry)
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("//!"):
                body = s[3:].strip()
                if body and not body.startswith("#"):
                    return body
            elif s and not s.startswith("//"):
                break
    return ""

def real_deps(man):
    """Path deps from [dependencies] only.

    [dev-dependencies] must be excluded or the graph appears cyclic: zp-receipt
    depends on zp-verify, and zp-verify dev-depends back on zp-receipt for its
    round-trip tests. Cargo permits that; an architecture map must not report it
    as a cycle, because a test-only edge is not a structural one. Reading them
    all in one regex left 29 of 44 crates unresolvable on first run.
    """
    deps, section = set(), ""
    for line in man.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s
            continue
        if "dev-dependencies" in section or "build-dependencies" in section:
            continue
        m = re.search(r'path\s*=\s*"\.\./([A-Za-z0-9_-]+)"', s)
        if m:
            deps.add(m.group(1))
    return deps


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    ws = read(root / "Cargo.toml")
    members = set(re.findall(r'"crates/([A-Za-z0-9_-]+)"', ws))

    crates = sorted(d for d in (root / "crates").iterdir() if (d / "Cargo.toml").exists())
    info = {}
    for c in crates:
        man = read(c / "Cargo.toml")
        name = toml_field(man, "name") or c.name
        deps = real_deps(man)
        loc = sum(len(read(f).splitlines()) for f in c.rglob("*.rs")
                  if "/target/" not in str(f))
        info[c.name] = {
            "name": name,
            "desc": toml_field(man, "description"),
            "doc": module_doc(c),
            "deps": deps,
            "loc": loc,
            "status": ("member" if c.name in members
                       else "standalone" if "[workspace]" in man else "orphan"),
            "bin": (c / "src/main.rs").exists(),
        }

    # dependents: reverse edges, keyed by directory name
    for k in info:
        info[k]["dependents"] = sorted(o for o, v in info.items() if k in v["deps"])

    # layer = dependency depth over sibling crates
    depth, guard = {}, 0
    while len(depth) < len(info) and guard < 50:
        guard += 1
        for k, v in info.items():
            if k in depth: continue
            sib = [d for d in v["deps"] if d in info]
            if all(d in depth for d in sib):
                depth[k] = 0 if not sib else 1 + max(depth[d] for d in sib)
    for k in info:
        info[k]["layer"] = depth.get(k, -1)   # -1 = cycle

    # documented: named in any governed doc
    idx = read(root / "docs/CANONICAL-CORPUS-INDEX-2026-07.md")
    listed = sorted(set(re.findall(r"\(((?:design/)?[A-Za-z0-9\-_.]+\.md)\)", idx)))
    corpus = "\n".join(read(root / "docs" / rel) for rel in listed)
    for k, v in info.items():
        v["documented"] = bool(re.search(rf"\b{re.escape(v['name'])}\b", corpus))

    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=root,
                                capture_output=True, text=True).stdout.strip() or "unknown"
    except Exception:
        commit = "unknown"

    def wiring(v):
        if v["dependents"]: return "consumed"
        return "entrypoint" if v["bin"] else "unwired"

    out = [f"# Architecture Map\n",
           f"**Generated** by `tools/architecture-map/architecture_map.py` from commit `{commit}`. "
           f"Derived, not authored — regenerate rather than edit.\n",
           f"{len(info)} crates · {sum(v['loc'] for v in info.values()):,} lines · "
           f"{sum(1 for v in info.values() if v['status']=='member')} workspace members\n"]

    for layer in sorted({v["layer"] for v in info.values()}):
        names = sorted(k for k, v in info.items() if v["layer"] == layer)
        label = "cycle" if layer < 0 else f"Layer {layer}"
        out.append(f"\n## {label}\n")
        out.append("| Crate | Purpose | Status | Wiring | Depends on | Used by | LOC | Doc'd |")
        out.append("|---|---|---|---|---|---|---|---|")
        for k in names:
            v = info[k]
            purpose = (v["desc"] or v["doc"] or "—").replace("|", "\\|")
            if len(purpose) > 110: purpose = purpose[:107] + "…"
            deps = ", ".join(sorted(d for d in v["deps"] if d in info)) or "—"
            used = ", ".join(v["dependents"]) or "—"
            out.append(f"| `{k}` | {purpose} | {v['status']} | {wiring(v)} | {deps} | {used} "
                       f"| {v['loc']:,} | {'yes' if v['documented'] else '**no**'} |")

    unwired = sorted(k for k, v in info.items() if wiring(v) == "unwired")
    undoc = sorted(k for k, v in info.items() if not v["documented"])
    out.append("\n## Attention\n")
    out.append(f"- **Unwired** ({len(unwired)}): {', '.join(f'`{u}`' for u in unwired) or 'none'}")
    out.append(f"- **Not described by any governed document** ({len(undoc)}): "
               f"{', '.join(f'`{u}`' for u in undoc) or 'none'}")
    non_member = sorted(k for k, v in info.items() if v["status"] != "member")
    out.append(f"- **Outside the workspace** ({len(non_member)}): "
               f"{', '.join(f'`{u}` ({info[u][chr(115)+chr(116)+chr(97)+chr(116)+chr(117)+chr(115)]})' for u in non_member) or 'none'}")

    (root / "docs" / "ARCHITECTURE-MAP.md").write_text("\n".join(out) + "\n")
    print(f"wrote docs/ARCHITECTURE-MAP.md — {len(info)} crates, commit {commit}")

if __name__ == "__main__":
    main()
