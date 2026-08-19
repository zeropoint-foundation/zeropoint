#!/usr/bin/env python3
"""Generate the ecosystem graph's state overlay.

Writes `crates/zp-server/assets/ecosystem-state.js`, a baked asset the
graph reads as `window.ZP_ECOSYSTEM_STATE`. Baked rather than fetched
because `/api/v1/system/state` and `/api/v1/tools` sit behind
`require_auth` and a browser on /ecosystem carries no session -- which is
why the page's LIVE STATE panel reports "Server offline or unreachable"
while the server is demonstrably serving the page it says that on. A
runtime fetch for this data would hit the same wall.

Discipline: **no node gets a state without a citation.** Crate nodes are
derived from `docs/lenses/source-manifest.json`'s `consumed_by`. Everything
else comes from the EVIDENCE table below, each entry carrying the file and
line it was read from. A node with no evidence renders `unknown` rather
than a guess -- the same posture `docs/lenses/manifest.json` takes with its
79 unclassifiable documents.

Regenerate, do not edit the output:
    python3 tools/ecosystem-state/ecosystem_state.py
Then `cargo build -p zp-server` -- the asset is include_str!'d.
"""
import json, pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "crates/zp-server/assets/ecosystem-state.js"

# state vocabulary, deliberately small:
#   live      built, and something depends on it or it runs
#   partial   built, incompletely wired -- works in one direction only
#   unwired   built, and nothing consumes it
#   absent    named by the graph, not present in the tree
#   unknown   no first-party evidence; not a judgement
EVIDENCE = {
    # --- core: verified running this session ---
    "zp-server":     ("live", "serves /ecosystem itself; the page you are reading is the proof",
                      "crates/zp-server/src/lib.rs:1625"),
    "receipt-chain": ("live", "append path exercised; chain integrity runtimes always on",
                      "crates/zp-server/src/lib.rs:2157-2171"),
    "audit-store":   ("live", "AuditStore::open_signed with a Genesis-derived audit signer",
                      "crates/zp-server/src/lib.rs:733-736"),
    "zeropoint":     ("live", "the substrate as a whole; boot path verified",
                      "crates/zp-server/src/lib.rs"),

    # --- concepts with hard evidence ---
    "quorum": ("unwired",
               "split_secret and reconstruct_secret have no callers outside their own module; "
               "quorum Genesis is built and tested but not reachable",
               "docs/design/NON-DELEGABLE-AUTHORITY-2026-08.md §11.1"),
    "sovereignty": ("partial",
                    "load_sovereign_root is a process-scoped OnceLock warmed once at boot; no "
                    "runtime authority decision re-invokes a provider",
                    "crates/zp-keys/src/sovereignty/mod.rs:636-653"),
    "governance-gate": ("live",
                        "every spawn routes through GovernanceGate::evaluate and the decision is "
                        "chain-sealed before the side effect",
                        "crates/zp-host/src/system.rs:79-155"),
    "ed25519": ("live", "KEEL II.1 signing primitive, in use on the audit and gate signers",
                "crates/zp-keys/src/audit_signer.rs:52"),
    "blake3":  ("live", "KEEL II.1 content hash, in use for chain linkage and module hashing",
                "crates/zp-policy/src/wasm_runtime.rs:90"),

    # --- services ---
    "analysis-api": ("absent",
                     "the page fetches /api/v1/analysis/index and that route does not exist "
                     "anywhere in the server; 'Analysis API unreachable' is permanently true",
                     "grep '/api/v1/analysis/index' crates/zp-server/src/lib.rs -> 0 hits"),
    "tools-api":     ("live", "governed tool registry and launch path",
                      "crates/zp-server/src/tool_ports.rs:97-109"),
    "port-allocator":("live", "port registry assigns and persists; hot-loop fix landed 2026-07",
                      "crates/zp-server/src/tool_ports.rs"),
    "tool-proxy":    ("live", "subdomain proxy routes tool pages",
                      "crates/zp-server/src/lib.rs:1586-1587"),

    # --- hardware: real, and boot-time only ---
    "touchid": ("partial", "provider exists and is exercised once at boot, never per action",
                "crates/zp-keys/src/sovereignty/touchid.rs:575-616"),
    "trezor":  ("partial", "same OnceLock posture as touchid",
                "crates/zp-keys/src/sovereignty/mod.rs:649-653"),

    # --- external ---
    "cloudflare": ("unwired", "zp-cloudflare has zero dependents in any Cargo.toml",
                   "source-manifest consumed_by == 0"),

    # --- runtime ---
    "wasm-runtime": ("partial",
                     "WasmRuntime::load_module computes a content hash and instantiates without "
                     "comparing it; verify_integrity re-reads metadata, not bytes",
                     "crates/zp-policy/src/wasm_runtime.rs:88-127"),
}

# ecosystem.js node id -> crate name, where the node *is* a crate
CRATE_NODES = {
    "zp-core": "zp-core", "zp-audit": "zp-audit", "zp-keys": "zp-keys",
    "zp-trust": "zp-trust", "zp-receipt": "zp-receipt", "zp-policy": "zp-policy",
    "zp-engine": "zp-engine", "mle-star": "mle-star-engine",
    "monte-carlo": "monte-carlo-engine",
}


def crate_states():
    p = ROOT / "docs/lenses/source-manifest.json"
    if not p.exists():
        return {}
    data = json.loads(p.read_text())
    crates = next(v for v in data.values() if isinstance(v, list))
    by_name = {c.get("name"): c for c in crates}
    out = {}
    for node_id, crate in CRATE_NODES.items():
        c = by_name.get(crate)
        if not c:
            out[node_id] = ("absent", f"no crate named {crate} in the workspace",
                            "docs/lenses/source-manifest.json")
            continue
        consumers = c.get("consumed_by") or []
        n = len(consumers) if isinstance(consumers, list) else int(consumers or 0)
        if n == 0:
            out[node_id] = ("unwired",
                            f"{crate} is {c.get('loc', '?')} lines and nothing imports it",
                            "docs/lenses/source-manifest.json consumed_by")
        else:
            out[node_id] = ("live",
                            f"{crate}, {c.get('loc','?')} lines, {n} dependent crate(s), "
                            f"primary role {c.get('primary_role','?')}",
                            "docs/lenses/source-manifest.json consumed_by")
    return out


def ecosystem_node_ids():
    js = (ROOT / "crates/zp-server/assets/ecosystem.js").read_text()
    return [m.group(1) for m in re.finditer(r'\{\s*id:\s*"([^"]+)",\s*label:', js)]


def head():
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True, timeout=10).stdout.strip() or None
    except Exception:
        return None


def main():
    states = dict(EVIDENCE)
    states.update(crate_states())          # measured beats hand-authored
    ids = ecosystem_node_ids()
    nodes = {}
    for nid in ids:
        if nid in states:
            st, why, cite = states[nid]
            nodes[nid] = {"state": st, "why": why, "cite": cite}
        else:
            nodes[nid] = {"state": "unknown",
                          "why": "no first-party evidence read for this node",
                          "cite": None}
    counts = {}
    for v in nodes.values():
        counts[v["state"]] = counts.get(v["state"], 0) + 1
    payload = {
        "generated_from_commit": head(),
        "node_total": len(ids),
        "counts": counts,
        "nodes": nodes,
    }
    OUT.write_text(
        "// GENERATED by tools/ecosystem-state/ecosystem_state.py — do not edit.\n"
        "// Regenerate, then `cargo build -p zp-server` (this asset is include_str!'d).\n"
        "window.ZP_ECOSYSTEM_STATE = "
        + json.dumps(payload, indent=2) + ";\n")
    print(f"wrote {OUT.relative_to(ROOT)} — {len(ids)} nodes")
    gnodes, gedges = parse_graph()
    write_artifact(gnodes, gedges, nodes, counts)
    for k in ("live", "partial", "unwired", "absent", "unknown"):
        if k in counts:
            print(f"  {k:<9}{counts[k]:>4}")



# ── Standalone artifact export ───────────────────────────────────────────
# The server asset above is include_str!'d into zp-server and needs a
# running substrate to look at. This second output is the same graph as a
# self-contained artifact: nodes, edges, state, and a *seed* layout, so the
# page needs no d3, no server and no network.
#
# The seed matters and the word is deliberate. The layout below is not the
# final picture: the artifact runs its own velocity-Verlet simulation in the
# browser, because label readability is the binding constraint and label
# widths cannot be known here -- they depend on the font the reader's machine
# actually resolves. Python places the nodes so the browser starts from a
# settled topology rather than a random cloud (same commit, same starting
# picture); the browser then separates *measured label boxes*, which is the
# part that could never have been precomputed.

W_CANVAS = 1320
H_CANVAS = 1010

def parse_graph():
    js = (ROOT / "crates/zp-server/assets/ecosystem.js").read_text()
    nodes = [{"id": m.group(1), "label": m.group(2), "type": m.group(3),
              "desc": m.group(4)}
             for m in re.finditer(
                 r'\{\s*id:\s*"([^"]+)",\s*label:\s*"([^"]+)",\s*type:\s*"([^"]+)",'
                 r'\s*desc:\s*"((?:[^"\\]|\\.)*)"', js)]
    edges = [{"source": m.group(1), "target": m.group(2), "label": m.group(3)}
             for m in re.finditer(
                 r'\{\s*source:\s*"([^"]+)",\s*target:\s*"([^"]+)",\s*label:\s*"([^"]+)"', js)]
    ids = {n["id"] for n in nodes}
    edges = [e for e in edges if e["source"] in ids and e["target"] in ids]
    return nodes, edges


def layout(nodes, edges, w=W_CANVAS, h=H_CANVAS, iters=900, seed=7):
    import math, random
    rnd = random.Random(seed)
    pos = {n["id"]: [rnd.uniform(0.15, 0.85) * w, rnd.uniform(0.15, 0.85) * h]
           for n in nodes}
    deg = {n["id"]: 0 for n in nodes}
    for e in edges:
        deg[e["source"]] += 1
        deg[e["target"]] += 1
    k = math.sqrt((w * h) / max(len(nodes), 1)) * 0.92
    for i in range(iters):
        t = (1 - i / iters) ** 1.4 * (w / 12) + 0.4
        disp = {n["id"]: [0.0, 0.0] for n in nodes}
        ids = list(pos)
        for a in range(len(ids)):
            for b in range(a + 1, len(ids)):
                ia, ib = ids[a], ids[b]
                dx, dy = pos[ia][0] - pos[ib][0], pos[ia][1] - pos[ib][1]
                d2 = dx * dx + dy * dy or 0.01
                d = math.sqrt(d2)
                f = (k * k) / d
                ux, uy = dx / d * f, dy / d * f
                disp[ia][0] += ux; disp[ia][1] += uy
                disp[ib][0] -= ux; disp[ib][1] -= uy
        for e in edges:
            ia, ib = e["source"], e["target"]
            dx, dy = pos[ia][0] - pos[ib][0], pos[ia][1] - pos[ib][1]
            d = math.sqrt(dx * dx + dy * dy) or 0.01
            f = (d * d) / k
            ux, uy = dx / d * f, dy / d * f
            disp[ia][0] -= ux; disp[ia][1] -= uy
            disp[ib][0] += ux; disp[ib][1] += uy
        for nid, p in pos.items():
            dx, dy = disp[nid]
            d = math.sqrt(dx * dx + dy * dy) or 0.01
            p[0] += dx / d * min(d, t)
            p[1] += dy / d * min(d, t)
            # gentle pull to centre keeps isolates from drifting off-canvas
            p[0] += (w / 2 - p[0]) * 0.010
            p[1] += (h / 2 - p[1]) * 0.014
            p[0] = max(62, min(w - 62, p[0]))
            p[1] = max(52, min(h - 52, p[1]))
    return pos, deg


def write_artifact(nodes, edges, states, counts):
    pos, deg = layout(nodes, edges)
    for n in nodes:
        st = states.get(n["id"], {"state": "unknown", "why": None, "cite": None})
        n["x"] = round(pos[n["id"]][0], 1)
        n["y"] = round(pos[n["id"]][1], 1)
        n["deg"] = deg[n["id"]]
        n["state"] = st["state"]
        n["why"] = st.get("why")
        n["cite"] = st.get("cite")
    out = ROOT / "dashboard/data/ecosystem-graph.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "generated_from_commit": head(),
        "width": W_CANVAS, "height": H_CANVAS,
        "counts": counts,
        "nodes": nodes, "edges": edges,
    }, indent=2) + "\n")
    print(f"wrote {out.relative_to(ROOT)} — {len(nodes)} nodes, {len(edges)} edges")
    write_html(nodes, edges, counts, out)


def write_html(nodes, edges, counts, data_path):
    """Render the standalone artifact from the template.

    The page is generated rather than hand-maintained on purpose: the graph
    JSON is inlined into it, and a hand-edited page drifts from the JSON the
    moment either is touched. One source, two artifacts.
    """
    tmpl = (ROOT / "tools/ecosystem-state/artifact.template.html").read_text()
    graph = json.loads(data_path.read_text())
    html = (tmpl
            .replace("__GRAPH_JSON__", json.dumps(graph, indent=2))
            .replace("__NNODES__", str(len(nodes)))
            .replace("__NEDGES__", str(len(edges)))
            .replace("__NUNKNOWN__", str(counts.get("unknown", 0)))
            .replace("__W__", str(W_CANVAS))
            .replace("__H__", str(H_CANVAS)))
    assert "__GRAPH_JSON__" not in html and "__W__" not in html
    dest = ROOT / "dashboard/ecosystem-map.html"
    dest.write_text(html)
    print(f"wrote {dest.relative_to(ROOT)} — {len(html):,} bytes")


if __name__ == "__main__":
    sys.exit(main())
