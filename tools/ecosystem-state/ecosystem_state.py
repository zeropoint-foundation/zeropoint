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



# ── Derivation: the node set, not just the state ─────────────────────────
# The first cut of this generator read its node set from ecosystem.js's
# hand-authored DATA.nodes array and attached derived state to whatever it
# found there. That made the *rings* evidence-backed and left the *topology*
# asserted, and the two rendered identically -- so a subsystem nobody had
# thought to type simply did not exist on the map. The credential vault is
# how that surfaced: 420 lines in zp-trust, a top-level CLI verb, call sites
# in eight crates, and no node. Eight of the workspace's crates were drawn;
# thirty-eight were not.
#
# So the node set is derived now. Crates come from the workspace manifest.
# Named subsystems that live inside a crate rather than as one -- the vault
# is the first -- are found by probing for their type, not by asserting them.
# Whatever remains hand-authored is marked `declared` and says so in its own
# tooltip, because the failure was never that declared nodes existed. It was
# that they were indistinguishable from measured ones.

SUBSYSTEM_PROBES = {
    # id -> (label, type, home crate, defining symbol, one-line description)
    "vault": ("Credential Vault", "core", "zp-trust", "CredentialVault",
              "Tiered encrypted credential store \u2014 providers / tools / system / "
              "ephemeral, ChaCha20-Poly1305 per-tier derived keys, reference chasing"),
}


def _manifest():
    p = ROOT / "docs/lenses/source-manifest.json"
    data = json.loads(p.read_text())
    return {c["name"]: c for c in data["crates"]}


def _crate_dirs():
    d = ROOT / "crates"
    return {x.name for x in d.iterdir() if x.is_dir() and (x / "Cargo.toml").exists()}


def derive_crate_nodes(declared_ids):
    """One node per workspace crate, plus the dependency edges between them.

    Crates already drawn under a different id (zp-core, mle-star, ...) keep
    their declared node; this only adds what was missing, so the curated
    labels and descriptions survive.
    """
    by_name = _manifest()
    dirs = _crate_dirs()
    # crate name -> existing node id. Built by matching declared ids against
    # crate names rather than read from a table, because CRATE_NODES was a
    # hand-written map and had the same omission problem one level down: it
    # listed eight crates and forgot zp-server, the largest one on the map.
    id_of = {v: k for k, v in CRATE_NODES.items()}
    id_of.update({d: d for d in declared_ids if d in by_name})
    nodes, edges = [], []

    for name in sorted(dirs | set(by_name)):
        if name in id_of:                                # already on the map
            continue
        c = by_name.get(name)
        if c is None:
            # In crates/ but absent from the manifest. Drawn, and drawn as a
            # gap in the manifest rather than quietly dropped -- the same
            # mistake one layer down.
            nodes.append({"id": name, "label": name, "type": "crate",
                          "desc": "crate directory exists; source-manifest.json does not "
                                  "list it, so nothing here is measured",
                          "origin": "derived"})
            continue
        n = len(c.get("consumed_by") or [])
        nodes.append({
            "id": name, "label": name, "type": "crate",
            "desc": f"{c.get('loc', 0):,} lines across {c.get('files', 0)} files "
                    f"\u2014 role {c.get('primary_role', '?')}, {n} dependent crate(s)",
            "origin": "derived"})
        id_of[name] = name

    for name, c in by_name.items():
        src = id_of.get(name, name)
        for dep in c.get("deps") or []:
            if dep in by_name:
                edges.append({"source": src, "target": id_of.get(dep, dep),
                              "label": "DEPENDS_ON", "kind": "derived"})
    return nodes, edges, by_name, dirs


def probe_subsystems(by_name):
    """Find named subsystems that are modules, not crates, by grepping for
    the type that defines them. The vault's edges are counted, not asserted:
    a crate is wired to it exactly when its sources name the type."""
    nodes, edges, states = [], [], {}
    for nid, (label, typ, home, symbol, desc) in SUBSYSTEM_PROBES.items():
        users = {}
        for crate_dir in sorted((ROOT / "crates").iterdir()):
            src = crate_dir / "src"
            if not src.is_dir():
                continue
            hits = 0
            for f in src.rglob("*.rs"):
                try:
                    hits += f.read_text(errors="ignore").count(symbol)
                except OSError:
                    pass
            if hits:
                users[crate_dir.name] = hits
        total = sum(v for k, v in users.items() if k != home)
        outside = {k: v for k, v in users.items() if k != home}
        nodes.append({"id": nid, "label": label, "type": typ, "desc": desc,
                      "origin": "derived"})
        edges.append({"source": nid, "target": home, "label": "DEFINED_IN",
                      "kind": "derived"})
        for k in sorted(outside):
            edges.append({"source": k, "target": nid, "label": "USES", "kind": "derived"})
        if outside:
            top = ", ".join(f"{k} ({v})" for k, v in
                            sorted(outside.items(), key=lambda kv: -kv[1])[:4])
            states[nid] = ("live",
                           f"{total} references to {symbol} across {len(outside)} crates "
                           f"outside {home} \u2014 {top}",
                           f"crates/{home}/src/vault.rs; grep {symbol} crates/*/src")
        else:
            states[nid] = ("unwired",
                           f"{symbol} is defined in {home} and named nowhere else",
                           f"grep {symbol} crates/*/src")
    return nodes, edges, states


def coverage(node_ids, dirs, by_name):
    """Silence and coverage must not look identical. This is the difference."""
    drawn = set(node_ids) | {CRATE_NODES[i] for i in node_ids if i in CRATE_NODES}
    missing = sorted(d for d in dirs if d not in drawn)
    unmeasured = sorted(d for d in dirs if d not in by_name)
    return {"crates_total": len(dirs), "crates_drawn": len(dirs) - len(missing),
            "crates_missing": missing, "crates_unmeasured": unmeasured}



# ── The producer-consumer rule, made mechanical ──────────────────────────
# MODEL-ADMISSION-PIPELINE-2026-08 §10.6: "before building a producer, name
# its consumer and confirm the consumer can represent what the producer
# emits." The rule was prose, so violations of it were only ever found by
# reading. This finds them.
#
# `consumed_by` counts Cargo edges and cannot see direction. zp-ontology has
# one dependent, so it scores live -- and that dependent is the cartographer,
# which is its *writer*. Five of its six read methods have never been called
# by anything. A store whose only reader is its own producer is the shape of
# a broken loop, and it was rendering the same green as a working one.
#
# Attribution is by declared dependency and by distinctive method name: a
# method whose name is also declared in another crate is discarded as
# evidence rather than guessed at, because `.get_object(` alone says nothing
# about which store it was called on. That costs recall and buys the right to
# state the result flatly.
#
# Result maps to `partial`, not a sixth colour: the existing vocabulary
# already defines partial as "built, incompletely wired -- works in one
# direction only", which is exactly this.

_WRITE_PREFIXES = ("insert_", "update_", "set_", "link_", "append_", "store_",
                   "write_", "put_", "remove_", "delete_", "record_", "save_")
_READ_PREFIXES = ("get_", "list_", "count_", "load_", "fetch_", "find_", "query_",
                  "read_", "most_", "relationships_", "receipts_", "last_",
                  "object_count", "all_", "iter_")
_GENERIC = {"new", "open", "default", "from_path", "open_memory", "clone",
            "len", "is_empty"}


def _rs_sources():
    """crate -> [(path, text)], read once."""
    out = {}
    for cd in sorted((ROOT / "crates").iterdir()):
        src = cd / "src"
        if not src.is_dir():
            continue
        out[cd.name] = [(f, f.read_text(errors="ignore")) for f in sorted(src.rglob("*.rs"))]
    return out


def store_direction(by_name):
    """For each crate exporting a *Store, who writes it and who reads it."""
    sources = _rs_sources()

    declared = {}
    for crate, files in sources.items():
        for _, txt in files:
            for m in re.finditer(r"\n\s*pub fn (\w+)", txt):
                declared.setdefault(m.group(1), set()).add(crate)

    dependents = {c: set() for c in sources}
    for crate in sources:
        t = ROOT / "crates" / crate / "Cargo.toml"
        if not t.exists():
            continue
        body = t.read_text()
        for other in sources:
            if other != crate and re.search(rf"^{re.escape(other)}\s*=", body, re.M):
                dependents.setdefault(other, set()).add(crate)

    out = {}
    for crate, files in sources.items():
        writes, reads = set(), set()
        for f, txt in files:
            if f.stem != "store" and not re.search(r"pub struct \w*Store\b", txt):
                continue
            for m in re.finditer(r"\n    pub fn (\w+)", txt):
                n = m.group(1)
                if n in _GENERIC or declared.get(n) != {crate}:
                    continue           # ambiguous name: not usable as evidence
                if n.startswith(_WRITE_PREFIXES):
                    writes.add(n)
                elif n.startswith(_READ_PREFIXES):
                    reads.add(n)
        if not (writes and reads):
            continue

        def hits(names, text):
            return len(re.findall(r"\.(" + "|".join(sorted(map(re.escape, names)))
                                  + r")\s*\(", text))

        w_by, r_by = {}, {}
        for dep in dependents.get(crate, ()):
            wt = sum(hits(writes, txt) for _, txt in sources.get(dep, ()))
            rt = sum(hits(reads, txt) for _, txt in sources.get(dep, ()))
            if wt:
                w_by[dep] = wt
            if rt:
                r_by[dep] = rt
        out[crate] = {"writers": w_by, "readers": r_by,
                      "n_write_methods": len(writes), "n_read_methods": len(reads)}
    return out


def producer_only_states(direction):
    out = {}
    for crate, d in direction.items():
        readers, writers = set(d["readers"]), set(d["writers"])
        if readers and readers <= writers:
            who = ", ".join(sorted(readers))
            out[crate] = ("partial",
                          f"store is written and read only by {who}, which is its own "
                          f"producer \u2014 nothing consumes it that does not also write it; "
                          f"{d['n_read_methods']} read methods exist for no outside caller",
                          f"crates/{crate}/src/store.rs; call-site scan over declared dependents")
    return out

def main():
    # declared half: whatever ecosystem.js names, kept for its curated labels
    gnodes, gedges = parse_graph()
    for n in gnodes:
        n.setdefault("origin", "declared")
    for e in gedges:
        e.setdefault("kind", "declared")
    declared_ids = {n["id"] for n in gnodes}

    # derived half: every crate, every workspace dep edge, every probed subsystem
    cnodes, cedges, by_name, dirs = derive_crate_nodes(declared_ids)
    snodes, sedges, sstates = probe_subsystems(by_name)

    # A declared node that IS a workspace crate was corroborated by derivation,
    # so it counts as derived. Marking zp-core "hand-declared, not found by
    # derivation" would be false: it was found, it simply already had a node.
    # What stays `declared` is the set derivation cannot speak to at all --
    # concepts, people, hardware, external services. That is the honest line:
    # not "who typed it" but "can the workspace confirm or deny it".
    crate_names = set(by_name)
    for n in gnodes:
        if n["id"] in CRATE_NODES or n["id"] in crate_names:
            n["origin"] = "derived"

    gnodes += [n for n in cnodes + snodes if n["id"] not in declared_ids]
    all_ids = {n["id"] for n in gnodes}
    gedges += [e for e in cedges + sedges
               if e["source"] in all_ids and e["target"] in all_ids
               and e["source"] != e["target"]]

    # dedupe: a declared edge and a derived edge for the same pair are one edge,
    # and the declared label wins because it says what the relationship means
    seen, deduped = set(), []
    for e in gedges:
        k = (e["source"], e["target"])
        if k in seen or (k[1], k[0]) in seen:
            continue
        seen.add(k); deduped.append(e)
    gedges = deduped

    states = dict(EVIDENCE)
    states.update(crate_states())          # measured beats hand-authored
    states.update(derived_crate_states(by_name, declared_ids))
    states.update(sstates)
    direction = store_direction(by_name)
    states.update(producer_only_states(direction))   # direction beats edge-count

    ids = [n["id"] for n in gnodes]
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
    origins = {}
    for n in gnodes:
        origins[n["origin"]] = origins.get(n["origin"], 0) + 1

    cov = coverage(ids, dirs, by_name)
    payload = {
        "generated_from_commit": head(),
        "node_total": len(ids),
        "counts": counts,
        "origins": origins,
        "coverage": cov,
        "nodes": nodes,
    }
    OUT.write_text(
        "// GENERATED by tools/ecosystem-state/ecosystem_state.py — do not edit.\n"
        "// Regenerate, then `cargo build -p zp-server` (this asset is include_str!'d).\n"
        "window.ZP_ECOSYSTEM_STATE = "
        + json.dumps(payload, indent=2) + ";\n")
    print(f"wrote {OUT.relative_to(ROOT)} — {len(ids)} nodes")
    write_artifact(gnodes, gedges, nodes, counts, origins, cov)
    for k in ("live", "partial", "unwired", "absent", "unknown"):
        if k in counts:
            print(f"  {k:<9}{counts[k]:>4}")

    # ── the guard ────────────────────────────────────────────────────────
    # Coverage is printed every run, passing or not, because a number that
    # only appears on failure trains you to read its absence as success.
    print(f"\ncrate coverage: {cov['crates_drawn']}/{cov['crates_total']} "
          f"({100*cov['crates_drawn']//max(cov['crates_total'],1)}%)")
    rc = 0

    # An unmeasured crate is the live failure mode. Derivation will still draw
    # it -- that is the point of deriving -- but it draws a node with nothing
    # behind it, because source-manifest.json has not been regenerated since
    # the crate appeared. The map would show full coverage over stale data,
    # which is the exact confusion this whole exercise exists to remove.
    if cov["crates_unmeasured"]:
        print(f"  UNMEASURED: {', '.join(cov['crates_unmeasured'])}")
        print("  in crates/ but absent from docs/lenses/source-manifest.json; "
              "these draw as nodes with no measurements behind them.")
        print("  regenerate: python3 docs/lenses/regenerate_source_manifest.py")
        rc = 1

    # This one is a postcondition, not a discovery: derivation adds a node for
    # every crate directory, so it should be impossible to trip. It is checked
    # anyway because "impossible" is a claim about code that keeps changing,
    # and an unfireable assertion costs one comparison to keep honest.
    if cov["crates_missing"]:
        print(f"  MISSING from the graph: {', '.join(cov['crates_missing'])}")
        print("  derivation dropped a crate it was supposed to add \u2014 this is a bug "
              "in derive_crate_nodes, not a gap in the map")
        rc = 1

    if rc:
        print("  refusing to call this a map of the workspace")
    return rc


def derived_crate_states(by_name, declared_ids):
    """Same rule as crate_states, applied to the crates nobody had named.

    With one correction the first pass got wrong. `consumed_by == 0` reads as
    "nothing imports this", which is only a defect for a *library*. A crate
    with no src/lib.rs exports nothing to import: zp-cli is a binary, zp-bench
    is a bench harness, and calling either unwired is a false positive dressed
    as a critical. The library test is derivable, so it is derived rather than
    hand-excepted -- an exception list would need maintaining and would rot.
    """
    out = {}
    for name, c in by_name.items():
        if name in declared_ids or name in CRATE_NODES.values():
            continue                       # already stated by EVIDENCE or crate_states
        d = ROOT / "crates" / name
        is_lib = (d / "src/lib.rs").exists()
        n = len(c.get("consumed_by") or [])
        loc = c.get("loc", 0)

        if not is_lib:
            kind = "binary" if (d / "src/main.rs").exists() else "bench or test harness"
            out[name] = ("unknown",
                         f"{loc:,} lines, no src/lib.rs \u2014 this is a {kind}, so "
                         f"'nothing imports it' is expected rather than a defect, and no "
                         f"first-party evidence was read that it runs",
                         f"crates/{name}/Cargo.toml; no crates/{name}/src/lib.rs")
        elif n == 0:
            tests = (d / "tests").is_dir()
            tail = ("; its own tests/ directory is the only thing exercising it"
                    if tests else "; it has no tests/ directory either")
            out[name] = ("unwired",
                         f"library crate, {loc:,} lines, and no crate in the workspace "
                         f"imports it{tail}",
                         "docs/lenses/source-manifest.json consumed_by")
        else:
            out[name] = ("live",
                         f"{loc:,} lines, {n} dependent crate(s), "
                         f"primary role {c.get('primary_role', '?')}",
                         "docs/lenses/source-manifest.json consumed_by")
    return out



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

W_CANVAS = 1680
H_CANVAS = 1180

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


def write_artifact(nodes, edges, states, counts, origins, cov):
    pos, deg = layout(nodes, edges)
    for n in nodes:
        st = states.get(n["id"], {"state": "unknown", "why": None, "cite": None})
        n["x"] = round(pos[n["id"]][0], 1)
        n["y"] = round(pos[n["id"]][1], 1)
        n["deg"] = deg[n["id"]]
        n["state"] = st["state"]
        n["why"] = st.get("why")
        n["cite"] = st.get("cite")
        n.setdefault("origin", "declared")
    out = ROOT / "dashboard/data/ecosystem-graph.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "generated_from_commit": head(),
        "width": W_CANVAS, "height": H_CANVAS,
        "counts": counts,
        "origins": origins,
        "coverage": cov,
        "nodes": nodes, "edges": edges,
    }, indent=2) + "\n")
    print(f"wrote {out.relative_to(ROOT)} — {len(nodes)} nodes, {len(edges)} edges")
    write_html(nodes, edges, counts, out, cov)


def write_html(nodes, edges, counts, data_path, cov):
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
            .replace("__COVERAGE__", f"{cov['crates_drawn']}/{cov['crates_total']}")
            .replace("__W__", str(W_CANVAS))
            .replace("__H__", str(H_CANVAS)))
    assert "__GRAPH_JSON__" not in html and "__W__" not in html
    dest = ROOT / "dashboard/ecosystem-map.html"
    dest.write_text(html)
    print(f"wrote {dest.relative_to(ROOT)} — {len(html):,} bytes")


if __name__ == "__main__":
    sys.exit(main())
