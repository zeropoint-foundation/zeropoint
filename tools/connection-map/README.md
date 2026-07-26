# connection-map

P1 of [`docs/design/CONNECTION-INTEGRITY-PROGRAM-2026-07.md`](../../docs/design/CONNECTION-INTEGRITY-PROGRAM-2026-07.md).

Derives the substrate's declared connections from sources already in the tree and assigns each one a status. **Nobody authors the inventory.** A hand-authored connection map would be the ninth variety of the defect the program exists to catch — an authoritative-looking artifact drifting silently from what it describes.

```bash
python3 tools/connection-map/connection_map.py .
```

Writes `connections.json` beside the script and prints a summary. The JSON is committed so drift is diffable between runs, the same way `docs/lenses/source-manifest.json` is.

## What counts as a connection

A **declared dependency, at its declaration site.** Someone wrote it down; the question this tool answers is whether anything checks that the far end is honoured.

Derived edges are deliberately out of scope. `graphify-out/graph.json` carries 126,231 nodes and 358,825 function-level links, none of which anyone asserted — so none of them can be an *unhonoured assertion*. This also settles the program's §9 alternative "extend graphify instead": graphify answers a different question. Call-graph reachability is not connection integrity.

This resolves the program's §10 open position on granularity. The unit is not uniform across kinds and should not be: it is whatever unit the declaration itself uses.

## Status

| Status | Meaning |
|---|---|
| `live` | a detector exists that would fail if this edge broke |
| `tied_off` | a declared exception carrying its reason at the site |
| `defect` | neither — including every edge nobody has classified |

There is deliberately no "works today." An edge that works and would break silently is a defect that has not fired yet.

## Sources

| Kind | Declaration site | Detector when live |
|---|---|---|
| `crate_dep` | `crates/*/Cargo.toml` path deps | `cargo build --workspace` |
| `code_to_corpus` | `//! Spec:` module citations | `corpus-lint check_spec_citations` |
| `corpus_to_code` | governed docs naming `` `crates/…/*.rs` `` | **none** — check_spec_citations is code→doc only |
| `corpus_to_keel` | `**Elaborates:**` §-references | `corpus-lint check_keel_refs` |
| `corpus_to_chain` | receipt strings in governed docs | `corpus-lint check_receipt_vocabulary` |
| `code_to_artifact` | `include_str!` / `read_to_string` / `File::open` / `read_dir` | `rustc` for compile-time embeds only |
| `pin` / `pin_exception` | `crates/zp-discipline/tests/*.rs` | `cargo test -p zp-discipline --no-fail-fast` |

Tier 3 and superseded documents are excluded from claim checks and the count is reported, not silently dropped. Their claims predate the conventions, and flagging them reports the corpus's age as a defect — the same error `corpus-lint`'s `frozen()` exists to avoid. The two definitions are deliberate mirrors and must not drift.

## Known limits

Both are owed to P2 and both are stated here rather than left to be discovered:

- **`code_to_artifact` overstates the C7 count.** It does not yet separate *operator data* reads (vault, config, session — resolved through `zp_core::paths`, legitimately absent on first run, handled) from *substrate artifact* reads (dossiers, prompts, policies — shipped with the substrate, and the actual C7 surface). Partitioning needs the path's provenance, not its call shape.
- **A tie-off does not attach across sites.** The dossier tie-off is recorded where the path is *constructed* (`crates/zp-server/src/regent.rs`); the `read_dir` that consumes it is in `crates/zp-regent/src/routing.rs` and still counts as a defect. Correct in the strict sense — that read is genuinely unchecked — but it means one declared exception can leave a related edge red.

Anything the tool skips is reported under `dropped`. No silent caps.
