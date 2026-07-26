# docs/lenses — ZeroPoint through the four canonical lenses

Self-contained visualization of the ZP corpus through the four lenses defined
in `docs/design/zp-visual-language.md`. Draws from the corpus itself as its
first target — since the runtime chain isn't live yet, the corpus IS what
there is to see. Same lens grammar will apply to receipts, delegation, and
information flow once the runtime materializes.

## Files

- **`zeropoint-through-four-lenses.html`** — the artifact. Single self-contained
  HTML, no CDN, ZP-dark palette. Three spatial lenses (Abacus, Weave, CodeFlow)
  plus Walk transport across the bottom. Open in any browser.
- **`manifest.json`** — the corpus manifest the artifact reads. Extracted from
  `docs/**/*.md` by walking each doc for its declared tier, composes-with
  references, KEEL section citations, build state, and mtime.

## Lens map

| Lens | Question | What it shows |
|---|---|---|
| **Abacus** | *When? How many?* | Three time-wires (docs/, docs/design/, docs/handoffs/), one bead per doc, placed at declared_date (falling back to mtime). Bead shape encodes build state; wire color encodes subdir. |
| **Weave** | *Who, authorized by whom?* | KEEL at center, elaborations orbiting in three sectors by subdir. Dashed edges = composes-with; solid edges = elaborates-KEEL. |
| **CodeFlow** | *How derived?* | Layered DAG with BFS depth from KEEL as column position. Leaves at the right. |
| **Walk** | *In what order, along what path?* | Transport bar across the bottom (Play/Reset/Scrub). Filters visible nodes to those with declared_date ≤ scrub position, replaying the corpus in temporal order. Composes with any spatial lens. |

## Build state

Each doc is classified `built | partial | scaffolded | candidate | unknown`
based on cross-referencing the doc's code mentions (`crates/zp-*`, `zp-*`
crate references, `tools/*` paths) against what actually exists in the
repo tree, plus aspirational-phrase signals (*"not yet implemented"*,
*"blocked on"*, *"immediate design work"*, *"pending implementation"*).
Filter chips in the header toggle visibility per build state.

Visual encoding of build state per node:
- **built** → solid filled circle
- **partial** → 50%-fill circle with heavier stroke
- **scaffolded** → hollow ring (bg-filled)
- **candidate** → dashed hollow ring
- **unknown** → tiny dim outline (filter defaults to hidden)

## Regenerating the manifest

The manifest is a snapshot at generation time. To refresh after doc changes:

```bash
cd <repo-root>
python3 docs/lenses/regenerate_manifest.py
```

Writes to `docs/lenses/manifest.json`. The extractor walks `docs/**/*.md`
(scoped to root + `design/` + `handoffs/` by default; use `--all-subdirs`
for exhaustive). Per-doc it extracts tier, subdir, mtime, word count,
declared date, author, code mentions cross-referenced against actual repo
directories, aspirational-phrase signals, composes-with edges, and reverse
edges. Options:

- `--out PATH` — write to a different path.
- `--root DOC` — set the corpus root anchor (default: `KEEL-2026-07.md`).
- `--all-subdirs` — walk every subdir under `docs/`, not just the two
  the artifact renders.

Build state is derived from cross-referencing code mentions against
`existing_code` (children of `crates/`, `tools/`, and top-level repo dirs
outside the blocklist) plus aspirational-phrase counts. Tune patterns
inline in the script — the totals it prints to stdout make drift legible.

Re-running today may produce slightly different totals than the currently
delivered `manifest.json` — the extractor patterns were refined when they
were lifted from the ad-hoc session logic into a persistent script.
Structure and semantics stay the same; individual counts may drift.
Regenerate to make the current authoritative and diff the stdout output
against the counts in the delivered manifest if the numbers matter.

## Composition with the rest of the visual substrate

- Composes with `docs/design/zp-visual-language.md` — this artifact is the
  first end-to-end implementation of the four-lens grammar (Walk currently
  formalized as transport bar only; spatial-lens drill-through partially
  wired).
- Composes with `docs/design/LENS-DISCIPLINE-2026-07.md` §7 — each of the
  three spatial lenses here is a concrete view-in `lens:declared:*` instance.
- Composes with `tools/mindmap-mcp` — the hierarchical mindmap tool
  complements the graph tools with a declarative structured-summary lens
  (not one of the four canonical, but composes with the same JSON-in / SVG-out
  contract).

## Non-goals for this iteration

- **Not a runtime chain viewer.** The corpus is a proxy for the eventual
  target (receipts + delegation + information flow). Same lens grammar will
  apply; different data source.
- **Not a code call-graph.** `graph-viz-wasm` + the graphify corpus already
  cover file/module structure at ~126K nodes. This artifact is about the
  design corpus and its composition, not the source tree.
- **Not a live editor.** The manifest is a snapshot; the artifact renders
  what's in it. Regenerate to reflect doc changes.

## Follow-ups

- Add real Walk state-transitions (per zp-visual-language: nodes light
  pending → active → settled as traversal advances). Currently the scrub bar
  just filters visible; the promised three-state activation animation is
  scoped out.
- Add a runtime-source variant that reads from a live chain query rather
  than the corpus manifest. Same lens grammar; different data source. Blocked
  on chain runtime.
- Extend graphify's extractor with the five information-flow edge classes
  proposed in the previous session (type-flow, receipt-schema, gate-crossings,
  signing seams, channel boundaries) so a CodeFlow lens over the *source tree*
  becomes available alongside the corpus lens. **Shipped as
  `source-codeflow.html`** — see section below.

---

## Source-CodeFlow (added 2026-07-25)

Companion artifact: **`source-codeflow.html`** — the substrate's **source
tree** through the flow lenses, complementing the corpus lenses above. Same
visual grammar; different data source (crates instead of docs).

### What it extracts

Two extractors ship; either produces the same `source-manifest.json` schema.

**`regenerate_source_manifest.py`** — regex-based, no build step, no Rust
toolchain required. Runs in ~2s on the 42-crate tree. Under-counts
struct-field types (scans only fn signatures), misses impl-block context,
mis-terminates on complex generics.

```bash
cd <repo-root>
python3 docs/lenses/regenerate_source_manifest.py
```

**`rust-ast-extractor/`** — real AST via `syn`. Runs in ~0.5s once built.
Catches struct/enum field types, impl-block method signatures with correct
impl-target attribution, complex generics with nested bounds, `pub use`
re-exports, and unions. See `docs/lenses/rust-ast-extractor/README.md` for
the snapshot comparison — AST produces about 27% more type-flow edges and
60% more type-flow signals than regex, from struct fields and impl blocks
that regex never sees.

```bash
cargo run --release \
  --manifest-path docs/lenses/rust-ast-extractor/Cargo.toml \
  -- --repo-root . --out docs/lenses/source-manifest.json
```

Both accept the same options: `--out PATH`, `--include-tools`. Both walk
`crates/*/**/*.rs` (every Rust file under each crate: `src/`, `benches/`,
`examples/`) and produce `source-manifest.json` with, per crate:

- **Cross-crate dependencies** (from Cargo.toml + `use` statements)
- **Info-flow signal counts** per class:
  - `sign_count` — `.sign()`, `SigningKey`, `HKDF`, `ed25519` occurrences
  - `gate_count` — `gate.check`, `PolicyEngine`, `verify_delegation`, gate/policy dispatch sites
  - `chain_count` — `chain.append`, `AuditStore::write`, `emit_receipt` sites
  - `verify_count` — `.verify()`, `verify_chain`, `verify_integrity` sites
- **Type-flow edges** — regex-based approximation of AST walking. Walks each
  `.rs` file, extracts type definitions (`struct` / `enum` / `type` /
  `pub struct` etc.) into a `type→owning-crate` map, then scans function
  signatures (returns + parameters) to attribute each type reference to a
  consumer crate. Aggregates as `types_produced` (per crate), `types_consumed`
  (per crate), and `type_flow_edges` (per producer→consumer crate pair with
  weight and top types). Filters out std/prim types. Not a full AST parse
  (no `syn`/`rust-analyzer` yet) but good enough to reveal implicit type
  channels including some that cross without a corresponding dep declaration.
- **Receipt-family authorship** — string literals matching known receipt-type
  prefixes (`regent:*`, `observation:*`, `embodiment:*`, `cognitive:*`,
  `coherence:*`, and more).
- **Primary role** — argmax over the signal counts, classifying each crate as
  `signing` | `gating` | `chain-emit` | `verifying` | `receipt-authoring` |
  `utility`.

### Two lenses

- **CodeFlow** — layered by dependency depth. Foundation crates (no
  ZP deps) at left; consumers at right. Node size = info-flow signal density.
  Node color = primary role. The picture shows how signing signal flows from
  identity crates through receipt crates to the server hub.
- **Weave** — radial dependency topology. Foundation at center; consumer
  rings outward. Angular position clustered by primary role so roles cluster
  together on each ring.

### Info-flow overlays

Six toggleable overlays in the header — signing / gating / chain-emit /
verifying / receipt-authoring / **type-flow**. When toggled, colored edges
are drawn over the dependency skeleton where either endpoint has non-zero
signal in that class. Edge opacity scales with combined signal. Flip
**signing** to see which dep-chains carry identity crypto; flip **gating**
to see the policy dispatch cone; flip **chain-emit** to see who actually
writes to the chain; flip **type-flow** to see the implicit type channels
(lavender arcs, weighted by count, drawn independently of the dep edges — so
you can spot type-crossings that don't line up with declared deps).

Type-flow shares canvas geometry with the other five overlays but is drawn
from the aggregated `type_flow_edges` set, not from crate deps directly. The
overlay caps at the top-60 edges by weight to stay readable; edges above the
weight threshold get inline count labels.

Overlays can be preselected via URL param: `?overlay=type-flow` (or any of
the other five) opens the artifact with that overlay pre-toggled.

### Sidebar

Empty state: **info-flow hot spots** — top 5 crates per role plus a
type-flow pseudo-role (top type producers and consumers), each clickable to
drill in. Once a crate is selected, sidebar shows its role, file/LOC counts,
all signal counts, dep and consumer lists (each clickable), receipt families
authored, a sample of the receipt slugs found in its source, and a
**type-flow section**: top types produced (defined in this crate), top types
consumed (referenced from other crates' definitions), and per-neighbor
IN/OUT type flows with the specific type list on each edge.

### Composes with

- **`docs/design/zp-visual-language.md`** — this artifact is the first
  end-to-end CodeFlow rendering over the *source* rather than a receipt chain.
  Same lens grammar; different substrate.
- **`docs/design/LENS-DISCIPLINE-2026-07.md`** §7 — the two spatial lenses
  are concrete `lens:declared:*` instances in the inside-out direction
  (substrate self-observation).
- **`graph-viz-wasm/`** and **`graphify-out/`** — where the file/module
  organizational graph already lives at 126K+ nodes. This artifact operates
  at crate granularity, showing information-flow signals rather than
  organizational structure. When the runtime is live, edge overlays here can
  be augmented with actual receipt-emission counts from the chain (rather
  than static grep counts from source).

### Non-goals for this iteration

- **Not a live receipt viewer.** Overlays reflect *where in the source* the
  info-flow classes live, not *what fires at runtime*. Fold in chain
  telemetry when the runtime lands.
- **Not file-granular.** Crate-level is enough to see the substrate's flow
  shape without drowning in noise. File-drill is a later add.
- **Not integrity-checked.** The dashed-red-edge-for-integrity-break behavior
  in zp-visual-language belongs to a CodeFlow-over-receipts, not a
  CodeFlow-over-source. What this artifact gives you is the map; integrity
  overlay comes with the runtime.
- **Type-flow shape depends on which extractor produced the manifest.**
  The regex extractor misses struct/enum field types and impl-block
  method context; the AST extractor catches both. Neither expands
  macros, so `#[derive(...)]`-generated types and macro-authored types
  are absent either way — a full `rust-analyzer` semantic pass would
  close that gap. Rough estimate: ~5-8% of substrate type usage.

### Snapshot at extraction

At the time of this artifact (2026-07-25), the source tree has 42 crates,
121 declared dependencies, 1,185 type definitions, and 213 cross-crate
type-flow edges carrying 3,206 type-flow signals. Biggest producers:
`zp-mesh` (246), `zp-server` (212), `zp-keys` (199). Biggest sink:
`zp-server` (363 consumed). Notable type-flow that doesn't align with dep
declarations: worth checking when the overlay is on.

Re-running `regenerate_source_manifest.py` today may produce slightly
different counts than the snapshot above — the pattern set was refined when
it was extracted into a persistent script (broadened crypto identifier
matching, wider gate/chain/verify patterns, inclusive crate discovery).
The shape stays right; individual signal totals may drift. Regenerate to
make the current numbers authoritative — the extractor's stdout output
makes the drift legible.
