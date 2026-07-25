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
python3 docs/lenses/regenerate_manifest.py > docs/lenses/manifest.json
```

(Script to be added — currently the extraction logic is embedded in the
session that produced this artifact. Extractor lives in the transcript.)

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
  becomes available alongside the corpus lens.

---

## Source-CodeFlow (added 2026-07-25)

Companion artifact: **`source-codeflow.html`** — the substrate's **source
tree** through the flow lenses, complementing the corpus lenses above. Same
visual grammar; different data source (crates instead of docs).

### What it extracts

The extractor (embedded in the session that produced this artifact; see the
session transcript for the Python) walks `crates/*/src/**/*.rs` and produces
`source-manifest.json` with, per crate:

- **Cross-crate dependencies** (from Cargo.toml + `use` statements)
- **Info-flow signal counts** per class:
  - `sign_count` — `.sign()`, `SigningKey`, `HKDF`, `ed25519` occurrences
  - `gate_count` — `gate.check`, `PolicyEngine`, `verify_delegation`, gate/policy dispatch sites
  - `chain_count` — `chain.append`, `AuditStore::write`, `emit_receipt` sites
  - `verify_count` — `.verify()`, `verify_chain`, `verify_integrity` sites
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

Five toggleable overlays in the header — signing / gating / chain-emit /
verifying / receipt-authoring. When toggled, colored edges are drawn over
the dependency skeleton where either endpoint has non-zero signal in that
class. Edge opacity scales with combined signal. Flip **signing** to see
which dep-chains carry identity crypto; flip **gating** to see the policy
dispatch cone; flip **chain-emit** to see who actually writes to the chain.

### Sidebar

Empty state: **info-flow hot spots** — top 5 crates per role, each clickable
to drill in. Once a crate is selected, sidebar shows its role, file/LOC
counts, all six signal counts, dep and consumer lists (each clickable),
receipt families authored, and a sample of the receipt slugs found in its
source.

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
