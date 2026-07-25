# Lens Discipline

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.17 (cognitive discipline sandwich), §III.19 (detectability), §III.22, and Part V (Composition Contract). Defines **lens** as a first-class substrate primitive: a scoped-attention discipline with structured schema, chain-anchored receipt lifecycle, and canonical composition with nested observers, coherence discipline, Cartographer, and Cognitive Input Plane. Canonical claims live in KEEL.

**Author:** Ken Romero (2026-07-21). Synthesis discussion with Claude preserved as reasoning trail; the design decisions in this document are Ken's.

**Status:** Design note. First-class primitive definition and receipt schema.

Composes with: `OBSERVER-COHERENCE-DISCIPLINE-2026-07.md`, `CHAIN-READ-CANARY-DISCIPLINE-2026-07.md`, `COGNITIVE-INPUT-PLANE-2026-07.md`, `COGNITIVE-SELF-OBSERVER-2026-07.md`, `STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md` (degenerate one-dimensional lens instance), `IMPROVEMENT-LOOP-DISCIPLINE-2026-07.md`, `OBSERVER-WINDOWS-INVESTIGATION-2026-07.md`, `EXECUTION-AUTHORITY-MODEL-2026-07.md` (Phase 6 nested observer windows), `ONTOLOGY-AND-CARTOGRAPHER-2026-07.md`, `COGNITIVE-TOOLS-OPPORTUNITY-MAPPING-2026-07.md` (first concrete lens instance).

CLAUDE.md workflow heuristic: *Opportunity markers: attention words that trigger lens application.*

---

## 1. Lens as first-class primitive

A lens is a scoped-attention discipline with the following schema:

- **`focus`**: temporal scope (short/medium/long) or domain (cognitive discipline, arc completion, trajectory coherence)
- **`dimensions`**: set of keyword categories that define the attention surface
- **`keyword_composition`**: ordered list of keywords that trigger invocation
- **`transformation_question`**: the coherence or pattern question this lens answers when invoked
- **`cross_references`**: optional links to other lenses, standing corrections, or substrate primitives

Lenses are declared once and may be composed or marked as conflicting.

## 2. Receipt schema

All lens activity is chain-anchored via the following receipt types:

- **`lens:declared:<lens_id>`** — initial declaration with full schema above. Signed by operator or Regent. Content-addressed.
- **`lens:applied:<lens_id>:<invocation_id>`** — emitted on every invocation. Carries: current work context hash, matched keyword_composition, transformation_question result, observer window that triggered it. Deterministic.
- **`lens:composed:<lens_a>:<lens_b>`** — declares that two lenses share keywords or dimensions and may be used together.
- **`lens:conflicts:<lens_a>:<lens_b>`** — declares that two lenses prescribe contradictory transformations on overlapping contexts.

All receipts are content-addressed, operator- or Regent-signed, and peer-verifiable by hash equality.

## 3. Composition with nested observers

Each observer window maintains its own lens set:

- **Short window**: immediate cognitive discipline lenses
- **Medium window**: arc completion and pattern accumulation lenses
- **Long window**: precedent chain and identity coherence lenses

Lens application is itself an observable event. Nested observers query `lens:applied` receipts to detect:

- Which lenses fired this cycle (short)
- Which lenses fired disproportionately during an arc (medium)
- Which lenses have gone silent over a trajectory (long)

Silent lens over long window is as significant as loud lens over short window — different failure mode, same observer machinery.

## 4. Composition with observer coherence discipline

Add **lens application coherence** as a new coherence class. If two observers (or operator + Regent) apply the same lens to the same work context and produce divergent invocations, that divergence is a coherence signal. Same discipline as chain readers or ontology queriers.

## 5. Composition with Cartographer

Cartographer materializes lens receipts into ontology nodes. Projects a lens graph showing:

- Active lenses per scope
- Composition relationships
- Conflicts
- Silence detection over time

Regent queries this graph as part of cognitive input plane composition: which lenses belong at Tier 1 for this cycle's context?

## 6. Outside-in / inside-out / view-in generalization

The lens structure is directional-agnostic. Three canonical directions of application:

- **Outside-in** — external framings composed with substrate primitives. Research, market landscape, adjacent-domain analogy, use-case scenarios. Example: `COGNITIVE-TOOLS-OPPORTUNITY-MAPPING-2026-07.md`.
- **Inside-out** — substrate self-observation at declared temporal scale. Nested observer windows, officer attention scopes, cognitive input plane composition. Example: officer lens declarations (formalized in `OFFICER-LENS-DECLARATIONS-2026-07.md`).
- **View-in** — operator UI projection of substrate state. Visualization surfaces that render substrate ontology through a specific question. Example: `zp-visual-language.md` four visualization lenses formalized in §7 below.

Same schema, same receipt types, same observer composition across all three directions.

## 7. Composition with visualization lenses (`zp-visual-language.md`)

The `zp-visual-language.md` four-lens visualization system (Abacus / Weave / CodeFlow / Walk) predates this formalization and uses "lens" in the view-in sense. Composition unifies both meanings under the same schema: each visualization lens is a `lens:declared:*` instance whose transformation_question is the operator-facing question the visualization answers, whose dimensions are the domain fields it renders, and whose keyword_composition is the receipts and concepts it consumes.

### Abacus — `lens:declared:visualization_abacus`

- **`focus`**: temporal + volume view of substrate activity (view-in)
- **`dimensions`**: time, receipt-type, actor, wire, epoch, outcome
- **`keyword_composition`**: [event stream, audit bead, receipt, telemetry, timeline, count, cadence, preflight, when, how many, live flow]
- **`transformation_question`**: *"when did this happen and how much of it?"*
- **`cross_references`**: chain integrity discipline, canary discipline, cognitive input composition receipts, epoch anchoring

### Weave — `lens:declared:visualization_weave`

- **`focus`**: authority and capability topology (view-in)
- **`dimensions`**: identity, delegation, capability, hierarchy, sovereign root, consumption relationship
- **`keyword_composition`**: [delegation, capability, sovereignty, hierarchy, key, agent, tool, provider, credential, authority, grant, revoke]
- **`transformation_question`**: *"who can do this, authorized by whom?"*
- **`cross_references`**: sovereignty provider system, delegation grants, `VAULT-KEY-SOVEREIGNTY-COMPOSITION-2026-07.md`, `GENESIS-ROTATION-CEREMONY-2026-07.md`

### CodeFlow — `lens:declared:visualization_codeflow`

- **`focus`**: derivation and provenance (view-in)
- **`dimensions`**: derivation edge, receipt lineage, hash-linkage, attestation, supersession, contradiction
- **`keyword_composition`**: [derivation, provenance, chains-from, supersedes, attests, signed-by, contradicts, verifies, integrity, hash-linkage, DAG]
- **`transformation_question`**: *"how was this derived?"*
- **`cross_references`**: chain integrity, `STANDING-CORRECTION-RECEIPT-SCHEMA` supersedes semantics, canary receipts, epoch anchoring

### Walk — lens-composition transport operator

Walk is distinct from the three spatial lenses. Per `zp-visual-language.md`: *"Walk is the interaction layer. It composes with any spatial lens."* Formally, Walk is not a lens itself — it is a **lens-composition transport operator** that traverses time and causation through any declared lens. Its role in this discipline is analogous to how operators compose or conflict lenses; Walk composes the temporal/causal dimension across any active lens.

Suggested receipt: `lens:transport:walk:<invocation_id>` for chain-anchored replay/scrub events, distinct from `lens:applied:*` because Walk operates over lenses rather than being invoked as one.

## 8. Reflexivity bounding

Lens-of-lens terminates structurally: a lens applied to itself either matches its own `keyword_composition` (invokes once, terminates) or does not (no invocation). No policy cap required. Bounded by definition.

## 9. Open design decision

Corpus primitive (chain-anchored receipts) vs workflow discipline (prose only). The nested-observer composition makes the stronger case for corpus primitive: inside-out lenses must be chain-anchored to be observable across time by the Regent and nested observers. This spec treats all four receipt types as load-bearing corpus primitives.
