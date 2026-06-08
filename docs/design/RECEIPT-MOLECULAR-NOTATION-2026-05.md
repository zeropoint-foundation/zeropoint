# Receipt Chain Molecular Notation — Design Note

*2026-05-19. Design inspiration from observing that a DMT molecule rendered
in standard skeletal/structural notation visually resembles ZeroPoint's
receipt chain graphs. Pursuing the analogy further: chemistry has spent
two centuries refining notation that conveys multiple kinds of information
simultaneously, with the eye doing semantic decoding. ZeroPoint's receipt
language can adopt that same density of meaning by mapping receipt
primitives onto molecular primitives.*

*This document captures the mapping, the vocabulary, the architectural
implications, and a phased adoption plan. Implementation follows; the
mapping is the design seed.*

## The observation

Standard molecular notation (skeletal/structural formulae) carries
information at four superimposed layers:

1. **Atoms** at vertices and labeled positions — carbon implicit at
   bends, heteroatoms (N, O, S, P) labeled where they appear
2. **Bonds** as lines — single, double, triple, sometimes wedge/dash
   for stereochemistry
3. **Functional groups** — recognized clusters (hydroxyl, amine,
   aromatic ring) read at a glance as semantic units, not assembled
   from primitives
4. **Composition** — rings indicate cyclic structure, branches
   indicate substituents, the whole describes a coherent compound

The eye decodes all four layers simultaneously. A chemist sees not
"thirteen carbons and one nitrogen with these bonds" but rather "an
indole ring with an ethylamine side chain bearing dimethyl substituents
on the nitrogen" — semantic structure at the appropriate level of
abstraction.

ZeroPoint's receipt chain has the same multi-layered structural truth
that current vocabulary collapses:

1. **Receipt instances** at vertices — most are common operational
   events (tool-fired, gate-allowed) that don't need labels;
   sovereign events (Genesis seal, canonicalization, key rotation)
   are heteroatoms — labeled because they change the chain's
   fundamental character
2. **Relationships** as edges — hash-link (chain backbone),
   reference (delegation parent, supersession), derivation
   (reconciliation pair), all currently undifferentiated in vocabulary
   but structurally distinct
3. **Recognized patterns** — onboarding ceremony, delegation
   grant-revoke pair, restart cycle, gate-allow-then-deny inversion;
   today rendered as sequences, but functionally a "functional group"
4. **Composition** — chains compose into branches (multi-receipt
   tool calls), rings (closed ceremonies), and side groups (audit
   trails parallel to operational flow)

The visual resemblance Ken observed isn't aesthetic — it's structural.
Receipts compose the way atoms do.

## The mapping

| Molecular | Receipt-chain | Notes |
|-----------|---------------|-------|
| Carbon vertex (implicit) | Common operational receipt (tool fired, gate decision, observation) | Don't label every node; the backbone reads as a line |
| Heteroatom (N, O, S, labeled) | Sovereign event — Genesis seal, canonicalization receipt, key rotation, sovereignty change | Labeled because they change the chain's character |
| Single bond | Hash-link to previous receipt | The backbone of the chain |
| Double bond | Cryptographic anchor — signature verification edge between receipt and signer's pubkey | Stronger structural commitment |
| Triple bond | (reserved) | Could indicate triple-attestation receipts in future |
| Aromatic ring | Closed ceremony (onboarding wizard run, e.g.) — sequence of receipts that closes back on itself | Recognized as a coherent unit, not decomposed |
| Side chain | Receipt cluster derived from one trigger (tool call emits launch + audit + cost receipts as parallel events) | Branches off the backbone |
| Functional group | Named recognized pattern (delegation grant + revoke, restart cycle, gate-allow-then-deny) | Operators read patterns as units |
| Wedge bond (stereochemistry) | Trust-tier annotation — which Required/Possible/Actual layer this lives in | Position in modal space |
| Charge annotation (+/−) | Surplus/deficit attestation — receipt with extra or missing signatures | Visible deviation from neutral |
| Lone pair | Pending or unsigned receipt — has capacity to receive future attestation | Open valence |

The mapping is bidirectional: every molecular primitive maps to a
substrate concept, and every substrate concept finds a molecular
analogue. Where it doesn't yet, the gap is interesting — it either
identifies an underdeveloped part of the substrate or an
overconstrained part of the notation.

## New terminology

The receipt language gains a layer of structural vocabulary. Adopting
the chemistry analogue gives ZP:

- **Backbone** — the canonical hash-linked sequence from Genesis to
  current head. Replaces "the chain" where structural emphasis is
  needed; "the chain" remains the broader system noun.
- **Substituent** — a receipt attached to the backbone by a non-
  hash-link edge (a reference, a derivation). Captures relationships
  that current vocabulary either ignores or treats as metadata.
- **Functional group** — a named pattern of receipts that operates as
  a unit. Examples: `onboarding-ceremony`, `delegation-cycle`,
  `restart-cluster`. Each is a recognized substrate pattern with a
  characteristic shape.
- **Valence** — the number of distinct edge types a receipt kind can
  carry. Genesis seal has valence n (many things reference it). A
  routine tool-fired receipt has valence 1–2 (hash-link + maybe one
  reference). Higher valence = more structural participation.
- **Sovereign atom** — a heteroatom receipt: Genesis, canonicalization,
  sovereignty change. Heteroatoms anchor structure; sovereign atoms
  anchor trust.
- **Aromatic** — a ceremony pattern that closes (start receipt
  references a corresponding end receipt). Stable, recognizable,
  participates in larger structures.
- **Open valence** — a receipt with pending attestation capacity
  (unsigned, awaiting reference). Today's substrate would call this
  "incomplete"; the analogue makes it a structural feature, not a
  defect.

These terms go into `docs/design/VOCABULARY-LOCK.md` as Tier-3
vocabulary (structural notation), separate from but consistent with
Tier-1 (canonical entities) and Tier-2 (formal modal operators).

## What this enables

### Visualization (immediate — informs #145)

The chain renders as a molecular structure, not a vertical card list:

- Backbone is the visible spine, drawn as a polyline
- Sovereign atoms (Genesis, canonicalization receipts) stand out
  visually (e.g., colored vertex with label) where they appear
- Substituents draw as branches off the backbone
- Functional groups are recognized and rendered as named clusters
  (a closed onboarding ceremony renders as a labeled ring)
- Anomalies surface structurally — broken hash-link draws as a
  missing bond; unsigned receipt shows open valence; tampered
  receipt as phantom edge that doesn't compose

The operator (or visitor) reads chain shape at a glance: "routine
day" (clean linear backbone with a few branches), "ceremony day"
(visible aromatic structure), "anomalous activity" (broken bonds,
unexpected valence).

### Verification (structural checks)

`zp verify` gains structural assertions in addition to current
signature + hash-link checks:

- Aromatic closure: ceremonies that should close as rings actually do
- Valence conservation: a receipt's declared valence matches its
  observed edge count
- Functional-group integrity: recognized patterns appear in canonical
  form (e.g., a delegation cycle has the expected grant + active +
  revoke triplet)

These checks are derived, not asserted — the structural rules emerge
from the molecular vocabulary applied to the receipt schema.

### Operator mental model

The biggest gain. Chemists don't reason about molecules atom-by-atom
once their training is complete; they reason about functional groups
and structural classes. Operators reasoning about chains atom-by-atom
hit cognitive ceilings around 20–50 receipts. Operators reasoning
about functional groups and structural patterns can read chains of
thousands of receipts at a glance.

This is the legibility layer the substrate has been missing — not
just visual, but conceptual.

### Documentation and pedagogy

The chemistry analogue is a stronger teaching device than "it's a
log of signed events." Visitors to the marketing surface get the
concept faster when it's presented as "a chemistry of trust" — the
metaphor carries its weight.

### Ambient deployment and fluency

The visualization is not a page, not a component, not a marketing
exhibit. It is a **system-level UI primitive** present across every
operator surface — collapsible sidebar in the daily working view,
expandable to full visualization on demand, lit by real-time
animation when chain events occur. Wherever ZeroPoint shows up, the
chain shows up with the visualizer rendering it.

**The goal is fluency.** Chemists develop their reading of molecular
structures through years of repeated exposure — textbooks, papers,
lectures, lab notebooks, whiteboard sketches. The structures become
*readable like sentences*: apprehended whole, not decoded atom-by-atom.
Operators develop receipt-chain fluency the same way: through repeated
exposure to the chain visualized consistently, with significant
events lighting up in real time, until the operator reads chain shape
the way a chemist reads a structural formula.

**Deployment characteristics:**

- **Ambient** — visible in the operator's peripheral vision during
  routine work. Collapsed sidebar mode shows the chain's tail (most
  recent N receipts) with minimal real estate; expanded mode shows
  the full visualization. The collapsed mode is the default; the
  operator's eye registers chain activity without leaving their
  primary task.
- **Real-time animated** — receipts appearing in real time animate
  visibly. Signing events visually form the bond between the new
  receipt and its predecessor; the bond "lights up" as the signature
  completes. Anomalies (broken hash-links, unsigned receipts,
  unexpected valence) draw attention through color and motion. The
  operator's peripheral awareness picks up the substrate's pulse.
- **Cross-surface consistent** — the same visual primitive appears
  in IronClaw chat, the foundation web surface, the wizard, the
  operator dashboard, `zp doctor` output, `zp ps` output, any
  future UI. One rendering language, many embeddings.
- **Designed for glance, available for depth** — at a glance: chain
  is healthy, a ceremony is in progress, an anomaly is present. On
  click: full receipt content, verification trace, signer attribution,
  related-receipt navigation.
- **Speaking the language** — Sage's narration, surface copy, error
  messages, CLI help text, and documentation all use molecular
  vocabulary consistently. Operators learn the language through
  repeated exposure in context, not from a one-time reading of the
  spec. The vocabulary becomes second nature because every surface
  reinforces it.

**Why this matters architecturally:**

The substrate's central claim is that the chain is the source of
truth. But truth surfaces only matter if they're read. Today the
chain is invisible — captured but rarely consulted; more artifact
than operating surface. Making the chain ambient makes it consulted.
Making it consulted makes it operational. Making it operational
closes the loop on Principle 1 (signing is gravity) — the chain
isn't gravity if no one feels it. Ambient visibility creates the
gravity that the cryptographic signing has earned.

This is also how the visualization graduates from "marketing
exhibit" to "operator instrument." A surface someone sees once is
decoration; a surface someone sees daily becomes literacy.
**Receipt-chain fluency is the literacy.** And literacy is what
turns the substrate from infrastructure-the-operator-trusts-because-
we-say-so into infrastructure-the-operator-reads-and-verifies-by-
reflex.

This composes with several adjacent design threads:

- **`docs/AGENT-AS-UX-ARCHITECTURE-2026-05.md`** — same theme of UX
  designed around continuous-presence rather than discrete-event
  surfaces, applied here to the chain itself
- **Sage's voice in the narration layer** (per
  `RECEIPT-CHAIN-VIZ-2026-05.md`) — becomes the in-line tutor for
  the molecular language; every animated event has a phrase
  attached that teaches the vocabulary in context
- **The "substrate proposes; operators sign" heuristic** (CLAUDE.md)
  — ambient visualization is the substrate proposing what it sees;
  operator interpretation is the literacy that turns proposal into
  understanding
- **Principle 7 (Contact does not commit)** — ambient visualization
  shows contact (events arriving, open valence, unsigned receipts)
  separately from commitment (signing, closed bonds, anchored
  structure). The operator sees the difference because the visual
  language has separate notation for each.

## Architectural implications

This mapping isn't just decorative. It surfaces architectural facts
the current vocabulary collapses:

- **Receipts have multiple relationship types**, today undifferentiated
  in the schema beyond `prev_hash`. Adopting molecular notation
  requires first-class edge typing in the schema (single bond =
  hash-link; double bond = signature anchor; reference bond =
  delegation parent).
- **Receipts have valence**, currently implicit. Making valence
  explicit requires schema annotations per receipt kind ("this
  receipt type can participate in N kinds of relationships").
- **Patterns are first-class**, currently inferred at query time.
  Functional groups become named substrate entities — the chain
  doesn't just record "these N receipts happened in order" but
  "these N receipts compose into a delegation cycle."
- **Stereochemistry maps onto modal layers** — wedge/dash bonds
  show relative orientation in 3D collapsed to 2D; trust-tier
  annotations show position in the Required/Possible/Actual modal
  space collapsed to the chain's 2D rendering.

In short: the substrate already has this structure; molecular
notation forces us to name and check it.

## Phases of adoption

**Phase 1 — Vocabulary capture (this document)**

Capture the mapping, the new terminology, the implications. No code
changes; the doc exists so subsequent work has a foundation.

**Phase 2 — Edge type explicitness (schema work)**

Receipt schema gains an `edge_type` field distinguishing hash-link
from reference from derivation. Migration: existing chains treat
implicit edges as hash-link; new receipts emit edge_type per
relationship. Composes with the foundation-worker-sign-receipts work
(#143) — the foundation chain becomes signed AND structurally
typed in one architectural pass.

**Phase 3 — Valence annotations**

Each receipt kind declares its valence and permitted edge types.
Verification gains structural checks. Discipline pin candidate:
"a receipt kind's observed edges must conform to its declared
valence."

**Phase 4 — Functional group recognition**

Named patterns become first-class. The substrate offers a
`zp chain pattern <pattern-name>` query: "find all delegation
cycles in the chain," "list all completed onboarding ceremonies."
Catalog of recognized patterns grows over time, each documented.

**Phase 5 — Molecular rendering**

The chain visualizer (#145) renders using molecular conventions.
Layout algorithms borrow from cheminformatics (force-directed
layouts, template-based rendering for known functional groups).
Sage's narration uses the molecular vocabulary.

**Phase 6 — Documentation and pedagogy**

Whitepaper v3, architecture doc, course materials updated to use the
molecular framework. Public-facing surfaces (the visualizer at
zeropoint.global/chain) lead with the chemistry analogue.

**Phase 7 — Ambient deployment**

The visualizer becomes a system-level UI primitive. Collapsible
sidebar in the operator's working view (IronClaw chat, foundation
web, wizard, dashboard); cross-surface consistent rendering;
real-time animation when chain events occur; on-glance peripheral
awareness with on-click depth. The operator's daily working surface
gains an ambient pulse from the substrate.

This is the phase where the molecular language transitions from
"specification" to "literacy." Without ambient deployment, the
language is documented but not spoken; with it, operators encounter
the vocabulary continuously enough to internalize it. Fluency
follows from exposure.

Deployment substrate: the `<zp-receipt-chain>` web component (per
`RECEIPT-CHAIN-VIZ-2026-05.md`) gains a `collapsed` mode and a
`mode="ambient"` attribute. Embeddings across surfaces use the
ambient mode by default; full visualization expands on operator
request.

## Open questions

- **How aggressive should renaming be?** "Backbone" reads natural;
  "substituent" might feel forced. Probably introduce gradually,
  retain existing names as aliases during transition.
- **What counts as a recognized functional group?** The catalog
  needs to be curated; not every two-receipt pair is a "group."
  Initial catalog: onboarding ceremony, delegation cycle (grant +
  revoke), restart cluster, gate-allow-then-deny inversion, port
  allocate-bind-release triplet.
- **Does the analogy survive at scale?** Chemistry handles molecules
  with thousands of atoms via recognized substructures and
  abbreviations (R groups for "any substituent"). Receipt chains at
  10k+ entries need similar abstraction. The functional-group layer
  is the answer.
- **What's the receipt language's equivalent of "isomerism"?** Two
  chains with the same atoms but different bonding produce different
  molecules with different properties. Two operators with the same
  set of receipts but different hash-link order would be a structural
  anomaly — the chain wouldn't compose. This is a strength: chemistry's
  isomers are real (different compounds); receipt-chain "isomers"
  would be tamper-detectable. Worth elaborating.
- **What's the equivalent of resonance structures?** A molecule
  delocalizes electrons across multiple equivalent structures. A
  receipt could be referenced from multiple positions in different
  derivation paths — same atom, multiple structural roles. The
  substrate already supports this; the notation surfaces it.

## Out of scope (for this design note)

- The complete catalog of recognized functional groups
- Implementation of edge-type schema
- Visualization implementation (#145)
- Renaming sweep across documentation
- Course material updates
- Whitepaper v3

This note establishes the mapping and the phased adoption framework.
Each phase gets its own design pass when prioritized.

## Composition with existing principles

- **Principle 1 (Signing is gravity)** — molecular notation makes
  signature attestation visible as a bond type. Unsigned receipts
  read as open valence; signed receipts as anchored bonds. The
  principle becomes legible visually.
- **Principle 2 (Identity is a key, not a location)** — Genesis is
  the heteroatom that all other structure references. Identity reads
  as cryptographic anchor (the heteroatom labeled Ω), not as a
  location in space.
- **Principle 4 (Every bit counts)** — molecular notation is dense.
  Every line, every label, every wedge carries information. The
  receipt language gains the same density.
- **Principle 7 (Contact does not commit)** — open valence is the
  notation for "received but not committed." A contact event renders
  as a receipt with open valence until a signing event closes the
  bond.
- **Principle 8 (One canonical path)** — one notation system,
  multiple deployments (linear card list for ordered-event reading;
  structural rendering for compositional reading; both consume the
  same underlying receipt language).

## Refs

- `docs/RECEIPT-CHAIN-VIZ-2026-05.md` — current chain visualizer
  spec (linear card list)
- `docs/design/VOCABULARY-LOCK.md` — Tier-1 and Tier-2 vocabulary
  (this introduces Tier-3 structural notation)
- `docs/foundations/FORMAL-PRIMITIVES.md` — formal primitives that
  underpin substrate vocabulary
- `docs/foundations/CLAIM-METHODOLOGY.md` — methodology for claims
  (which become "atoms" in the molecular framing)
- `docs/foundations/INVARIANT-CATALOG-v1.md` — invariants (which
  gain structural counterparts under molecular notation)
- `docs/ARCHITECTURE-2026-04.md` — eight design principles, Part VIII
  (Compute Surface Awareness, reserved); this work suggests a future
  Part IX on structural notation
- Task #143 — foundation worker signs receipts (Phase 2 of this
  adoption composes with the foundation signing work)
- Task #145 — chain visualizer (Phase 5 of this adoption is the
  visualizer's design substrate)
- 2026-05-19 design session — Ken's observation of DMT skeletal
  structure resembling receipt chains; the seed of this design note

---

*This document is the seed. The mapping is the design; the phases
are the path. Adoption is gradual, opt-in, retains existing names
as aliases during transition. The goal is not to rename ZeroPoint's
substrate; the goal is to give the receipt language the density of
meaning it has already earned but hasn't yet articulated.*
