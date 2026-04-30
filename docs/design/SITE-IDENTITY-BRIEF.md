# ZeroPoint Site Identity Brief

**Date:** 2026-04-25
**Purpose:** Single document capturing the converging design threads — visual identity, library structure, roadmap visualization, diorama series, glossary architecture, and localization — as projections from one coherent aesthetic. This is the design constitution. Everything the site produces derives from it.

---

## 1. Design Identity

### The Sensibility

ZeroPoint's visual identity is inseparable from its intellectual identity. The four formal primitives — canonicalization, trust-as-trajectory, governance-without-runtime, receipts-are-canonical — are not just ideas to be explained. They are the design grammar.

The design does not *decorate* the ideas. The design *is* the ideas, expressed visually.

**Principle: Primitive 4 governs everything.** "Receipts are canonical, protocols are projections." The design system works the same way. There is one canonical aesthetic — a set of commitments about space, color, typography, motion, and information architecture. Every artifact the project produces — website, whitepaper PDF, slide deck, interactive diorama, roadmap visualization, printed document — is a projection from that canonical source. If a projection contradicts the identity, the projection is wrong.

### The Commitments

**Space.** Generous negative space. Content breathes. The ratio of empty to occupied should feel closer to a gallery wall than a dashboard. Dense information is presented in expandable layers, never crammed. First impression: quiet authority.

**Color.** The palette is cold, restrained, and functional.

| Role | Token | Hex | Usage |
|------|-------|-----|-------|
| Background | `--bg` | `#0a0a0c` | Primary canvas. Near-black, not pure black. |
| Elevated surface | `--bg-elevated` | `#111116` | Cards, panels, floating elements. |
| Subtle surface | `--bg-subtle` | `#18181f` | Secondary panels, code blocks. |
| Primary text | `--text` | `#e8e6e3` | Body copy. Warm off-white against cold background. |
| Muted text | `--text-muted` | `#8a8a8e` | Labels, captions, secondary information. |
| Dim text | `--text-dim` | `#5a5a5e` | Tertiary information, decorative text. |
| Accent | `--accent` | `#7eb8da` | Links, emphasis, interactive elements. A steel-blue — technical, calm, trustworthy. |
| Accent dim | `--accent-dim` | `#4a7a96` | Eyebrows, labels, muted interactive elements. |
| Rule | `--rule` | `#222228` | Borders, dividers. Barely visible — structural, not decorative. |

**Color is semantic, not decorative.** In diagrams and interactive elements, color maps to meaning:

| Color | Meaning |
|-------|---------|
| Accent blue (`#7eb8da`) | Lifecycle events, canonicalization, identity |
| Warm amber | Content events, claims, assertions |
| Danger red | Refusals, errors, broken integrity, failed verification |
| Muted gray | Telemetry, background operations, structural elements |
| Green (sparingly) | Verified, intact, well-formed |

The palette does not grow. New information types map to existing colors. If a new color feels necessary, the information architecture is wrong.

**Typography.** Two families, no exceptions.

- **Inter** (300, 400, 500, 600) — Body text, headings, UI elements. Clean, neutral, excellent at small sizes.
- **JetBrains Mono** (400, 500) — Code, technical identifiers, the logo mark, eyebrow labels. Monospace signals "this is precise; this is verifiable."

Headings are light-weight (300–400), not bold. Authority comes from space and hierarchy, not weight. The only bold elements are inline emphasis and occasional heading accents.

**Motion.** Restrained. Transitions are 200ms ease. Nothing bounces, nothing overshoots. New elements fade in or slide from a logical origin. Existing elements never move — the abacus rule: "a placed bead never moves." Animation exists to communicate state change, never to entertain.

**Information density.** Progressive disclosure everywhere. First view: the thesis in one sentence. Click: the argument in one paragraph. Click: the formal treatment. Click: the falsifier. Four layers of depth, each self-contained, each inviting the next. No page should require scrolling to grasp its purpose.

### Light Mode

Not yet. The identity is dark-first. A light projection may be derived later for print contexts (PDF, physical media). When it arrives, it inverts the surface hierarchy but preserves the color semantics — accent blue remains accent blue, danger red remains danger red. Typography and spacing are unchanged.

### The Logo and Mark

The `◈` glyph (Unicode 25C8, diamond in a box) serves as the ZeroPoint mark. It appears in the nav bar, in monospace weight, paired with the wordmark in Inter. The diamond-in-a-box is the visual metaphor for the canonicalization invariant: something exists within a governed boundary.

### The Governance Seal

Any site or application governed by ZeroPoint carries a **governance seal** — a small, quiet, living element that serves the same function as a cornerstone inscription on a significant building. It is not a marketing badge. It is a proof mark.

**Visual form.** The seal inherits the hash ring from the course attestation certificate: 64 SVG tick marks arranged in a circle, each tick's opacity derived from nibbles of the current chain head hash. The ring is a visual fingerprint unique to the deployment and its governance state — the pattern changes with every deployment, making it a living mark rather than a static stamp.

Inside the ring: the `◈` glyph and the genesis date.

```
       ◈
  est. 2026-03-15
```

**The "year zero" significance.** The genesis date in the seal is not merely a timestamp. It is a founding date — the moment this site entered governed existence. "Est. 2026" declares participation in the first generation of cryptographically governed presence on the internet. A decade from now, early genesis dates carry the weight of provenance: proof you were here when the foundation was laid. The name itself — *Zero*Point — is the origin, the place you measure from. The seal makes that origin visible.

**Behavior.** The seal is:

- **Small.** Cornerstones don't shout. Footer-positioned, never competing with content. Roughly 48–64px diameter.
- **Live.** The hash ring pattern reflects the actual chain head. When the site deploys, the ring changes. The seal is a projection from the chain (Primitive 4).
- **Clickable.** Clicking the seal opens the Verify page. The seal is the doorway to full chain verification — the "est. 1936" that, unlike a building's cornerstone, you can actually interrogate.
- **Queryable.** A lightweight API endpoint (or inline data attribute) allows external tools to confirm the seal is genuine — that the displayed genesis date and chain head match the published chain file. This is the "query and confirm it's legit" surface.

**The standard mark.** The governance seal is not exclusive to zeropoint.global. Any site or application that implements ZeroPoint governance and publishes its chain can display the seal with its own genesis date. The seal becomes the universal visual indicator of governed, verifiable web presence — the equivalent of the padlock icon for HTTPS, but for content integrity rather than transport encryption.

**Palette.** The ring uses `--accent` (`#7eb8da`) at varying opacities. The genesis text uses `--text-dim` (`#5a5a5e`). The `◈` glyph uses `--accent`. On verification success, a subtle green pulse (the verified green from the semantic palette) confirms integrity. On failure, danger red. The seal never draws attention to itself unless something is wrong.

---

## 2. Library Architecture

### The Problem

The project has accumulated substantial documentation — whitepaper, architecture spec, formal primitives, invariant catalog, falsification guide, claim methodology, design specs, UX specs, future-work documents. Currently these are organized by *type* (docs/, docs/design/, docs/foundations/, docs/future-work/). Visitors must already know what they're looking for.

### The Solution: Organize by Intent

Four reading rooms, each answering one question a visitor arrives with. The rooms are not physical directories — they are projections (Primitive 4) from the same document collection, organized by the reader's intent.

**Room 1: Understand the Ideas**
*"What is this and why should I care?"*

Entry point for anyone — executive, researcher, journalist, investor, curious engineer. Documents here explain the thesis, the primitives, the differentiation. No code. No implementation detail. The whitepaper lives here. The Formal Primitives document lives here. A future "ZeroPoint in 5 Minutes" piece lives here.

Documents: Whitepaper, Formal Primitives, future executive summary, future "5-minute" explainer.

**Room 2: Test the Claims**
*"How do I know this is real?"*

For the skeptic, the security researcher, the academic reviewer. Every claim is falsifiable; this room is where the falsifiers live. The Falsification Guide, the Invariant Catalog, the Claim Methodology — these are the project's intellectual accountability layer.

Documents: Falsification Guide, Invariant Catalog, Claim Methodology, future independent audit reports.

**Room 3: Build With It**
*"How do I integrate this into my system?"*

For the developer, the platform engineer, the DevOps team. Integration guides, API reference, MCP configuration, SDK documentation, the architecture spec (as a reference, not a narrative). Code examples. Setup instructions.

Documents: Architecture spec, integration guide, setup guide, API reference, SDK docs, future cookbook.

**Room 4: See It in Action**
*"Show me."*

The interactive layer. Playground dioramas, receipt chain explorer, trust triangle visualization, mindmap gallery, the narrated audio walkthroughs. This is the "Explore" section from the site reorg proposal, elevated to a first-class reading room.

Documents/artifacts: Playground, diorama series, receipt chain demo, trust triangle, mindmaps, audio narrations.

### Cross-Cutting: The Glossary

The glossary is not a room — it is infrastructure that serves all four rooms. See Section 5 below.

### Navigation

The site nav maps directly to the four rooms plus a home page. The rooms replace the current flat page list with an intent-driven hierarchy. Each room has a landing page that orients the visitor and presents its documents as cards with one-sentence descriptions.

---

## 3. Roadmap Visualization

### The Requirement

Ken's words: "I want them to think 'this looks Cool! and I can understand it!'" and "in a way that you don't need to speak English to understand." This rules out Gantt charts, text-heavy timelines, and bullet-point roadmaps. The visualization must carry meaning through visual structure alone, with text as a secondary layer available on demand.

### The Design: Flow Topology

Inspired by node-graph editors (NodeRED, Unreal Blueprints) but stripped to essentials. The roadmap is a directed graph where:

**Nodes** represent capabilities or milestones. Each node is a card with:
- An **icon** (simple, geometric, language-independent) representing the capability domain
- A **fill state** communicating status:
  - Solid fill = delivered
  - Outlined (stroke only) = planned
  - Pulsing outline = in active development
- A **color** communicating domain:
  - Accent blue = governance primitives
  - Amber = agent runtime
  - Teal = network / mesh
  - Purple = external integration (DLT, protocols)
  - Gray = infrastructure / tooling

**Edges** represent dependency or flow. A line from node A to node B means "A enables B" or "A feeds into B." Edge style:
- Solid line = hard dependency
- Dashed line = soft dependency / enhancement

**Clusters** group related nodes. A subtle background region (using `--bg-elevated`) groups nodes that belong to the same phase or domain. No labels required — the spatial grouping communicates relationship.

### Interaction Layers

**Layer 0 (default view):** The topology. Nodes, edges, clusters. No text except minimal icon labels (1–2 words, optional). A visitor who speaks no English sees: "some things are done (solid), some are planned (outlined), they connect in this pattern, they cluster into these groups." The shape of the project is visible.

**Layer 1 (hover/tap):** A tooltip appears with the node's name and a one-sentence description. In localized versions, this text is translated. The visual structure remains identical.

**Layer 2 (click/expand):** The node expands into a detail card showing: description, current status, key deliverables, links to relevant documents in the library. This is the "on demand" layer Ken described.

### Implementation Notes

- SVG-based, rendered with D3 or vanilla SVG. No canvas — SVG is searchable, scalable, and printable.
- Layout computed by dagre (same library recommended in the visual language doc for CodeFlow).
- The visualization is a projection from a structured data file (`roadmap.json` or similar) that contains nodes, edges, status, and localized text. The visualization code never contains content — it renders whatever the data file says.
- Print/PDF version: same topology, rendered as a static SVG with Layer 1 labels always visible.

---

## 4. Diorama Series

### The Concept

Interactive 3D scenes (using the existing Three.js playground infrastructure) that simulate real-world governance scenarios. Each diorama foregrounds different formal primitives based on the scenario's constraints. They are stories told through simulation.

### Diorama 1: Supply Chain (DLT Anchoring)

*Already partially built as the existing playground.*

**Scenario:** Cross-organizational supply chain with multiple operators, each running their own ZeroPoint deployment. Goods move between organizations; governance must compose across trust boundaries.

**Foregrounded primitives:** External truth anchoring, cross-mesh trust, opportunistic anchoring. The ledger infrastructure is already present for the commercial transaction — governance anchoring piggybacks.

**Visual focus:** Multiple receipt chains (one per organization) with anchor points connecting them through a shared external ledger. The viewer can see trust compose across organizational boundaries without a central authority.

**Revamp needed:** The current playground was hand-waved on DLT specifics. The revamped version grounds every interaction in the reality that public transactions already involve a ledger.

### Diorama 2: Natural Disaster Response (Mesh Sovereignty)

*Planned and waiting in the wings.*

**Scenario:** Drone fleet deployed for search-and-rescue after a natural disaster. Communications infrastructure is degraded. Drones must operate with intermittent connectivity, making governance decisions locally while maintaining auditability.

**Foregrounded primitives:** Governance without runtime (the chain survives infrastructure failure), canonicalization (drones are canonicalized before deployment — their identity survives comms loss), trust-as-trajectory (accumulated trust enables autonomous decisions when the operator is unreachable).

**Visual focus:** A disaster zone with dynamic weather, degraded cell towers, mesh network links appearing and disappearing. Drones make governance decisions locally; when connectivity returns, receipt chains synchronize and the full trajectory is verifiable.

**Alternative infrastructure:** Meshtastic, Reticulum. The diorama demonstrates that ZeroPoint's governance is transport-agnostic — it works over TCP, over mesh radio, over sneakernet (USB drive with a chain file). This is governance-without-runtime taken to its physical limit.

### Diorama 3: Regulatory Compliance (Future)

**Scenario:** A financial services firm running governed AI agents that must demonstrate compliance to regulators. The regulator is an external auditor with no access to the firm's systems.

**Foregrounded primitives:** Governance without runtime (the regulator audits the chain cold), receipts-are-canonical (the regulator's view is a projection from the chain, same as the firm's dashboard), canonicalization (every agent, tool, and model provider is canonicalized — the regulator can see exactly what was authorized to operate).

**Visual focus:** Split view — the firm's operational dashboard on one side, the regulator's cold-audit terminal on the other. Same chain, two projections, identical conclusions.

### Design Coherence Across Dioramas

Each diorama uses the same visual language (color palette, typography, motion principles) but adapts the environment to the scenario. The governance visualization layer — receipt chains, canonicalization markers, anchor points — uses identical visual grammar across all dioramas. A viewer who understands the supply chain diorama's governance layer can immediately read the disaster response diorama's governance layer, even though the environments are completely different.

The governance grammar is the constant. The world is the variable.

---

## 5. Glossary Architecture

### The Canonical Source

A single structured data file (`glossary.json` or `glossary.yaml`) containing every term defined in the Vocabulary Lock document. Each entry includes:

```
{
  "term": "Canonicalization",
  "short": "Anchoring an entity to genesis via signed receipt chain.",
  "full": "The act of anchoring an entity to the genesis identity via a signed receipt chain. The only governance primitive that is constitutive — it establishes what exists rather than recording what happened.",
  "see_also": ["canonical-identity", "canonicalization-receipt", "canonicalization-chain"],
  "category": "core",
  "first_use_expand": true
}
```

### Three Projections

**Projection 1: Tooltips (Web)**
On the website, every occurrence of a glossary term is wrapped in a tooltip trigger. Hover (desktop) or tap (mobile) reveals the `short` definition. The tooltip appears in a floating panel styled with `--bg-elevated` background, `--text` foreground, accent-blue border-top. Terms are linked to the full glossary page for deeper reading.

Implementation: A small JS module scans rendered content for glossary terms and wraps them in `<abbr>` or `<span data-glossary="...">` elements. The glossary data is loaded once and cached. The scanning respects context — terms inside code blocks, headings, or already-wrapped elements are not double-wrapped.

**Projection 2: Margin Glosses (Print/PDF)**
For printable media (PDF whitepaper, printed documentation), glossary terms on their first occurrence per section are annotated with margin notes. The margin gloss contains the `short` definition, set in a smaller type size (9pt) in `--text-muted` color equivalent. This follows the academic tradition of marginal notation — the reader's eye can glance right for a definition without leaving the paragraph.

Implementation: The PDF generation pipeline (likely via LaTeX, Typst, or a custom PDF tool) reads the same `glossary.json` and inserts margin notes at first-occurrence positions. The source document marks glossary terms with a lightweight syntax (e.g., `{term}` or a custom marker) that the pipeline interprets.

**Projection 3: Standalone Document**
A full glossary page on the website and a glossary appendix in the whitepaper PDF. Terms grouped by category (Core Identity, Canonicalization, Receipt and Chain, Architecture, Protocol, Thesis, Grammar, Methodology, Truth Anchoring). Each entry shows the full definition, cross-references, and a link to the document section where the term is most thoroughly explained.

### The Principle

One data file. Three projections. The glossary data is canonical; the presentations are derived. If a definition changes, it changes in one place and propagates to all three projections. This is Primitive 4 applied to documentation infrastructure.

---

## 6. Localization Architecture

### The Commitment

Ken: "I will eventually want to localize the entire site to Chinese too." This means every design decision must be evaluated against the question: "Does this survive translation?"

### What Survives Translation Unchanged

- **The visual grammar.** Color semantics, spatial layout, typography hierarchy, motion principles, the roadmap topology, the diorama governance layer, the four-lens visualization system (Abacus, Weave, CodeFlow, Walk). These carry meaning through structure, not language.
- **The icon system.** Roadmap node icons, diorama governance markers, navigation icons. All geometric, no culturally-specific symbols.
- **The color palette.** Accent blue means lifecycle/identity in every locale.
- **The data structures.** `glossary.json`, `roadmap.json`, receipt chain data. Structure is language-independent; only string values are localized.

### What Gets Localized

- **All text content.** Headings, body copy, tooltips, button labels, alt text, ARIA labels, meta descriptions, structured data (JSON-LD).
- **Glossary entries.** Each glossary term gets a `zh` (or locale-keyed) version of `short` and `full` definitions. The term itself may be translated or transliterated depending on whether a standard Chinese equivalent exists. Technical terms without established Chinese equivalents are transliterated with the English in parentheses on first use.
- **Roadmap node labels.** Layer 1 and Layer 2 text. Layer 0 (the topology itself) is already language-independent.
- **Diorama UI overlays.** Status panels, event descriptions, tutorial text. The 3D environment and governance visualization layer are language-independent.
- **Document content.** Each document in the library has a localized version. The library structure (four rooms) is identical across locales — only the room names and document content change.

### Architecture

The site uses a locale-prefix URL structure: `zeropoint.global/` (English, default), `zeropoint.global/zh/` (Chinese). The locale prefix selects a string table; all structural elements (CSS, JS, SVG, 3D assets) are shared.

Content files are organized as:
```
content/
  en/
    whitepaper.md
    glossary.json
    roadmap.json
  zh/
    whitepaper.md
    glossary.json
    roadmap.json
```

The build pipeline reads locale-specific content and renders it into the shared template structure. Templates reference string keys, not literal text.

### Chinese-Specific Considerations

- **Typography:** Inter supports Latin + CJK. If CJK rendering quality is insufficient, add Noto Sans SC (Simplified Chinese) as a fallback. The monospace family (JetBrains Mono) is used only for code and technical identifiers, which remain in English/ASCII even in the Chinese locale.
- **Layout:** Chinese text is typically denser than English (fewer characters convey equivalent meaning). The generous spacing in the design identity accommodates this — the breathing room that feels "quiet" in English will feel "comfortable" in Chinese rather than "empty."
- **Glossary:** Many governance and cryptography terms have established Chinese equivalents (e.g., 零知识证明 for zero-knowledge proof). Where ZeroPoint coins new terms (canonicalization, autorecursive trust substrate), the Chinese version will need careful translation that preserves the conceptual precision. This is a translation task, not a design task — but the glossary architecture (one canonical data file with locale-keyed definitions) makes it tractable.

---

## 7. How the Projections Cohere

Every artifact described in this brief is a projection from the same canonical identity:

| Artifact | Projects From | Medium | Audience |
|----------|--------------|--------|----------|
| Website pages | Identity + library structure | HTML/CSS/JS | All |
| Whitepaper PDF | Identity + glossary (margin glosses) | PDF | Researchers |
| Roadmap visualization | Identity + roadmap data | SVG/interactive | All |
| Diorama series | Identity + scenario data + visual language | Three.js/WebGL | All |
| Glossary tooltips | Identity + glossary data | JS overlay | Web readers |
| Glossary standalone | Identity + glossary data | HTML page / PDF appendix | Reference |
| Audio narrations | Identity (tone, pacing) + document content | Audio/MP3 | Listeners |
| Slide decks | Identity + content | PPTX/PDF | Presenters |
| Chinese site | Identity + localized content | Same as English | Chinese audience |

The identity is the chain. The artifacts are the projections. The projections are lossy by design — a slide deck discards depth to gain brevity, a tooltip discards context to gain immediacy. The identity preserves what the projections discard.

**The test:** If someone sees the roadmap visualization, then the whitepaper PDF, then a diorama, then the Chinese site — do they feel like the same project made all of these? If yes, the identity is working. If any artifact feels like it came from a different project, the artifact is wrong, not the identity.

---

## 8. Existing Assets and Their Status

| Asset | Status | Action |
|-------|--------|--------|
| `zp-visual-language.md` | Strong. Four-lens system (Abacus, Weave, CodeFlow, Walk) is well-defined. | Incorporate as the visualization grammar section of the identity. No changes needed to the content — it becomes a referenced sub-document. |
| `VOCABULARY-LOCK.md` | Strong. Canonical terms, anti-patterns, unified thesis paragraph. | Drives the glossary data file. Lock approval needed before glossary build. |
| `SITE-REORG-PROPOSAL.md` | Good structure, needs alignment with the library concept. | The four-room library model supersedes the tier-based organization. The Explore hub maps to Room 4. Decision points still pending Ken's review. |
| CSS variables in `index.html` | Canonical. The palette defined there is the palette. | Extract into a shared `variables.css` or design token file when the site build pipeline is formalized. |
| Three SVG diagrams | Functional. Delegation chain, governance gate, trust tiers. | Audit against the color semantics defined in this brief. May need minor palette alignment. |
| Playground (Three.js) | Functional but hand-waved on DLT. | Full revamp before Diorama 1. Governance visualization layer needs to match the visual language. |

---

## 9. Execution Priority

This is not a sequential plan — it is an ordering by dependency and impact.

**Foundation (do first):**
1. Extract the glossary data file from the Vocabulary Lock
2. Extract design tokens (colors, typography, spacing) into a shared file
3. Build the tooltip projection (highest-impact, lowest-effort glossary projection)

**Structure (do second):**
4. Implement the four-room library navigation on the site
5. Build the roadmap data file and initial visualization
6. Formalize the localization content structure (`content/en/`, `content/zh/`)

**Experience (do third):**
7. Revamp the playground into Diorama 1 (supply chain / DLT anchoring)
8. Build Diorama 2 (disaster response / mesh sovereignty)
9. Build the margin-gloss projection for PDF output

**Polish (do fourth):**
10. Chinese localization of core content (whitepaper, glossary, roadmap labels)
11. Diorama 3 (regulatory compliance)
12. Print/PDF design system (light-mode projection, margin glosses, standalone glossary)

---

*This brief is itself a projection — from the conversations, decisions, and design instincts accumulated across the project's history. The canonical source is the accumulated context. This document makes it legible.*
