# zeropoint.global — Site Reorganization Proposal

**Status:** Draft for Ken's review
**Date:** 2026-04-25

---

## The Problem

The site has grown organically from 5 pages to 20+. The content is strong — deep technical writing, immersive interactive demos, good visual identity. But the information architecture has sprawled:

- **5 orphaned pages** (dashboard, trust-triangle-player, course-sdk, verify, sentinel/index) — high-effort content that no visitor can reach from the main navigation
- **Content overlap** between for-agents and integrate, between trust-triangle and trust-triangle-player, between demo-chain and exhibits
- **No clear learning path** — a developer who wants to go from "what is this?" to "how do I integrate?" has to guess which pages to visit in which order
- **Missing concepts** — canonicalization, GAR, and the component catalog don't appear anywhere on the site yet
- **Sentinel is a separate product** living in a subdirectory with no navigation bridge
- **The whitepaper page is 132KB** — comprehensive but undifferentiated from the docs. It's the most-linked page (40 inbound) serving as the catch-all for "I want to go deeper"

## Design Principles for the Reorg

1. **Three audiences, three depths.** Executive ("why should I care?"), developer ("how do I use it?"), researcher ("how does it work?"). Every page serves one primary audience.
2. **One path per audience.** No dead ends, no "choose your own adventure" without a map.
3. **Canonicalization woven in, not bolted on.** The reorg is also the ripple-out opportunity.
4. **Interactive content is a first-class section,** not scattered across standalone pages.
5. **Reduce pages, increase coherence.** Fewer, denser pages beat many thin ones.

---

## Proposed Site Map

### Tier 1: Entry Points (3 pages)

| Page | URL | Audience | Purpose |
|------|-----|----------|---------|
| **Home** | `/` (index.html) | Everyone | The thesis in 30 seconds. Hero → three value props → interactive demo teaser → integration CTA → footer. Updated with canonicalization language. |
| **For Operators** | `/operators` (for-agents.html, renamed) | AI operators, CTOs | Why you need governed agents. Canonicalization as the differentiator. Leads to integrate or whitepaper. Absorbs the relevant parts of current `for-agents.html`. |
| **For Developers** | `/developers` (new, merges integrate + setup) | Engineers | How to integrate. MCP config, trait integration, SDK. Code examples. Leads to course or architecture. Merges current `integrate.html` + `setup.html`. |

### Tier 2: Deep Dives (4 pages)

| Page | URL | Audience | Purpose |
|------|-----|----------|---------|
| **Architecture** | `/architecture` | Architects, security engineers | System map, five surfaces, containment model, canonicalization chain. Updated with GAR framing. Absorbs useful content from current `architecture.html`. |
| **Whitepaper** | `/whitepaper` | Researchers, deep technical | The full whitepaper. Updated with canonicalization and GAR sections. |
| **Footprint** | `/footprint` | Security teams, compliance | Coverage map against OWASP, MITRE ATLAS, NIST. Updated with 2026 threat landscape. |
| **Constraints** | `/constraints` | Protocol designers | Constitutional rules, grammar formalism, invariant catalog. Light touch — already strong. |

### Tier 3: Interactive Experiences (1 hub + sub-pages)

| Page | URL | Audience | Purpose |
|------|-----|----------|---------|
| **Explore** | `/explore` (new hub) | Everyone | Hub page linking to all interactive content. Cards with thumbnails and descriptions. |
| **→ Playground** | `/explore/playground` | Learners | The 3D agent society. Unchanged but now reachable from the hub. |
| **→ Receipt Chain** | `/explore/receipt-chain` | Developers | Current demo-chain.html. |
| **→ Trust Triangle** | `/explore/trust-triangle` | Conceptual learners | Merge trust-triangle + trust-triangle-player into one page with toggle. |
| **→ Mindmaps** | `/explore/mindmaps` (NEW) | Everyone | Published mindmaps and visual artifacts — ZP architecture, canonicalization chain, governance surfaces, protocol stack, implementation phases. Exportable/downloadable. Source from MindMap AI plugin exports or custom SVGs. |

### Tier 4: Reference & Tools (3 pages)

| Page | URL | Audience | Purpose |
|------|-----|----------|---------|
| **Dashboard** | `/dashboard` | Internal / build-in-public followers | Live build status. Link from nav (currently orphaned). |
| **Course** | `/learn` (course.html, renamed) | Developers in learning mode | Internals course. Link course-sdk as Track 2 within the same page, not a separate file. |
| **Attestation** | `/verify` | Auditors | Receipt verification and attestation display. Linked from architecture page. |

### Sentinel (Separate Product Sub-Site)

| Page | URL | Purpose |
|------|-----|---------|
| **Sentinel Home** | `/sentinel` | Product landing page for the network edge component. Own nav bar with "← Back to ZeroPoint" link. |
| **Sentinel Configurator** | `/sentinel/configurator` | Install wizard. Already good. |

### Utility

| File | Purpose | Changes |
|------|---------|---------|
| **llms.txt** | Machine-readable summary | Add canonicalization, GAR, component catalog. Update core primitives list. |
| **letter.html** | Founder's letter | Keep as-is. Link from About section in footer, not main nav. |
| **exhibits.html** | Technical deep dive | Absorb into whitepaper or architecture. Retire as standalone page. |

---

## Navigation Structure

```
┌─────────────────────────────────────────────────────────┐
│  ◈ zeropoint    Operators  Developers  Architecture     │
│                 Explore  Footprint  Whitepaper  [GitHub] │
└─────────────────────────────────────────────────────────┘
```

**Primary nav (always visible):** Home, Operators, Developers, Architecture, Explore, Footprint, Whitepaper, GitHub

**Footer:** Dashboard, Course, Attestation, Sentinel, Letter, llms.txt

**Explore dropdown (on hover/click):**
- Playground
- Receipt Chain
- Trust Triangle
- Mindmaps

---

## What Gets Merged / Retired

| Current Page | Disposition | Rationale |
|-------------|-------------|-----------|
| `for-agents.html` | → Renamed to **Operators** | Audience-aligned naming |
| `integrate.html` | → Merged into **Developers** | Was 70% overlap with setup.html |
| `setup.html` | → Merged into **Developers** | Natural continuation of integrate |
| `exhibits.html` | → Absorbed into **Whitepaper** or **Architecture** | Standalone deep dive is redundant when those pages are updated |
| `trust-triangle.html` | → Merged with player into **Explore / Trust Triangle** | Two pages for one concept |
| `trust-triangle-player.html` | → Merged (see above) | Was orphaned anyway |
| `course-sdk.html` | → Track 2 tab within **Course** | Was orphaned |
| `verify.html` | → Linked from Architecture as **Attestation** | Was orphaned |
| `dashboard.html` | → Linked from footer | Was orphaned |
| `sentinel/index.html` | → Own nav with back-link | Was orphaned |
| `letter.html` | → Footer link only | Nice but not primary nav material |

---

## The Mindmaps Section

Ken wants to publish curated mindmaps and visual artifacts — both the custom SVGs from our sessions and exports from the MindMap AI plugin. The `/explore/mindmaps` page would:

- Display a grid of visual artifacts with titles and descriptions
- Each artifact is a high-res PNG (for embedding) backed by an interactive HTML version (for exploration)
- Categories: Architecture, Canonicalization, Governance, Protocol Stack, Implementation
- Download buttons for PNG and HTML versions
- Accept exports from the MindMap AI plugin in whatever format it produces (likely SVG or HTML)
- Integrate with the site's existing dark theme and visual language

This becomes a living gallery that grows as the project evolves — a visual changelog of how the architecture has been thought about.

---

## Migration Strategy

1. **Don't break existing URLs.** Old paths redirect to new locations via Cloudflare redirects or `_redirects` file.
2. **Shared nav component.** Extract the navigation into a reusable include (or JS component) so changes propagate.
3. **Batch the work.** Do the reorg in one pass alongside the GAR/canon ripple-out — don't reorganize first and then update content (two passes through the same files).
4. **Test the link graph.** After reorg, crawl for dead links.

---

## Decision Points for Ken

- [ ] Approve the proposed site map (or suggest changes)
- [ ] Confirm "Operators" as the rename for "For Agents" (or prefer "For Teams"?)
- [ ] Confirm Explore hub approach for interactive content
- [ ] Confirm Mindmaps section inclusion
- [ ] Confirm Sentinel as separate sub-site vs. integrated section
- [ ] Confirm exhibits absorption (or keep as standalone?)
- [ ] Approve doing reorg + ripple-out as one pass
