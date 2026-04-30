# ZeroPoint Site Outline v2 — The Site as Governed Artifact

**Date:** 2026-04-25
**Supersedes:** SITE-REORG-PROPOSAL.md (structural recommendations absorbed; flat-tier model replaced by intent-based library)
**Companion:** SITE-IDENTITY-BRIEF.md (design identity, glossary architecture, localization, diorama series)

---

## The Thesis

The site does not explain ZeroPoint. The site *is* ZeroPoint.

Every page is a governed artifact — content-hashed, receipted, signed, chain-linked. The receipt chain for the site itself is published, downloadable, and cold-auditable. A visitor who wants to verify that the page they're reading is the page the operator published needs nothing but the chain file and a verifier. No trust required. No API. No cooperation.

This is not a demo. This is not a simulation. This is the real system governing its own public presence. The site becomes the project's most visible proof: "We use this on ourselves. Verify us."

---

## What "Functional ZeroPoint" Means for a Static Site

### Build-Time Governance

Every deployment is a governance event. When the site is built and published:

1. **Each page is content-hashed** (Blake3) at build time. The hash covers the rendered HTML — what the visitor receives.
2. **A deployment receipt is generated** — signed with the operator's key, referencing the previous deployment receipt (chain-linking). The receipt contains: page manifest (path → content hash), deployment timestamp, operator signature, previous chain head.
3. **The receipt is appended to the site's receipt chain** — a single file (`/chain/site-chain.json` or similar) served alongside the pages.
4. **The chain head is optionally anchored** to an external ledger (Hedera HCS) — creating an independent timestamp that survives operator compromise.

### Visitor-Side Verification

Any visitor can verify any page:

1. **Fetch the chain** — it's a static file, cached at the CDN edge like everything else.
2. **Hash the page they're viewing** — the verifier runs client-side (JS or WASM), hashes the page content.
3. **Walk the chain** — verify signatures, verify hash-linking, find the receipt that covers the current page, compare hashes.
4. **Result:** Either the page matches the chain (provably the content the operator published) or it doesn't (tampering detected — by the CDN, by a MITM, by anyone in the delivery path).

This is governance without runtime applied to a website. The chain file is the governance. The server is just delivery.

### What This Proves

- **Primitive 1 (Canonicalization):** The site has a canonical identity. Each page is canonicalized — anchored to the operator's genesis key via the deployment receipt chain.
- **Primitive 2 (Trust as Trajectory):** The chain records every deployment. The site's history is a verifiable trajectory, not a snapshot. A visitor can see not just "is this page authentic now?" but "what was this page last week?"
- **Primitive 3 (Governance Without Runtime):** Download the chain. Turn off the server. Verify the chain cold. The governance survives the site going down.
- **Primitive 4 (Receipts Are Canonical):** The chain is the truth. The HTML you see in your browser is a projection. If the projection (rendered page) contradicts the chain (content hash), the projection is wrong.

---

## Site Map

### The Governance Layer (new)

These pages are the site's self-governance surface — the proof that it practices what it preaches.

| Page | Path | Purpose |
|------|------|---------|
| **Verify** | `/verify` | The verification terminal. Visitor can: (a) verify the page they just came from, (b) verify any page by URL, (c) download the full chain, (d) run the cold-audit verifier. Shows the current chain head, deployment count, anchor status. This is the site's most important page after the home page. |
| **Chain** | `/chain/` | Raw chain data. The receipt chain as a downloadable JSON file. Machine-readable. This is what an auditor downloads. Also serves individual receipts by ID for deep-linking. |
| **Manifest** | `/chain/manifest.json` | Current deployment manifest — every page path with its content hash. A snapshot of the latest deployment receipt's page table. |

### Room 1: Understand (the ideas)

*"What is this and why should I care?"*

| Page | Path | Purpose |
|------|------|---------|
| **Home** | `/` | The thesis in 30 seconds. Hero statement, three value props, verification badge (live — shows chain head and last deployment), link to Verify page. Not a landing page — a statement of position. |
| **Whitepaper** | `/whitepaper` | The full whitepaper with section navigation, narration player, and glossary tooltips. The deepest single document on the site. |
| **Primitives** | `/primitives` | The four formal primitives — standalone page derived from FORMAL-PRIMITIVES.md. Accessible treatment of the formal contributions without the whitepaper's full scope. |
| **Letter** | `/letter` | Founder's letter. Linked from footer, not primary nav. Personal, not technical. |

### Room 2: Test (the claims)

*"How do I know this is real?"*

| Page | Path | Purpose |
|------|------|---------|
| **Falsify** | `/falsify` | The Falsification Guide — every claim paired with the test that would disprove it. The intellectual accountability layer. Visitors can run falsifiers against a live or simulated chain. |
| **Invariants** | `/invariants` | The Invariant Catalog — the 13 invariants (M1–M13), 6 productions (P1–P6), and 4 cross-layer rules (X1–X4). Formal reference. |
| **Methodology** | `/methodology` | The Claim Methodology — how ZeroPoint defines, tests, and honestly reports the status of its own claims. |
| **Footprint** | `/footprint` | Coverage map against OWASP, MITRE ATLAS, NIST. Shows what the system covers and — equally important — what it doesn't. |

### Room 3: Build (with it)

*"How do I integrate this into my system?"*

| Page | Path | Purpose |
|------|------|---------|
| **Architecture** | `/architecture` | System map, five mediation surfaces, containment model, the GAR. The reference document for anyone building on ZeroPoint. |
| **Integrate** | `/integrate` | Practical integration guide. MCP configuration, trait integration, SDK setup, code examples. Merges current integrate.html + setup.html. |
| **Constraints** | `/constraints` | Constitutional rules, grammar formalism. The formal contract between operator and system. |
| **Course** | `/learn` | Internals course. Progressive learning path from concepts to implementation. Absorbs course-sdk.html as Track 2. |

### Room 4: See (it in action)

*"Show me."*

| Page | Path | Purpose |
|------|------|---------|
| **Explore Hub** | `/explore` | Gateway to interactive content. Cards with thumbnails, one-sentence descriptions. |
| **Playground / Diorama 1** | `/explore/supply-chain` | 3D supply chain diorama — cross-organizational governance with DLT anchoring. The revamped playground grounded in the reality that public transactions already involve a ledger. |
| **Diorama 2** | `/explore/disaster-response` | Disaster response diorama — drones, degraded comms, mesh sovereignty. Foregrounding governance without runtime and alternative transports (Meshtastic, Reticulum). |
| **Receipt Explorer** | `/explore/receipt-chain` | Interactive receipt chain visualization — current demo-chain.html, evolved. Now can also visualize the site's own chain. |
| **Trust Triangle** | `/explore/trust-triangle` | Merged trust-triangle + trust-triangle-player. |
| **Mindmaps** | `/explore/mindmaps` | Gallery of visual artifacts — architecture maps, governance flows, phase diagrams. Exportable PNG + interactive HTML. |
| **Roadmap** | `/explore/roadmap` | The language-independent roadmap visualization. Node-graph topology, three interaction layers (topology → tooltip → detail card). Data-driven from roadmap.json. |

### Sentinel (Sub-Site)

| Page | Path | Purpose |
|------|------|---------|
| **Sentinel Home** | `/sentinel` | Product landing for the network edge component. Own nav with back-link. |
| **Configurator** | `/sentinel/configurator` | Install wizard. Already strong. |

### Utility

| File | Purpose |
|------|---------|
| `llms.txt` | Machine-readable project summary. Updated with canonicalization, GAR, formal primitives, truth anchoring. |
| `dashboard.html` | Build status. Footer-linked. Internal / build-in-public audience. |

---

## The Verify Page in Detail

This is the site's signature page — the one that makes people stop and think. It deserves its own section.

### What the Visitor Sees

**On load:** A clean terminal aesthetic. The current chain head (truncated hash), deployment number, timestamp of last deployment, anchor status (anchored / unanchored, with ledger transaction ID if anchored). A prominent "Verify This Site" button.

**On clicking "Verify This Site":** The verifier walks the chain in real time, displaying each step:

```
Fetching chain...                              ✓ 47 receipts
Verifying signature on receipt #47...           ✓ Ed25519 valid
Verifying hash link #47 → #46...               ✓ Blake3 match
  ...
Verifying genesis receipt #1...                 ✓ Genesis sealed
Chain integrity:                                ✓ INTACT

Verifying current page manifest...
  /index.html          → hash matches           ✓
  /whitepaper          → hash matches           ✓
  /verify              → hash matches           ✓
  ... (all pages)
Page integrity:                                 ✓ ALL PAGES MATCH

Checking external anchor...
  Hedera HCS topic:    0.0.XXXXX
  Last anchor receipt:  #44
  Consensus timestamp:  2026-04-25T14:32:00Z    ✓ VERIFIED

Verdict: This site is governed.
```

**On clicking a specific page:** The verifier fetches that page, hashes it client-side, and compares against the manifest. Shows whether the content the visitor received matches what the operator signed.

**Download options:**
- Download the full chain (JSON)
- Download the verifier binary (standalone, no dependencies — proves governance without runtime)
- Download the page manifest

### The Key UX Moment

The visitor realizes: "I just verified this entire website without trusting anyone. The server could be compromised, the CDN could be hostile, and I would know." That's the product pitch delivered as a lived experience, not a claim.

### Edge Cases

**What if verification fails?** The page shows the failure clearly — which receipt broke, which hash didn't match, which signature failed. This is governance without runtime: the chain reveals its own failures. A failing verification is still a working verification — it's doing its job by catching the problem.

**What about dynamic content?** Glossary tooltips, roadmap interactions, diorama state — these are client-side JavaScript operating on static data. The JS files are in the manifest and content-hashed. The data files (glossary.json, roadmap.json) are in the manifest and content-hashed. Dynamic behavior is a projection from hashed sources.

**What about the chain file itself?** The chain is self-verifying — every receipt references the previous receipt's hash. The chain doesn't need to be in the manifest because it carries its own integrity proof. The chain verifies the site; the chain verifies itself.

---

## Navigation

```
┌──────────────────────────────────────────────────────────────────┐
│  ◈ zeropoint     Understand  Test  Build  Explore     ✓ Verify  │
└──────────────────────────────────────────────────────────────────┘
```

**Primary nav:** Home (◈), Understand, Test, Build, Explore, Verify

The four rooms are the nav categories. Verify sits apart — visually distinguished (perhaps with a checkmark icon or accent-blue highlight) because it is the site's proof-of-integrity surface, not a content category.

**Room dropdowns (on hover/click):**

- **Understand:** Whitepaper, Primitives, Letter
- **Test:** Falsify, Invariants, Methodology, Footprint
- **Build:** Architecture, Integrate, Constraints, Course
- **Explore:** Supply Chain Diorama, Disaster Response, Receipt Explorer, Trust Triangle, Mindmaps, Roadmap

**Footer:** Dashboard, Sentinel, llms.txt, GitHub, Chain Data

---

## The Self-Governance Build Pipeline

### How It Works

The build pipeline is itself a ZeroPoint operation:

1. **Content authored** — Markdown, HTML, JSON data files edited by the operator.
2. **Build triggered** — Static site generator (or build script) renders all pages.
3. **Manifest generated** — Script walks the output directory, Blake3-hashes every file, produces `manifest.json`.
4. **Deployment receipt created** — The manifest hash, timestamp, and previous chain head are assembled into a receipt payload, signed with the operator's Ed25519 key, and appended to the chain file.
5. **Chain integrity verified** — The build pipeline walks the chain before publishing. If the chain is broken, deployment fails. The governance system governs the deployment itself (autorecursive).
6. **Site published** — Chain file, manifest, and all pages deployed to CDN.
7. **Optional: anchor** — If the operator has an anchor backend configured, the chain head is anchored to the external ledger. This can be automatic on deploy or manual.

### What the Operator Needs

- An Ed25519 keypair (the genesis key for the site's governance)
- The `zp-receipt` crate (or a lightweight CLI tool) for receipt creation and signing
- Blake3 for content hashing
- A deployment script that integrates steps 2–6

This is intentionally minimal. A static site governed by ZeroPoint doesn't need a running ZeroPoint server — it needs a build script that produces receipts. Governance without runtime, applied to the deployment pipeline itself.

### The Chain as Changelog

Every deployment receipt implicitly records what changed — the manifest diff between receipt N and receipt N-1 shows which pages were added, modified, or removed. The chain becomes the site's verifiable changelog. Not a git log (which records *intent to change*) but a governance log (which records *what was published, signed by whom, at what moment*).

---

## Migration Path from Current Site

| Current Page | Destination | Notes |
|-------------|-------------|-------|
| `index.html` | `/` (Home) | Add verification badge, update hero |
| `whitepaper.html` | `/whitepaper` | Add glossary tooltips, update section numbering |
| `for-agents.html` | Retire → content into `/` and `/integrate` | Audience-specific framing absorbed into rooms |
| `integrate.html` | `/integrate` | Merge with setup.html |
| `setup.html` | `/integrate` | Merge with integrate.html |
| `architecture.html` | `/architecture` | Update with GAR framing |
| `constraints.html` | `/constraints` | Light touch |
| `footprint.html` | `/footprint` | Move to Test room |
| `course.html` | `/learn` | Absorb course-sdk.html |
| `course-sdk.html` | `/learn` (Track 2) | Merge into course |
| `playground.html` | `/explore/supply-chain` | Full revamp as Diorama 1 |
| `demo-chain.html` | `/explore/receipt-chain` | Evolve to also visualize site's own chain |
| `trust-triangle.html` | `/explore/trust-triangle` | Merge with player |
| `trust-triangle-player.html` | `/explore/trust-triangle` | Merge |
| `exhibits.html` | Absorb into `/whitepaper` or `/architecture` | Standalone is redundant |
| `verify.html` | `/verify` | Major evolution — becomes live governance verification |
| `dashboard.html` | `/dashboard` | Footer-linked |
| `letter.html` | `/letter` | Footer-linked |
| `sentinel/index.html` | `/sentinel` | Sub-site with back-link |
| `sentinel/configurator.html` | `/sentinel/configurator` | Keep |

**New pages (no current equivalent):**

| Page | Why |
|------|-----|
| `/primitives` | Formal primitives deserve a standalone accessible page, not just whitepaper-depth |
| `/falsify` | Falsification Guide — the accountability layer |
| `/invariants` | Invariant Catalog — formal reference |
| `/methodology` | Claim Methodology — how claims are tested |
| `/explore` | Hub page for interactive content |
| `/explore/supply-chain` | Diorama 1 (playground revamp) |
| `/explore/disaster-response` | Diorama 2 |
| `/explore/mindmaps` | Visual artifact gallery |
| `/explore/roadmap` | Language-independent roadmap visualization |
| `/chain/` | Receipt chain data endpoint |
| `/chain/manifest.json` | Current deployment manifest |

### URL Preservation

Old paths redirect to new locations via `_redirects` or Cloudflare rules. No broken links. The chain records the migration as a deployment event — the manifest changes, but the chain continues.

---

## What Makes This Different from Every Other Project Site

Most project sites say "trust us." They have an About page, a team page, maybe a security audit PDF.

This site says "verify us." It publishes its own governance chain. It gives you the tools to audit it cold. It proves that the content you're reading is the content the operator signed. It demonstrates every formal primitive it claims to have invented — not in a sandbox, not in a simulation, but on itself.

The Verify page is not a feature. It is the argument. Every other page on the site is a claim. The Verify page is the proof.

---

## Decision Points

- [ ] Approve four-room library model (Understand / Test / Build / See)
- [ ] Approve self-governance layer (build-time receipting, chain publication, verify page)
- [ ] Confirm DLT backend for site anchoring (Hedera HCS is the current reference)
- [ ] Confirm Sentinel as sub-site vs. integrated section
- [ ] Approve new pages (Primitives, Falsify, Invariants, Methodology, Explore hub, Roadmap)
- [ ] Approve exhibits.html absorption
- [ ] Priority: Verify page first, or structural reorg first?
