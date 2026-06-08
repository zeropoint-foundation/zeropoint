# Surface boundaries

*2026-05-24. Canonical reference for what surface serves what concern.
Pinned to prevent re-collapse of distinctions the substrate's history
has already moved past.*

This document is reference, not investigation. Ken decides; this captures
what's decided. Updates to this doc are architectural acts and should be
treated as such — not edited casually.

## Named concepts

These names are pinned. The architecture uses them; design docs cite
them; future work refines them without renaming them.

| Name | What it is |
|---|---|
| **ZeroPoint** (substrate, core ZP) | The trust-infrastructure primitives. Rust crates under `crates/zp-*`. What adopters install and run. |
| **ZP Surface Spec** | The contract that defines how cockpits integrate with ZP Console — what surface area a cockpit exposes (chat, voice, tool invocations, status, tile contributions), how the Console composes those surfaces, event routing, lifecycle, trust attribution. A published interface specification, transport-agnostic. |
| **ZP Console** | The reference operator surface — workspace shell, navigation, tile renderer, cockpit slot per the Surface Spec, chain viz integration. Bundled with substrate distribution but architecturally separable. Adopters deploy this or fork it. |
| **Cockpit** | A conversational agent that integrates with ZP Console via the Surface Spec. The foundation runs IronClaw. Others run Ember, KiloCode, Agent Zero, future cockpits. Pluggable. |
| **foundation Console** | The ZP Foundation's specific deployment of ZP Console, at `app.zeropointfoundation.org`, with IronClaw configured as the cockpit and the foundation's chain data. One instance of the general pattern. |
| **Adopter Console** | Any other deployment of ZP Console — same software, different configuration, different chain, different cockpit choice. |

## The three surfaces

### 1. Core ZP — the substrate

**What it is:** the trust-infrastructure primitives. The Rust crates
under `crates/zp-*`, the audit chain, the gate envelope, the vault, the
signing hierarchy, the discipline pins, the mesh transport, the policy
engine.

**Who consumes it:** adopters. Anyone building agentic systems who needs
portable trust infrastructure. The foundation is one such consumer; it
is not the only one and is not privileged.

**What it is NOT:** a SaaS product. A mail platform. An agent framework.
A dashboard application. A workspace.

**Distribution:** installed and run by adopters on their own
infrastructure. The substrate runs as `zp serve` on the adopter's host.

### 2. foundation Console — `app.zeropointfoundation.org`

**What it is:** the foundation's deployment of ZP Console. Authenticated.
Hosts the IronClaw cockpit (configured as the foundation's cockpit via
the Surface Spec), the Console's reference workspace surfaces (chain
viz, trust posture, operations, preferences), the artifact library
tile renderer (calendars, kanban, documents, mail, checklists, decks,
agent surfaces — see `docs/ARTIFACT-LIBRARY-2026-05.md`), the
foundation's mail, all signed-artifact work, and any future foundation-
internal extensions of Console.

**Who consumes it:** foundation directors and authorized foundation
operators. Authenticated via Cloudflare Access (outer) and the
foundation's session cookie (inner — see commit `10203ed`).

**What it is NOT:** core ZP. Not part of the substrate. Not adopted by
anyone outside the foundation. It is one configuration of ZP Console —
the same software any other adopter would deploy, just configured for
foundation data and cockpit choice. The pattern is general; this
instance is foundation-specific.

**Currently:** IronClaw is at `app.*` via Cloudflare Tunnel. The
Console pages currently live at `zeropointfoundation.org/` and need to
be migrated to `app.*`. The `app.*` arrangement (single Worker routing
between IronClaw tunnel and Console bundle) is the chosen shape — see
Migration commitments below.

### 3. Public site — `zeropointfoundation.org`

**What it is:** the foundation's public-facing surface. What visitors,
adopters, journalists, and the general public see when they navigate to
the bare domain.

**Who consumes it:** anyone on the public internet. No authentication.

**What it shows:** foundation mission and identity, the public vision /
whitepaper, adoption documentation, setup and install guides for core
ZP, course/educational content, optionally a public chain-viz demo
rendered against synthetic data for illustration.

**What it is NOT:** authenticated. Personalized. A workspace surface. A
place to render any director's personal chain. A SOC dashboard.

**Currently:** mostly mismatched. Authenticated content and Console
pages are still rendering here. The public-site content itself is
largely unspecified and needs to be authored or imported. The migration
empties this surface before refilling it.

## Dependency direction

Allowed:

- **ZP Console** may consume **core ZP** (via the substrate's HTTP /
  mesh APIs) and **the ZP Surface Spec** (to define its cockpit slot).
- **Cockpits** (IronClaw, Ember, etc.) may consume **core ZP** (sign
  gate calls, emit receipts) and **the ZP Surface Spec** (to integrate
  with any Console implementation). Cockpits do not require a Console
  to be useful — they remain usable as standalone agents.
- **foundation Console** is a configuration of **ZP Console**. It may
  add foundation-specific configuration (cookie scope, branding, data
  bindings) but does not add foundation-specific code that other
  adopters couldn't reuse.
- **Public site** may reference **core ZP** for documentation (link to
  docs, embed setup commands, etc.) but does not consume substrate
  state.
- **Adopters** consume **core ZP** and (optionally) **ZP Console** and
  (optionally) **the ZP Surface Spec** if they're building cockpits.

Forbidden:

- **Core ZP** must not consume ZP Console code, the Surface Spec, or
  cockpit assumptions. The substrate must work without any UI. (Eventual
  discipline pin: build-time test that `crates/zp-*` does not import
  anything from Console code.)
- **The ZP Surface Spec** must not depend on any specific Console or
  cockpit implementation. It is the contract; implementations target it.
- **Public site** must not display authenticated state, personal chain
  data, or Console UI.
- **foundation Console** must not contain foundation-specific code that
  isn't also useful to other adopters. Foundation-specific stuff lives
  in foundation's deployment configuration, not in Console source.

## What this clarifies that wasn't clear before

- The "SOC" framing was an artifact of an earlier era when ZP was also
  trying to be the agent framework. That conflation is closed; the
  agent territory belongs to consumer cockpits (the foundation's
  cockpit is IronClaw). The SOC label and its dashboard go.
- ZP never processed mail. Mail at `mail/index.html` is foundation-
  internal Console infrastructure, not substrate. It belongs at `app.*`
  as part of foundation Console, not on the public site.
- The director's personal chain viz is a Console surface (authenticated,
  personalized). A public chain-viz demo using synthetic data is a
  separate surface that may live on the public site for illustration.
- `webui-next/` is accumulated developmental scratch, not a coherent
  library. Of its contents, only ~17 files are git-tracked; the rest
  (including `Tiles/`, `SurfaceCatalog/`, package config, most of
  `Bridge/`) is local-only experimentation. When ZP Console is built,
  it draws on what's in `webui-next/` as informal reference but is not
  an extraction from it.
  - **`src/components/Bridge/`** content is exploratory SOC dashboard
    chrome from the agent-framework era. Tracked tail informs the
    cleanup arc, not the Console implementation.
  - **`src/components/Tiles/`** is local-only sketch of what an artifact
    library tile renderer might look like. May inform the eventual
    Console tile renderer; not a current production component.

- **The artifact library is a cross-cutting primitive**, not exclusively
  Console. The data (content-addressed, signable artifacts) and the
  storage/signing protocol are substrate primitives — they live in
  `crates/zp-*` alongside the receipt and signing primitives. The
  rendering layer (tile components inside ZP Console, operator review
  UX) is Console-level. The public site may consume signed artifacts
  for illustration (e.g., a public chain-viz demo rendered from a
  signed synthetic-data artifact), but it never generates or signs them.

- **The ZP Surface Spec is the contract between cockpits and ZP Console.**
  Like Ethereum's EIP-1193 or MCP's primitive set, it is small,
  versioned, and external to any specific implementation. Substrate
  does not depend on it. Console implements it (defines what surface
  area cockpits can contribute). Cockpits implement it (expose chat,
  voice, tools, status, tiles per the spec). Future cockpits and
  future Console implementations both target the same spec; the spec
  is the durable artifact. Recommended naming and structuring follows
  the SPIFFE → SPIRE pattern (spec named separately from any reference
  implementation).

## Migration commitments

These are the deltas between current state and target state, captured
here so the migration arc has a defined endpoint.

1. **Move authenticated content off the public site.** The onboarding
   storyboard, SOC pages, mail, Investigation, Default Agent picker,
   and all director-personalized surfaces leave `zeropointfoundation.org`
   and land at `app.zeropointfoundation.org` as part of foundation
   Console.
2. **Reissue the cookie session under the `app.*` cookie scope** so the
   migrated foundation Console authenticates correctly.
3. **Stand up the public site.** Author or import the foundation's
   public content. Public site is empty of Console UI by the end of
   migration.
4. **Build out the `app.*` arrangement.** A single Cloudflare Worker
   at `app.*` routes between the IronClaw tunnel (for cockpit traffic
   per the Surface Spec) and the foundation Console bundle (for
   workspace surfaces, tile renderer, chain viz). Both halves
   authenticated via the same session.
5. **Design the ZP Surface Spec.** The contract between cockpits and
   ZP Console — what cockpits expose, how Console composes,
   event/lifecycle/trust semantics. Standalone published artifact,
   versioned separately from substrate and Console.
6. **Build the ZP Console reference implementation.** Workspace shell,
   navigation, chain viz integration, tile renderer, cockpit slot per
   the Surface Spec. Bundled with substrate distribution; replaceable
   by adopters who want to fork.
7. **Drop the "SOC" label entirely.** SOC was agent-framework-era
   framing; it's superseded by ZP Console.
8. **Decommission agent-framework era artifacts** — Default Agent
   picker, Investigation persona filters, deprecated officer personas
   (Atlas / Aegis / Themis / Sparky / Echo) wherever they appear.
9. **Land the artifact library storage decision** (R2 / D1 / KV per
   `docs/ARTIFACT-LIBRARY-2026-05.md` §3) before foundation Console
   ships. Console consumes the library; the library needs a backing
   store before its consumers are operational.

## What's NOT in this document

- Specific cleanup commits (those live in the audit design doc and the
  cleanup arc that follows it)
- The discipline pin that will enforce the substrate↔Console
  boundary (proposed but not yet written)
- The future shape of cross-foundation adoption (if multiple foundations
  ever exist, each operating their own deployment of Console on top of
  core ZP, the structure here scales but specifics are out of scope)

## Refs

- `CLAUDE.md` — current project framing ("portable trust infrastructure
  for the Agentic Age")
- `docs/ARCHITECTURE-2026-04.md` — the substrate's north star spec; this
  doc is complementary, defining the surfaces around the substrate
- `docs/ARTIFACT-LIBRARY-2026-05.md` — the cross-cutting primitive that
  spans substrate (data + signing protocol) and ZP Console (tile
  rendering surface). The `Tiles/` directory in `webui-next/` is local-
  only sketch material that may inform the eventual implementation.
- `docs/handoffs/ui-freshness-audit-investigation-2026-05.md` — the
  investigation brief whose findings triggered the architectural reset
  that produced this document
- `docs/handoffs/ui-freshness-audit-design-2026-05.md` — the audit
  design doc whose per-surface verdicts will be re-evaluated against
  this boundary architecture
- `docs/handoffs/chain-viz-v1-foundation-deployment-design-2026-05.md`
  — earlier surface-decision doc, partially superseded by this one (the
  two-surface split it described was directionally right but mis-
  identified which surface was workspace)

---

*Reference, not investigation. Edited as architectural acts.*
