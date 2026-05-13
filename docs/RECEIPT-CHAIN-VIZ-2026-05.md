# Receipt Chain Visualization — Standard Artifact

*2026-05-13. The legibility layer the substrate has been missing.
Ken-pilot's deepest finding: we built the chain, we write to the
chain, but we don't read the chain — and what isn't read can't be
load-bearing. This artifact closes that gap.*

## What it is

A reusable, embeddable component that renders a live receipt chain
visually. Receipts appear as cards in vertical sequence, linked by
explicit hash-chain references. New receipts arrive in real time and
slide in at the bottom; the chain visibly grows.

The same component serves multiple surfaces:

- **Public marketing** — `zeropoint.global/chain` shows a
  visibility-filtered view of live foundation activity. Replaces the
  current abstract "see the chain in action" stub. Visitors see
  receipts being written by real operators, with signatures they can
  verify.
- **FoundationTimeline (#102)** — internal director-facing surface.
  Shows everything visible to the viewer's role. Click any receipt
  for full content + verification trace.
- **Wizard handoff** — at Phase 7, instead of just naming the
  receipt count, show the freshly-written chain. "Your ceremony just
  wrote these 9 receipts." Concretizes for the director the moment
  they finish.
- **Sage chat surface** — when Sage answers "what happened?", the
  chain view is the visual companion to Sage's prose.

## Why this is the move

ZeroPoint's central claim is that the chain is the source of truth.
But the chain has been operationally invisible — captured, but never
*surfaced*. When today's Ken-pilot hit bugs, we debugged via console,
logs, and SQL. We never queried the chain. The chain became an
artifact rather than the operating surface.

That gap is exactly what makes the marketing demo abstract for
visitors AND makes the substrate underutilized for us. Building this
artifact closes both ends of the same problem.

Connects to CLAUDE.md → *Workflow heuristics* → "name and shape
artifacts for their downstream consumer" — the chain viz IS the
consumer-side of the receipt-emission contract. Once it exists,
emitting receipts becomes consumer-shaped instead of fire-and-forget.

## Two audiences, one component, different modes

The chain viz serves two distinct audiences with different needs.
Treating them as one surface produces something that's halfway-
right for both.

**Public visitor** (`zeropoint.global/chain`) — first time meeting
the concept of receipts. Needs the abstract concept *concretized*.
Pedagogical mode. Verification interactions are first-class: this
is where someone *experiences* tamper-evidence by trying to tamper,
*experiences* cryptographic verification by running the math in
their own browser. Sage's voice explains *what receipts ARE* and
*why verification matters*.

**Director** (FoundationTimeline, wizard handoff, internal surfaces)
— operator of the system. Doesn't need to learn what receipts are;
needs to *read what they say*. Operational legibility mode. The viz
surfaces *what's happening / what happened*, filterable by time,
operator, claim. Sage's voice explains *what the receipts mean* —
"this is your registration", "this is when you selected your
voice", "this is the capability check that fired". Verification
interactions exist as a power-user option but are off the primary
surface; directors aren't trying to learn cryptography, they're
trying to find a receipt or audit a moment.

Same component (`<zp-receipt-chain>`), different `mode` attribute,
different copy. The visual primitives (animated formation, chain
links, signature status) are shared. What differs is the affordances
and the narration.

## What makes the concept actually land — three layers

For the **public visitor**, real-time formation alone makes the
chain *visible* but not *meaningful*. A visitor who watches receipts
appear without interacting can come away thinking "cool animation,
so... it's a log?" Visibility ≠ understanding.

The chain viz lands the concept *for the public visitor* when it
composes three layers, not just the first. For directors, the
animation + legibility (filter, navigate, read meaning) is the
primary value; the deeper verification layer is optional.

### Layer 1 — Animation (the entry surface)

Receipts form, chain extends, hash links draw. Pulls the visitor in,
makes the chain visible. But by itself: theater.

### Layer 2 — Verification (the closer)

Three interactive moves that turn watching into doing:

- **Click-to-verify.** Each receipt has a verify action. Clicking it
  runs SHA-256 + signature verification *in the visitor's own
  browser*, against the predecessor hash, against the chain. The
  computed values are shown alongside. That moment — "I just
  computed a cryptographic claim with my own machine, not trusting
  the server" — is what makes "verifiable not trusted" concrete.

- **Try-to-tamper.** A guided interactive: edit any field of a
  receipt. Watch the entire downstream chain go red, hash links
  break, verify buttons fail. The visitor doesn't read about
  tamper-evidence; they experience the chain rejecting tampering in
  real time.

- **Side-by-side / replay.** "Here's what Ken saw when he onboarded;
  here's what you're seeing now. Byte-identical." Or a scrubber
  through the chain's history, showing it rebuild at every point.
  Makes "single source of truth, no privileged view" tangible.

Without these, the animation is theater. With them, the visitor
performs the cryptography themselves and leaves with a concept they
*used*.

### Layer 3 — Narration (the interpreter)

Each UI event is paired with pre-authored copy in Sage's voice:

- Visitor clicks verify → display: *"Your browser just computed the
  SHA-256 of this receipt and checked it against the signature. The
  foundation server wasn't involved. That's why this works —
  verification doesn't require trusting us."*
- Visitor tampers → display: *"You just changed a single byte.
  Notice every receipt downstream is now red — that's tamper-
  evidence. Not even the foundation can fix this; the chain itself
  rejected it."*
- Visitor idles → display: *"Try clicking verify on the last
  receipt — you'll be running the cryptography yourself."*

Without narration, verification is a UI puzzle — the user clicks
verify and sees math they don't know how to read. With narration,
every interaction has a meaning attached.

### Narration is voice, not live agent

Critical architectural distinction: **the narration layer is
pre-authored copy in Sage's voice, bound to specific UI events.
It is NOT a live agent.**

- No LLM call at narration time
- No conversational surface
- No authentication required for the visitor (it's static-shaped
  reactive copy, like a guided tour)
- The visual treatment (Sage chat bubble) is shared with the wizard
  via the existing `sageHtml()` primitive

This matches how the wizard ceremony already works: `sageHtml(...)`
renders pre-written bubbles per phase. Sage *as a character* is
present everywhere the foundation speaks; Sage *as a running agent*
is gated behind authentication and stays on internal surfaces.

The public chain viz exposes Sage's voice through carefully authored
copy, just as the wizard does. It does not expose a live LLM agent
to anonymous visitors. That boundary is intentional — direct agent
exposure is an architectural commitment the foundation hasn't yet
made and shouldn't make casually for a marketing exhibit.

A live conversational Sage (operator asks Sage arbitrary questions,
Sage queries the chain and answers) is a real future capability —
but it lives behind authenticated surfaces only, with explicit
authorization. It is not a v1 dependency of the chain viz on any
surface. See v2 future-work notes below.

### What makes this the right shape

The three layers, in sequence: animation pulls visitors in,
verification gives them agency, narration gives them understanding.
A useful acceptance test: *can a visitor, after 60 seconds with the
viz, answer "what would I do if I suspected the foundation was
lying"?* If yes, the concept landed. If no, we built theater.

## Architecture

### One component, multiple surfaces

A web component (`<zp-receipt-chain>`) — framework-agnostic, self-
contained, embeddable anywhere by including a single script tag.

```html
<script src="https://zeropoint.global/lib/zp-receipt-chain.js"></script>
<zp-receipt-chain
  feed="/api/receipts/stream"
  operator="ken"
  since="1h"
  verify="true">
</zp-receipt-chain>
```

Attributes (all optional except `feed`):

| Attribute | Purpose |
|---|---|
| `feed` | URL of the receipt feed — SSE endpoint preferred, polling fallback |
| `operator` | Filter to a single operator's receipts |
| `since` | Time window (e.g., `1h`, `24h`, `7d`, or ISO timestamp) |
| `claim-pattern` | Filter by claim glob (e.g., `onboard:*`) |
| `verify` | `"true"` to fetch and verify signatures inline |
| `mode` | `"live"` (default), `"historical"`, or `"replay"` |
| `max-receipts` | Cap the visible chain (default 50; older receipts scroll out) |

### Data shape

Each receipt rendered comes from the foundation's audit API in this
shape (consumer-side; the producer adapts to this):

```json
{
  "id": "rcp-7c4ed102",
  "prev_id": "rcp-a3f9c821",
  "operator_id": "ken",
  "claim": "onboard:identity:generated",
  "subject": "ken",
  "capability_used": null,
  "metadata": {"fingerprint": "47d7...7b92"},
  "signature": "ed25519:base64url:...",
  "signature_status": "verified|pending|unsigned|invalid",
  "created_at": "2026-05-13T14:23:15Z"
}
```

Note `signature_status` — the visualization renders this directly. If
the foundation hasn't yet signed receipts (today's state, see #143),
it returns `"unsigned"` and the viz makes that visually obvious. The
viz itself becomes a forcing function for signing.

### Feed contract

The endpoint is consumer-side: it gives the viz what it needs.

- **SSE preferred** (`text/event-stream`) — each event is a single
  receipt JSON. New receipts emitted as written. Connection survives
  across foundation activity.
- **Polling fallback** — GET returns most recent N receipts in JSON
  array. Component polls every 2-5 seconds based on activity level
  (backoff when idle).
- **Filter params** are applied server-side — the component never
  receives receipts it shouldn't see. Visibility filtering (per #105
  ACL work) is enforced at the API boundary, not in the viz.

### Visual rules

- Vertical chain, top-down (oldest at top, newest at bottom for replay
  mode; reversed for live mode where newest arrives at bottom)
- Each receipt is a card with: claim, operator + time + meta
  one-liner, id prefix, prev prefix, signature status
- Hash links between cards are explicit (vertical stem +
  chevron-down). The chain visibility IS the concept.
- Click to expand: full receipt content, full signature, predecessor
  trail, verify button
- Real-time arrivals: slide in from below, the hash link draws
  itself, the chain extends. ~400ms total animation.
- Replay mode: receipts appear sequentially with configurable speed.
  Same animation as live, just scripted.

### Styling

Uses the foundation's design system (dark theme, --bg: #0a0a0c,
accent #7eb8da, Inter + JetBrains Mono). Auto-adapts to light/dark
mode if hosted on a light surface (web-component CSS scoped via
shadow DOM).

The marketing-site version may override styles for the
zeropoint.global aesthetic; the foundation-internal version uses the
substrate's design tokens directly.

## Implementation notes

### Component scaffold

- Lit (https://lit.dev) or vanilla custom element — no framework
  dependency
- Shadow DOM for style encapsulation
- Lazy-load Chart.js if a "ceremony summary" graphic is needed (not
  in v1)
- ~400-600 lines total for the core component

### Foundation worker endpoint additions

- `GET /api/receipts/stream` — SSE feed of new receipts (filtered)
- `GET /api/receipts` — paginated list of recent receipts (filtered)
- `GET /api/receipts/:id` — single receipt with full content
- `POST /api/receipts/:id/verify` — server-side signature verify
  (returns the verification trace; the viz can also verify
  client-side once #143 lands)

All gated by the viewer's session and the receipt's visibility
metadata.

### Where it ships first

1. **Wizard Phase 7 handoff** — drop in the component pointed at the
   ceremony's receipts. Director sees their own chain on completion.
   Lowest-risk first deploy. Probably the smallest install.
2. **FoundationTimeline (#102)** — full live view for directors, with
   filters.
3. **zeropoint.global/chain** — public-facing version with visibility
   filtering at the API layer. Replaces the current abstract demo.

### Dependencies

- Foundation receipt API surfaced as described above (~half-day of
  worker work)
- Receipt signing (#143) — not strictly required to ship the viz, but
  the `signature_status: "unsigned"` state on the marketing site is
  not a good look. Sequence: ship viz with unsigned state → ship
  signing (#143) → marketing-site exposure follows naturally.

## Spec checklist

The production component must:

- [ ] Render as a web component (`<zp-receipt-chain>`)
- [ ] Accept feed URL + filter params
- [ ] Animate receipt arrivals (slide-in, hash link draws)
- [ ] Show signature status as first-class visual (verified, pending,
      unsigned, invalid)
- [ ] Expand-on-click for full receipt detail
- [ ] Support replay mode (configurable speed) for marketing demo
- [ ] Auto-adapt to light/dark mode
- [ ] Handle SSE feed with polling fallback
- [ ] Respect visibility filtering enforced at API layer
- [ ] Lazy-load (component initializes only when in viewport)
- [ ] Be embeddable without framework dependencies

## v2 future work (not on the v1 critical path)

### Live conversational Sage on internal surfaces

Today's Sage is character + copy: voice patterns rendered through
pre-authored bubbles bound to events. A future capability is
*conversational* Sage — directors asking arbitrary questions, Sage
querying the chain and answering. That's a real runtime surface
that requires:

- Authentication (no anonymous access)
- Rate-limiting and abuse protections
- A defined capability scope for Sage (what queries can Sage answer,
  what data can Sage surface, what actions can Sage take)
- Audit-chain receipts for every Sage query and answer (Sage's
  reasoning is itself a chain-recorded event)

This belongs behind the same substrate-session authentication that
protects `app.zeropointfoundation.org`. It is explicitly NOT on any
public-facing surface, including the marketing-site chain viz.

### Magic-moment graph integration

When the Ecosystem graph becomes live (#146), receipts can drive
node activations — a receipt about Ken pulses the Ken node, a
receipt about Receipt Chain pulses the Receipt Chain node, the
edges light up momentarily. The graph becomes the substrate's
nervous system, the chain viz becomes the event stream that
animates it. Beautiful, but requires both halves to be live; not
on the chain-viz v1 path.

## Refs

- `docs/handoffs/director-pilot-preflight-2026-05.md` — preflight
  surfaces that the chain wasn't a debugging surface today
- `docs/AGENT-AS-UX-ARCHITECTURE-2026-05.md` — Sage's voice and
  patterns; this spec extends Sage's *voice* to a new surface, not
  Sage as a live agent
- Task #102 — FoundationTimeline v1 (this artifact is the rendering
  layer)
- Task #143 — Foundation receipt signing (the "trust" half of the
  legibility/trust pair)
- Task #145 — production implementation of this spec
- Task #146 — Ecosystem graph live-ness (gates the v2 magic-moment
  integration)
- CLAUDE.md → Workflow heuristics → "name and shape artifacts for
  their downstream consumer"
