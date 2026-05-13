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

## Refs

- `docs/handoffs/director-pilot-preflight-2026-05.md` — preflight
  surfaces that the chain wasn't a debugging surface today
- Task #102 — FoundationTimeline v1 (this artifact is the rendering
  layer)
- Task #143 — Foundation receipt signing (the "trust" half of the
  legibility/trust pair)
- Task #145 (to be filed) — production implementation of this spec
- CLAUDE.md → Workflow heuristics → "name and shape artifacts for
  their downstream consumer"
