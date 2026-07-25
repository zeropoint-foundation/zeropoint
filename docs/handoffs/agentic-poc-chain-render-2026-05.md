# Handoff — Agent-Rendered Chain PoC (production-staged)

*2026-05-13. Target: terminal Claude working in `~/projects/ironclaw`
(`zp-daily-driver` branch) and `~/projects/zeropoint/zeropointfoundation.org`.
Refs: AGENTIC-SURFACE-2026-05.md, #72, #73, #145, the design conversation
that birthed this PoC.*

## Goal

Build the smallest viable test of agent-rendered substrate UX:
IronClaw renders Ken's onboarding receipt chain in chat, in the Regent's
voice. Staged to the deployed foundation workspace; tested against
production data. No localhost rig.

This is a *proof of concept*, not a v1 of anything. Its job is to
generate evidence that informs whether the agentic-surface direction
(per `AGENTIC-SURFACE-2026-05.md`) is usable for daily director UX
or whether HTML surfaces remain the right shape for the foundation
in the near term.

## Why this scope

A larger commitment to agent-rendered surfaces (the wizard ceremony,
the chain viz, the per-director status panels) requires evidence the
paradigm actually works at "truly useful to humans" quality. That
evidence doesn't exist yet — MCP and AG-UI are protocols with thin
deployment track records, and ZP would be early to lean on them for
foundation-level UX. A small empirical exercise turns the bet into
data.

If the PoC lands cleanly, we commit to B (agent-rendered) for chain
viz and progressively for ceremonies. If it doesn't, we learn
specifically why and adjust — possibly keeping HTML for some
surfaces, possibly waiting for the agentic substrate to mature.

## Mechanism: live-agent narration (not templating)

Per CLAUDE.md's workflow heuristic *prerendered public, live-agent
internal*, this PoC runs on an internal authenticated surface and
should use live agent interpretation, not pre-authored per-claim
copy with placeholder substitution. The latter is templating
dressed as agent rendering and would prove nothing about whether
agent-rendered UX actually works.

The shape:

- The "bundle" is a voice anchor + a small number of few-shot
  examples. It is NOT a per-claim copy map.
- At render time, IronClaw fetches the operator's receipts, then
  asks the Regent (via its existing model surface) to narrate the chain
  in voice, using the anchor as guidance.
- the Regent interprets each receipt in context. Narration is fresh per
  render, can synthesize across receipts ("three identity steps
  clean, recovery confirmed"), and references actual metadata
  fields.
- Unknown / edge / never-seen-before claims handle themselves —
  the Regent reads the receipt as data and narrates in voice. No
  hardcoded fallback needed.

Risks this exposes that templating would have hidden — and these
are exactly the questions the PoC is for:

- Latency: one LLM call per chain render
- Quality variance: occasional off-tone narrations
- Cost: every render burns tokens
- Non-determinism: harder to test deterministically

If these risks are tolerable, agent-rendered chain surfaces are
viable for the foundation. If they're not, the PoC tells us why
and where the line is.

## What's already in place

- Ken's 9 onboarding receipts exist in production D1 (`zpmail`,
  operator_id = 'ken'). Schema from migration 0002.
- IronClaw runs at `app.zeropointfoundation.org`, behind
  substrate-session auth (#138 landed). Authenticated, capability-
  aware sessions work end-to-end.
- Foundation worker at `zeropointfoundation.org` deployed, healthy
  (per smoke-test-auth.sh).
- The wizard's existing `sageHtml()` calls in
  `zeropointfoundation.org/onboard/index.html` are the source for
  extracting Regent-voice copy.

## Build, in order

### 1. Author the voice anchor (NOT per-claim copy)

Create a small voice anchor that gives the Regent enough to narrate any
receipt from the foundation onboarding workflow in voice. This is a
guidance artifact, not a template. New file:

`zeropointfoundation.org/narratives/foundation-director-onboarding.yaml`

Shape:

```yaml
workflow_id: foundation/director-onboarding
version: 1
voice: sage

voice_anchor:
  reference: docs/AGENT-AS-UX-ARCHITECTURE-2026-05.md
  patterns: |
    Composed, anticipatory, no fawning. Dry wit when warranted, owns
    refusals plainly, treats the principal as capable. Frames decisions
    for the principal rather than dictating. The Jarvis reference is
    the anchor: service-flavored competence without subordination.

  do_not:
    - Time-of-day framing ("good morning", "have a good evening", etc.)
    - Praise or congratulations beyond what the receipt warrants
    - Filler explanation of what receipts are (the operator is past that)
    - Hedging or apology

  examples:
    - context: "claim onboard:identity:generated; fingerprint 47d7…7b92"
      narration: "You generated your keypair. The fingerprint is 47d7…7b92 — glance at the first and last four characters."

    - context: "claim onboard:recovery:acknowledged; both checkboxes confirmed"
      narration: "You acknowledged the recovery phrase. Both checkboxes — written by hand, stored in two separate places. Those 24 words are the long-term path back in if this device is ever lost."

    - context: "claim onboard:capability:demonstrated:deny; capability succession:invoke"
      narration: "The gate evaluated succession:invoke — and refused it. That's not a bug; it's the boundary doing exactly what it's designed to do."

    - context: "claim onboard:complete; 9 receipts in chain"
      narration: "Ceremony complete. Nine receipts mark each step that just happened — that's the formal record of your joining."

field_extraction_hints:
  - claim fields available on every receipt: id, operator_id, claim,
    subject, capability_used, metadata, created_at
  - the wizard emits metadata-rich payloads; the renderer should pass
    the full receipt object to the Regent so all fields are available for
    interpretation
```

Notes on shape:

- No per-claim copy. The agent reads each receipt and narrates it.
- Examples serve as in-context anchors for tone, NOT as templates to
  match. Three to six examples is enough; more risks drift toward
  template-matching behavior.
- Claim names anywhere they appear (anchor examples, agent prompt
  construction, log lines) must match the stored format exactly —
  no `claim:` prefix, no transformation. The wizard's `emit()` writes
  values like `onboard:identity:generated` straight into the
  `receipts.claim` column, and that's the form to use everywhere.
- Edge / unknown claims need no special handling. the Regent reads them as
  data.
- The bundle is not signed in this PoC. Bundle signing is future work
  parallel to receipt signing (#143).

Serve this file from the foundation worker via the existing
`[assets]` binding (no worker change needed for serving). Stable URL:
`/narratives/foundation-director-onboarding.yaml`

### 2. Foundation worker endpoint for the operator's chain

Add or formalize:

```
GET /api/operator/me/chain
  Query: claim_pattern=onboard:*  (optional)
  Auth:  substrate-session cookie (already in place)
  Returns: JSON array of receipts for the authenticated operator,
           ordered by created_at ASC
```

Build on existing receipts table. No new schema. Visibility scoped
to the requesting operator's own receipts for this PoC (broader
visibility filtering is #105).

Smoke-test endpoint with `curl` after deploy — same shape as
existing smoke-test-auth.sh checks.

### 3. IronClaw chain-render capability (live agent)

Land this as a built-in Rust tool per AGENTS.md (runtime-coupled
capability). Both natural-language invocation ("show me my
onboarding chain", "what happened in my onboarding") and a slash
route (`/chain`) route through the same tool.

The tool:

1. Calls `/api/operator/me/chain?claim_pattern=onboard:*` using the
   substrate-session cookie already on the IronClaw request
2. Loads the voice anchor from
   `/narratives/foundation-director-onboarding.yaml` (once per
   session; cache after first fetch)
3. **Constructs a prompt for the Regent** that includes:
   - the voice anchor (patterns, do_not list, examples)
   - the receipts as structured data (full receipt objects, not
     summaries)
   - a clear directive: *"Narrate this operator's onboarding chain
     in voice. One line per receipt, in chain order. Use the
     anchor's tone. Reference actual receipt content. Do not
     summarize at the end unless the chain itself ends with a
     completion receipt."*
4. **Makes an LLM call** through IronClaw's existing model surface
   (whatever provider is configured) and captures the response
5. Outputs the response as a markdown message in IronClaw's chat
   surface

This step is the heart of the PoC. The narration is generated
fresh each time; the Regent interprets the receipts in the moment using
the anchor as guidance. No template substitution. No per-claim
key lookup. The tool delegates voice work to the LLM and trusts
the anchor to keep tone consistent.

Substrate-session auth is already wired
(`src/channels/web/platform/auth.rs`, `tests/bearer_substrate.rs`).
The tool uses the existing session cookie path; no new auth code
required.

### 4. Optional: live-update mode

If straightforward, also subscribe to a receipt-stream (SSE) so new
receipts appear in chat as they're written elsewhere. Not required
for the PoC. Punt if it adds significant complexity.

## Acceptance criteria

After deploy, Ken runs the following test:

1. Opens IronClaw at `app.zeropointfoundation.org`.
2. Issues the chain command (slash or natural language).
3. Within ~10 seconds, sees his 9 onboarding receipts narrated by
   the Regent in chat.
4. the Regent's voice is recognizable across the chain — composed,
   anticipatory, no fawning, no time-of-day framing. Tone is
   consistent across receipts (the anchor is doing its job).
5. Narration references actual receipt content — fingerprint,
   chosen voice, capability evaluated — not generic statements
   that could apply to any chain.
6. Running the command twice in a row produces narrations that
   are recognizably the same voice and content, even if the exact
   wording differs (this is the live-agent test — it's interpreting,
   not echoing a template).

If 5 of 6 pass, the PoC has landed. If multiple fail — especially
4 or 5 — the failure mode tells us whether the issue is the anchor
(refine it), the model (try a different provider), or the
approach (fall back to templated public + templated internal).

## Explicit non-goals

- Workflow registry (#131) — narrative bundles in this PoC are
  static files, not registry entries. That's later.
- AG-UI streaming protocol — the PoC uses simple JSON over HTTPS.
  AG-UI integration is #73, separate work.
- MCP tool exposure — the PoC implements one capability in IronClaw
  directly; MCP-via-zp-mcp is #72, separate work.
- Replacing the HTML wizard — wizard stays as-is for Carlie's
  pilot. PoC results inform whether to migrate later.
- Public-facing chain viz — separate concern (per the public/internal
  agent heuristic in CLAUDE.md). Out of scope.

## What we'll learn

| Outcome | Implication |
|---|---|
| All five acceptance criteria pass; UX feels natural | Pattern is validated for chain viewing. Commit to B for chain viz in #145 v1. Begin migrating other read-shaped surfaces. |
| Mostly passes but UX feels rough (slow, hard to scan, narration distracts) | Pattern works in principle, needs UX iteration. Surfaces specific design problems. Commit cautiously, iterate. |
| Pattern doesn't feel useful — markdown chat is worse than an HTML page | Real signal. Either the protocol surface needs more, or HTML stays the right shape for some surfaces. Don't commit B broadly until we know why. |

## Refs

- `docs/AGENTIC-SURFACE-2026-05.md` — the architectural direction
  this PoC tests
- `docs/RECEIPT-CHAIN-VIZ-2026-05.md` — the spec that was queued
  before this PoC inserted itself
- CLAUDE.md → Workflow heuristics → "only production tests production"
  — this PoC honors that rule
- Task #145 — gated by this PoC's outcome
- Tasks #72, #73 — the longer-horizon agentic surface work this
  is a small forerunner to
