# ZP Surface Spec — Cockpit Tier Contract

*Dated 2026-06. The runtime-neutral contract between the Cockpit tier and
ZP Console. Names which affordances a cockpit implementation MUST have,
which it MAY have, and which it MUST NOT have, so that affordance gaps are
immediately classifiable as degradations vs disqualifications vs correct
postures.*

*Updates to this doc are architectural acts and should be treated as such.*

---

## 1. What this doc is

This is the Cockpit tier contract — the operational complement to
`SURFACE-BOUNDARIES-2026-05.md` at the Cockpit-Console integration surface.
SURFACE-BOUNDARIES pinned the terminology: "The ZP Surface Spec — the
contract that defines how cockpits integrate with ZP Console — what surface
area a cockpit exposes (chat, voice, tool invocations, status, tile
contributions), how the Console composes those surfaces, event routing,
lifecycle, trust attribution. A published interface specification,
transport-agnostic." This document partitions that specification into
Required, Optional, and Forbidden affordances.

The contract is runtime-neutral by construction. IronClaw, the Foundation's
deployed cockpit, is the reference implementation. Other cockpits — Ember,
Agent Zero, KiloCode, and any future implementation in any language or
framework — conform to the same contract. The contract is what makes them
interchangeable.

This document is the spoke for Tier 4 in the taxonomy established by
`SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md`. The adjacent Tier 3 spoke is
`CONSOLE-CONFORMANCE-CONTRACT-2026-06.md` — the Console tier contract.
Console and Cockpit are adjacent peers, not nested tiers: Console provides
the slot; Cockpit fills it via this Spec. Console conformance does not
depend on which cockpit is installed; Cockpit conformance does not depend
on which Console hosts it.

SURFACE-BOUNDARIES recommends the SPIFFE → SPIRE naming pattern for this
specification: the spec named separately from any reference implementation.
This document is the spec's contract form; IronClaw is the SPIRE analog.
The spec stands alone.

---

## 2. The category statement

A Cockpit is a pluggable conversational agent that projects chain-anchored
operator authority into conversational form — dialogue, voice, structured
tool invocations, status surfaces — and integrates with a ZP Console via
this Spec. The Cockpit does not hold authority; it projects authority that
the chain grants to the operator. Every affordance it presents corresponds
to a capability the operator currently holds on the chain; every tool
invocation it initiates passes through the substrate's gate before
producing any side effect; every cross-session state it maintains is either
held in the chain or does not exist.

This category sits at the intersection of two structural commitments. The
first is the cockpit-OS framing from Architecture §4b: the cockpit is a
pure projection of chain-anchored state into a native interaction mode.
What the operator can do right now is what the current chain state
authorizes, rendered by the cockpit as conversational affordances — a set
of available tools, a voice capable of issuing gate-checked commands, a
dialogue partner whose answers are grounded in chain receipts rather than
hallucinated from prior context. The second is the project-not-decide
integration pattern from `SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md`:
the cockpit renders chain-anchored state; authority lives in the chain.
There is no cockpit-resident authority claim, no static menu of available
actions, no cross-session capability declaration that persists outside what
the chain records.

The Cockpit is not the substrate. It does not sign receipts, run the gate,
or hold the chain. It is the operator's conversational face for a substrate
that is doing all three. A cockpit that mistakes itself for the substrate —
that signs its own authorizations, holds its own delegation state, or routes
operator actions around the gate — has violated the architectural separation
that makes cockpits pluggable and the substrate trustworthy.

---

## 3. Required affordances

An implementation lacking any of these cannot serve as a conformant ZP
cockpit. The fallback when the Cockpit tier is absent is for the operator
to interact with the substrate directly via CLI or Console without a
conversational agent surface. That is a real capability degradation — no
conversational chain interpretation, no natural-language verb invocation,
no voice-driven operator action — but the substrate's correctness is
entirely unaffected. The gate still runs; receipts are still signed; the
chain still holds.

**1. Surface Spec event protocol.** A cockpit must speak the Surface Spec's
event protocol to the hosting Console: declaring its capabilities on
registration, accepting substrate events routed through Console, emitting
action intents toward Console for forwarding to the gate, and surfacing
state changes through Console's renderers rather than maintaining a parallel
display. The event protocol is the cockpit's sole integration surface with
Console. A cockpit that bypasses the protocol — that, for example, renders
its own floating UI outside Console's tile layout without declaring it
through the slot lifecycle — is not integrated; it is co-located. The
protocol is the canonical path (P8) for every capability the cockpit
contributes to the workspace.

**2. Capability declaration on registration.** On connecting to a Console
slot, the cockpit must declare its capabilities: which verb categories it
can request invocation for (based on the current operator's chain-derived
capability scope), which surface contributions it brings (chat panel, voice
surface, tile contributions, status widget), and what lifecycle events it
handles. The capability declaration is not static: it must reflect what the
operator's current chain state authorizes, not a hardcoded feature list. A
cockpit that declares "I can invoke all delegation verbs" regardless of
whether the operator holds delegation authority is asserting capability the
chain has not granted — a correctness failure, not merely a UX error.

**3. Gate-mediated verb invocation.** Every cockpit-initiated action that
produces a substrate side effect must be requested through the gate, via
Console's event routing, rather than executed directly. The cockpit
assembles the intent (verb name, actor, subject, claim, capability-used);
Console routes it to the operator's substrate; the gate evaluates it; the
result — allowed or denied, with the corresponding receipt — comes back
through Console to the cockpit. The cockpit surfaces the outcome to the
operator. No shortcut that lets the cockpit produce an execution receipt
without a gate evaluation is conformant, regardless of how the cockpit's
runtime is structured. **P1, P3.**

**4. Chain-anchored conversation substance.** The cockpit's conversational
output — answers about what happened, proposals for next actions, narration
of chain state, interpretation of receipts — must be grounded in chain-
anchored evidence, not in the cockpit's own session-local state or hallucinated
from prior context. When the operator asks "what did I authorize for the
delegation to Agent Zero?", the cockpit must consult the chain receipts via
the substrate's query APIs, through Console's event routing, and base its
answer on what the chain records. This is not a quality-of-service
requirement; it is a structural commitment: a cockpit that produces answers
about chain state without consulting the chain is not projecting the chain,
it is replacing it. **P1, P5.**

**5. Lifecycle hooks: registration, capability refresh, teardown.** The
cockpit must implement three lifecycle transitions. On registration, it
connects to the Console slot, declares capabilities, and begins accepting
events. On capability refresh — triggered when the operator's chain state
changes in a way that affects what the cockpit can offer (a new delegation
lands, an expired capability is withdrawn) — the cockpit re-derives its
available verb set from the updated chain state and re-declares to Console
without requiring a full re-registration. On teardown, it cleanly removes
all surface contributions from the Console layout and releases the slot. A
cockpit that does not handle capability refresh will, over time, present
operators with affordances corresponding to expired authority — exactly the
failure mode the chain-configures-cockpit heuristic exists to prevent.

---

## 4. Optional affordances

Each optional affordance improves the operator experience without affecting
chain correctness.

**Specific voice and persona.** A cockpit may have a named character — a
voice profile, a conversational style, a name the operator knows it by.
IronClaw's foundation deployment is configured with the Foundation's persona
conventions. Ember, KiloCode, and Agent Zero have different characters. The
character is a configuration choice; the structural commitments above are
invariant across characters.

**Custom cockpit-rendered chrome within the surface contribution boundary.**
Within the tile or panel region that Console has allocated to the cockpit
through the slot lifecycle, the cockpit may render its own UI elements beyond
a plain chat thread — structured receipt summaries, artifact previews,
confirmation dialogs for multi-step actions. These must remain within the
declared surface contribution boundary and must not render outside it.

**Extended tool sets beyond the gate's minimum.** A cockpit may integrate
additional tools specific to its deployment context — a Foundation cockpit
may surface artifact library management tools, a domain-specific cockpit may
surface custom verb families — provided every such tool routes through the
gate and every invocation produces a receipt. Having more tools than a
minimal cockpit is optional; bypassing the gate for any of them is forbidden.

**Conversational style and interaction patterns.** How the cockpit phrases
proposals, how it handles ambiguity, whether it asks for confirmation before
multi-step actions, how verbose its chain narration is — these are style
choices that adopters configure per deployment. The Foundation's conversational
conventions (documented in `docs/AGENT-AS-UX-ARCHITECTURE-2026-05.md`) are
one instance of this; they are not the contract.

**Multilingual support and localization.** A cockpit may support operator
interaction in multiple languages. The chain's receipt content is language-
neutral by construction; the cockpit's conversational surface over it is not.
Localization is entirely optional.

**Proactive surface contributions.** A cockpit may proactively push tile
contributions, status updates, or notification-style surface items to
Console's layout — for example, surfacing a pending delegation approval as a
tile when the relevant receipt lands on the chain. This requires the cockpit
to subscribe to chain events via the substrate's event stream (through
Console's routing) and trigger surface contributions reactively. Without this
affordance, the cockpit responds to operator-initiated dialogue only; the
chain notifies the operator through Console's own chain viz, not through the
cockpit's surface.

---

## 5. Forbidden affordances

The forbidden category names things a runtime-capable cockpit implementation
must not do at this tier. Lacking a forbidden affordance is correct posture,
not degradation.

**1. Bypassing the gate for any verb invocation.** The cockpit must not
produce execution receipts, emit chain entries, or trigger substrate side
effects through any path that does not pass through the gate. This includes
direct calls to substrate APIs that skip gate evaluation, Console-mediated
shortcuts that the Console implementation provides as a convenience, and any
cockpit-internal logic that decides the operator "obviously" has authority
and acts on that assumption without a gate evaluation. The gate exists
because "obviously authorized" is not a cryptographic proof; only a gate-
issued receipt is. **P1 (a signed receipt from the gate is the only
structural attestation that an action was authorized), P3 (a cockpit that
makes its own authorization decisions is a center forming in the
conversational layer).**

**2. Holding cross-session state outside the chain.** The cockpit must not
persist operator-derived state — what capabilities the operator holds, what
delegations are in effect, what the operator has recently done — in cockpit-
local storage that survives across sessions independently of the chain. The
chain is the durable record. On the next session, the cockpit re-derives
its capability set from the chain's current state. A cockpit that maintains
its own capability ledger alongside the chain will drift from the chain;
when the two disagree, the cockpit presents operators with affordances that
the chain no longer supports. **P3 (the cockpit's cross-session state is a
center), P5 (the chain is the primary mode; cockpit-local storage that
duplicates it is an inverted store-and-forward).**

**3. Claiming authority the operator has not been granted on the chain.**
The cockpit must not fabricate delegation grants, assert capability scope
the operator's chain does not record, or present affordances as available
when no chain receipt authorizes them. This applies to optimistic displays
("I'll show you the delegation tool now and we'll get the authorization
sorted afterward") and to implicit self-authorization ("I can invoke this
verb because the operator is clearly authorized based on context"). Authority
exists when the chain records it and does not exist when the chain does not,
regardless of what the cockpit's session context suggests. **P1, P3.**

**4. Persisting operator-derived chain material outside the chain.** The
cockpit must not write receipts, delegation grants, capability state, chain
tip hashes, or other operator-derived chain material to cockpit-local durable
storage. Reading chain material to inform the current conversation is
required; retaining it locally beyond the session is forbidden. A cockpit
that archives receipts into a local database has created a second chain — one
it controls, one that can diverge, and one whose divergence the operator
cannot detect. **P3, P4** (a cockpit-local receipt store is a duplicate data
path that earns its place through no cryptographic necessity).

**5. Speaking directly to the substrate, bypassing Console's slot lifecycle
and event protocol.** The cockpit must not establish direct connections to
the operator's substrate that circumvent Console's slot lifecycle — for
example, by maintaining a separate WebSocket to `zp serve` that carries verb
invocations outside the Surface Spec event channel. The Surface Spec event
protocol is the canonical path (P8) for cockpit-to-substrate communication.
A cockpit that creates a second path has introduced half-state: Console may
be in one lifecycle phase while the cockpit's direct connection is in
another. This is the Console-tier analog of what edge workers must not do to
the chain. **P8 (one canonical path per substrate concern).**

**6. Acting under another operator's identity within a single session.** The
cockpit must not switch the operator identity it is projecting for — the
principal whose chain it consults, whose gate it invokes, whose delegation
scope it uses — during an active session without a new authentication
ceremony. A cockpit session projects the authority of exactly one operator:
the one authenticated at session establishment. If a multi-operator deployment
requires different operators to share a workspace, each operator's cockpit
session must be independently authenticated against their own chain. The
cockpit must not infer a second operator's authority from context. **P2
(identity is a key, not a location — the operator is identified by their
Genesis-rooted key, not by a conversational claim made mid-session), P3.**

---

## 6. Composition with principles

The contract's shape derives from three clusters of principles, parallel in
structure to the Console tier's derivation but scoped to the conversational
projection surface.

**P3 (there is no center) is the load-bearing principle for the Forbidden
category.** Entries 2–4 prevent the cockpit from accumulating its own
persistent state that competes with the chain. Entry 1 prevents it from
issuing its own authorizations that compete with the gate. Entry 5 prevents
it from creating routing paths that compete with the Surface Spec channel.
Entry 6 prevents it from claiming multiple operator identities within a
session. Each forbidden entry is a way a cockpit could become a center —
an authority, a state store, or a channel — that the architecture has
specifically committed to not having.

**P1 (signing is gravity) justifies entries 1 and 3 jointly.** The gate's
receipt is the only structural attestation that a verb invocation was
authorized. A cockpit that bypasses the gate produces an action with no
chain-anchored authorization — an action that happened in the world but not
in the substrate's own account of what it authorized. Entry 3 is the same
failure mode at the capability-declaration level: an affordance the cockpit
presents without chain backing is an assertion without a witness.

**P8 (one canonical path) justifies entry 5 directly.** The Surface Spec
event protocol is the one canonical path for cockpit-to-substrate
communication. A direct connection alongside the Spec channel is a second
path for the same concern; the two will drift. This is the same shape as
the substrate concern in `SINGULAR-SOVEREIGN-ROOT-2026-05.md` (one credential
loader, not multiple) and in the audit chain (one signed record, not
chain-plus-separate-log). The structural correction is always the same:
retire the second path.

**P6 (a tool is intent, crystallized) justifies the Required affordances.**
The cockpit's conversational surface is the rendering of operator intent in
dialogue form. Required affordances #1–3 (Surface Spec protocol, capability
declaration, gate-mediated invocation) are what makes conversational intent
structurally real: the cockpit does not merely discuss actions, it routes
them through the gate and surfaces what the gate decided. Required affordance
#4 (chain-anchored substance) is what makes conversational content
structurally grounded: the cockpit's answers are derived from signed evidence,
not from session context that may have diverged from the chain.

**P2 (identity is a key, not a location) justifies entry 6 directly and
Required affordance #2 structurally.** The operator is the key; the key is
Genesis-rooted; the session authenticates against that key. The cockpit's
capability declaration must reflect what the chain records for that key's
authority, not what the cockpit infers from conversational context.

---

## 7. Portability sketches

The Spec is runtime-neutral. Conformance does not imply any particular
language, deployment platform, or agent framework.

**IronClaw (Foundation cockpit, current reference implementation).** A
Cloudflare Workers deployment connected to the Foundation Console at
`app.zeropointfoundation.org` via Cloudflare Tunnel. Persona: the Foundation's
conversational conventions from `AGENT-AS-UX-ARCHITECTURE-2026-05.md`.
All Required affordances are present. Optional affordances in scope: extended
tool sets (artifact library management, Foundation-specific verb families),
proactive surface contributions (delegation approval notifications), voice
surface integration through Console's voice routing. IronClaw is the SPIRE
analog for this Spec; it is not the only conformant implementation.

**Ember (planned adopter cockpit).** A cockpit implementation targeting a
different operator's Console deployment, with different tooling and a
different conversational character. Conformance: all Required affordances,
including gate-mediated invocation and chain-anchored substance from Ember's
own operator's chain, not from IronClaw's. Ember's capability declaration
reflects Ember's operator's chain state; IronClaw's reflects the Foundation's.
The Spec makes the two interchangeable from Console's perspective.

**Agent Zero and KiloCode (code-generation cockpits).** Cockpits whose
primary surface is structured code generation and workspace manipulation
rather than conversational dialogue. These may implement the chat surface
minimally and focus surface contributions on structured artifact tiles
(generated code blocks, diff previews, deployment manifests). All Required
affordances apply equally: gate-mediated invocation is required even for
code-generation artifacts, which produce chain receipts like any other
substrate action. Optional affordances: extended tool sets (code-specific
verb families), custom cockpit-rendered chrome for structured artifact
presentation.

**Hypothetical cockpit in a different language or framework.** A Go
implementation, a Python implementation, a native mobile companion app
acting as a voice-only cockpit. Required affordances are achievable in any
environment capable of HTTP or WebSocket communication (for the Surface Spec
event protocol) and of making structured API calls to the substrate's verb
endpoints (via Console's routing). The Spec makes no claim about the cockpit's
internal architecture, only about the contract surface it presents. A cockpit
implemented in Python that speaks the event protocol and routes all verb
invocations through the gate is conformant. One that bypasses the gate in any
language is not.

---

## 8. Autoregressive update triggers

1. **A new cockpit type is adopted.** If the ecosystem gains a cockpit that
   exercises the Spec in ways the current Required affordances did not
   anticipate — a headless cockpit with no conversational surface, a cockpit
   serving multiple operators in read-only projection mode — this doc should
   be updated. Required affordances should remain invariant unless the new
   cockpit type makes one genuinely inapplicable.

2. **A new Console deployment surface is adopted.** Since the cockpit connects
   to Console via the Surface Spec event protocol, changes to Console's hosting
   model may affect what the Spec's event protocol must carry. Update this doc
   when Console's Required affordances change in ways that affect the cockpit-
   facing protocol.

3. **A Required affordance proves hard to implement portably.** If "cockpit
   must re-derive capability declaration from chain on every refresh" turns
   out to require chain API access patterns that some deployers cannot support
   without unacceptable latency, the question is whether to relax the timing
   requirement or accept that some deployments degrade to a longer capability
   refresh cycle. Either answer belongs in the contract.

4. **A Forbidden affordance is proposed for relaxation.** If someone proposes
   "allow the cockpit to cache delegation grants across sessions for offline
   conversational continuity," this doc is what the proposal must justify
   against. The default answer is no; justification must advance at least one
   of the four claims without weakening any other.

5. **A new Optional affordance is added.** Each addition should be interrogated
   for whether it is genuinely optional or has quietly become load-bearing for
   conformant cockpit behavior.

6. **A new principle is added to Architecture Part V½.** Each new principle
   may reclassify existing Optional affordances as Forbidden or elevate
   currently-implicit Required affordances to explicit ones.

---

## 9. Refs

- `docs/SURFACE-BOUNDARIES-2026-05.md` — the sibling surface-layer reference;
  pins the Cockpit concept, the ZP Surface Spec concept, and the dependency
  direction. This doc is the per-tier contract for Tier 4; that doc is the
  surface taxonomy that names the tier and the Spec.
- `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` — the hub contract; §4
  Tier 4 entry, §5 contract template, §6 integration patterns
  (project-not-decide, propose-not-sign, sign-then-act)
- `docs/CONSOLE-CONFORMANCE-CONTRACT-2026-06.md` — the adjacent Console tier
  contract (Tier 3 spoke); the Console side of the cockpit-slot relationship
- `docs/EDGE-TIER-CONTRACT-2026-06.md` — the template exemplar; established
  the Required / Optional / Forbidden partition and the composition-with-
  principles structure this doc follows
- `docs/ARCHITECTURE-2026-04.md` §4b — the cockpit-OS framing; the category
  claim that a cockpit is a pure projection of chain-anchored state, not a
  seat of authority
- `docs/ARCHITECTURE-2026-04.md` Part V½ — the eight design principles that
  every per-tier contract derives from
- `docs/AGENT-AS-UX-ARCHITECTURE-2026-05.md` — the Foundation's conversational
  surface specification; describes the five UX sub-surfaces and the chain-
  enforceability commitments that IronClaw implements as the reference cockpit
- `docs/handoffs/clic-console-cockpit-2026-06.md` — the Console/cockpit
  dispatch brief; surfaces the chain-configures-cockpit heuristic whose
  structural implications this doc formalizes
- `CLAUDE.md` workflow heuristics — "the chain configures the cockpit; cockpits
  are pure projections" and "pair conversational interfaces with reference
  surfaces that reveal the control space" — the heuristics this contract
  translates into per-tier structural commitments
- `crates/zp-verbs` — the verb set that all gate-mediated cockpit invocations
  reference; the canonical enumeration of what the cockpit can request
