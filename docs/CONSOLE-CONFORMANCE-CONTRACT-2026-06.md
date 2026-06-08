# Console Tier Contract — What a Workspace Shell Must, May, and Must Not Do

*Dated 2026-06. The runtime-neutral contract between the Console tier and
the substrate tier. Names which affordances a Console implementation MUST
have, which it MAY have, and which it MUST NOT have, so that affordance
gaps are immediately classifiable as degradations vs disqualifications vs
correct postures.*

*Updates to this doc are architectural acts and should be treated as such.*

---

## 1. What this doc is

This is the Console tier contract — the operational complement to
`SURFACE-BOUNDARIES-2026-05.md` at the Console-substrate integration
surface. Where SURFACE-BOUNDARIES names the concept and pins its dependency
arrows ("ZP Console may consume core ZP via the substrate's HTTP/mesh APIs
and the ZP Surface Spec"), this document partitions that integration into
Required, Optional, and Forbidden affordances so that every proposed
Console feature can be classified in one lookup rather than re-derived from
principles.

The contract is runtime-neutral by construction. The Foundation Console at
`app.zeropointfoundation.org` — a Cloudflare Workers + D1 deployment with
IronClaw configured as the cockpit — is the reference implementation.
Alternative deployments (an Adopter Console, a hypothetical Console built
from scratch in a different framework) conform to the same contract; they
are not exceptions to it.

This document is the spoke for Tier 3 in the taxonomy established by
`SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md`. The adjacent Tier 4 spoke is
`ZP-SURFACE-SPEC-2026-06.md` — the Cockpit tier contract. Console and
Cockpit are adjacent peers: Console hosts the cockpit slot; Cockpit fills
it. Neither tier contains or subordinates the other.

---

## 2. The category statement

A ZP Console is a workspace shell that projects chain-anchored operator
state into a usable surface for reading and acting. It gives the operator
navigation, chain visualization, a tile renderer for the artifact library,
and a cockpit slot that accepts any cockpit conforming to the ZP Surface
Spec. The Console's job is projection, not authority: it reads the chain,
renders what is authorized, routes operator actions to the substrate, and
hosts the cockpit's surface contributions. The chain decides what the
operator currently holds; the Console makes that legible.

This category is distinct from both the substrate (which produces and
verifies chain state) and the cockpit (which interprets chain state
conversationally). Console is neither the seat of trust nor the voice of
the system. It is the workspace in which both are visible — the frame that
holds the chain visualization on one tile, the cockpit conversation on
another, and the operator's pending actions in a third. Structurally, the
Console is a rendering surface over a chain-anchored authority model that
it does not own. An implementation that accumulates its own authority, that
acts as a policy gate, or that holds operator-derived material outside
what the substrate explicitly authorizes has stopped being a Console and
started being a center — the failure mode Principle 3 exists to prevent.

The cockpit-OS framing in Architecture §4b names this role precisely: every
cockpit is a pure projection of chain-anchored state into a native mode.
Console is the native mode for workspace interaction — navigation, tiles,
chain viz, structured operator action — exactly as the CLI is the native
mode for terminal interaction and the conversational cockpit is the native
mode for dialogue.

---

## 3. Required affordances

An implementation lacking any of these cannot serve as a ZP Console. The
fallback when the Console tier is absent is for the operator to interact
with the substrate directly via CLI and cockpit without a workspace shell.
That is a real capability degradation — no tile renderer, no chain
visualization as a workspace surface, no unified artifact library UX — but
the substrate's correctness (chain integrity, gate enforcement, operator
authority) is entirely unaffected, because the chain lives at the substrate
regardless of what workspace renders it.

**1. Authenticated operator channel.** Console must establish and maintain
an authenticated connection to the operator's substrate before rendering
any chain-derived state. The specific mechanism varies by deployment —
session cookie issued by the substrate's authentication surface, OIDC token
bound to the operator's identity, mutual TLS with a substrate-issued
certificate, or equivalent — but the affordance is: *Console knows which
operator it is rendering for, and the substrate has authenticated that
claim, before any chain state is projected.* Without this, Console is
rendering chain state for an unknown principal, which is a correctness
failure: the affordance set should differ by operator, and without
authentication there is no operator to derive it from.

**2. Chain state projection surface.** Console must be able to read the
operator's chain — receipts, delegation grants, gate decisions, artifact
library state — through the substrate's APIs and render that state as the
primary content of the workspace. The rendering modality is implementation-
defined (tiles, panels, list views, graph renderings). What is not
implementation-defined is the invariant: the rendered state must derive
from the chain, not from Console-local storage that might have drifted from
it. A chain visualization that shows receipts from a Console-side cache
without a substrate round-trip is a projection of stale state, not of the
chain.

**3. Cockpit slot with Surface Spec lifecycle.** Console must expose a
structured slot for accepting a cockpit conforming to the ZP Surface Spec.
The slot must handle cockpit registration (accepting the cockpit's
capability declaration), event routing (forwarding substrate events to the
cockpit and cockpit-generated actions toward the gate), surface contribution
rendering (mounting the cockpit's chat surface, voice surface, tile
contributions, and status elements into the workspace layout), and lifecycle
teardown (graceful removal of cockpit contributions on disconnection or
replacement). The specific cockpit is deployment-determined; the slot must
accept any conformant cockpit. An implementation without a cockpit slot is
a workspace shell only; it cannot host the conversational authority surface
the architecture requires for operator-agent interaction.

**4. Substrate event routing.** Console must route operator actions taken
in the workspace — approving an artifact candidate, accepting a delegation,
acknowledging a gate-denied event, triggering a verb invocation — toward
the substrate's gate, not execute them locally. Console may present the
action and receive confirmation; the gate evaluation happens on the
substrate. This is the project-not-decide pattern from the integration
patterns catalog. Without event routing, Console has to run the gate
evaluation itself, which is forbidden.

**5. Artifact rendering surface.** Console must be able to render signed
artifacts from the artifact library — calendars, documents, task lists,
chain-narration artifacts, and whatever other artifact kinds the operator's
substrate holds — as workspace tiles. The rendering must clearly distinguish
candidate artifacts (unsigned, pending operator review) from canonical
artifacts (signed, operator-endorsed) by construction, not merely by a
visual label. An implementation that renders candidates and canonical
artifacts identically breaks the propose-not-sign lifecycle at the
workspace surface. The operator must be able to tell, by looking at a
rendered artifact, whether it has been signed.

---

## 4. Optional affordances

Each optional affordance is a strict improvement over its absence.
Lacking any one of them degrades the operator experience without breaking
chain correctness.

**Theming and branding.** Deployments may skin the Console for their
organization's identity — color schemes, typography, logo placement,
custom navigation labels. The Foundation Console uses the canonical dark
theme (`--bg: #0a0a0c`, accent `#7eb8da`, Inter + JetBrains Mono). Adopter
Consoles may diverge. Theme is surface dressing; the chain projection
beneath it is invariant.

**Multi-tile layouts and workspace customization.** Console may support
operator-configurable tile arrangements — drag-and-drop workspace panels,
saved layout presets, split-view chain viz alongside cockpit conversation,
floating artifact tiles. Without this affordance the workspace defaults to
a fixed layout; no correctness implication.

**Deep-linking and navigation history.** Console may support URL-based
deep-linking into specific chain views, artifact tiles, or cockpit states.
Without this, navigation starts from the workspace root on every visit;
the workspace is less bookmarkable but no less correct.

**Plugin and extension surface.** Console may expose an extension API
through which operators or adopters add custom tile types, custom artifact
renderers, or custom navigation items. Without this, the Console ships only
its built-in tile vocabulary; adopters with specialized artifact kinds must
fork the Console implementation rather than registering an extension.

**Voice integration.** Console may route microphone input through the
cockpit slot as a first-class input mode, allowing the cockpit's voice
surface to operate within the workspace without the operator switching to a
separate voice interface. Without this, voice is available only through the
cockpit's own standalone surface, not through the workspace layout.

**Accessibility extensions.** Console may provide screen-reader annotations,
keyboard-navigation completeness, reduced-motion variants, and high-contrast
themes. Without these the workspace is less accessible to operators with
specific needs; the chain projection is unaffected.

**Content-blind telemetry.** Console may log request rates, tile render
latencies, navigation patterns, and error counts — metrics that do not
inspect receipt contents or operator-derived chain material. Without this,
operational visibility into Console performance is limited to what the
substrate's own metrics expose.

---

## 5. Forbidden affordances

The forbidden category is the architecturally significant one. Each entry
names something a runtime-capable Console implementation must not do at
this tier, with an explicit principle citation. Lacking a forbidden
affordance is correct posture at this tier, not degradation. When in doubt
about tier-scoping: the substrate uses these capabilities; Console at this
tier must not use them in the named way.

**1. Holding chain authority.** Console must not hold signing keys for
canonical receipts, evaluate policy decisions, or make gate-level authority
claims of its own. The chain lives at the substrate; authority derives from
the chain. Console projects what the chain grants; it does not decide what
the operator is authorized to do, even transiently, even as a performance
optimization. **P1 (signing is gravity):** a Console-issued authorization
claim would be unsigned by any chain key, making it structurally
meaningless as a trust claim. **P3 (there is no center):** a Console that
holds authority is a center forming in the rendering layer.

**2. Signing receipts.** Console must not produce `Receipt` structs signed
with any key that the substrate would recognize as authoritative — the
operator's audit-chain key, the Genesis-derived envelope key, or any
delegation-issued descendant. Receipt signing is what the substrate's gate
does on the operator's substrate, with the operator's Genesis-derived audit
key, against a verified chain tip. A receipt signed by Console is signed
by a non-authoritative key and cannot be verified against the operator's
chain; emitting one produces exactly the kind of decorative signing that
P1 prohibits. **P1.**

**3. Enforcing policy decisions independently of the gate.** Console must
not evaluate constitutional rules, delegation envelope constraints, or
capability scope conditions on behalf of the substrate. The gate lives on
the operator's substrate for the same reason the chain does: evaluation
against a chain that Console only partially holds is not gate evaluation,
it is a guess. Console may present the gate's decision (allowed/denied) as
a workspace affordance; it may not make the decision. **P3, P8.**

**4. Mediating cockpit traffic with Console's own authority claims.** Console
routes events between the cockpit and the substrate — it is the transport
for the Surface Spec's event protocol. Console must not augment, filter,
reinterpret, or authorize cockpit-bound traffic with authority the Console
claims for itself. If the substrate says the gate denied a cockpit-initiated
verb invocation, Console forwards the denial. If the substrate says the
invocation is allowed, Console forwards the intent. Console is
renderer-and-router, not arbiter. An implementation that interposes Console-
side authority between the cockpit and the gate has created a second gate —
a center within the workspace that the architecture has no ground for. **P3,
P8.**

**5. Persisting operator-derived material with stronger-than-session
semantics, outside explicit substrate authorization.** Console may cache
chain state for the duration of the operator's session to reduce read
latency. Console must not persist receipts, delegation grants, capability
grants, chain tip hashes, or any other operator-derived chain material into
Console-side durable storage — browser localStorage, a worker-side D1
table, an edge KV store — with retention across sessions, unless the
substrate has explicitly authorized that caching as a known-and-accepted
projection path. Persistent operator-derived state at the Console tier
creates a center: a copy of chain truth that may drift, may be stale, and
cannot be verified against the chain itself. **P3, P4** (a duplicate data
path for chain state is a bit that doesn't earn its place by cryptographic
necessity).

---

## 6. Composition with principles

The contract's shape derives from three clusters of principles.

**P3 (there is no center) is the load-bearing principle for the Forbidden
category.** Every forbidden entry either prevents Console from accumulating
authority (entries 1–3), prevents Console from interposing as an authority
arbiter (entry 4), or prevents Console from becoming a persistent copy of
chain truth (entry 5). All five are ways of forming a center in the
rendering layer, and P3 prohibits centers by construction.

**P1 (signing is gravity) justifies entries 1–2 directly.** Console cannot
sign authoritative receipts because Console does not hold the chain they
would attest to. A Console-issued signature on a receipt is structurally
analogous to an edge worker signing canonical receipts — technically
possible, architecturally meaningless, and the specific correction the
foundation-canonical-v1 arc already made at the edge tier. The Console tier
runs the same risk in the rendering layer.

**P8 (one canonical path) justifies entry 3 and 4 jointly.** There is one
canonical gate for policy evaluation, and it lives on the operator's
substrate. There is one canonical routing path for cockpit-to-substrate
events, and it is the Surface Spec event protocol without Console
interposition. Two policy evaluations — one at the Console, one at the gate
— produce half-state: the two may disagree, and the operator cannot know
which to trust.

**P6 (a tool is intent, crystallized) justifies the Required affordances.**
Console's affordances must be grounded in chain-anchored state because
the cockpit-OS framing demands it: what the operator can do right now is
what the current chain state authorizes, rendered by Console into workspace
form. Required affordance #1 (authenticated channel) ensures Console knows
whose chain to project. Required affordance #4 (event routing) ensures
operator actions become intents reaching the gate rather than Console-local
effects. Required affordance #5 (artifact rendering) ensures the
propose-not-sign lifecycle is structurally visible in the workspace, not
just asserted by copy.

**P5 (store-and-forward) is the basis for Required affordance #2's
chain-primacy invariant.** The chain survives outages. Console's rendering
derives from the chain, not from a live heartbeat. A workspace that renders
correctly only when the substrate is reachable in real time has inverted
store-and-forward into a live-connectivity requirement.

---

## 7. Portability sketches

The contract is runtime-neutral. These sketches demonstrate what conformance
looks like across deployment shapes.

**Foundation Console (`app.zeropointfoundation.org`).** A Cloudflare Workers
deployment with D1 backing for session state, configured with IronClaw as
the cockpit, the Foundation's chain data, and Cloudflare Access as the outer
authentication primitive. All Required affordances are present. Optional
affordances in scope for this deployment: theming (Foundation dark theme),
voice integration (through IronClaw's voice surface), content-blind telemetry
(Cloudflare Analytics). The Foundation Console is one deployment of ZP
Console software; it does not contain Foundation-specific code that other
adopters couldn't reuse.

**Adopter Console (forked, different configuration).** An adopter who forks
ZP Console, replaces Foundation branding with their own, configures a
different cockpit (e.g., Ember or KiloCode), and connects it to their own
operator substrate. Conformance: all Required affordances must remain
present, including the authenticated channel to the adopter's substrate and
the cockpit slot that accepts the adopter's chosen cockpit. The fork may
add extension tiles for adopter-specific artifact kinds; those extensions
must not introduce Forbidden affordances (e.g., must not add a Console-side
policy gate for adopter-specific rules).

**Hypothetical alternative Console built from scratch.** A team implements
a Console in a different web framework — React Server Components, SvelteKit,
or a native desktop shell — targeting the same ZP Surface Spec and substrate
APIs. Conformance: all five Required affordances are achievable in any
framework that can establish authenticated HTTP connections and mount
arbitrary UI components into a layout. The contract makes no claim about
JavaScript, WebAssembly, DOM, or any specific runtime. An implementation
that omits the cockpit slot is not a conformant Console; one that implements
all five Required affordances in Rust + Tauri or Python + Textual qualifies.

---

## 8. Autoregressive update triggers

The contract tracks what the substrate has learned. Revisions are triggered
by architectural transitions, not by feature additions alone.

1. **A new Console deployment surface is adopted.** If the substrate ships
   a Console variant for a runtime not covered by the portability sketches
   above — a native desktop application, a mobile shell, a TUI — this doc
   should be updated with the affordance availability for that runtime. Even
   if conformance is straightforward, the public record helps future
   deployment decisions.

2. **A Required affordance proves hard to implement portably.** If "every
   Console must expose a cockpit slot with Surface Spec lifecycle" turns out
   to exclude a runtime worth supporting — perhaps because that runtime has
   no component-mounting model — the question is whether to relax the
   affordance or accept the runtime is out of scope for the Console tier.

3. **A Forbidden affordance is proposed for relaxation.** If someone
   proposes "let the Console cache delegation grants cross-session for
   offline capability negotiation," this doc is what the proposal must
   justify against. The default answer is no; justification must advance at
   least one of the four claims without weakening any other.

4. **A new Optional affordance is added.** Each addition should be
   interrogated: is it genuinely optional, or has the substrate come to
   depend on it? Optional affordances can graduate to Required if correctness
   turns out to depend on them.

5. **A new cockpit type is adopted.** New cockpits exercising new Surface
   Spec capabilities may surface Required affordances in the Console slot
   lifecycle that were previously only exercised by IronClaw. This doc
   should be updated if conformance gaps are discovered.

6. **A new principle is added to Architecture Part V½.** Each new principle
   may reclassify existing Optional affordances as Forbidden.

---

## 9. Refs

- `docs/SURFACE-BOUNDARIES-2026-05.md` — the sibling surface-layer reference;
  pins the Console concept, dependency direction, and the named surfaces
  around the substrate. This doc is the per-tier contract for Tier 3; that
  doc is the surface taxonomy that names the tier.
- `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` — the hub contract;
  §4 Tier 3 entry, §5 contract template, §6 integration patterns
  (project-not-decide, propose-not-sign, sign-then-act)
- `docs/ZP-SURFACE-SPEC-2026-06.md` — the adjacent Cockpit tier contract
  (Tier 4 spoke); the contract between Console and whatever cockpit fills its
  slot
- `docs/EDGE-TIER-CONTRACT-2026-06.md` — the template exemplar; established
  the Required / Optional / Forbidden partition and the composition-with-
  principles structure this doc follows
- `docs/ARCHITECTURE-2026-04.md` §4b — the cockpit-OS framing; the category
  claim that Console is a rendering surface, not a seat of authority
- `docs/ARCHITECTURE-2026-04.md` Part V½ — the eight design principles that
  every per-tier contract derives from
- `docs/ARTIFACT-LIBRARY-2026-05.md` — the cross-cutting artifact library
  primitive; Console renders its tile layer; Required affordance #5 derives
  from the propose-not-sign lifecycle this doc establishes
- `docs/handoffs/clic-console-cockpit-2026-06.md` — the Console/cockpit
  dispatch brief that preceded this contract; surfaces the chain-configures-
  cockpit heuristic whose structural implications this doc formalizes
- `CLAUDE.md` workflow heuristics — "the chain configures the cockpit; cockpits
  are pure projections" and "the substrate proposes; operators sign" — the
  heuristics this contract translates into per-tier structural commitments
