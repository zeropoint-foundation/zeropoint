# Minimum Viable Interaction

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §II.8 (chain-anchored receipts), Part XI (Genesis ceremony), Part VIII (bounded operator sovereignty). Specifies the smallest useful substrate interactions — at N=1 (single sovereign) and N=2 (bilateral) scales — and how everything else composes upward from these foundations. Shapes onboarding UX, value proposition, and field pilot design. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `TRANSPORT-ABSTRACTION-AND-CONSTRAINED-NETWORKS-2026-07.md` (substrate operates at any transport tier including offline), `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (kinship is one class of N=2 interaction), `CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md` (commitments are canonical N=2 primitive), `DISCOVERY-AND-BOOTSTRAP-2026-07.md` (onboarding via minimum viable interaction), `SUBSTRATE-FORM-2026-07.md` (MVI works at any Form).

## Framing

Substrate value should exist from the first day, at the smallest scale, for the individual operator, without depending on any peer being available, any network being reachable, or any community being present. This is the minimum viable interaction question: what's the smallest useful thing the substrate does, and how does value grow as scale increases?

Two answers matter:

**MVI at N=1** — single sovereign, no peers. A person installs substrate on their device and derives value alone. This is baseline. Everything else composes upward from N=1 substrate providing meaningful value to its single operator.

**MVI at N=2** — two sovereigns exchange chain-anchored primitive. This is the smallest cooperative interaction. If value at N=2 is meaningful, substrate scales by peer-graph accretion; every additional relationship adds value without redesign.

Three properties frame the discipline:

1. **N=1 provides value from day one.** Chain-anchored operator self-decisions, receipts about own activities, structured memory across time — all valuable to the operator alone. Peers are enhancement, not prerequisite.
2. **N=2 provides value from first peer.** First mutual identity verification, first shared commitment, first coordination signal — all valuable at 2. Adding more peers scales the same primitives; there's no discontinuity at 3, 10, or 100.
3. **MVI shapes onboarding UX and product framing.** If MVI is clear and compact, first-time operators experience value quickly. If MVI is diffuse or requires many primitives to compose, onboarding friction defeats adoption.

## MVI at N=1 — Single sovereign chain-anchored self-substrate

The substrate has meaningful value even before any peer exists. A single operator running a fresh substrate installation with no peers can derive real value from:

### Chain-anchored self-decisions

Operator makes a decision — architectural, personal, professional, health-related. They chain-anchor it: `sovereign:decision:<decision_id>` receipt with:

- Decision content (what was decided)
- Considered alternatives (what else was on the table)
- Rationale (why this choice)
- Expected outcome (what operator expects to see)
- Optional revisit-window (when operator wants to check whether outcome matched expectation)

Later, operator or their future self can query the chain, see what past-self decided and why, and reflect on the actual outcome vs expected. This is *retrospective coherence infrastructure* — the operator's own decision history preserved with cryptographic integrity, queryable, not lost to memory drift.

Value at N=1: operator with substrate for 6 months has 6 months of decision history that they can walk through when facing similar decisions. Substrate is a personal reasoning tool.

### Structured memory across time

Operator's substrate can chain-anchor observations they consider worth remembering: `sovereign:observation:<observation_id>` receipts with content, context, tags. Later query surfaces past observations relevant to current situations.

Value at N=1: operator's substrate becomes a chain-anchored notebook with structured retrieval. Not a novel product category (Obsidian, Roam, etc. exist) but substrate discipline adds cryptographic integrity, chain-anchored precedent for future decisions, and composition with Regent cognition (Regent can query and reason over structured memory).

### Regent cognitive presence

Operator has a Regent running locally (per EXECUTION-AUTHORITY-MODEL). Regent narrates observations, proposes decisions, provides cognitive presence around the operator's chain-anchored activities. This works entirely at N=1 — Regent doesn't need peers to serve their sovereign.

Value at N=1: operator has cognitive companion for reasoning about their own decisions and observations. Regent context is grounded in operator's chain-anchored history; narrations are chain-anchored evidence rather than ephemeral chat.

### Substrate self-observation and posture awareness

Substrate's own officers (Steward, Sentinel, Forge, Cleo, Aegis per SYSTEM-OFFICER-CADRE) observe substrate state and surface findings. Operator can check "what does my substrate see about itself right now" and get chain-anchored answers about integrity, security posture, operational state.

Value at N=1: operator has continuous self-awareness of their own substrate's state. Discovery of anomalies, drift, or degradation happens through chain-anchored observation rather than manual inspection.

### Legacy planning and identity preservation

Operator declares executors, legacy scopes, memorial preferences (per OPERATOR-DEATH-AND-LEGACY) at N=1. Even before peers exist, chain-anchored legacy declarations preserve operator intent for eventual transition.

Value at N=1: substrate becomes identity infrastructure that persists across the operator's lifetime and beyond, chain-anchored per their own ceremony.

### The N=1 baseline claim

**Substrate at N=1 is valuable to the operator alone without any peer, network, or community.** Onboarding UX should demonstrate this within the first substrate session. New operator installs substrate; performs Genesis ceremony; chain-anchors their first decision, observation, or commitment; queries chain to see it back. That's the smallest complete substrate interaction — and it should feel like value from the first ceremony.

## MVI at N=2 — First bilateral interaction

Two sovereigns discover each other (via any DISCOVERY-AND-BOOTSTRAP layer) and want to derive value from their newly-established connection. The smallest cooperative interactions:

### Mutual identity verification

Two sovereigns exchange chain-anchored identity claims and verify each other's Genesis-signed presence. `peer:mutual_verification:<verification_id>` receipt on each substrate.

Value at N=2: both sovereigns have chain-anchored evidence they've verified each other. Substrate becomes shared identity infrastructure — future interactions reference the mutual verification.

### First shared commitment

Two sovereigns exchange a chain-anchored commitment: "I'll take care of your dog next weekend." Both substrates emit `commitment:mutual:<commitment_id>` receipts. Later, either party can chain-query the commitment; substrates can chain-watch for commitment fulfillment / breach / renegotiation.

Value at N=2: commitments become chain-anchored rather than ambient. Reduces "did we agree on that?" friction. Provides precedent for future commitments between same pair.

### First kinship declaration

Two sovereigns who've decided their relationship is worth chain-anchoring as kinship exchange kinship declaration ceremony (per SOVEREIGN-KINSHIP-PRIMITIVES). Kinship exists chain-anchored; scope grants can be added incrementally over time.

Value at N=2: sovereign relationship becomes chain-anchored infrastructure. Household coordination, shared calendars, safety check-ins, mutual presence signaling — all composable primitives built on kinship foundation.

### First rendezvous signal exchange

Two sovereigns meet at an event; exchange rendezvous signals for post-event follow-up (per DISCOVERY-AND-BOOTSTRAP Layer 4). Chain-anchored one-shot discoverability that either party can act on within the validity window.

Value at N=2: substrate composes with event-scale ephemeral relationships. Not every peer needs to be kindred; some are one-encounter contacts.

### The N=2 baseline claim

**Substrate at N=2 provides value from the first mutual verification.** Onboarding UX should demonstrate this within the operator's first cross-substrate interaction. Once two operators can chain-anchor mutual verification and exchange one commitment, the substrate's N=2 value proposition is realized. Everything more elaborate (kinship, household, coordination, crisis response) composes upward from this foundation.

## The canonical MVI recommendation

Given multiple candidates for smallest-useful-interaction, the substrate's canonical MVI is:

**N=1**: chain-anchor one operator decision with rationale, then query it back next session. First-session value is felt when operator sees their own decision chain-anchored and can reflect on why they made it later.

**N=2**: mutual identity verification, followed by one shared commitment. First-cross-substrate value is felt when two operators have chain-anchored evidence of both knowing each other and agreeing on something.

Everything else in the corpus composes upward from these. Kinship extends the mutual-verification into deeper relational scope. Household composition extends multi-party mutual verification into shared coordination. Crisis response extends commitment into declared-trigger response. Discovery layers extend verification into mesh growth. Extensions add capability but don't change what value at MVI feels like.

## Composition upward from MVI

Adding scale and complexity composes primitives without redesigning MVI:

- **N=3 to N=10**: same primitives; more peers; some become kindred, some remain acquaintance-scope, some become household. Substrate scale grows via peer-graph accretion.
- **Household (N ≈ 4-8)**: HOUSEHOLD-COMPOSITION multi-party primitive; same underlying kinship + coordination scopes; charter formalizes shared context.
- **Extended community (N ≈ 20-200)**: seed nodes, commons reputation, community-scale coordination surfaces per COMMUNITY-COORDINATION and DISTRIBUTED-KNOWLEDGE-COMMONS.
- **Federation-scale (N ≈ 1000+)**: peer federation, cross-community coordination, reputation flow, extension marketplaces. Same primitives; more sophisticated composition.

**No redesign at any scale threshold.** Same signature discipline, same chain-anchoring, same peer-trust-anchor primitive, same commitment schema. Scale-related concerns (rate limiting, discovery efficiency, reputation aggregation) are calibration decisions within existing primitives.

## Onboarding UX implications

MVI shape drives onboarding design:

- **First session (N=1)**: install substrate, perform Genesis ceremony, chain-anchor first decision or observation, query it back. Time-to-first-value: minutes. No dependencies on peers, community, or connectivity.
- **First cross-substrate session (N=2)**: discover first peer via any DISCOVERY-AND-BOOTSTRAP layer, verify mutual identity, exchange first commitment or kinship-scope grant. Time-to-cross-substrate-value: within first hour of substrate use if peer is available; days if peer requires human coordination.
- **First household session (N=3+)**: multiple mutual verifications, first household declaration, first shared scope grant. Time-to-household-value: session-scale if operators are physically together; days if remote.

Onboarding failure modes to avoid:

- **Value requires many peers before feeling substantive.** If substrate doesn't feel valuable at N=1 or N=2, first-time operators abandon before reaching community-scale value. Substrate must feel valuable immediately.
- **Substrate assumes peers exist.** Onboarding that gates value on "add your first peer" produces high abandonment when first peer isn't immediately available. N=1 value bypasses this failure mode.
- **Substrate assumes connectivity.** Onboarding over LoRa or off-grid must work identically to onboarding over broadband. Genesis ceremony, first receipt, chain query all work at any transport tier per TRANSPORT-ABSTRACTION.

## Field pilot implications

MVI shape informs pilot design:

- **Solo-user pilots**: single operator uses substrate at N=1 for decision-tracking, observation logging, cognitive companion. Chain-anchored evidence of substrate value at scale-of-one.
- **Small-group pilots (N=2-5)**: dyad or small friend group uses substrate for mutual verification, commitment coordination, kinship declarations. Chain-anchored evidence of substrate value at cooperative smallest-scale.
- **Household pilots (N=3-8)**: family or household uses substrate for shared coordination, household presence, commitment coordination for chores/care/scheduling. Chain-anchored evidence of substrate value at household-scale.
- **Community pilots (N=20+)**: local community or mesh group (Michigan Mesh, regional maker collective) uses substrate for coordination, commons participation, cross-household composition. Chain-anchored evidence of substrate value at community-scale.

Each pilot tier informs different design surfaces. Solo pilots inform Regent + chain-query UX. Small-group pilots inform kinship + commitment coordination. Household pilots inform HOUSEHOLD-COMPOSITION + coordination scope. Community pilots inform commons + discovery-layer + seed federation.

Pilots should start smallest (N=1) and expand upward. Each tier's success informs subsequent tier's design.

## Composition with existing specs

- **TRANSPORT-ABSTRACTION-AND-CONSTRAINED-NETWORKS-2026-07.md**: MVI works at any transport tier. N=1 works offline entirely; N=2 works over any message-oriented transport that satisfies contract.
- **SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md**: kinship is one class of N=2 primitive; not all N=2 relationships escalate to kinship.
- **CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md**: commitment receipts are canonical N=2 substrate primitive; chain-watcher provides commitment lifecycle discipline.
- **DISCOVERY-AND-BOOTSTRAP-2026-07.md**: five discovery layers each support MVI at N=2 — mutual verification composes with any discovery layer.
- **SUBSTRATE-FORM-2026-07.md**: MVI works at any Form. Sovereign Form, Appliance Form, Companion Form all support N=1 value from day one.
- **EXECUTION-AUTHORITY-MODEL-2026-07.md**: Regent cognitive presence is part of N=1 value proposition; operates without peers per operator's local delegation.
- **OPERATOR-DEATH-AND-LEGACY-2026-07.md**: legacy declarations happen at N=1; preserved chain infrastructure survives beyond individual sovereign lifetime.

## Attack model

- **Attacker exploits MVI's simplicity to introduce backdoored operations**: Genesis-signed operations verify regardless of complexity. MVI has same signature discipline as more elaborate operations.
- **Attacker manipulates first-peer verification for supply-chain-adjacent attacks**: peer trust anchor discipline gates admission; discovery layers filter through commons reputation; first-peer decisions are operator judgment.
- **Attacker floods small-pilot substrate with junk to overwhelm operator**: extension surface admission and QUARANTINE-PLANE discipline apply at every scale; rate-limiting and operator budget constraints protect small-scale deployments same as large.
- **Attacker gates operator to depend on their availability by becoming primary peer**: operator can always add more peers via any DISCOVERY-AND-BOOTSTRAP layer; over-reliance on single peer is operator choice, not substrate-enforced.

## Failure modes

- **N=1 value feels insufficient to operator**: individual operators vary in what they value; substrate provides multiple N=1 value classes (decisions, observations, cognitive presence, legacy planning) so operator can find their fit.
- **N=2 first-peer relationship goes badly**: kinship revocation, peer-trust-anchor revocation, commons reputation flow all available. Operator can withdraw relationship without losing substrate value; substrate continues at N=1.
- **Operator over-invests in substrate at small scale, expects big-scale features that don't yet exist**: honest onboarding about current capabilities vs future roadmap; substrate does not oversell.
- **Onboarding friction still too high despite MVI clarity**: continuous UX refinement based on pilot feedback; MVI is a floor to defend, not a ceiling on onboarding investment.

## Non-goals

- **Not a formal minimum feature list**. MVI is a design discipline about value at scale, not a checklist. Different operators will find value in different subsets of MVI primitives.
- **Not a marketing claim**. MVI shapes onboarding UX and product framing but does not itself become the substrate's tagline. Value proposition is broader than MVI.
- **Not a locked-in interaction pattern**. MVI is starting point; sophistication grows as operators adopt more primitives. MVI does not constrain operator progression.
- **Not a substitute for pilot design**. Field pilots test MVI in practice; MVI-as-designed vs MVI-as-experienced may differ.
- **Not equal value at every scale**. Some substrate value only emerges at scale (federation-level reputation, cross-community coordination). MVI names what's true at every scale, not what's true only at large scale.

## Open positions

- **Onboarding UX for each MVI class**. Dashboard flows, CLI verbs, Regent narration for first-decision-anchoring, first-mutual-verification, first-commitment-exchange.
- **Time-to-value metrics per pilot tier**. Empirical measurement of how long operators take to reach each MVI value class; feedback loop to onboarding UX.
- **Cross-tier progression UX**. How operators graduate from N=1 to N=2 to N=3+ to household to community; substrate primitives to smooth progression.
- **Solo pilot recruitment strategy**. Which operators are good candidates for N=1 pilots vs N=2 pilots vs household pilots.
- **MVI variations for constrained-transport-only deployments**. Sneakernet or LoRa-only substrates have different N=2 interaction cadence; MVI shape may differ.
- **Community-scale MVI**. What's the smallest useful thing a community (N ≈ 20+) can do that solo or household substrate can't? Composes with COMMUNITY-COORDINATION.

## What composes from here

Immediate design work:

1. **Onboarding UX for N=1 first-decision-anchoring** — dashboard flow + CLI verb + Regent narration
2. **Onboarding UX for N=2 first-mutual-verification + first-commitment** — same across dashboard, CLI, Regent
3. **Substrate self-narration of MVI value** — Regent explains substrate value proposition per operator's actual usage
4. **Time-to-value measurement discipline** — chain-anchored evidence of pilot progression through MVI tiers

Near-term implementation:

1. **Onboarding runtime** in `crates/zp-server/src/onboarding/`
2. **First-time-operator UX flow** — dashboard-embedded, Regent-narrated, no-external-dependencies path from install through first-decision-anchoring
3. **First-cross-substrate-session flow** — dashboard-embedded, mutual-verification + commitment-exchange in one session
4. **Value narration protocol** — Regent's ongoing narration of substrate value based on operator's actual usage
5. **CLI verbs**: `zp onboard status`, `zp mvi walk-through`, `zp mvi progress`

## Framing note

Minimum viable interaction names the design discipline for smallest useful substrate operations. Same principle as chain-anchored discipline elsewhere: value from first ceremony, chain-anchored evidence of value, composable primitives that scale without redesign.

The load-bearing insight: **substrate provides value at N=1 without any peer or network, and provides additional value at N=2 from first mutual verification onward — everything else composes upward from these foundations without redesign at any scale threshold.** Operators experience value immediately regardless of whether peers are available. As peer graph grows, substrate provides more value using the same primitives at deeper composition.

Combined with the substrate's structural discipline across every trust boundary, minimum viable interaction closes the value-proposition envelope. What was previously implicit — that substrate is valuable somehow at some scale — becomes structural: N=1 value classes enumerated (self-decisions, structured memory, Regent presence, self-observation, legacy planning); N=2 value classes enumerated (mutual verification, shared commitment, kinship declaration, rendezvous exchange); onboarding UX shaped to demonstrate value quickly; field pilot design informed by MVI tier progression. Sovereignty is preserved because value at N=1 doesn't require operator to trust any peer; safety is preserved because scale doesn't require redesign or new trust assumptions; continuity is preserved because same primitives operate across the full scale range from solo to federation.
