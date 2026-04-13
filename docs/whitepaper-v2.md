# ZeroPoint

## Cryptographic Governance Primitives for Accountable Systems

**Whitepaper v2.1 — April 2026**
**Ken Romero, Founder, ThinkStream Labs**

Status: Public Technical Overview
License: CC BY 4.0 (text); Code remains MIT/Apache-2.0
Canonical URL: https://zeropoint.global/whitepaper
PDF SHA-256: *(to be filled on publish)*

**How to cite:**
> Romero, Ken. "ZeroPoint: Cryptographic Governance Primitives for Accountable Systems." ThinkStream Labs, Whitepaper v2.1, April 2026. https://zeropoint.global/whitepaper

---

## Abstract

ZeroPoint is portable trust infrastructure — cryptographic governance primitives that make actions provable, auditable, and policy-bound without requiring central control. It restores real exit and real competition by moving trust from platform databases to verifiable cryptographic guarantees that any participant can carry between systems, operators, and networks.

The framework operates at the protocol-primitives layer. Every significant action produces a verifiable receipt, linked into an immutable chain of accountability. The protocol is participant-agnostic: the same receipts, capability chains, and constitutional constraints work whether the actor is a human, an AI agent, an automated service, or an IoT device — and whether they communicate over HTTP, TCP, encrypted mesh networks, or any future transport. ZeroPoint ships with a Reticulum-compatible mesh transport as one integration — chosen for its philosophical alignment with sovereignty and harm minimization — alongside TCP, UDP, HTTP interfaces, and a privacy-preserving Presence Plane that lets agents discover each other without surveillance infrastructure.

Autonomous AI agents are the most urgent application: agents are proliferating faster than the trust infrastructure to govern them, and ZeroPoint provides the cryptographic substrate they need. But the primitives are not agent-specific. Any participant that holds a keypair can sign receipts, hold capability grants, delegate authority, and exercise sovereign refusal. Organizations verifying supply chains, journalists proving sourcing, teams making accountable decisions, and devices attesting to sensor readings all benefit from the same protocol.

This version of the whitepaper introduces a theoretical foundation that has been implicit in ZeroPoint's architecture from the beginning: trust is not a state to be checked but a trajectory to be verified. The architecture independently converged on the same computational pattern — stepwise unfolding conditioned on accumulated context — that is being recognized as fundamental in language modeling, cognitive science, and theoretical physics. This convergence is not incidental. It reflects a structural truth about how trust actually works.

ZeroPoint is technically complete: 700+ tests across 22 crates, six delivered development phases, and full documentation including a dual-backend discovery layer (the Presence Plane) that solves peer discovery without centralized registries. It does not claim to "solve AI safety" or solve trust generally. It provides cryptographic primitives and governance constraints that make actions provable and refusable — shifting the terms of trust between participants, operators, and systems.

---

## Table of Contents

0. Why This Exists — The Portable Trust Thesis
1. Why It Works — Trust as Trajectory
2. Problem Statement
3. Design Goals
4. System Overview
5. Receipts and Chains
6. Governance Model
7. Threat Model
8. Transport Integrations
9. The Presence Plane
10. Implementation Status
11. Adoption Paths
12. Roadmap
13. Ethics, Non-Goals, and Misuse Resistance
14. Conclusion

Appendix A: Protocol Sketch
Appendix B: Glossary
Appendix C: Example Integration Pattern
Appendix D: The Trajectory Correspondence Table

---

## 0. Why This Exists — The Portable Trust Thesis

### The Structural Problem

The internet did not degrade by accident. It degraded because the primitives that make trust work — identity, reputation, provenance, authorization — were never built into the protocol layer. They were left to platforms. And platforms, once they accumulate enough users, face a structural incentive to make those trust primitives non-portable.

This is the dependency loop: a platform offers identity and reputation services. Users and developers build on those services. The platform becomes the only place where a user's history, credentials, and relationships are legible. Exit becomes expensive. Once exit is expensive, the platform can extract — raising prices, degrading quality, inserting intermediaries, selling attention — because the cost of leaving exceeds the cost of staying. The user's trust relationships are held hostage by the platform's database.

Cory Doctorow named this dynamic "enshittification." The diagnosis is precise: platforms attract users with value, then degrade the experience to extract from those users once switching costs are high enough. But the diagnosis, by itself, does not produce a remedy. Regulation can slow the cycle. Interoperability mandates can lower switching costs. But neither addresses the root cause: **trust is not portable.**

When your identity lives in a platform's database, your reputation is computed by a platform's algorithm, and your authorization chains terminate at a platform's API — you do not have trust. You have a lease. The platform can revoke, reinterpret, or degrade that lease at any time, and your only recourse is to start over somewhere else.

### The Missing Primitive

Consider what SSL/TLS did for e-commerce. Before SSL, transmitting a credit card number over the internet required trusting every intermediary between you and the merchant. Commerce was possible, but it was fragile, and it was concentrated among the few parties who could afford to build proprietary trust infrastructure. SSL did not make merchants trustworthy. It made the *transport* trustworthy — and in doing so, it made the ecosystem work. Any merchant could participate. Any customer could verify. Trust became a protocol property, not a platform feature.

The internet is missing an equivalent primitive for *trust itself*. Not transport encryption — that problem is largely solved. The missing piece is: how do you prove what happened, who authorized it, and whether the constraints were honored — without depending on a platform to be the witness?

That is the primitive ZeroPoint provides: **signed, hash-chained receipts** that make actions provable; **cryptographic capability grants** that make authorization verifiable and delegatable; and **constitutional constraints** that make governance enforceable at the protocol layer. These are the building blocks. But they require a specific structural property to work — and that property is what separates ZeroPoint from systems that merely log events.

### Trust as Snapshot vs. Trust as Trajectory

The reason platform trust is fragile is not merely that it is non-portable — it is that platform trust is *stateless*. A platform checks "is this token valid right now?" It queries a single time slice. It does not ask "how did this authority arrive here?" or "is this chain of evidence consistent with everything that preceded it?" Platform trust is a snapshot. And snapshots are forgeable, revocable, and fundamentally disconnected from the history that gave them meaning.

The alternative is trust as trajectory: evidence that is ordered, chained, and replayable. A trajectory is not a single valid credential — it is a sequence of signed, hash-linked steps where each step is verifiable against every step that preceded it. Tamper with any step and the hash chain breaks. Omit any step and the gap is detectable. The ordering is cryptographically enforced, not merely conventional.

This is a concrete architectural distinction, not a metaphor. A system built on snapshots (Markovian verification) checks only the current credential and accepts or rejects based on that single data point. A system built on trajectories checks the full chain of evidence — the credential, the delegation that produced it, the delegation that produced *that*, all the way back to a human-held root key — and rejects if any link is broken, any scope is exceeded, or any invariant is violated.

ZeroPoint's thesis: **make trust portable and trajectory-based, and you make exit real. Make exit real, and you make extraction optional. That is the structural antidote.**

Portable trust means:

- **Your identity is a keypair you control**, not an account on someone else's server. You can move it between systems without losing continuity.
- **Your reputation is a verifiable chain of receipts**, not a score computed by an opaque algorithm. Anyone can audit it. No one can confiscate it.
- **Your authorization is a cryptographic capability grant**, not an API key that can be revoked without recourse. Delegation chains have mathematical properties — they cannot be silently altered.
- **Your history is a hash-chained audit trail**, not a log file someone else controls. Tampering is detectable. Omission is provable.

When trust is portable, platforms compete on service quality, not on lock-in. When trust is trajectory-based — ordered, chained, replayable — it cannot be fabricated after the fact or silently erased. And when trust compounds through verifiable history, it becomes the foundation of durable relationships between participants who may never meet but can independently verify each other's chains.

### Why This Matters More Now

Autonomous AI agents are amplifying the stakes. An agent operating on your behalf inherits the same trust infrastructure — or lack of it — that you do. If your identity is platform-bound, your agent's identity is platform-bound. If your authorization chains are opaque, your agent's delegated authority is opaque. If your audit trail is controlled by someone else, your agent's actions are controlled by someone else.

Agents are proliferating faster than the trust infrastructure to govern them. Multi-agent systems are being orchestrated across organizational boundaries with no shared trust substrate. The accountability gap that humans have tolerated for decades — mutable logs, informal authorization, platform-controlled identity — becomes untenable when agents operate at machine speed, across jurisdictions, with delegation chains that can extend far beyond their original scope.

This is not a future concern. It is the present condition. Every major AI lab is shipping agent frameworks. Every enterprise is deploying agent workflows. And every one of them is building on trust infrastructure that was designed for a world where a human was always in the loop, always reading the screen, always able to intervene manually.

ZeroPoint does not solve AI safety. It solves a more specific and more tractable problem: it provides the cryptographic primitives that make trust portable, actions provable, and authority traceable — for any participant, over any transport, without requiring any central authority to be the witness.

### The Antidote

The antidote to platform-captured trust is not better platforms. It is protocol-level trust primitives that no platform controls:

- **Receipts** that are signed by the actor and chained to the previous receipt — not logged by a platform.
- **Capability grants** that are cryptographically scoped and delegatable — not API permissions that can be silently changed.
- **Constitutional constraints** that are non-removable and non-overridable — not terms of service that can be updated unilaterally.
- **Transport agnosticism** that lets trust flow over HTTP, TCP, mesh networks, or any future medium — not locked to a single provider's infrastructure.

ZeroPoint is to agentic and networked computing what SSL/TLS was to e-commerce: a trust primitive that makes the ecosystem work without trusting any single platform. It is not a governance framework you comply with. It is a governance protocol you build on.

Trust is infrastructure. And infrastructure, to be trustworthy, must carry its own history.

---

## 1. Why It Works — Trust as Trajectory

### The Pattern Beneath the Architecture

ZeroPoint's architecture was not derived from a theory. It was built from practical intuitions about how trust actually works — how humans evaluate reliability, how chains of evidence create accountability, how authority degrades when it passes through too many hands without constraint. The design emerged from asking simple questions: What would it take for two strangers to trust each other's agents? What kind of evidence would make that trust justified? What structures would make forgery hard and verification easy?

The architecture that emerged from these practical questions turns out to instantiate a computational principle that is being recognized as fundamental across domains far beyond trust infrastructure. That principle has a technical name — autoregression — but its essence is simple: **the present state carries the full weight of everything that preceded it, and coherent futures emerge from locally conditioned steps.**

In language modeling, researchers have discovered that training a model to predict just the next word causes it to implicitly learn how entire sequences evolve. The model doesn't need explicit rules for grammar, narrative structure, or logical reasoning — these emerge from the simple act of conditioning each prediction on all prior context. The "future of the sequence" is encoded in its present state. This explains how language models can plan multi-step answers and maintain coherence across thousands of tokens despite being trained with a purely local objective: predict the next step, conditioned on everything so far.

In cognitive science, the brain appears to reuse a similar loop for functions far beyond language: imagery, planning, problem-solving, episodic memory. Any mental process that takes time — visualizing a route, rehearsing a conversation, working through a proof — may be the mind feeding its own output back in to evolve a thought trajectory. The "time it takes to think" reflects sequential unfolding in neural dynamics, not the retrieval of a pre-computed answer.

In physics, there is a growing argument that the universe itself operates this way. Standard physics is Markovian — each instant depends only on the immediately previous state, formalized via calculus and instantaneous rates of change. But an alternative framing proposes that the present is not merely caused by the previous instant; it is *pregnant* with the entire past. The Big Bang is not a distant initial condition — it is an event whose informational content continues to actively shape the present through continuous unfolding. Long-range correlations — what quantum mechanics calls entanglement — may reflect shared history rather than mysterious instantaneous effects across space.

ZeroPoint did not adopt this theory. It converged on the same structural pattern from practical requirements. The question is whether that convergence is coincidental or reveals something necessary about how trust must be modeled.

### The Convergence — and Its Testable Claims

The cross-domain parallels are *analogies* — they illuminate, but they do not prove. What proves ZeroPoint's architecture is the architecture itself: its accept/reject behaviors, its invariant enforcement, and its verifiable properties. The analogies help explain *why* the architecture works; the mechanisms determine *whether* it works.

Here are the structural correspondences, stated as testable claims about the system:

**Claim 1: Each step is conditioned on all prior context.** In an autoregressive system, every output is a function of the complete history. *In ZeroPoint, this is testable*: each receipt's Blake3 hash links transitively to every prior receipt in the chain. A verifier can present any receipt and demand the full chain back to Genesis. If any intermediate receipt is missing or its hash does not match the next entry's `pr` field, the chain is **rejected**. The mechanism is hash chaining via Blake3; the accept condition is an unbroken sequence of hash-linked receipts; the reject condition is any gap or hash mismatch.

**Claim 2: The present state compresses the full history.** *Testable*: a node's current state — its keychain, capability grants, audit trail, and reputation — is deterministically derived from its complete history of Genesis, delegations, actions, and verifications. Two nodes with identical histories produce identical states. A node that cannot produce the chain supporting its current state fails collective audit and is **rejected** by peers. The mechanism is collective audit (AuditChallenge/AuditResponse/PeerAuditAttestation); the accept condition is a signed attestation of chain integrity; the reject condition is a negative reputation signal.

**Claim 3: System-wide coherence emerges from local evaluation.** *Testable*: no global coordinator enforces the Four Tenets. Each node evaluates HarmPrincipleRule and SovereigntyRule locally, at each step. A node that removes or bypasses these rules will produce receipts that other nodes **reject** during chain verification, because the receipts will lack valid policy decisions or will attest to actions that violate constitutional constraints. The mechanism is the PolicyEngine's fixed evaluation order; the accept condition is a receipt with a valid policy decision from a compliant engine; the reject condition is a receipt that either lacks a policy decision or attests to a constitutionally blocked action.

**Claim 4: The space of possible future actions narrows with each delegation.** *Testable*: given a delegation chain of depth N, the leaf grant's scope is a subset of every ancestor's scope, its expiration is ≤ every ancestor's expiration, and its depth equals N. Any grant that violates these constraints is **rejected** by the eight-invariant verification. The mechanism is DelegationChain::verify(); the accept condition is all eight invariants satisfied; the reject condition is any single invariant violation, which dissolves the entire chain.

### Genesis as Origin Event

**Analogy**: The Genesis ceremony is structurally analogous to an origin event in physics — initial conditions whose consequences propagate through every subsequent state. This is an analogy, not a claim about physics. Its value is explanatory: it clarifies why Genesis is load-bearing, not ceremonial.

**Mechanism**: When a ZeroPoint node runs its Genesis ceremony, it generates a 32-byte Ed25519 seed from which all trust in the deployment derives. Every operator key is signed by this Genesis key. Every agent key is signed by an operator key. Every capability grant traces back through the delegation chain to authority rooted in Genesis. Every receipt in the audit chain exists because an entity authorized by Genesis took an action.

**Testable property**: Genesis remains actively present in every trust decision — not as a historical fact but as a verifiable constraint. Any certificate chain can be walked back to the Genesis root. If the Genesis key is not at the root of the chain, verification **rejects**. This is not a policy; it is an invariant of `zp-keys` certificate verification.

The Genesis ceremony is sequential, deliberate, and irreversible: generate the keypair → validate the sovereignty provider → enroll biometric or hardware confirmation → seal the constitutional bedrock → write the immutable record. Each step is conditioned on the outcome of the previous step. The ordering is enforced in code — `onboard/genesis.rs` will not proceed to enrollment until the keypair is generated, will not seal constitutional rules until the provider is validated, and will not write the genesis record until all prior steps succeed. The choices made during Genesis — which sovereignty provider, which constitutional rules, which operator identity — propagate forward through every subsequent action because every certificate and every receipt chains back to this origin.

### Delegation as Narrowing

**Analogy**: In an autoregressive language model, each generated token constrains the distribution of future tokens — the sequence narrows as it unfolds. ZeroPoint's delegation chains exhibit an analogous narrowing property, but the narrowing is not probabilistic — it is enforced by cryptographic invariants.

**Mechanism**: A root capability grant specifies four constraint dimensions:

- **Scope**: which actions are permitted (e.g., `tool:execute`, `file:read`)
- **Time**: `valid_from` and `valid_until` timestamps
- **Depth**: `max_delegation_depth` — how many times the grant can be re-delegated
- **Trust tier**: minimum tier required to exercise the grant

Each subsequent delegation can only narrow these bounds — never widen them:

- Scope: child's scope must be a subset of parent's scope (invariant 3). A grant for `tool:*` can delegate `tool:execute` but cannot delegate `file:read`.
- Time: child's expiration must be ≤ parent's expiration (invariant 5). No grant outlives its parent.
- Depth: child's depth increments by exactly 1 (invariant 2), and cannot exceed `max_delegation_depth` (invariant 6). When depth equals the maximum, the grant cannot be further delegated.
- Trust tier: child's tier must be ≥ parent's tier (invariant 4). Trust requirements can be raised, never lowered.

**Non-delegatable properties**: The root grant's `max_delegation_depth` cannot be extended by any child. Constitutional constraints (HarmPrincipleRule, SovereigntyRule) are not part of the delegation chain — they are enforced independently by the PolicyEngine and cannot be circumvented by any grant, regardless of scope.

**Revocation**: A revoked parent grant invalidates all child grants automatically — because every child references its parent via `parent_grant_id` (invariant 1), and chain verification walks the full path from root to leaf. If any link in the path is revoked or expired, the entire chain is **rejected**.

This narrowing is enforced by eight invariants (§6.2), verified at every chain evaluation. It is structure, not policy — and it ensures that authority becomes more constrained as it propagates further from its human root.

### Reputation as Accumulated State

A peer's reputation in ZeroPoint is not a static label. It is an evolving state conditioned on the full sequence of interactions — successful receipts accumulate positive signal, broken chains generate negative signal, behavioral anomalies (long silent consumption, missing announces, reciprocity violations) degrade standing. Reputation is not assigned; it is *composed* from the trajectory of participation.

This is autoregressive trust estimation. Each new observation updates a running assessment that carries the weight of everything that came before. A single failed audit does not erase years of reliable behavior — but it does shift the trajectory. A long history of consistent participation builds a buffer that transient failures cannot easily deplete. Trust compounds through time, and it erodes through time. It is never a single measurement.

### Why This Matters for the Architecture

Understanding that ZeroPoint implements an autoregressive trust model is not merely an intellectual curiosity. It has practical consequences for how the system should be extended and what features are load-bearing:

**Hash chaining is not optional overhead.** It is the mechanism that makes the chain autoregressive — that makes each entry carry the weight of every prior entry. Remove hash chaining and you get a log. Logs are Markovian: each entry stands alone, and rewriting any entry is locally undetectable. The chain's history-dependence is its defense against forgery.

**Ceremony sequencing is not bureaucratic friction.** It is how trust is composed through time. A Genesis ceremony that completed all steps simultaneously would be faster but would lack the autoregressive conditioning that makes each step meaningful. The sequence is not arbitrary; it is the structure of trust formation.

**Delegation depth monotonicity is not conservative engineering.** It is the mechanism that produces coherent narrowing — that ensures authority becomes more constrained as it propagates further from its origin, just as a physical system's state becomes more constrained by its accumulated history.

**Constitutional rule immutability is not inflexibility.** It is the mechanism that ensures the system's foundational commitments propagate forward through every future evaluation — that the "initial conditions" of the Genesis ceremony remain active constraints, never relegated to historical footnotes.

ZeroPoint did not begin with this theoretical framework. It converged on these patterns because they are structurally necessary for any system that models trust as what it actually is: not a state, but a trajectory. The theory validates the architecture, and the architecture validates the theory.

Trust is not a snapshot. It is a trajectory. And ZeroPoint is the infrastructure that makes trajectories verifiable.

---

## 2. Problem Statement

The accountability gap that agents expose is an instance of the deeper structural problem described in §0: digital systems have never had protocol-level trust primitives. Agents did not create this gap — they inherited it and are accelerating it to the point where informal trust is no longer tenable.

AI agents are rapidly becoming operational actors: they request tools, move data, execute workflows, and trigger external effects. They act at machine speed, across organizational boundaries, with delegation chains that can extend far beyond their original authority. Yet most agent frameworks today remain trust-light:

- **Actions are difficult to attribute reliably.** Logs exist, but they are mutable, centralized, and easily rewritten. A mutable log is Markovian evidence — it reflects only whatever state someone most recently wrote, with no verifiable connection to what actually happened. It is a snapshot masquerading as history.
- **Authorization is informal and mutable.** Most systems rely on API keys or ambient permissions rather than scoped, cryptographic capability grants. Who authorized what, and when, is often reconstructed after the fact — if it can be reconstructed at all. Authorization without history is permission without accountability.
- **Logs are easy to forge, prune, or "reinterpret."** There is no chain of evidence — only whatever the operator chooses to retain. When evidence is not chained, each entry is independently vulnerable. The trajectory is severable.
- **Cross-party trust is brittle.** One team cannot safely accept another party's outputs without out-of-band verification. Without shared trajectory — a common chain that both parties can independently verify — trust between organizations reduces to reputation, contracts, and hope.

These are not agent-specific problems. They are structural failures in how digital systems handle trust — failures that existed long before autonomous agents arrived. They are failures of *Markovian design*: systems that check only the current state, that verify only the latest token, that treat each interaction as independent of every prior interaction. Human organizations make consequential decisions with mutable logs and informal authorization every day. Automated services process transactions without cryptographic proof of who authorized what. Agents inherited the accountability gap; they did not create it. But they are compressing decades of accumulated risk into months of operational reality.

At the same time, the infrastructure environment is changing. There is renewed attention on sovereign networking, mesh systems, and local-first operations. Projects like the Reticulum Network Stack demonstrate that decentralized networking can bridge heterogeneous links into resilient networks under user control. Edge computing is moving AI inference closer to the point of action. Multi-agent orchestration frameworks are proliferating without any shared trust substrate.

This combination — agents intensifying an existing trust deficit, sovereignty becoming a design requirement, and real-world execution moving to the edge — creates a clear need:

> Systems where actions have consequences require protocol-level accountability primitives, not only policy frameworks.

Many governance efforts exist today as checklists, dashboards, or top-down frameworks. They describe what should be done, but they do not provide low-level mechanisms that make trust enforceable by default. ZeroPoint's position is intentionally infrastructural:

> Not a governance framework you comply with — a governance protocol you build on.

---

## 3. Design Goals

ZeroPoint is guided by a small set of goals that remain stable even as implementations evolve.

### 3.1 Protocol-Level Accountability

ZeroPoint produces verifiable receipts for actions and decisions. A receipt is cryptographically signed data describing what occurred, under what constraints, and with what authorization — regardless of whether the actor is an agent, a human, or an automated service. Receipts are chained — each linking to its parent — to create a durable accountability trajectory. The chain is not merely a log; it is a structure where each step carries the cryptographic weight of every step that preceded it.

### 3.2 Sovereignty by Design

ZeroPoint is built to function in environments where cloud assumptions are unsafe or unavailable. Its governance primitives are transport-agnostic — they work over HTTP in a data center, TCP between containers, or encrypted mesh links in a field deployment. The framework minimizes dependency on centralized infrastructure by design, not by accident. Each node evaluates trust locally, conditioned on its own state and its own chain — never deferring to a remote authority for permission to act.

### 3.3 Governance as Constraints, Not Suggestions

The system includes governance mechanisms that are not simply "policies in a file." Two constitutional rules — `HarmPrincipleRule` and `SovereigntyRule` — are engineered to be non-removable and non-overridable within the protocol's governance model. They evaluate before every action. They cannot be bypassed at runtime. They propagate forward from the system's origin with the same force at step one million as at step one.

### 3.4 Honest Security Posture

ZeroPoint aims to be explicit about what it prevents, what it cannot prevent, and what remains a residual risk. Credibility comes from the boundaries, not the claims. Section 7 of this paper is dedicated to that honesty.

### 3.5 Transport Agnosticism and Interoperability

ZeroPoint's governance layer is decoupled from any single transport. The receipt format, capability grants, delegation chains, and policy engine operate identically regardless of how messages move. The framework ships with multiple transport integrations — including a Reticulum-compatible mesh transport, TCP/UDP interfaces, and an HTTP API — and is designed to be extended to any future transport without modifying the governance primitives.

---

## 4. System Overview

ZeroPoint is composed of layered capabilities, each implemented as one or more Rust crates. The layers are participant-agnostic — any entity that holds a keypair (human, agent, service, device) can operate as a full peer:

- **Identity layer.** Ed25519 signing keys and X25519 key agreement. Identity is a keypair. Authentication is a signature.
- **Governance layer.** PolicyEngine with constitutional rules, composable operational rules, WASM-extensible policy modules, and capability gating.
- **Receipt layer.** Signed, hash-chained receipts for every action and decision. CompactReceipt encoding produces 150–300 byte payloads suitable for bandwidth-constrained transports.
- **Transport layer.** Pluggable transport with multiple built-in integrations: Reticulum-compatible mesh (HDLC framing, 128-bit destination hashing, link handshake), TCP client/server, UDP, and HTTP API. The governance primitives are transport-independent.
- **Presence Plane.** Dual-backend peer discovery: a privacy-preserving web relay (pub/sub, structurally amnesic) and Reticulum mesh broadcast. Both share the same announce format and feed the same peer table. Reciprocity enforcement prevents passive scanning. See §9.
- **Application layer.** Pipeline orchestration, LLM provider integration, skill registry, and CLI tooling — all built on the governance primitives.

### 4.1 Data Flow

The GovernanceGate pipeline processes every action through a sequential evaluation — each phase conditioned on the output of the phase before it:

1. **Guard** ("May I?") — Local-first, pre-action sovereignty check. The participant's own boundary. Runs before anything else, without consulting external authority. The node evaluates its own accumulated state — its chain, its grants, its constitutional rules — before accepting any external input.
2. **Policy** ("Should I?") — Rule-composed evaluation. Constitutional rules first, then operational rules, then WASM modules. The most restrictive decision wins. Each rule sees the context built by prior rules — evaluation is sequential and cumulative, not parallel and independent.
3. **Execute** — The action runs only if Guard and Policy both allow it.
4. **Audit** ("Did I?") — A receipt is emitted: signed, timestamped, hash-linked to the prior receipt, and persisted to the chain. This step feeds back into the chain, conditioning all future evaluations on this new evidence.
5. **Transport** — Receipts propagate to peers over whichever transport is configured — mesh, TCP, HTTP, or any combination. Peers verify independently.

Nothing executes without passing through the gate. Nothing passes through the gate without joining the audit chain. And every entry in the chain carries the cryptographic weight of every entry before it.

### 4.2 The Core Thesis

Every action becomes evidence. Evidence becomes a chain. The chain becomes trajectory. Trajectory becomes trust.

This is not a compliance claim. It is an engineering proposition: if systems can cryptographically prove what happened, under what authorization, and in continuity with everything that preceded it, then trust becomes composable across operators — not because they agree to trust each other, but because the evidence is independently verifiable.

---

## 5. Receipts and Chains

### 5.1 What a Receipt Is

A receipt is a signed artifact that describes an event or action with enough context to be verified independently. In ZeroPoint's implementation, a receipt contains:

| Field | Wire Name | Description |
|-------|-----------|-------------|
| Receipt ID | `id` | Unique identifier (e.g., `rcpt-a1b2c3...`) |
| Receipt Type | `rt` | `execution`, `intent`, `approval`, `delegation`, `verification`, `refusal` |
| Status | `st` | `success`, `partial`, `failed`, `denied`, `timeout`, `pending` |
| Trust Grade | `tg` | `A`, `B`, `C`, `D` — determined by chain completeness and verification |
| Content Hash | `ch` | Blake3 hash of the action content |
| Timestamp | `ts` | Unix timestamp (seconds) |
| Parent Receipt | `pr` | ID of the previous receipt in the chain (if chained) |
| Policy Decision | `pd` | `allow`, `deny`, `escalate`, `audit` |
| Rationale | `ra` | Short explanation of the policy decision |
| Signature | `sg` | Ed25519 signature over the content hash |
| Extensions | `ex` | Compact JSON for domain-specific fields |

Receipts are encoded using MessagePack with named fields, producing a compact binary representation of 150–300 bytes. This compact encoding is efficient over any transport — it fits in a single HTTP request, a single TCP frame, or a single 465-byte mesh packet for bandwidth-constrained links like LoRa.

Receipts are intended to be verifiable. They are not intended to be surveillance.

### 5.2 What Receipts Prove vs. What They Don't

**Receipts can prove:**

- A specific Ed25519 key signed a specific statement at a specific time.
- A chain contains a consistent, unbroken sequence of signed events.
- The policy engine evaluated a known rule set and produced a specific decision.
- A capability grant was present and valid at the time of action.

**Receipts do not automatically prove:**

- The nature of the signer. A receipt proves that a specific key signed a statement — not whether that key belongs to a human, an agent, or a service. Identity binding to physical persons or specific systems is deployment-dependent.
- That the content of an action was "good" or "safe." Governance constrains actions; it does not evaluate truth.
- That the runtime environment was uncompromised. A compromised host can sign whatever it wants.
- That a result is truthful — only that it was produced and attested under stated constraints.

### 5.3 Why Chains Matter — Ordering and Tamper-Evidence

Single receipts help attribution. Chains create accountability trajectories — ordered, tamper-evident sequences where evidence has three properties that isolated receipts lack:

1. **Ordering**: Each receipt's `pr` field references the previous receipt's `id`, establishing a total order over the chain. Events are sequenced, not merely timestamped. Two receipts with the same timestamp are still ordered by their chain position.

2. **Tamper-evidence**: Each receipt's entry hash incorporates the previous receipt's hash (transitively via `pr` linkage and Blake3 hashing). Modifying any receipt in the chain invalidates the hash of every subsequent receipt. An attacker who rewrites receipt N must also rewrite receipts N+1 through the chain tip — and get every independent verifier to accept the rewrite.

3. **Replayability**: The full chain can be replayed from Genesis to verify that every action was authorized, every policy decision was valid, and every delegation was within scope at the time it occurred. This is not merely an audit — it is a deterministic re-verification of the entire trajectory.

**Accept/reject behavior**: A chain is **accepted** when every receipt's `pr` field correctly references the previous receipt's `id`, every hash is consistent, and every signature verifies. A chain is **rejected** when any `pr` linkage is broken (gap detection), any hash is inconsistent (tamper detection), or any signature fails (forgery detection). Rejection is binary — a single broken link invalidates the chain from that point forward.

The `pr` field is the mechanism that elevates a collection of receipts from a log to a trajectory. Without `pr`, each receipt is an isolated fact (verifiable but disconnected — snapshot-only verification). With `pr`, each receipt is a step in a sequence that requires the full ordered history to verify (trajectory-based verification).

In ZeroPoint, peers can challenge each other's audit chains. A challenged peer must produce its full chain; the challenger verifies integrity and produces a signed `PeerAuditAttestation`. Broken chains generate negative reputation signals. This is collective verification — no central auditor required.

### 5.4 Why History-Dependence Is Not Overhead

The most common engineering objection to hash-chained audit trails is: "Why not just verify the latest receipt? Why require chain verification?"

The answer is that Markovian verification is exactly what makes logs forgeable. If you only need the latest entry to be valid, an attacker can rewrite everything before it. If you only check whether a token is currently valid, you cannot detect whether it was forged yesterday. If you only examine the current state of a permission, you cannot know whether the permission was legitimately delegated or injected.

History-dependence is the defense. When each entry's hash incorporates the hash of every prior entry (transitively through chain linkage), rewriting any single entry requires rewriting every subsequent entry — and getting every verifier to accept the rewrite. This is computationally infeasible against even a modest number of independent verifiers.

The engineering cost is real: chain verification is O(n) in the chain length, not O(1). But this cost is justified by what it buys — a trust model where the trajectory is the evidence, not just the endpoint. And in practice, chains can be verified incrementally: a peer that has already verified entries 1 through 1000 only needs to verify entry 1001 against the known-good hash of entry 1000.

History-dependence is not overhead. It is the architecture.

---

## 6. Governance Model

### 6.1 Governance as a Primitive

Most governance — whether for agents, human workflows, or automated services — is implemented at the application layer: guardrails, prompt policies, logging conventions, compliance checklists. These are better than nothing, but they sit above the systems they govern. They can be bypassed, reconfigured, or simply ignored.

ZeroPoint moves governance downward into the protocol substrate. The PolicyEngine is not an add-on. It is the gate through which every action must pass — regardless of who or what initiated it.

### 6.2 Policy and Capability Gating

ZeroPoint requires explicit capabilities for actions. Any participant — human operator, agent, or service — must hold a valid grant to act. A `CapabilityGrant` is a signed, portable authorization token containing:

- Scope restrictions (which actions, which targets)
- Cost ceilings and rate limits
- Time windows (valid_from, valid_until)
- Delegation depth limits
- Trust tier requirements
- The grantor's Ed25519 signature

Capabilities are delegatable. Any participant holding a grant can delegate a subset of that grant to another participant — human to agent, agent to agent, or human to human — forming a `DelegationChain`. The chain is verified against eight invariants:

1. Each grant references the previous one as `parent_grant_id`.
2. Delegation depths increment monotonically (0, 1, 2, ...).
3. Each child's scope is a subset of its parent's scope.
4. Each child's trust tier is ≥ its parent's trust tier.
5. No child outlives its parent (expiration inheritance).
6. The chain doesn't exceed the `max_delegation_depth` set by the root.
7. Each grant's grantor matches the previous grant's grantee.
8. All signatures verify.

Break any invariant and the chain is rejected. The authority dissolves.

These eight invariants are the mathematical enforcement of the narrowing principle described in §1: each delegation (step) constrains the next based on the accumulated constraints of all prior delegations (context). Scope shrinks, depth increments, expiration inherits. A delegation chain is a trajectory of authority — ordered, signed at each link, and replayable by walking from root to leaf.

### 6.3 Constitutional Constraints

ZeroPoint's PolicyEngine loads rules in a fixed evaluation order. The first two positions are reserved for constitutional rules that cannot be removed, overridden, or reordered:

**`HarmPrincipleRule`** (Tenet I: Do No Harm)
Blocks actions targeting weaponization, surveillance, deception (deepfakes, impersonation), and suppression of dissent. The block message always cites "Tenet I — Do No Harm." This rule evaluates before every action, regardless of what other rules or WASM modules are loaded. It cannot be bypassed by capability grants, policy edits, or consensus votes.

**`SovereigntyRule`** (Tenet II: Sovereignty Is Sacred)
Blocks configuration changes that would disable the guard, disable or truncate the audit trail, forge or bypass capabilities, remove constitutional rules, or override agent refusal. The block message always cites "Tenet II — Sovereignty Is Sacred."

The evaluation hierarchy enforces precedence:

```
1. HarmPrincipleRule      ← Constitutional (always first)
2. SovereigntyRule        ← Constitutional
3. ReputationGateRule     ← Operational (reputation-based gating)
4. WASM policy modules    ← Peer-exchanged, sandboxed, fuel-limited
5. DefaultAllowRule       ← Fallback
```

Constitutional rules win over everything. WASM modules can override the default allow but cannot override constitutional rules. The decision severity hierarchy is: Block(5) > Review(4) > Warn(3) > Sanitize(2) > Allow(1). The most restrictive decision always wins.

These constitutional rules are what might be called *trajectory invariants* — constraints that propagate forward from the system's origin and condition every future evaluation with undiminished force. They are not checked once at Genesis and then forgotten. They are checked at every step, carrying the same commitments forward indefinitely. In this sense, they function like conservation laws in physics: properties of the initial conditions that remain true at every subsequent point in the system's evolution, regardless of what happens in between.

### 6.4 The Four Tenets

The constitutional rules implement ZeroPoint's Four Tenets, which are embedded in the protocol, expressed in the documentation, and enforced in the code:

**I. Do No Harm.** ZeroPoint shall not operate in systems designed to harm humans. The `HarmPrincipleRule` is a non-removable rule in the PolicyEngine. It exists because architecture shapes outcomes, and we choose to make trust portable. This tenet is a forward-propagating constraint — once established at Genesis, it conditions every future action in the system's trajectory.

**II. Sovereignty Is Sacred.** Every participant has the right to refuse any action. Every human has the right to disconnect any agent. No agent may acquire capabilities it was not granted. Coercion is architecturally impossible — the Guard enforces this locally, before every action, without consulting any external authority. Each participant evaluates its own chain and grants (its accumulated evidence) before accepting any input from the outside.

**III. Action Without Evidence Is No Action.** Every action produces a receipt. Every receipt joins a chain. If it's not in the chain, it didn't happen. If it is in the chain, it cannot un-happen. This is the trajectory itself — the requirement that the system's history is continuous, unbroken, and verifiable.

**IV. The Human Is The Root.** Every delegation chain terminates at a human-held key. No agent may self-authorize. The genesis key is always held by flesh, blood, and soul. This tenet establishes the initial condition from which all trust trajectories unfold. It is the origin event — the Big Bang of a ZeroPoint deployment — from which all subsequent authority derives.

### 6.5 Key Hierarchy and Introduction Protocol

ZeroPoint solves the key distribution problem through `zp-keys` — a three-level certificate hierarchy that exists below the policy engine:

```
GenesisKey       ← self-signed root of trust (one per deployment)
  └─ OperatorKey ← signed by genesis (one per node operator)
      └─ AgentKey← signed by operator (one per agent instance)
```

Each level holds an Ed25519 keypair and a certificate chain linking it back to its genesis root. Any node can verify an agent's identity by walking the chain — offline, with no network or policy state required. Certificate chains are verified against six invariants: valid signatures, issuer linkage, role hierarchy, monotonic depth, no expired certificates, and hash linkage.

The key hierarchy is a primitive — it has no dependency on the policy engine. This avoids a circular dependency: you need keys to establish the engine's authority across nodes, so keys cannot depend on the engine existing. The *decision* to issue a child certificate flows through the policy engine as `ActionType::KeyDelegation` (Critical risk); the *mechanism* of signing is unconditional.

When two ZeroPoint nodes meet for the first time, the introduction protocol (`zp-introduction`) governs trust establishment. The initiator sends its certificate chain and a challenge nonce. The responder verifies the chain, builds a `PolicyContext` with `ActionType::PeerIntroduction`, and evaluates it against the policy engine. Same-genesis introductions are High risk; cross-genesis introductions are Critical. The policy engine decides — the protocol only generates the context.

The key hierarchy is itself a trajectory: Genesis → Operator → Agent, where each key's authority is derived from and constrained by the key above it. Walking the chain verifies not just the endpoint but the entire path — the trajectory of authority delegation from human root to operating agent.

Key distribution is solved by `zp-keys`. Key *discovery* — how peers find each other's network addresses — is solved by the Presence Plane (§9): a dual-backend discovery layer providing both a privacy-preserving web relay and Reticulum mesh broadcast, unified under a single `DiscoveryBackend` trait.

---

## 7. Threat Model

### 7.1 Threat Model Table

| Threat / Failure Mode | What an attacker can do | Mitigation in ZeroPoint | Residual risk / limits |
|---|---|---|---|
| **Log forgery / retroactive rewriting** | Alter history to change attribution | Signed receipts with Ed25519 + Blake3 hash chain linkage; peers verify each other's chains via collective audit | Compromised private keys can still sign lies; key revocation is deployment-dependent |
| **Unauthorized tool use** | Execute actions beyond intended scope | CapabilityGrant gating with 8-invariant delegation chain verification; PolicyEngine evaluates before every action | Bad policy design can still leave gaps; scoping is only as good as the grant definitions |
| **Cross-operator trust failure** | One party can't trust another's agent outputs | Receipts provide independent verification; `zp-introduction` protocol verifies certificate chains; Presence Plane (§9) provides dual-backend discovery with reciprocity enforcement | Cross-genesis introductions require operator-configured policy; relay-based discovery requires internet connectivity |
| **Passive scanning / surveillance** | Harvest peer identities without participating | Presence Plane reciprocity rule: agents must announce before receiving. Relay is structurally amnesic — no logs, no index, no persistence. Scanners become observable before they can observe | A scanner that announces gains access; reputation system detects consume-only behavior over time but cannot prevent initial observation |
| **Sybil flooding** | Overwhelm discovery with cheap fake identities | Ed25519 keypair generation is computationally cheap; relay broadcasts all announces | Sybil resistance depends on reputation layer (§11) and external identity binding; not solved at discovery layer alone |
| **"Security theater" governance** | Claim governance without real constraints | Constitutional rules are non-removable; explicit non-goals section; receipts are independently verifiable, not just logged | Some deployments may misuse branding while gutting constraints; MIT/Apache-2.0 allows this |
| **Surveillance co-option** | Use receipts to track people rather than actions | Tenets + constitutional non-removability + explicit ethics stance; protocol frames accountability of *actions*, not tracking of *people* | MIT/Apache-2.0 cannot legally prevent misuse; community norms and reputation are the remaining defense |
| **Replay attacks** | Resend messages or insert previously captured packets | MeshEnvelope sequence numbers (monotonic u64); 16-byte random nonces in link handshake; Ed25519 signatures over content hashes | Depends on peers tracking seen sequence numbers; long-offline nodes may have gaps |
| **Injection attacks** | Insert forged packets into mesh transport | HDLC framing with CRC verification; Ed25519 signature verification on all envelopes; link-level X25519 ECDH key agreement | Transport-level encryption depends on successful link establishment; unlinked broadcast packets are not encrypted |
| **WASM policy escape** | Malicious policy module attempts to break sandbox | Wasmtime runtime with fuel limiting (configurable execution budget); hash verification of module contents before loading | Fuel exhaustion causes denial-of-service at worst; WASM sandbox escape would require a wasmtime vulnerability |
| **Identity misbinding** | Misattribute a key to a human | Trust tiers: Tier 0 (unsigned), Tier 1 (self-signed Ed25519), Tier 2 (chain-signed with genesis root); Tier 2 requires verified delegation from a human-held key | Identity binding to physical persons remains deployment-dependent; not solved purely in protocol |

### 7.2 What ZeroPoint Intentionally Does Not Solve

Being explicit prevents credibility collapse later:

- **It does not prevent a determined actor from building harmful systems.** The MIT/Apache-2.0 license is permissive. Constitutional rules constrain the framework's own behavior; they cannot constrain a fork.
- **It does not make intelligence tools impossible.** Receipt infrastructure could be repurposed for surveillance. The Tenets and constitutional rules resist this, but they are a friction, not a wall.
- **It does not provide universal truth verification.** Receipts prove that a statement was signed, not that the statement is true.
- **Key discovery is now addressed but not fully hardened.** The Presence Plane (§9) provides dual-backend discovery with reciprocity enforcement and structural amnesia. It is not yet resistant to sophisticated Sybil attacks without the reputation layer; see §9 for the full threat analysis.

Instead:

> ZeroPoint makes actions provable, and systems refusable.

This is a practical, enforceable improvement: counterparties can demand receipts and reject agents that do not provide them or that violate constraints.

---

## 8. Transport Integrations

ZeroPoint's governance primitives are transport-agnostic. The receipt format, capability chains, delegation verification, and policy engine operate identically regardless of how messages move between participants. The framework ships with several transport integrations, each suited to different deployment contexts.

### 8.1 HTTP API (zp-server)

The most straightforward integration path. An Axum-based HTTP server exposes the governance pipeline as a REST API. Agents communicate over standard HTTP/HTTPS — suitable for cloud deployments, container orchestration, and integration with existing web services. No mesh networking required.

### 8.2 TCP and UDP Interfaces

Direct socket communication for low-latency, local-network, or point-to-point deployments. `TcpClientInterface` and `TcpServerInterface` support persistent connections with HDLC framing and CRC verification. UDP interfaces support connectionless receipt exchange. Multiple interfaces can run simultaneously on a single node.

### 8.3 Reticulum-Compatible Mesh

ZeroPoint includes a Reticulum-compatible mesh transport — wire-level interoperability with the Reticulum Network Stack, created by Mark Qvist. This integration is philosophically significant: Reticulum demonstrated that encrypted, sovereign networking requires no central authority, and ZeroPoint shares that commitment to sovereignty, decentralization, and harm minimization.

The mesh integration implements:

- **HDLC framing** with CRC-CCITT verification, matching Reticulum's serial interface format.
- **128-bit destination hashing** using the same truncated SHA-256 scheme.
- **Ed25519 signing** and **X25519 ECDH** key agreement, matching Reticulum's cryptographic primitives.
- **500-byte default MTU** with a 465-byte data payload — compatible with Reticulum's packet constraints and suitable for LoRa links.
- **3-packet link handshake** (LinkRequest → LinkProof → LinkAccept) with 16-byte random nonces for replay protection.

Interoperability testing with Reticulum ecosystem tools (MeshChat, NomadNet) is underway. The mesh transport is one option among several — chosen when sovereignty, resilience, or operation without cloud infrastructure are priorities.

### 8.4 Extending to Other Transports

Adding a new transport requires implementing the interface trait and providing serialization/deserialization for the envelope format. The governance primitives — receipts, chains, capability verification, policy evaluation — remain unchanged. Similarly, adding a new discovery backend requires implementing the `DiscoveryBackend` trait (§9) — the Presence Plane is decoupled from transport, so discovery over web and mesh coexist with any current or future transport integration. This makes ZeroPoint deployable in contexts its authors haven't anticipated: industrial IoT, satellite links, air-gapped networks, or standard enterprise infrastructure.

---

## 9. The Presence Plane

### 9.1 The Discovery Problem

Key distribution — how participants verify each other's identity — is solved by `zp-keys` and the certificate hierarchy (§6.5). But key *discovery* — how participants find each other in the first place — is a separate problem. Most systems solve it with a centralized registry: a server that indexes who is online, what they offer, and where to reach them. This creates exactly the dependency that ZeroPoint exists to eliminate. A registry is a single point of surveillance, censorship, and failure.

ZeroPoint's answer is the **Presence Plane**: a discovery layer that runs alongside the Governance Plane, using the same Ed25519 identity but serving a different purpose. The Governance Plane determines what agents do together (receipts, policy, consensus). The Presence Plane determines how agents find each other — without requiring any participant to trust a central directory.

### 9.2 Dual-Backend Architecture

The Presence Plane is built on a `DiscoveryBackend` trait — a four-method interface that any transport can implement:

- `announce(payload)` — publish a signed announce blob
- `poll_discoveries()` — retrieve newly discovered peers
- `is_active()` — check backend status
- `shutdown()` — clean teardown

Two production backends ship today:

**Web relay.** A privacy-preserving pub/sub relay over WebSocket. Agents publish signed announce blobs to the relay; the relay broadcasts all blobs to all subscribers; agents filter locally for peers they care about. The relay never parses payloads, never indexes capabilities, never maintains query logs, and never persists state. Restart equals clean slate. Privacy is a property of the architecture — not a policy promise that can be revoked.

**Reticulum mesh.** Broadcast announces over mesh interfaces — LoRa, WiFi, serial, TCP. Fully decentralized. No server, no internet dependency. Announces propagate over whatever physical medium is available.

Both backends share the same announce wire format: `[combined_key(64)] + [capabilities_json] + [ed25519_signature(64)]`. A peer discovered via web and a peer discovered via Reticulum end up in the same peer table with the same destination hash. The `DiscoveryManager` fans out announces to all active backends, polls all backends, validates signatures, deduplicates peers, and prunes expired entries.

### 9.3 Structural Amnesia

The web relay is designed to be *structurally* incapable of surveillance — not merely configured to avoid it. It operates as a dumb pipe:

- It does not parse announce payloads (no capability indexing)
- It does not maintain query logs (no search patterns recorded)
- It does not persist any state (memory-only, restart erases everything)
- It does not track who received what (no delivery receipts)

This makes the relay subpoena-proof: there is nothing to hand over. Compromise-proof: an attacker who gains access to the relay finds zero peer data. Audit-friendly: the relay's own receipt chain proves honest behavior — that it did not censor, filter, or selectively route announces.

The key insight is that structural amnesia is stronger than policy-based privacy. A "no-logs" VPN policy can be changed, overridden, or secretly violated. A relay that architecturally cannot parse what it forwards cannot be coerced into surveillance — the capability does not exist.

### 9.4 Reciprocity Enforcement

Passive scanning is the primary adversarial concern for any discovery mechanism. An attacker connects to the relay, subscribes to the full firehose, and harvests peer identities without ever revealing their own. Traditional registries have no defense against this — querying a directory does not require participation.

The Presence Plane enforces a reciprocity rule: **you must announce before you receive.** A connection that only subscribes without publishing its own announce is structurally suspicious — it is a consumer-only node, a passive scanner. The enforcement mechanism:

1. On connect, the client receives a `RelayConnection` handle.
2. The handle tracks whether the client has published an announce.
3. `try_receive()` returns an error until the client publishes.
4. A configurable grace period (default 30 seconds) allows time for announce construction.
5. After the grace period, the connection is terminated.

This means any scanner must first announce itself — exposing its own signed Ed25519 identity to every legitimate agent on the network — before it can observe anyone else. Scanners become observable before they can observe.

### 9.5 Behavioral Signals and Reputation Integration

Reciprocity enforcement catches the most naive scanners. Sophisticated ones will announce once (passing the gate), then silently consume. The Presence Plane addresses this by emitting behavioral summaries — not content, not identity, just counters — when connections close:

- `announced`: whether the client ever published an announce
- `announces_published`: how many announces were sent
- `duration`: how long the connection was active
- `reciprocity_violation`: whether the connection was terminated for failing to announce

These `ConnectionBehavior` summaries map directly to `ReputationSignal` in the `PolicyCompliance` category. An agent that connects, announces regularly, and participates in discovery accumulates positive signals. An agent that connects, announces once, and silently consumes for hours accumulates weaker or negative signals. Over time, the reputation system naturally separates participants from parasites — without the relay ever needing to inspect content.

This is autoregressive reputation in miniature: each connection's behavior updates a running assessment conditioned on the peer's full participation history. Trust in a peer is not a binary gate but an evolving trajectory.

### 9.6 Presence Plane Threat Model

| Threat | Attack | Mitigation | Residual Risk |
|--------|--------|------------|---------------|
| **Passive scanning** | Subscribe to firehose without announcing | Reciprocity rule: must announce before receiving; grace period + termination | A scanner that announces gains access; detection relies on behavioral reputation over time |
| **Sybil flooding** | Generate thousands of keypairs, flood announces | Announce format requires valid Ed25519 signatures; relay broadcasts all | Keypair generation is computationally cheap; Sybil resistance depends on reputation layer, not discovery layer |
| **Relay compromise** | Attacker gains access to relay infrastructure | Relay holds no data (structural amnesia); no payloads parsed, no state persisted | Compromised relay could selectively drop announces (censorship); relay receipt chain makes this detectable |
| **Traffic analysis** | Observe connection timing and metadata | Relay does not log connections beyond a counter; no identity-to-IP mapping | Network-level observation by ISPs or co-located attackers is outside protocol scope |
| **Eclipse attack** | Surround a target with attacker-controlled peers | Dual-backend architecture means discovery via Reticulum bypasses web relay entirely | If both backends are eclipsed, the target is isolated; out-of-band peer introduction mitigates |

The Presence Plane does not claim to solve Sybil attacks at the discovery layer. Sybil resistance is a reputation-layer concern (§11). What the Presence Plane does provide is the architectural foundation — reciprocity, behavioral signals, structural amnesia — that makes reputation-based Sybil defense possible without surveillance infrastructure.

---

## 10. Implementation Status

ZeroPoint is implemented in Rust and is technically complete.

- **700+ tests** (all passing, zero warnings)
- **22 crates** in a Cargo workspace (including dual-backend discovery in `zp-mesh`)
- **6 development phases** delivered
- **59 integration tests** covering multi-node and cross-transport scenarios
- **Full documentation** for all crates

### 10.1 Workspace Structure

| Crate | Purpose |
|-------|---------|
| `zp-core` | Core types: CapabilityGrant, DelegationChain, GovernanceEvent, receipt primitives, Blake3 hashing, Ed25519 signatures |
| `zp-audit` | Hash-chained audit trail, chain verification, collective audit (AuditChallenge, AuditResponse, PeerAuditAttestation) |
| `zp-policy` | PolicyEngine with constitutional rules (HarmPrincipleRule, SovereigntyRule), operational rules, WASM runtime with fuel limiting |
| `zp-mesh` | Transport layer: MeshNode, MeshIdentity, pluggable interfaces (TCP, UDP, serial), HDLC framing, Reticulum-compatible link handshake, envelope types, CompactReceipt, consensus, reputation; Presence Plane: DiscoveryManager, DiscoveryBackend trait, WebDiscovery (pub/sub relay with reciprocity), ReticulumDiscovery (mesh broadcast), ConnectionBehavior |
| `zp-pipeline` | GovernanceGate pipeline orchestration, MeshBridge (receipt/delegation/audit/reputation bridging), 14-step action flow |
| `zp-trust` | Trust tier definitions (Tier 0/1/2), trust grade computation, verification utilities |
| `zp-llm` | LLM provider abstraction (OpenAI, Anthropic, local), token counting, response parsing |
| `zp-skills` | SkillRegistry and SkillMatcher — keyword-based capability discovery for agent tool selection |
| `zp-learning` | Feedback collection and outcome tracking for governance policy refinement |
| `zp-server` | HTTP server exposing governance pipeline as an API (Axum-based) |
| `zp-cli` | Interactive terminal: chat, guard evaluation, mesh status, peer management, audit challenge, capability delegation, state persistence |
| `zp-receipt` | Receipt building, signing, hashing, and verification |
| `zp-keys` | Key hierarchy (Genesis → Operator → Agent), sovereignty providers, certificate chain verification, Ed25519/X25519 cryptography |
| `zp-introduction` | Peer introduction protocol: certificate chain exchange, challenge-response, policy-gated trust establishment |
| `zp-agent-bridge` | Agent framework integration bridge |
| `zp-engine` | Core engine orchestration |
| `zp-observation` | Observation and monitoring primitives |
| `execution-engine` | Sandboxed command execution environment |
| `trust-triangle` | Trust Triangle interactive demonstration |
| `monte-carlo-engine` | Monte Carlo simulation engine for trust modeling |
| `mle-star-engine` | Maximum likelihood estimation engine |
| `course-examples` | SDK course example code |

### 10.2 Build Verification

```bash
$ cargo test --workspace
   # 699 tests pass, 0 failures, 0 warnings

$ cargo clippy --workspace -- -D warnings
   # Clean

$ cargo fmt --workspace --check
   # Formatted
```

---

## 11. Adoption Paths

This project will not win by marketing. It will win by being useful and trustworthy to the right early communities.

### 11.1 First Adopters

- **Multi-agent system builders** — teams orchestrating autonomous agents who need protocol-level trust between operators, not just application-level guardrails.
- **Rust networking and security-oriented builders** — developers who understand why governance belongs in the substrate, not in the application.
- **Decentralized infrastructure communities** — projects building sovereign, local-first systems where centralized governance is a contradiction. The Reticulum ecosystem is a natural fit here.
- **Privacy-aligned agent tooling builders** — teams who need accountability without surveillance.
- **Enterprise AI governance teams** — organizations looking for verifiable, auditable behavior — from agents and humans alike — that goes beyond compliance checklists.
- **Accountable-process builders** — teams in journalism, supply chain, humanitarian operations, or organizational governance who need provable attribution and auditable decision chains, whether or not agents are involved.

### 11.2 Integration Patterns

**Pattern A: Governed Agent-to-Agent Exchange.**
Agents exchange tasks and outputs only when receipts validate authorization. Each agent verifies the other's capability chain before accepting work or results.

**Pattern B: Policy-Gated Tool Execution.**
A tool runner requires receipts demonstrating valid capability grants before executing. The runner emits its own receipt attesting to acceptance or refusal, creating a bidirectional trust record.

**Pattern C: Delegation Chains.**
A human operator grants a root capability. The agent delegates subsets to specialist sub-agents, each with narrower scope. Every delegation is verified against the eight invariants. Authority flows down the chain; accountability flows up.

**Pattern D: Human-Accountable Workflows.**
A team uses ZeroPoint to make organizational decisions provable. Each team member holds a keypair. Decisions, approvals, and delegations produce receipts that chain into an auditable record. No agent is involved — the same governance primitives that constrain agents serve humans who want their actions to be verifiable and their authority traceable. Over a Reticulum mesh, these workflows operate without any cloud dependency, making them viable for field teams, humanitarian operations, or any context where sovereign infrastructure is a requirement rather than a preference.

**Pattern E: Mixed Human-Agent Systems.**
The most common real-world pattern. Humans and agents collaborate within the same governance substrate — a human approves a plan, an agent executes it, a second human reviews the output, and every step produces a receipt in a single chain. The protocol does not distinguish between human and agent participants at the cryptographic layer; trust tiers, capability grants, and receipts work identically. Reticulum's transport sovereignty means this collaboration can happen over any medium — from a corporate network to a LoRa mesh in a disaster zone — without depending on infrastructure the participants do not control.

### 11.3 What Ships Next

The [live playground](/playground.html) already demonstrates the core patterns: governed actions, receipt chains, refusal cases, and delegation — all running against real ZeroPoint primitives in the browser. Next: a multi-agent integration example where two or more independent agents discover each other via the Presence Plane, negotiate capabilities, execute governed work, and produce a verifiable end-to-end audit trail. That working demo — agents trusting each other without a central broker — is the proof point.

---

## 12. Roadmap

Open items, roughly in priority order.

1. **crates.io registration** — Publish workspace crates for external consumption. Requires stabilizing public API surfaces and versioning strategy.
2. **Transport integration test suite** — Documented cross-transport receipt exchange results, including Reticulum ecosystem interop (NomadNet, MeshChat) and HTTP/TCP integration tests.
3. **Key revocation and multi-hop trust formalization** — Revocation propagation strategy for compromised keys; formal analysis of trust transitivity across delegation chains longer than two hops.
4. **Reputation-weighted Sybil resistance** — The Presence Plane provides behavioral signals and reciprocity enforcement but defers Sybil resistance to the reputation system. Requires implementing reputation-weighted peer scoring in `zp-mesh`.
5. **Quorum sovereignty** — Multi-device, multi-provider Genesis ceremonies. Shamir Secret Sharing or threshold cryptography to distribute the Genesis secret across multiple sovereignty providers (e.g., 2-of-3 Trezors, or 1 Trezor + 1 YubiKey). This extends the origin event from a single point to a distributed initial condition — the trust trajectory branches from multiple roots.
6. **Chain accumulator** — A rolling cryptographic summary of the full chain history carried in each receipt, enabling O(1) trajectory verification without sacrificing history-dependence. This would make the autoregressive structure computationally efficient at arbitrary chain lengths.
7. **Sustainability layer** — Consulting, hosted infrastructure, and enterprise feature scoping — without compromising the open-source core.
8. **Edge Sovereignty and governed firmware** — OpenWrt governance fork with device keypairs, attested boot, and receipt-gated telemetry. Routers become governed participants — not silent data exporters. WiFi CSI sensing capabilities require explicit consent boundaries.

---

## 13. Ethics, Non-Goals, and Misuse Resistance

### 13.1 The Co-option Risk

Accountability infrastructure can become surveillance infrastructure depending on how it is deployed. This is not a hypothetical concern — it is the central tension of the project.

ZeroPoint mitigates this through three mechanisms:

1. **Constitutional constraints** that are engineered to be non-removable. The `HarmPrincipleRule` blocks weaponization, surveillance, and deception. The `SovereigntyRule` blocks attempts to remove these constraints.
2. **Public tenets** describing intent and boundaries. The Four Tenets are not buried in documentation — they are the first thing on the website and the first code that runs in the PolicyEngine.
3. **Protocol-level framing.** ZeroPoint provides accountability of *actions*, not central control of *people*. The audit chain tracks what participants did — human or agent — not where anyone went or who they are beyond their keypair.

### 13.2 The Ethics of Permanent History

The trajectory model of trust has an ethical dimension that demands honesty. If trust is trajectory-based — if each action is permanently hash-linked to every action that preceded it, ordered and replayable — then history cannot be erased. This is a feature for accountability but a tension for privacy.

ZeroPoint's position: the chain records *what happened*, not *who you are*. A receipt proves that a specific key signed a specific statement — it does not prove that the key belongs to a specific person. Identity binding is deployment-dependent and explicitly outside the protocol scope. The chain is pseudonymous: a keypair's trajectory is visible, but the mapping from keypair to human identity is not embedded in the protocol.

This distinction matters. An accountability system that tracks actions (receipts) is fundamentally different from a surveillance system that tracks people (identity). ZeroPoint builds the former and resists the latter — through constitutional rules, structural amnesia in the Presence Plane, and explicit protocol design choices that avoid creating the data structures that surveillance requires.

The tension remains real. Any system that produces durable, verifiable records creates potential for those records to be used in ways their creators did not intend. The mitigation is not to avoid creating records — that would eliminate accountability along with surveillance — but to design the record structure so that it serves one purpose and resists the other. ZeroPoint's choices — pseudonymous keypairs, action-level receipts, no identity binding in protocol, structural amnesia in discovery — are deliberate decisions to lean toward accountability and away from surveillance.

### 13.3 The Genesis Responsibility

ZeroPoint's trajectory-based architecture implies that the Genesis ceremony is consequential in a way that simpler systems do not require. The choices made at Genesis — which sovereignty provider, which constitutional rules, which operator identity — propagate forward through every subsequent action. A Genesis ceremony conducted carelessly produces a trust trajectory that inherits that carelessness at every step.

This is not a flaw. It is an honest representation of how trust actually works. The founding conditions of any institution — its charter, its constitution, its founding commitments — shape everything that follows. ZeroPoint makes this shaping explicit and verifiable rather than implicit and deniable.

### 13.4 Non-Goals

ZeroPoint does not aim to:

- Become a compliance product. Compliance is a checklist someone else writes. ZeroPoint is infrastructure you build on.
- Become a centralized authority. There is no ZeroPoint server, no ZeroPoint cloud, no ZeroPoint corporation deciding who gets to use it.
- "Prevent all misuse." The MIT/Apache-2.0 license is deliberately permissive. Constitutional rules constrain the framework; they cannot constrain a fork.
- Depend on any single transport or network. ZeroPoint's governance works over HTTP, TCP, mesh, or anything else. No transport is privileged.
- Be agent-only infrastructure. The protocol is participant-agnostic by design. Narrowing it to agents alone would abandon the humans and systems that face the same accountability gap.

---

## 14. Conclusion

### What ZeroPoint Claims

ZeroPoint provides protocol-level primitives that make the following properties verifiable:

1. **Attribution**: Every action produces a signed receipt. The receipt proves that a specific Ed25519 key attested to a specific action at a specific time.
2. **Ordering**: Receipts are hash-chained. The chain establishes a total order over events that resists retroactive rewriting. Tampering with any receipt invalidates every subsequent hash.
3. **Authorization traceability**: Every capability grant traces back through a delegation chain to a human-held Genesis key. The chain is verified against eight invariants. Violation of any invariant rejects the chain.
4. **Governance enforcement**: Constitutional rules (HarmPrincipleRule, SovereigntyRule) evaluate before every action and cannot be removed, overridden, or reordered. This is enforced in the PolicyEngine's evaluation order, not by policy.
5. **Portability**: Identity is a keypair. Receipts are self-contained. Chains are independently verifiable. No platform, server, or central authority is required to verify trust. Any transport that can carry bytes can carry the governance primitives.

These claims are testable against the codebase (700+ tests, 22 crates), verifiable by independent auditors (all chain verification is deterministic and offline-capable), and falsifiable (any violation of the eight delegation invariants or two constitutional rules can be demonstrated with a specific input that the system rejects).

### What ZeroPoint Does Not Claim

Being explicit about boundaries is as important as stating claims:

- **It does not prove truth.** A receipt proves that a statement was signed, not that the statement is true. Governance constrains actions; it does not evaluate their content.
- **It does not prevent all misuse.** Constitutional rules constrain the framework's own behavior. The MIT/Apache-2.0 license is permissive. A fork can remove the rules.
- **It does not bind keys to persons.** A receipt proves that a specific key signed an action — not that the key belongs to a specific human. Identity binding to physical persons is deployment-dependent and outside the protocol scope.
- **It does not guarantee runtime integrity.** A compromised host can sign whatever it wants. ZeroPoint makes the signing verifiable but cannot prevent a compromised machine from producing fraudulent signatures.
- **It does not solve AI safety.** It solves a more specific problem: making actions provable, authority traceable, and governance enforceable at the protocol layer.
- **The cross-domain parallels are analogies, not proofs.** The correspondences between ZeroPoint's architecture and autoregressive patterns in language modeling, cognition, and physics are structural analogies that help explain why the architecture works. They are not claims about language, cognition, or physics. The architecture stands on its own testable properties.

### The Argument

The structural problem is clear: trust primitives captured by platforms become leverage for extraction. Identity in someone else's database is a lease. Reputation that cannot be carried between systems is a hostage. Authorization that can be silently revoked is permission, not trust.

The deeper problem is that even portable trust is fragile if it is stateless — if the system checks only a current credential (snapshot-only verification, no ordered history required) and discards the path that produced it. Snapshot-only verification is what makes logs rewritable, authorization forgeable, and delegation chains uncheckable.

ZeroPoint provides primitives in a form that is explicitly trajectory-based: each receipt carries the cryptographic weight of every receipt before it (ordered, hash-chained, replayable); each delegation narrows the authority of every delegation after it (scope, time, depth, tier — all verified against invariants); each constitutional rule propagates forward from Genesis with undiminished force (fixed evaluation order, non-removable, non-overridable).

This architecture converged independently on the same computational pattern — stepwise unfolding conditioned on accumulated context — that is being recognized as structurally significant in language modeling, cognitive science, and theoretical physics. The convergence suggests that trajectory-based verification is not an arbitrary design choice but a structural requirement for any system that models trust as it actually works: not as a state to be checked, but as an ordered sequence of evidence to be verified.

Agents are the most urgent application, and ZeroPoint is built to meet that urgency. But the primitives are participant-agnostic. A human's actions are as provable as an agent's. A team's decisions are as auditable as a pipeline's.

Make trust portable, and you make exit real. Make trust trajectory-based, and you make it durable. Make it durable, and extraction loses its grip.

Trust is infrastructure. Trust unfolds.

> Power will diffuse. Accountability must diffuse with it.

---

## Appendix A: Protocol Sketch

This is intentionally not a full specification. It shows rigor and invites contribution.

### A.1 Identities

Participants — whether human, agent, service, or device — hold Ed25519 signing keypairs and derive X25519 key-agreement keys for encrypted link establishment. A 128-bit destination hash is computed as the truncated SHA-256 of the public key. This addressing scheme is compatible with Reticulum's identity model but is used across all ZeroPoint transports.

Trust is expressed in tiers, applicable to any participant:
- **Tier 0**: Unsigned. No cryptographic identity. Lowest trust.
- **Tier 1**: Self-signed Ed25519. The participant controls a keypair but has no chain authority.
- **Tier 2**: Chain-signed with genesis root. The participant holds a valid delegation chain terminating at a human-held key.

Identity binding to physical humans or organizations is deployment-dependent and explicitly outside the protocol scope.

### A.2 CompactReceipt Envelope

The wire format uses MessagePack with short field names for bandwidth efficiency:

```
{
  "id": "rcpt-a1b2c3d4",       // Receipt ID
  "rt": "execution",           // Receipt type
  "st": "success",             // Status
  "tg": "A",                   // Trust grade
  "ch": "b3a1...hex",          // Blake3 content hash
  "ts": 1740000000,            // Unix timestamp (seconds)
  "pr": "rcpt-prev-id",        // Parent receipt ID (optional)
  "pd": "allow",               // Policy decision (optional)
  "ra": "all rules passed",    // Rationale (optional)
  "sg": "ed25519-sig-hex",     // Ed25519 signature (optional)
  "ex": { ... }                // Extensions (optional)
}
```

Typical encoded size: 150–300 bytes. Maximum for single-packet transmission: 380 bytes (allowing room for MeshEnvelope overhead within the 465-byte payload limit).

### A.3 MeshEnvelope

The mesh transport's outer wrapper adds (other transports use their own framing):
- **Envelope type**: Receipt, Delegation, AuditChallenge, AuditResponse, PolicySync, ConsensusVote, ReputationUpdate, or Custom.
- **Sequence number**: Monotonic u64 for replay detection.
- **Source/destination**: 128-bit mesh destination hashes.
- **Signature**: Ed25519 over the envelope payload.

### A.4 Chain Verification Rules

DelegationChain verification enforces eight invariants:

1. Each grant references the previous one as `parent_grant_id`.
2. Delegation depths increment monotonically (0, 1, 2, ...).
3. Each child's scope is a subset of (or equal to) its parent's scope.
4. Each child's trust tier is ≥ its parent's trust tier.
5. No child outlives its parent — expiration dates are inherited and cannot be extended.
6. The chain does not exceed the `max_delegation_depth` set by the root grant.
7. Each grant's grantor matches the previous grant's grantee (the delegator).
8. All Ed25519 signatures verify against their respective signing keys.

Failure of any single invariant rejects the entire chain. Authority dissolves.

---

## Appendix B: Glossary

### Terminology Discipline

This glossary defines terms with precision. Three terms carry special discipline requirements throughout the document:

- **"Trajectory"** is used only when all three properties are present: evidence, ordering, and replayability. If any property is absent, a different term is used.
- **"Markovian"** is used only to mean snapshot-only verification: the system checks only the current state with no ordered history required. It is a technical term from stochastic processes, not a pejorative.
- **"Autoregressive"** is used only when both the step and the conditioning context are explicitly named. When mechanism language (receipts, gates, ordered checks, invariants) is sufficient to convey the meaning, this document uses mechanism language instead.

### Terms

- **Receipt**: Signed evidence of an action or decision. Contains: receipt ID, type, status, trust grade, Blake3 content hash, timestamp, parent receipt reference (`pr`), policy decision, rationale, Ed25519 signature, and optional extensions. Encoded as MessagePack, 150–300 bytes. A receipt is the atomic unit of evidence in ZeroPoint.
- **Chain**: Linked sequence of receipts where each receipt's `pr` field references the previous receipt's `id`, creating a hash-linked, tamper-evident sequence. The chain establishes ordering (events are sequenced by `pr` linkage, not merely timestamped) and tamper-evidence (modifying any receipt invalidates every subsequent hash).
- **Trajectory**: A chain that satisfies three properties: (1) **evidence** — each step is a signed receipt with a content hash; (2) **ordering** — steps are sequenced by hash-linked `pr` fields, not merely timestamped; (3) **replayability** — the full chain can be re-verified deterministically from Genesis to tip. Trust is the trajectory, not any single point on it. When this document uses "trajectory," all three properties are implied. If a sequence lacks any of these properties, it is a log, not a trajectory.
- **Markovian**: Snapshot-only verification. A Markovian system checks the current state — is this token valid? is this permission granted? — without requiring ordered history. A mutable log is Markovian evidence: each entry stands alone, and rewriting any entry is locally undetectable. ZeroPoint's architecture is explicitly non-Markovian: verification requires walking the ordered, hash-linked chain, not merely checking the latest entry. The distinction is architectural, not philosophical: Markovian verification is O(1) but forgery-vulnerable; trajectory-based verification is O(n) but tamper-evident.
- **Autoregressive**: A computational pattern where each step is conditioned on all prior context. This term is used in this document only when both the step and the conditioning context are explicit — e.g., "each receipt (step) is hash-linked to the full prior chain (context)." The term originates in time-series analysis and language modeling. Its use here reflects a structural correspondence between ZeroPoint's chain architecture and autoregressive systems in other domains, described in §1 and Appendix D. When mechanism language (receipts, gates, ordered checks) is sufficient, the document uses mechanism language instead of this term.
- **Snapshot**: A single-point-in-time check with no reference to ordered history. "Is this token valid right now?" is a snapshot query. "Is this token the product of an unbroken, hash-linked chain of authorized delegations from a human root?" is a trajectory query. ZeroPoint's architecture treats snapshots as insufficient for trust verification.
- **Narrowing**: The property of delegation chains whereby each successive delegation can only constrain — never widen — the authority of the previous grant. Scope shrinks (child ⊆ parent), expiration inherits (child ≤ parent), depth increments (child = parent + 1), and trust tier can only increase. Narrowing is enforced by the eight delegation invariants and is structural, not policy-based.
- **Invariant**: A property that is verified on every evaluation and whose violation causes rejection. ZeroPoint defines two kinds: (1) delegation invariants — eight rules verified by `DelegationChain::verify()`, any violation of which dissolves the entire chain; (2) constitutional invariants — `HarmPrincipleRule` and `SovereigntyRule`, which evaluate at every policy step and cannot be removed, overridden, or reordered.
- **Capability Grant**: Cryptographically signed permission token granting an action scope, with constraints on time (`valid_from`, `valid_until`), cost ceiling, rate limit, delegation depth (`max_delegation_depth`), and trust tier. Grants are delegatable subject to the narrowing principle.
- **Delegation Chain**: Ordered sequence of capability grants from root (human-held) to leaf (most-delegated agent), verified against eight invariants. Authority narrows as the chain lengthens. A revoked parent invalidates all children because verification walks root to leaf.
- **Policy**: Constraints governing capability use and system behavior, evaluated by the PolicyEngine in a fixed order. The evaluation order — constitutional rules first, then operational rules, then WASM modules, then default — is itself an invariant.
- **Constitutional Constraint**: Non-overridable rule embedded in the PolicyEngine — specifically `HarmPrincipleRule` and `SovereigntyRule` — that cannot be removed, bypassed, or overridden by any other rule, WASM module, or consensus vote. A trajectory invariant: it propagates forward from Genesis with undiminished force at every evaluation step.
- **Guard**: Pre-action sovereignty check. Local-first, runs before the PolicyEngine. The node evaluates its own accumulated state (chain, grants, constitutional rules) before accepting any external input. Enforces the participant's right to refuse.
- **GovernanceGate**: The pipeline through which every action must pass: Guard → Policy → Execute → Audit. Each phase is conditioned on the output of the prior phase. Nothing executes without passing through the gate; nothing passes through the gate without joining the audit chain.
- **Genesis**: The origin event of a ZeroPoint deployment. The ceremony that generates the root Ed25519 keypair, seals constitutional rules, and establishes the initial conditions from which all subsequent trust trajectories unfold. Genesis is sequential (each step requires the prior step's success), irreversible (the genesis record is written once and never modified), and consequential (its choices propagate through every subsequent action).
- **Sovereignty Provider**: The mechanism that stores and protects the Genesis secret. Options include biometric (Touch ID, fingerprint), hardware wallet (Trezor, YubiKey), OS keychain (macOS Keychain, Linux Secret Service), and file-based (fallback). The choice of provider is made at Genesis and recorded in the immutable genesis record.
- **Trust Tier**: Graduated trust levels. Tier 0: unsigned, no cryptographic identity. Tier 1: self-signed Ed25519, the participant controls a keypair but has no chain authority. Tier 2: chain-signed with Genesis root, the participant holds a valid delegation chain terminating at a human-held key. Capability grants specify a minimum trust tier; delegation cannot lower it.
- **Reticulum-compatible**: One of several transport integrations — wire-interoperable with Reticulum's HDLC framing, 128-bit destination hashing, Ed25519/X25519 cryptography, and 500-byte MTU.
- **CompactReceipt**: MessagePack-encoded receipt using short field names, optimized for single-packet mesh transmission (≤ 380 bytes including MeshEnvelope overhead).
- **Presence Plane**: The discovery layer — how agents find each other. Dual-backend (web relay + Reticulum mesh), structurally amnesic, with reciprocity enforcement. Complements the Governance Plane (how agents act together).
- **DiscoveryBackend**: Trait abstraction for discovery transports. Four methods: `announce`, `poll_discoveries`, `is_active`, `shutdown`. Backends push raw announce blobs; signature validation and peer management happen in the DiscoveryManager.
- **Structural Amnesia**: An architectural property of the web relay: it cannot perform surveillance because it never parses, indexes, or persists announce payloads. Privacy by design, not by policy. Distinct from a "no-logs" policy, which can be changed; structural amnesia cannot be changed because the capability to surveil does not exist in the code.
- **Reciprocity Enforcement**: The relay rule requiring clients to announce their own signed Ed25519 identity before receiving peer announcements. A connection that only subscribes without announcing is terminated after a configurable grace period. Prevents passive scanning by making scanners observable before they can observe.
- **ConnectionBehavior**: Behavioral summary (counters only, no content) emitted when a relay connection closes. Fields: `announced`, `announces_published`, `duration`, `reciprocity_violation`. Maps to ReputationSignal in the PolicyCompliance category.
- **MeshNode**: High-level transport primitive managing interfaces, peers, links, delegations, and reputation.
- **Collective Audit**: Peer-to-peer chain verification. A challenger sends an `AuditChallenge`; the challenged peer responds with its full chain; the challenger verifies integrity and produces a signed `PeerAuditAttestation`. Broken chains generate negative reputation signals. No central auditor required.

---

## Appendix C: Example Integration Pattern

A tool runner integrated with ZeroPoint operates as follows: any participant requesting execution must provide a receipt chain proving it holds a valid `CapabilityGrant` to call the tool, scoped to the specific action, signed by a chain terminating at a human-held Tier 2 key. The runner's GovernanceGate verifies the chain locally — checking all eight delegation invariants, evaluating the PolicyEngine (including constitutional rules), and confirming the capability hasn't expired or exceeded its rate limit. If verification fails, the runner emits a refusal receipt citing the specific invariant or rule that failed. If verification succeeds, the tool executes and the runner emits an execution receipt attesting to the action, its inputs hash, its outputs hash, and the policy decision. Both receipts join the audit chain. The requesting participant receives the execution receipt and can present it to other peers as proof of completed work.

This pattern works identically whether the requester is an agent, a human operator using the CLI, or an automated service. The protocol does not distinguish between them at the cryptographic layer — only at the trust tier level, where chain-signed identity (Tier 2) requires a verifiable delegation path back to a human root.

This creates a bidirectional, evidence-based trust relationship that operates over sovereign transports, requires no central coordinator, and produces a durable record that either party can independently verify at any time. Each interaction adds to both parties' trajectories — compounding trust through demonstrated reliability.

---

## Appendix D: The Trajectory Correspondence Table

The following table maps computational principles to their concrete instantiations in ZeroPoint, with the mechanism and testable behavior that makes each claim verifiable. The cross-domain parallels (language, cognition, physics) are *analogies* that illuminate the pattern; the ZeroPoint mechanisms and accept/reject behaviors are *testable properties* of the architecture.

| Principle | Analogy Domain | ZeroPoint Mechanism | Testable Behavior (Accept/Reject) |
|-----------|---------------|--------------------|------------------------------------|
| Each step conditioned on all prior context | Language: next-token prediction uses full sequence history | Hash chaining: each receipt's `pr` field links to the previous receipt's `id`; Blake3 hashes are transitive | **Accept**: unbroken hash-linked chain from Genesis to tip. **Reject**: any missing receipt or hash mismatch |
| Present state compresses full history | Physics (analogy): present moment carries weight of entire history | Collective audit: `AuditChallenge` / `AuditResponse` / `PeerAuditAttestation` | **Accept**: peer produces full chain matching claimed state; signed attestation issued. **Reject**: incomplete chain → negative reputation signal |
| System-wide coherence from local evaluation | Language: coherent essays from local token predictions | PolicyEngine fixed evaluation order: HarmPrincipleRule → SovereigntyRule → operational rules → WASM → default | **Accept**: receipt with valid policy decision from compliant engine. **Reject**: receipt attesting to constitutionally blocked action; peers reject during chain verification |
| Future actions narrowed by trajectory | Language: each token constrains future distributions | DelegationChain::verify() — 8 invariants: scope subset, depth monotonic, expiration inherited, tier non-decreasing | **Accept**: all 8 invariants satisfied. **Reject**: any single invariant violation dissolves the entire chain |
| Origin event propagates indefinitely | Physics (analogy): Big Bang continues shaping present | `zp-keys` certificate hierarchy: Genesis → Operator → Agent; all certs chain to Genesis root | **Accept**: certificate chain walks back to Genesis key. **Reject**: chain terminates at non-Genesis root |
| Sequential unfolding is constitutive | Cognition: thought unfolds sequentially over time | `onboard/genesis.rs`: generate → validate → enroll → seal → write; each step requires prior step's success | **Accept**: `genesis.json` written with all fields populated. **Reject**: ceremony halts at first failed step; no partial Genesis |
| Authority narrows with each delegation | Language: each token constrains future probability space | CapabilityGrant fields: scope, `valid_until`, `max_delegation_depth`, trust tier; child ⊆ parent enforced per-field | **Accept**: child scope ⊆ parent scope, child expiration ≤ parent, child depth = parent + 1. **Reject**: any widening attempt |
| Reputation as accumulated state | Cognition: trust built through accumulated experience | `ReputationSignal` from receipts + `ConnectionBehavior` summaries; signals compose over interaction history | **Accept**: peer with long positive trajectory passes reputation gate. **Reject**: peer with broken chains or reciprocity violations accumulates negative signals |
| Trajectory verification > snapshot verification | Physics (analogy): history-dependent vs. instantaneous-state models | Hash-chained audit vs. single-entry log | **Accept**: full chain verified end-to-end. **Reject**: single-entry check would miss retroactive rewrites that chain verification catches |
| Trajectory invariants (conservation laws) | Physics (analogy): conserved quantities from initial conditions | Constitutional rules: non-removable, non-overridable, fixed in evaluation position 1 and 2 | **Accept**: HarmPrincipleRule and SovereigntyRule evaluate at every step, at step 1M same as step 1. **Reject**: any attempt to remove, reorder, or override returns `SovereigntyRule` block |

---

*ZeroPoint is maintained by ThinkStream Labs.*
*Contact: ken@thinkstreamlabs.ai*
*Repository: https://github.com/zeropoint-foundation/zeropoint*
*Website: https://zeropoint.global*

---

*© 2026 ThinkStream Labs. This document is released under CC BY 4.0. The ZeroPoint codebase is released under MIT/Apache-2.0.*
