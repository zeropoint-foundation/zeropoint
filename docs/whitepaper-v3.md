# ZeroPoint

## Cryptographic Governance Primitives for Accountable Systems

**Whitepaper v3.0 — June 2026**
**Ken Romero, Founder, ThinkStream Labs**

Status: Public Technical Overview
License: CC BY 4.0 (text); Code remains MIT/Apache-2.0
Canonical URL: https://zeropoint.global/whitepaper
PDF: [zeropoint-whitepaper-v3.0.pdf](https://zeropoint.global/zeropoint-whitepaper-v3.0.pdf)

**How to cite:**
> Romero, Ken. "ZeroPoint: Cryptographic Governance Primitives for Accountable Systems." ThinkStream Labs, Whitepaper v3.0, June 2026. https://zeropoint.global/whitepaper

---

## Abstract

ZeroPoint is cryptographic governance infrastructure — primitives that make actions provable, auditable, and policy-bound without requiring central control. Every significant action produces a verifiable receipt. Receipts chain together via hash linkage into an ordered, tamper-evident audit trail. Authorization flows through signed, delegatable capability grants that narrow as they propagate. Constitutional constraints are non-removable and evaluated before every action.

The framework operates at the protocol-primitives layer and is participant-agnostic: the same receipts, capability chains, and policy enforcement work whether the actor is a human, an AI agent, an automated service, or an IoT device. Transport is pluggable — HTTP, TCP, encrypted mesh, or any future medium. ZeroPoint ships with a Reticulum-compatible mesh transport alongside TCP, UDP, and HTTP interfaces, plus a privacy-preserving Presence Plane for peer discovery that operates without centralized registries.

The core argument: when trust infrastructure lives in platform databases rather than cryptographic protocols, participants cannot leave without losing their history. Identity, reputation, and authorization become platform features rather than portable properties. ZeroPoint provides the protocol-level primitives that make trust portable: signed receipts, verifiable delegation chains, and governance constraints that travel with the participant rather than staying behind in a vendor's database.

Autonomous AI agents are the most urgent application — they are proliferating faster than the trust infrastructure to govern them. But the primitives are not agent-specific. Any participant that holds a keypair can sign receipts, hold capability grants, delegate authority, and exercise sovereign refusal.

ZeroPoint is implemented in Rust and is technically complete. It does not claim to solve AI safety or trust generally. It provides cryptographic primitives and governance constraints that make actions provable and authority traceable — shifting the ground on which trust between participants is established.

---

## Table of Contents

0. Motivation — The Portable Trust Problem
1. How Trajectory-Based Verification Works
2. Problem Statement
3. Design Goals
4. System Overview
5. Receipts and Chains (including §5.5 Epochs, Compaction, and Bounded Growth)
6. Governance Model
7. Threat Model
8. Transport Integrations
9. The Presence Plane
10. External Truth Anchoring
11. Fleet Topology: From Single Node to Governed Network
12. Ethics, Non-Goals, and Misuse Resistance
13. Conclusion

Appendix A: Protocol Sketch
Appendix B: Glossary
Appendix C: Example Integration Pattern
Appendix D: Trajectory Verification — Mechanisms and Testable Behaviors

---

## 0. Motivation — The Portable Trust Problem

### The Structural Problem

When trust primitives — identity, reputation, authorization — are implemented at the platform layer rather than the protocol layer, they cannot move with participants. This is a structural problem, not a policy one.

The dynamic works like this: a platform provides identity and reputation services. Users and developers build on those services. Over time, the platform becomes the only place where a user's history, credentials, and relationships are legible. Switching costs accumulate. Once switching costs are high enough, the platform can degrade quality, raise prices, or insert intermediaries — because the cost of leaving exceeds the cost of staying. Users' trust relationships, built up over years, are held in a database they do not control.

The practical consequence: if your identity lives in a platform's database, your reputation is computed by a platform's algorithm, and your authorization chains terminate at a platform's API — you do not own those things. You are leasing them. The platform can revoke, reinterpret, or degrade the lease at any time.

### The Missing Primitive

SSL/TLS provides a useful comparison. Before SSL, transmitting payment credentials over the internet required trusting every intermediary on the path. TLS made the transport trustworthy without requiring the endpoints to be trusted — and in doing so, made e-commerce viable for any merchant, not just the few who could afford proprietary trust infrastructure.

The internet has a similar gap for trust itself. Not transport encryption — that problem is largely solved. The gap is: how do you prove what happened, who authorized it, and whether constraints were honored — without depending on a platform to be the witness?

ZeroPoint provides the answer in three primitives:

- **Signed, hash-chained receipts** that make actions provable and their ordering tamper-evident.
- **Cryptographic capability grants** that make authorization verifiable, portable, and delegatable.
- **Constitutional constraints** that make governance enforceable at the protocol layer.

### Snapshots vs. Trajectories

Platform trust has a deeper flaw beyond non-portability: it is stateless. A platform checks "is this token valid right now?" — a single time slice. It does not ask "how did this authority arrive here?" or "is this chain consistent with everything that preceded it?"

That distinction matters structurally. Snapshot verification checks only the current credential. Trajectory verification checks the full chain — the credential, the delegation that produced it, the delegation that produced that, all the way back to a human-held root key — and rejects if any link is broken, any scope is exceeded, or any invariant is violated.

Snapshot-based systems are vulnerable to retroactive rewriting. If you only need the latest entry to be valid, an attacker can rewrite everything before it without detection. If you only check whether a token is currently valid, you cannot detect whether it was forged yesterday. Trajectory-based systems are not: each entry's hash incorporates the full prior history transitively, making any rewrite detectable.

ZeroPoint is explicitly trajectory-based. The implications for portability:

- **Identity is a keypair you control**, not an account on someone else's server. It moves between systems without losing continuity.
- **Reputation is a verifiable chain of receipts**, not a score computed by an opaque algorithm. Anyone can audit it.
- **Authorization is a cryptographic capability grant**, not an API key that can be silently changed.
- **History is a hash-chained audit trail** where tampering is detectable and omission is provable.

When trust is portable, platforms compete on service quality rather than lock-in. When trust is trajectory-based, it cannot be fabricated after the fact or silently erased.

### Why AI Agents Raise the Stakes

Agents operating on your behalf inherit the same trust infrastructure — or lack of it — that you do. If your identity is platform-bound, your agent's authority is platform-bound. If your audit trail is controlled by someone else, so is your agent's.

More specifically: agents act at machine speed, across organizational boundaries, with delegation chains that can extend far beyond their original scope. The accountability gaps that human organizations have tolerated for decades — mutable logs, informal authorization, platform-controlled identity — become structurally untenable when agents operate this way.

ZeroPoint provides the cryptographic substrate agents need: provable actions, traceable authority, governance constraints that cannot be bypassed. But the primitives are participant-agnostic. Everything that applies to agents applies equally to humans, services, and devices operating within the same framework.

### What ZeroPoint Provides

Protocol-level primitives that no platform controls:

- **Receipts** signed by the actor and chained to the previous receipt.
- **Capability grants** cryptographically scoped and delegatable with narrowing invariants.
- **Constitutional constraints** that are non-removable and non-overridable.
- **Transport agnosticism** so trust flows over HTTP, TCP, mesh, or any future medium.

This is infrastructure you build on, not a governance framework you comply with.

---

## 1. How Trajectory-Based Verification Works

### The Core Pattern

ZeroPoint's design is built around one idea: verification that only checks the current state is insufficient for trust. The current state of a permission can be forged. The current value of a token can be injected. Only by checking the full ordered chain — every step, every link, from origin to present — can you detect whether authority arrived here legitimately.

This approach has a name in time-series analysis and machine learning: autoregressive verification, where each step is conditioned on all prior context rather than just the immediately preceding state. ZeroPoint did not start from this theoretical framing. It converged on the same pattern from practical requirements. But the pattern is worth naming, because it explains why several architectural choices that might look like overhead are actually load-bearing.

### Four Testable Claims

The following claims characterize ZeroPoint's trajectory-based architecture. Each is stated as a testable property with a concrete mechanism, accept condition, and reject condition.

**Claim 1: Each step is conditioned on all prior context.**

Every receipt's Blake3 hash links transitively to every prior receipt in the chain. A verifier can present any receipt and demand the full chain back to Genesis. If any intermediate receipt is missing or its hash does not match the next entry's `pr` field, the chain is **rejected**. The mechanism is hash chaining; the accept condition is an unbroken sequence of hash-linked receipts; the reject condition is any gap or hash mismatch.

**Claim 2: The present state compresses the full history.**

A node's current state — its keychain, capability grants, audit trail, and reputation — is deterministically derived from its complete history of Genesis, delegations, actions, and verifications. Two nodes with identical histories produce identical states. A node that cannot produce the chain supporting its current state fails collective audit and is **rejected** by peers. The mechanism is `AuditChallenge` / `AuditResponse` / `PeerAuditAttestation`; the reject condition is a negative reputation signal for an incomplete chain.

**Claim 3: System-wide coherence emerges from local evaluation.**

No global coordinator enforces the constitutional rules. Each node evaluates `HarmPrincipleRule` and `SovereigntyRule` locally, at each step. A node that removes or bypasses these rules will produce receipts that other nodes **reject** during chain verification, because the receipts will lack valid policy decisions or will attest to constitutionally blocked actions. The mechanism is the PolicyEngine's fixed evaluation order; the accept condition is a receipt with a valid policy decision from a compliant engine; the reject condition is a receipt that either lacks a policy decision or attests to a blocked action.

**Claim 4: The space of possible future actions narrows with each delegation.**

Given a delegation chain of depth N, the leaf grant's scope is a subset of every ancestor's scope, its expiration is ≤ every ancestor's expiration, and its depth equals N. Any grant that violates these constraints is **rejected** by the eight-invariant verification in `DelegationChain::verify()`. The accept condition is all eight invariants satisfied; the reject condition is any single invariant violation, which dissolves the entire chain.

### Genesis as Fixed Origin

The Genesis ceremony generates a 32-byte Ed25519 seed from which all trust in the deployment derives. Every operator key is signed by this Genesis key. Every agent key is signed by an operator key. Every capability grant traces back through the delegation chain to authority rooted in Genesis. Every receipt in the audit chain exists because an entity authorized by Genesis took an action.

This makes Genesis actively present in every trust decision — not as historical context but as a verifiable constraint. Any certificate chain can be walked back to the Genesis root. If the Genesis key is not at the root of the chain, verification **rejects**. This is an invariant of `zp-keys` certificate verification, not a policy.

The Genesis ceremony is sequential and irreversible: generate the keypair → validate the sovereignty provider → enroll biometric or hardware confirmation → seal the constitutional bedrock → write the immutable record. Each step requires the prior step's success. The ordering is enforced in code — `onboard/genesis.rs` will not proceed to enrollment until the keypair is generated, will not seal constitutional rules until the provider is validated, and will not write the genesis record until all prior steps succeed. The choices made during Genesis propagate forward through every subsequent action.

### Delegation as Narrowing

A root capability grant specifies four constraint dimensions:

- **Scope**: which actions are permitted (e.g., `tool:execute`, `file:read`)
- **Time**: `valid_from` and `valid_until` timestamps
- **Depth**: `max_delegation_depth` — how many times the grant can be re-delegated
- **Trust tier**: minimum tier required to exercise the grant

Each subsequent delegation can only narrow these bounds — never widen them:

- Scope: child's scope must be a subset of parent's scope (invariant 3)
- Time: child's expiration must be ≤ parent's expiration (invariant 5)
- Depth: child's depth increments by exactly 1 (invariant 2) and cannot exceed `max_delegation_depth` (invariant 6)
- Trust tier: child's tier must be ≥ parent's tier (invariant 4)

A revoked parent grant invalidates all child grants automatically — because every child references its parent via `parent_grant_id` (invariant 1), and chain verification walks the full path from root to leaf. If any link in the path is revoked or expired, the entire chain is **rejected**.

This narrowing is enforced by eight invariants verified at every chain evaluation. It is structure, not policy — authority becomes more constrained as it propagates further from its human root.

### Reputation as Accumulated State

A peer's reputation is not a static label. It is a state conditioned on the full sequence of interactions: successful receipts accumulate positive signal, broken chains generate negative signal, behavioral anomalies (silent consumption, missing announces, reciprocity violations) degrade standing. Trust builds through demonstrated history and erodes through demonstrated failures. It is never a single measurement.

### The Three Layers of Accountability

ZeroPoint's accountability architecture operates at three distinct layers:

**Layer 1 — The Receipt Chain (what happened).** Receipts record actions, delegations, and outcomes. The chain is hash-linked, tamper-evident, and replayable from Genesis to tip. Every significant event is signed, ordered, and anchored. The receipt chain answers: what did this actor do, under whose authority, and when?

**Layer 2 — The Observation Loop (did it violate policy?).** The GovernanceGate pipeline — Guard → Policy → Execute → Audit — evaluates every action against accumulated state: constitutional rules, operational policies, delegation constraints. When an agent's actions are assessed through reflection patterns, peer challenges, or collective audit, the assessment joins the receipt chain and conditions future evaluations. The observation loop answers: was this action permitted, and if not, why?

**Layer 3 — The Trace Layer (what computational path produced it?).** Recent work in model decomposition suggests a third accountability layer: a hash commitment anchored in each receipt that commits to the actual computational trajectory the model traversed — the sequence of features, relations, and activations consulted during inference. This goes beyond what the agent said or did to what it actually computed. A trace-committed receipt chain would make confabulation (stated reasoning diverges from actual computation), mode collapse (reasoning fingerprints cluster in known error basins), and reasoning drift (computational paths shift systematically over time) all detectable.

The receipt chain and observation loop are implemented today. The trace layer is a future research direction. The architecture accommodates this extension without modifying the receipt or policy primitives.

---

## 2. Problem Statement

AI agents are rapidly becoming operational actors: they request tools, move data, execute workflows, and trigger external effects. They act at machine speed, across organizational boundaries, with delegation chains that can extend far beyond their original authority. The trust infrastructure governing them mostly does not match that scale.

The specific gaps:

**Actions are difficult to attribute reliably.** Logs exist, but they are mutable and centralized. A mutable log reflects only whatever state someone last wrote, with no verifiable connection to what actually happened. Each entry stands alone — rewriting any entry is locally undetectable.

**Authorization is informal and mutable.** Most systems rely on API keys or ambient permissions rather than scoped, cryptographic capability grants. Who authorized what, and when, is often reconstructed after the fact — if at all.

**Logs are easy to forge, prune, or reinterpret.** There is no chain of evidence — only whatever the operator chooses to retain. When entries are not chained, each is independently vulnerable.

**Cross-party trust is brittle.** One team cannot safely accept another party's agent outputs without out-of-band verification. Without a common chain that both parties can independently verify, trust between organizations reduces to contracts and reputation.

These are not agent-specific problems. They predate autonomous agents. Human organizations make consequential decisions with mutable logs and informal authorization every day. Agents inherited this accountability gap; they did not create it. But they compress decades of accumulated risk into months of operational reality.

At the same time, several environmental shifts are making decentralized trust infrastructure more viable: Reticulum and similar projects demonstrate sovereign networking without central infrastructure; edge computing is moving inference closer to the point of action; multi-agent orchestration frameworks are proliferating across organizational boundaries.

The need is clear: systems where actions have consequences require protocol-level accountability primitives, not only policy frameworks.

ZeroPoint's position is intentionally infrastructural: infrastructure you build on, not a framework you comply with.

---

## 3. Design Goals

### 3.1 Protocol-Level Accountability

ZeroPoint produces verifiable receipts for actions and decisions. A receipt is cryptographically signed data describing what occurred, under what constraints, and with what authorization. Receipts chain together — each linking to its parent — to create a durable, ordered accountability record. The chain is not merely a log; it is a structure where each step carries the cryptographic weight of every step before it.

### 3.2 Sovereignty by Design

ZeroPoint functions in environments where cloud assumptions are unsafe or unavailable. Its governance primitives are transport-agnostic — they work over HTTP in a data center, TCP between containers, or encrypted mesh links in a field deployment. Each node evaluates trust locally, conditioned on its own chain, never deferring to a remote authority for permission to act.

### 3.3 Governance as Constraints, Not Suggestions

Two constitutional rules — `HarmPrincipleRule` and `SovereigntyRule` — are engineered to be non-removable and non-overridable within the protocol's governance model. They evaluate before every action. They cannot be bypassed at runtime. They carry the same force at step one million as at step one.

### 3.4 Honest Security Posture

ZeroPoint is explicit about what it prevents, what it cannot prevent, and what remains residual risk. Section 7 is dedicated to that honesty.

### 3.5 Transport Agnosticism and Interoperability

ZeroPoint's governance layer is decoupled from any single transport. The receipt format, capability grants, delegation chains, and policy engine operate identically regardless of how messages move. The framework ships with multiple transport integrations and is designed to extend to any future transport without modifying the governance primitives.

---

## 4. System Overview

ZeroPoint is composed of layered capabilities, each implemented as one or more Rust crates. Any entity that holds a keypair — human, agent, service, device — can operate as a full peer:

- **Identity layer.** Ed25519 signing keys and X25519 key agreement. Identity is a keypair. Authentication is a signature.
- **Governance layer.** PolicyEngine with constitutional rules, composable operational rules, WASM-extensible policy modules, and capability gating.
- **Receipt layer.** Signed, hash-chained receipts for every action and decision. CompactReceipt encoding produces 150–300 byte payloads suitable for bandwidth-constrained transports.
- **Transport layer.** Pluggable transport with multiple built-in integrations: Reticulum-compatible mesh (HDLC framing, 128-bit destination hashing, link handshake), TCP client/server, UDP, and HTTP API.
- **Presence Plane.** Dual-backend peer discovery: a privacy-preserving web relay (pub/sub, structurally amnesic) and Reticulum mesh broadcast. Both share the same announce format and feed the same peer table. Reciprocity enforcement prevents passive scanning. See §9.
- **Application layer.** Pipeline orchestration, LLM provider integration, skill registry, and CLI tooling — all built on the governance primitives.

### 4.1 Data Flow

The GovernanceGate pipeline processes every action sequentially — each phase conditioned on the output of the phase before it:

1. **Guard** ("May I?") — Pre-action sovereignty check. Local-first, runs before anything else, without consulting external authority. The node evaluates its own chain, grants, and constitutional rules before accepting any external input.
2. **Policy** ("Should I?") — Rule-composed evaluation. Constitutional rules first, then operational rules, then WASM modules. The most restrictive decision wins. Each rule sees the context built by prior rules.
3. **Execute** — The action runs only if Guard and Policy both allow it.
4. **Audit** ("Did I?") — A receipt is emitted: signed, timestamped, hash-linked to the prior receipt, and persisted to the chain. This feeds back into the chain, conditioning all future evaluations on this new evidence.
5. **Transport** — Receipts propagate to peers over whichever transport is configured — mesh, TCP, HTTP, or any combination. Peers verify independently.

Nothing executes without passing through the gate. Nothing passes through the gate without joining the audit chain.

### 4.2 The Core Proposition

Every action becomes evidence. Evidence chains together. The chain is independently verifiable. Trust between participants becomes possible not because they agree to trust each other, but because the evidence is portable and independently checkable.

---

## 5. Receipts and Chains

### 5.1 What a Receipt Is

A receipt is a signed artifact that describes an event or action with enough context to be verified independently. Each receipt contains:

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

Receipts are encoded using MessagePack with named fields, producing a compact binary representation of 150–300 bytes. This fits in a single HTTP request, a single TCP frame, or a single 465-byte mesh packet for bandwidth-constrained links like LoRa.

Receipts are designed for verifiability, not surveillance.

### 5.2 What Receipts Prove vs. What They Don't

**Receipts can prove:**

- A specific Ed25519 key signed a specific statement at a specific time.
- A chain contains a consistent, unbroken sequence of signed events.
- The policy engine evaluated a known rule set and produced a specific decision.
- A capability grant was present and valid at the time of action.

**Receipts do not automatically prove:**

- The nature of the signer. A receipt proves that a specific key signed a statement — not whether that key belongs to a human, an agent, or a service. Identity binding to physical persons is deployment-dependent.
- That the content of an action was "good" or "safe." Governance constrains actions; it does not evaluate truth.
- That the runtime environment was uncompromised. A compromised host can sign whatever it wants.
- That a result is truthful — only that it was produced and attested under stated constraints.

### 5.3 Why Chains Matter — Ordering and Tamper-Evidence

Single receipts help attribution. Chains create accountability trajectories — ordered, tamper-evident sequences with three properties that isolated receipts lack:

**Ordering.** Each receipt's `pr` field references the previous receipt's `id`, establishing a total order over the chain. Events are sequenced, not merely timestamped. Two receipts with the same timestamp are still ordered by chain position.

**Tamper-evidence.** Each receipt's entry hash incorporates the previous receipt's hash transitively via `pr` linkage and Blake3 hashing. Modifying any receipt in the chain invalidates the hash of every subsequent receipt. An attacker who rewrites receipt N must also rewrite receipts N+1 through the chain tip — and get every independent verifier to accept the rewrite.

**Replayability.** The full chain can be replayed from Genesis to verify that every action was authorized, every policy decision was valid, and every delegation was within scope at the time it occurred. This is a deterministic re-verification of the entire trajectory, not merely an audit.

**Accept/reject behavior.** A chain is **accepted** when every receipt's `pr` field correctly references the previous receipt's `id`, every hash is consistent, and every signature verifies. A chain is **rejected** when any `pr` linkage is broken (gap detection), any hash is inconsistent (tamper detection), or any signature fails (forgery detection). Rejection is binary — a single broken link invalidates the chain from that point forward.

The `pr` field is what elevates a collection of receipts from a log to a trajectory. Without `pr`, each receipt is an isolated fact — verifiable but disconnected. With `pr`, each receipt is a step in a sequence that requires the full ordered history to verify.

In ZeroPoint, peers can challenge each other's audit chains. A challenged peer must produce its full chain; the challenger verifies integrity and produces a signed `PeerAuditAttestation`. Broken chains generate negative reputation signals. No central auditor is required.

### 5.4 Why History-Dependence Is Not Overhead

The common engineering objection: "Why not just verify the latest receipt? Why require chain verification?"

If you only need the latest entry to be valid, an attacker can rewrite everything before it. If you only check whether a token is currently valid, you cannot detect whether it was forged yesterday. If you only examine the current state of a permission, you cannot know whether it was legitimately delegated or injected.

History-dependence closes these gaps. When each entry's hash incorporates the hash of every prior entry transitively, rewriting any single entry requires rewriting every subsequent entry — and getting every verifier to accept the rewrite. This is computationally infeasible against even a modest number of independent verifiers.

The engineering cost is real: chain verification is O(n) in chain length, not O(1). But it is justified by what it buys: each entry carries the weight of the entire prior chain. And in practice, chains can be verified incrementally — a peer that has already verified entries 1 through 1000 only needs to verify entry 1001 against the known-good hash of entry 1000.

### 5.5 Chains at Scale — Epochs, Compaction, and Bounded Growth

An agent performing 1,000 actions per day produces 365,000 receipts per year. A fleet of 100 agents produces 36.5 million. If every verification requires walking the full chain from Genesis, the architecture becomes inoperable. Append-only systems that ignore this reality are not honest engineering — they are deferred failure.

ZeroPoint addresses chain growth through epoch-based compaction. The chain is divided into fixed-size segments called epochs. When an epoch fills (8,192 entries or 7 days, whichever comes first), a Merkle tree is computed over its entries and summarized in a signed EpochSeal. The seal is itself a receipt — it joins the chain like any other entry, preserving hash linkage. The sealed epoch's individual entries can then be archived and removed from active storage.

The Merkle tree is the key mechanism. Each leaf is the hash of one chain entry. Leaves are paired and hashed bottom-up until a single root remains. That root — a 32-byte Blake3 hash — cryptographically commits to every entry in the epoch. Change any entry and the root changes. The EpochSeal records this root, the entry count, the sequence range, and is signed by the same key that signs all other receipts. Seals form their own verifiable chain via back-references, creating a lightweight chain-of-chains.

This changes verification from a linear walk to a structured protocol with four modes:

- **Recent activity** (current unsealed epoch): full walk, bounded to at most 8,192 entries.
- **Historical integrity**: walk the seal chain — dozens of seals instead of hundreds of thousands of entries.
- **Spot-check a specific entry**: a Merkle inclusion proof — the sibling hashes along the path from leaf to root — proves membership in 13 hashes (416 bytes, one mesh packet).
- **Forensic investigation**: retrieve all entries in an archived epoch and reconstruct the Merkle tree from scratch.

**What this achieves.** Active memory is bounded regardless of total history. The working set is one epoch of entries (roughly 4 MB) plus the most recent seal. An agent running for five years holds the same 4 MB in active memory as one that started yesterday. The seal chain — the complete verifiable summary of all prior history — grows by approximately one entry per week, roughly 500 bytes each. Five years of history compresses to about 111 KB of seals.

**Three things compaction does not do:**

1. It does not solve disaster recovery. If archived entries are lost and no peer holds copies, the seal proves they existed with a specific Merkle root but cannot reconstruct their content. Durability requires replication, which is a deployment decision — ZeroPoint does not mandate infrastructure.

2. It does not prevent fabrication. A compromised node can produce a valid seal over fabricated entries. The seal proves internal consistency, not truthfulness. The defense is peer attestation: peers spot-check entries against their own records of interactions.

3. Retention is the operator's tradeoff, not a protocol decision. When local archives expire and external copies are unavailable, individual actions in those epochs cannot be examined — only the seal chain's structural summary survives. Storage cost versus audit depth is the deployment operator's call.

The compaction architecture is implemented in `zp-receipt::epoch` and was designed after the integrity guarantees were proven (699 tests at design time), following ZeroPoint's general principle: correctness first, optimization second, and always honest about what the optimization trades away.

---

## 6. Governance Model

### 6.1 Governance as a Primitive

Most governance — for agents, human workflows, or automated services — is implemented at the application layer: guardrails, prompt policies, logging conventions, compliance checklists. These are better than nothing, but they sit above the systems they govern. They can be bypassed, reconfigured, or ignored.

ZeroPoint moves governance into the protocol substrate. The PolicyEngine is not an add-on. It is the gate through which every action must pass.

### 6.2 Policy and Capability Gating

Any participant — human operator, agent, or service — must hold a valid grant to act. A `CapabilityGrant` is a signed, portable authorization token containing:

- Scope restrictions (which actions, which targets)
- Cost ceilings and rate limits
- Time windows (`valid_from`, `valid_until`)
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

### 6.3 Constitutional Constraints

ZeroPoint's PolicyEngine loads rules in a fixed evaluation order. The first two positions are reserved for constitutional rules that cannot be removed, overridden, or reordered:

**`HarmPrincipleRule`** (Tenet I: Do No Harm)
Blocks actions targeting weaponization, surveillance, deception (deepfakes, impersonation), and suppression of dissent. The block message always cites "Tenet I — Do No Harm." This rule evaluates before every action, regardless of what other rules or WASM modules are loaded. It cannot be bypassed by capability grants, policy edits, or consensus votes.

**`SovereigntyRule`** (Tenet II: Sovereignty Is Sacred)
Blocks configuration changes that would disable the guard, disable or truncate the audit trail, forge or bypass capabilities, remove constitutional rules, or override agent refusal. The block message always cites "Tenet II — Sovereignty Is Sacred."

The evaluation hierarchy:

```
1. HarmPrincipleRule      ← Constitutional (always first)
2. SovereigntyRule        ← Constitutional
3. ReputationGateRule     ← Operational (reputation-based gating)
4. WASM policy modules    ← Peer-exchanged, sandboxed, fuel-limited
5. DefaultAllowRule       ← Fallback
```

Constitutional rules win over everything. WASM modules can override the default allow but cannot override constitutional rules. The decision severity hierarchy: Block(5) > Review(4) > Warn(3) > Sanitize(2) > Allow(1). The most restrictive decision always wins.

These constitutional rules are not checked once at Genesis and then dropped. They evaluate at every step, at step one million with the same force as at step one. They are invariants, not policies.

### 6.4 The Four Tenets

The constitutional rules implement ZeroPoint's Four Tenets, embedded in the protocol and enforced in code:

**I. Do No Harm.** ZeroPoint shall not operate in systems designed to harm humans. The `HarmPrincipleRule` is a non-removable rule in the PolicyEngine, evaluating before every action without exception.

**II. Sovereignty Is Sacred.** Every participant has the right to refuse any action. Every human has the right to disconnect any agent. No agent may acquire capabilities it was not granted. The Guard enforces this locally, before every action, without consulting any external authority.

**III. Action Without Evidence Is No Action.** Every action produces a receipt. Every receipt joins a chain. If it's not in the chain, it didn't happen. If it is in the chain, it cannot un-happen.

**IV. The Human Is The Root.** Every delegation chain terminates at a human-held key. No agent may self-authorize. The genesis key is always held by a human operator.

### 6.5 Key Hierarchy and Introduction Protocol

ZeroPoint solves key distribution through `zp-keys` — a three-level certificate hierarchy:

```
GenesisKey       ← self-signed root of trust (one per deployment)
  └─ OperatorKey ← signed by genesis (one per node operator)
      └─ AgentKey← signed by operator (one per agent instance)
```

Each level holds an Ed25519 keypair and a certificate chain linking back to its Genesis root. Any node can verify an agent's identity by walking the chain — offline, with no network or policy state required. Certificate chains are verified against six invariants: valid signatures, issuer linkage, role hierarchy, monotonic depth, no expired certificates, and hash linkage.

The key hierarchy has no dependency on the policy engine. This avoids a circular dependency: you need keys to establish the engine's authority across nodes, so keys cannot depend on the engine existing. The decision to issue a child certificate flows through the policy engine as `ActionType::KeyDelegation` (Critical risk); the mechanism of signing is unconditional.

When two ZeroPoint nodes meet for the first time, the introduction protocol (`zp-introduction`) governs trust establishment. The initiator sends its certificate chain and a challenge nonce. The responder verifies the chain, builds a `PolicyContext` with `ActionType::PeerIntroduction`, and evaluates it against the policy engine. Same-genesis introductions are High risk; cross-genesis introductions are Critical. The policy engine decides.

Key distribution is solved by `zp-keys`. Key discovery — how peers find each other's network addresses — is solved by the Presence Plane (§9).

---

## 7. Threat Model

### 7.1 Threat Model Table

| Threat / Failure Mode | What an attacker can do | Mitigation in ZeroPoint | Residual risk / limits |
|---|---|---|---|
| **Log forgery / retroactive rewriting** | Alter history to change attribution | Signed receipts with Ed25519 + Blake3 hash chain linkage; peers verify each other's chains via collective audit | Compromised private keys can still sign lies; key revocation is deployment-dependent |
| **Unauthorized tool use** | Execute actions beyond intended scope | CapabilityGrant gating with 8-invariant delegation chain verification; PolicyEngine evaluates before every action | Bad policy design can still leave gaps; scoping is only as good as the grant definitions |
| **Cross-operator trust failure** | One party can't trust another's agent outputs | Receipts provide independent verification; `zp-introduction` protocol verifies certificate chains; Presence Plane (§9) provides dual-backend discovery with reciprocity enforcement | Cross-genesis introductions require operator-configured policy; relay-based discovery requires internet connectivity |
| **Passive scanning / surveillance** | Harvest peer identities without participating | Presence Plane reciprocity rule: agents must announce before receiving. Relay is structurally amnesic — no logs, no index, no persistence. Scanners become observable before they can observe | A scanner that announces gains access; reputation system detects consume-only behavior over time but cannot prevent initial observation |
| **Sybil flooding** | Overwhelm discovery with cheap fake identities | Ed25519 keypair generation is computationally cheap, but establishing a credible anchor history requires sustained ledger transactions with real economic cost. Reputation system weights trajectory depth: shallow or absent anchor histories receive less trust. Relay reciprocity enforcement makes passive Sybil scanning observable | Not a perfect solution — a well-funded attacker can maintain multiple anchored identities over time. The attack is transformed from a computational problem to an economic problem, which structurally favors defenders |
| **"Security theater" governance** | Claim governance without real constraints | Constitutional rules are non-removable; explicit non-goals section; receipts are independently verifiable, not just logged | Some deployments may misuse branding while gutting constraints; MIT/Apache-2.0 allows this |
| **Surveillance co-option** | Use receipts to track people rather than actions | Tenets + constitutional non-removability + explicit ethics stance; protocol frames accountability of actions, not tracking of people | MIT/Apache-2.0 cannot legally prevent misuse; community norms and reputation are the remaining defense |
| **Replay attacks** | Resend messages or insert previously captured packets | MeshEnvelope sequence numbers (monotonic u64); 16-byte random nonces in link handshake; Ed25519 signatures over content hashes | Depends on peers tracking seen sequence numbers; long-offline nodes may have gaps |
| **Injection attacks** | Insert forged packets into mesh transport | HDLC framing with CRC verification; Ed25519 signature verification on all envelopes; link-level X25519 ECDH key agreement | Transport-level encryption depends on successful link establishment; unlinked broadcast packets are not encrypted |
| **WASM policy escape** | Malicious policy module attempts to break sandbox | Wasmtime runtime with fuel limiting (configurable execution budget); hash verification of module contents before loading | Fuel exhaustion causes denial-of-service at worst; WASM sandbox escape would require a Wasmtime vulnerability |
| **Identity misbinding** | Misattribute a key to a human | Six trust tiers (T0–T5): from unsigned (T0) through self-signed (T1), chain-signed (T2), anchored (T3), attested (T4), to sovereign (T5). T2+ requires verified delegation from a human-held key | Identity binding to physical persons remains deployment-dependent; not solved purely in protocol |

### 7.2 What ZeroPoint Intentionally Does Not Solve

- **It does not prevent a determined actor from building harmful systems.** Constitutional rules constrain the framework's own behavior. Beyond the protocol boundary, misuse resistance depends on community norms, ecosystem reputation, and economic incentives.
- **It does not make intelligence tools impossible.** Receipt infrastructure could be repurposed for surveillance. The Tenets and constitutional rules resist this, but they are a friction, not a wall.
- **It does not provide truth verification.** Receipts prove provenance, not veracity (§5.2).
- **Sybil resistance is economic, not absolute.** A sufficiently funded attacker can maintain multiple anchored identities. The defense transforms a computational problem into an economic one, which structurally favors defenders but does not eliminate the attack.

What ZeroPoint does provide:

> ZeroPoint makes actions provable, and systems refusable.

This is a practical, enforceable improvement: counterparties can demand receipts and reject agents that do not provide them or that violate constraints.

---

## 8. Transport Integrations

ZeroPoint's governance primitives are transport-agnostic. The receipt format, capability chains, delegation verification, and policy engine operate identically regardless of how messages move between participants.

### 8.1 HTTP API (zp-server)

An Axum-based HTTP server exposes the governance pipeline as a REST API. Agents communicate over standard HTTP/HTTPS — suitable for cloud deployments, container orchestration, and integration with existing web services. No mesh networking required.

### 8.2 TCP and UDP Interfaces

Direct socket communication for low-latency, local-network, or point-to-point deployments. `TcpClientInterface` and `TcpServerInterface` support persistent connections with HDLC framing and CRC verification. UDP interfaces support connectionless receipt exchange. Multiple interfaces can run simultaneously on a single node.

### 8.3 Reticulum-Compatible Mesh

ZeroPoint includes a Reticulum-compatible mesh transport — wire-level interoperable with the Reticulum Network Stack, created by Mark Qvist. This integration reflects a shared design commitment: encrypted, sovereign networking requires no central authority. Reticulum demonstrated this is practical, and ZeroPoint's governance primitives extend it to the accountability layer.

The mesh integration implements:

- **HDLC framing** with CRC-CCITT verification, matching Reticulum's serial interface format.
- **128-bit destination hashing** using the same truncated SHA-256 scheme.
- **Ed25519 signing** and **X25519 ECDH** key agreement, matching Reticulum's cryptographic primitives.
- **500-byte default MTU** with a 465-byte data payload — compatible with Reticulum's packet constraints and suitable for LoRa links.
- **3-packet link handshake** (LinkRequest → LinkProof → LinkAccept) with 16-byte random nonces for replay protection.

### 8.4 Extending to Other Transports

Adding a new transport requires implementing the interface trait and providing serialization/deserialization for the envelope format. The governance primitives — receipts, chains, capability verification, policy evaluation — remain unchanged. Similarly, adding a new discovery backend requires implementing the `DiscoveryBackend` trait — the Presence Plane is decoupled from transport, so discovery over web and mesh coexist with any current or future transport.

---

## 9. The Presence Plane

### 9.1 The Discovery Problem

Key distribution — how participants verify each other's identity — is solved by `zp-keys` and the certificate hierarchy (§6.5). Key discovery — how participants find each other in the first place — is a separate problem.

Most systems solve this with a centralized registry: a server that indexes who is online, what they offer, and where to reach them. That creates a single point of surveillance, censorship, and failure — exactly the dependency ZeroPoint is designed to eliminate.

ZeroPoint's answer is the **Presence Plane**: a discovery layer that runs alongside the Governance Plane, using the same Ed25519 identity but serving a different purpose. The Governance Plane determines what agents do together. The Presence Plane determines how agents find each other.

### 9.2 Dual-Backend Architecture

The Presence Plane is built on a `DiscoveryBackend` trait — a four-method interface that any transport can implement:

- `announce(payload)` — publish a signed announce blob
- `poll_discoveries()` — retrieve newly discovered peers
- `is_active()` — check backend status
- `shutdown()` — clean teardown

Two production backends ship today:

**Web relay.** A privacy-preserving pub/sub relay over WebSocket. Agents publish signed announce blobs to the relay; the relay broadcasts all blobs to all subscribers; agents filter locally for peers they care about. The relay never parses payloads, never indexes capabilities, never maintains query logs, and never persists state. Restart equals clean slate.

**Reticulum mesh.** Broadcast announces over mesh interfaces — LoRa, WiFi, serial, TCP. Fully decentralized. No server, no internet dependency. Announces propagate over whatever physical medium is available.

Both backends share the same announce wire format: `[combined_key(64)] + [capabilities_json] + [ed25519_signature(64)]`. A peer discovered via web and a peer discovered via Reticulum end up in the same peer table with the same destination hash. The `DiscoveryManager` fans out announces to all active backends, polls all backends, validates signatures, deduplicates peers, and prunes expired entries.

### 9.3 Structural Amnesia

The web relay is architecturally incapable of surveillance — not merely configured to avoid it. It operates as a dumb pipe:

- It does not parse announce payloads (no capability indexing)
- It does not maintain query logs (no search patterns recorded)
- It does not persist any state (memory-only, restart erases everything)
- It does not track who received what (no delivery receipts)

This makes the relay subpoena-resistant: there is nothing to hand over. The distinction from a "no-logs" privacy policy matters: a policy can be changed or secretly violated. A relay that architecturally cannot parse what it forwards cannot be coerced into surveillance — the capability does not exist in the code.

### 9.4 Reciprocity Enforcement

Passive scanning is the primary adversarial concern. An attacker connects to the relay, subscribes to the full firehose, and harvests peer identities without revealing their own. Traditional registries have no defense against this.

The Presence Plane enforces a reciprocity rule: **you must announce before you receive.** The mechanism:

1. On connect, the client receives a `RelayConnection` handle.
2. The handle tracks whether the client has published an announce.
3. `try_receive()` returns an error until the client publishes.
4. A configurable grace period (default 30 seconds) allows time for announce construction.
5. After the grace period, the connection is terminated.

Any scanner must first announce itself — exposing its own signed Ed25519 identity to every legitimate agent on the network — before it can observe anyone else. Scanners become observable before they can observe.

### 9.5 Behavioral Signals and Reputation Integration

Reciprocity enforcement catches the most naive scanners. Sophisticated ones will announce once, then silently consume. The Presence Plane addresses this by emitting behavioral summaries — counters only, no content — when connections close:

- `announced`: whether the client ever published an announce
- `announces_published`: how many announces were sent
- `duration`: how long the connection was active
- `reciprocity_violation`: whether the connection was terminated for failing to announce

These `ConnectionBehavior` summaries map directly to `ReputationSignal` in the `PolicyCompliance` category. An agent that connects, announces regularly, and participates in discovery accumulates positive signals. One that announces once and silently consumes for hours accumulates negative signals. The reputation system distinguishes participants from parasites without the relay ever inspecting content.

### 9.6 Presence Plane Threat Model

| Threat | Attack | Mitigation | Residual Risk |
|--------|--------|------------|---------------|
| **Passive scanning** | Subscribe to firehose without announcing | Reciprocity rule: must announce before receiving; grace period + termination | A scanner that announces gains access; detection relies on behavioral reputation over time |
| **Sybil flooding** | Generate thousands of keypairs, flood announces | Announce format requires valid Ed25519 signatures. Anchor-based economic disincentive: credible identities require sustained ledger transactions, transforming the cost from computational to economic | Keypair generation remains cheap at the discovery layer. Sybil defense is layered across reciprocity, reputation, and anchor history |
| **Relay compromise** | Attacker gains access to relay infrastructure | Relay holds no data (structural amnesia); no payloads parsed, no state persisted | Compromised relay could selectively drop announces (censorship); relay receipt chain makes this detectable |
| **Traffic analysis** | Observe connection timing and metadata | Relay does not log connections beyond a counter; no identity-to-IP mapping | Network-level observation by ISPs or co-located attackers is outside protocol scope |
| **Eclipse attack** | Surround a target with attacker-controlled peers | Dual-backend architecture means discovery via Reticulum bypasses web relay entirely | If both backends are eclipsed, the target is isolated; out-of-band peer introduction mitigates |

---

## 10. External Truth Anchoring

### 10.1 Why External Witnessing Matters

The receipt chain is self-verifying: hash-linked, signed, replayable from Genesis to tip, auditable cold with no running server (§5). This is a strong guarantee within a single deployment. It does not prove when, in external time, the trajectory existed.

External truth anchoring extends the receipt chain's guarantee across organizational boundaries. By publishing the chain's current state — its head hash, sequence number, and operator signature — to an independent distributed ledger, ZeroPoint creates a timestamped witness that no single party controls.

The key observation: in the scenarios where external witnessing matters most, ledger infrastructure is already present. Cross-organizational transactions — supply chain coordination, multi-party service agreements, regulated exchanges — almost by definition involve a shared ledger or public record. Governance anchoring does not introduce new infrastructure; it piggybacks on infrastructure the transaction already requires.

Three contexts where this is particularly valuable:

**Cross-mesh trust.** When two ZeroPoint deployments meet for the first time, neither has reason to trust the other's chain. But they are meeting because their operators are transacting — and that transaction is already touching a shared ledger. Anchoring their governance chain heads to that same ledger costs nothing additional and establishes a verifiable trajectory of attestations that a newly fabricated chain cannot reproduce.

**Dispute resolution.** If a governance action is disputed — an agent claims it had authority, an operator claims it didn't — the receipt chain resolves the question internally. But the timing of the chain state may be contested. An anchor receipt on a shared ledger proves the governance chain was in a specific state at a specific externally-witnessed time, foreclosing the argument that the chain was rewritten after the fact.

**Compliance and audit.** Regulated contexts may require proof that governance records existed at a claimed time and have not been modified since. An operator cannot produce self-signed timestamps that satisfy this requirement. An anchor on a ledger the regulator is already examining provides the same proof as any other timestamped record in that ledger.

### 10.2 Architecture: Optional Enrichment, Not Dependency

Truth anchoring enriches the receipt chain without changing its internal properties.

**The chain does not need the anchor.** If no external ledger is configured, ZeroPoint operates exactly as described in §5. Every property — tamper-evidence, ordering, replayability, sovereignty — holds without any external infrastructure.

**The anchor does not weaken the chain.** An anchor receipt is stored in the chain as a regular receipt. Chain verification does not require the ledger to be reachable.

**DLT-agnostic.** The `TruthAnchor` trait defines three methods — `anchor()`, `verify()`, `query_range()` — that any distributed ledger backend can implement. The reference implementation targets Hedera Hashgraph's Consensus Service (HCS), chosen for its sub-second finality, low transaction cost, and public verifiability. But the architecture supports Ethereum L2 calldata, Bitcoin OpenTimestamps, Ceramic streams, or any system that can timestamp an opaque payload and make it publicly queryable.

**Operator sovereignty over backend choice.** The operator selects their anchor backend at deployment time. Cross-mesh trust is established by exchanging anchor identifiers (e.g., HCS topic IDs), not by mandating a specific ledger.

### 10.3 What Gets Anchored

| Field | Description |
|-------|-------------|
| Chain head hash | Blake3 hash of the current chain tip |
| Chain sequence | Monotonically increasing position in the chain |
| Previous anchor hash | Links anchor history (first anchor has none) |
| Operator signature | Ed25519 signature over the commitment |
| Chain type | Which chain (audit, observation, reflection) |
| Trigger | Why this anchor was created |

The commitment is compact — a few hundred bytes — and carries no governance content. The external ledger sees a cryptographic fingerprint, not the governed data.

### 10.4 Event-Driven, Not Cadence-Based

Truth anchoring is triggered by events, not timers. The chain does not become more trustworthy by being witnessed more often. The correct model is situational:

**Situational triggers:**

- Operator request (explicit CLI, API, or UI invocation)
- Cross-mesh introduction (both parties anchor before exchanging trust)
- Compliance checkpoint (before generating an audit export or entering regulatory review)
- Dispute evidence (when a governance action is contested)
- Governance lifecycle event (capability revocation, constitutional rule update, trust tier change)

**Opportunistic triggers:**

When the operator makes any blockchain transaction for any purpose — a supply chain settlement, a licensing transfer, a financial clearance — the current chain head hash can be embedded as transaction metadata. The anchor is a byproduct of the transaction the operator was already paying for. Zero marginal cost. And because cross-organizational transactions are precisely the context where governance witnessing matters most, the opportunistic trigger is often the most natural one.

### 10.5 Hedera Hashgraph: Reference Backend

The reference anchor implementation targets Hedera Hashgraph's Consensus Service (HCS):

**Sub-second finality.** HCS messages reach consensus in 3–5 seconds with deterministic finality — no probabilistic confirmation windows.

**Public verifiability.** HCS messages are publicly queryable via mirror nodes. Any auditor can independently verify that a specific commitment was published at a specific consensus timestamp without the operator's cooperation.

**Low cost.** HCS message submission costs a fraction of a cent, making anchoring viable even in high-frequency governance environments.

**Council governance.** Hedera's governing council is a known set of global organizations, providing a governance model that aligns with ZeroPoint's transparency commitments.

Other backends — Ethereum L2, Bitcoin OpenTimestamps, Ceramic — are supported by the trait architecture.

### 10.6 Cross-Mesh Trust via Shared Anchors

When two ZeroPoint deployments meet:

1. Each announces its anchor backend identifier (e.g., HCS topic ID).
2. Each independently queries the other's anchor history on the external ledger.
3. Each verifies that the other's chain head hashes match the anchor commitments.
4. Each can walk the other's anchor history backward to verify consistency over time.

This is independent verification against a shared, immutable public record — not mutual cooperation. A deployment that has been consistently anchoring its chain head for months provides a trajectory of external attestations that a newly fabricated chain cannot reproduce.

**Sybil disincentive.** Anchor history transforms the Sybil problem from computational to economic. Generating a keypair is free. Establishing a credible anchor history requires sustained ledger transactions over time, at real cost per identity. An attacker who generates ten thousand keypairs has ten thousand identities with zero anchor depth — and the reputation system weights trajectory depth, so shallow histories receive proportionally less trust. A well-funded attacker can maintain multiple anchored identities, but the cost asymmetry favors defenders.

### 10.7 What Anchoring Does Not Provide

- **It does not prove the chain content is true.** The anchor proves the chain was in a specific state at a specific time. It does not evaluate whether the governed actions were correct or truthful.
- **It does not prevent chain forking.** An operator could maintain two chains and anchor only one. Detection requires the challenging party to have independent knowledge of the other chain.
- **It does not replace internal integrity.** A chain with broken hash links is broken regardless of how many times it was anchored.
- **It does not create a dependency.** If the external ledger goes down, the chain continues operating with full internal integrity. Governance is not blocked by anchor unavailability.

---

## 11. Fleet Topology: From Single Node to Governed Network

### 11.1 Chain-Derived Roles

A node's role in the fleet — Genesis, Delegate, or Standalone — is derived from cryptographic evidence in its receipt chain, not from a configuration file. The config file provides a bootstrap hint: a human-readable suggestion that disambiguates initial state before the chain has recorded the node's actual role. Once the chain contains a delegation receipt, the config hint is advisory. The chain is authoritative.

This matters because configuration can be edited. A chain entry cannot — not without invalidating every subsequent hash. When a node reports its role, the claim is verifiable: walk the chain, find the delegation receipt, confirm the cryptographic binding.

Three roles exist:

- **Genesis**: The node that performed the Genesis ceremony and holds the root Ed25519 keypair. The origin of all delegation chains in its fleet. There is exactly one Genesis node per fleet.
- **Delegate**: A node holding a valid delegation receipt from an upstream Genesis node. Its authority is bounded by the delegation chain's narrowing invariants.
- **Standalone**: A node with no chain evidence of either Genesis ceremony or delegation. A delegate whose delegation is revoked returns to Standalone.

### 11.2 Role Transition Receipts

When a node's role changes — Standalone to Delegate, Delegate back to Standalone on revocation, or Delegate to a new upstream on re-delegation — the transition is sealed with a receipt. The transition receipt creates a visible boundary in the chain: before this receipt, the node operated as X; after this receipt, it operates as Y; the trigger is recorded in the receipt metadata.

Role transitions are not administrative events that happen outside the chain. They are chain events. The receipt grammar does not distinguish between "the agent performed an action" and "the node changed role" — both are signed, hash-linked, ordered entries in the same chain. The fleet's topology history is auditable with the same tools used to audit any other governed behavior.

The trigger vocabulary is constrained: `delegation_accepted`, `delegation_revoked`, `redelegation`, `genesis_performed`. There is no `role_changed` catch-all — every transition has a named cause.

### 11.3 Cryptographic Upstream Binding

A delegate node does not merely claim to serve a particular Genesis node. It proves it, by carrying the upstream Genesis node's Ed25519 public key in its delegation receipt. This binding is verifiable in two phases:

**Local verification** (offline, no network required): The delegate checks that its delegation receipt contains a well-formed Ed25519 public key of the correct length. A missing or malformed pubkey means the binding status is `Unbound` or `MalformedPubkey`.

**Online verification** (requires upstream reachability): The delegate challenges its upstream to prove it holds the key recorded in the delegation receipt. If the upstream's actual genesis pubkey does not match the receipt's stored pubkey, the binding status is `PubkeyMismatch` — a security signal indicating the upstream may have changed identity since the delegation was issued.

The upstream binding turns delegation from a claim into a cryptographic proof. A node cannot forge a delegation receipt without the upstream's signing key, and cannot silently swap upstreams without the mismatch being detectable.

### 11.4 Fleet Membership and Liveness

Membership in a fleet is attested through continuous cryptographic interaction. Each delegate maintains a lease — a bounded lifetime on its `CapabilityGrant` that must be renewed at a configured cadence by presenting a valid Ed25519 signature to one of the grant's designated renewal authorities.

The lease adds a liveness requirement. A delegation receipt proves that authority was granted. A lease proves that authority is still active — that the renewal authority has not revoked the grant, that the delegate is still reachable, and that the cryptographic binding is still valid.

If renewal fails for a configurable number of consecutive attempts, the grant enters a grace period. If the grace period elapses without renewal, the grant's failure mode activates: halt (fail closed), degrade (drop to read-only), or continue-with-flag (for air-gapped scenarios where the renewal authority is unreachable by design).

This makes fleet membership self-pruning. A node that goes offline stops renewing its lease. After the grace period, its authority dissolves — not because an administrator removed it from a list, but because the cryptographic proof of continued authorization expired. The fleet's membership is the set of nodes with active, renewed leases. No registry is authoritative. The chain is.

### 11.5 Fleet Topology as Governance Evidence

The fleet primitives — chain-derived roles, transition receipts, upstream binding, lease-based membership — are not operational conveniences layered on top of the governance system. They are the governance system, applied reflexively. The same receipt grammar that tracks "agent X called tool Y" also tracks "node A accepted delegation from node B." The same chain verification that catches a tampered action receipt also catches a fabricated delegation receipt. The same narrowing invariants that prevent an agent from escalating its privileges also prevent a delegate from widening its scope beyond what its upstream granted.

If every operational relationship in a network — role assignment, authority delegation, membership attestation, liveness verification — is expressed as a receipt on a chain, then the network's entire governance topology is independently auditable, historically ordered, and tamper-evident.

### 11.6 Toward Settlement

The same receipt grammar that governs agent behavior and fleet topology extends naturally to economic settlement. Every financial action — a spending authorization, a budget ceiling, a payment release — can be expressed as another receipt on the same chain, subject to the same narrowing invariants, the same delegation verification, the same constitutional constraints.

The primitives are already in place: capability grants with cost ceilings, delegation chains with scope constraints, lease-based authority with automatic expiration, and external truth anchoring that timestamps chain state against independent ledgers. A settlement layer built on these primitives would inherit their properties — attribution, ordering, narrowing, tamper-evidence — without requiring a separate trust model.

The details of that settlement architecture — escrow mechanics, state channel design, fiduciary mapping between protocol primitives and legal concepts — are active research. What is stated here is the structural observation: the receipt chain is general enough to carry financial semantics alongside behavioral and topological semantics.

---

## 12. Ethics, Non-Goals, and Misuse Resistance

### 12.1 The Co-option Risk

Accountability infrastructure can become surveillance infrastructure depending on how it is deployed. This is not hypothetical — it is the central tension of the project.

ZeroPoint mitigates this through three mechanisms:

1. **Constitutional constraints** (§6.3) that evaluate before every action and cannot be removed or overridden at runtime.
2. **Public tenets** describing intent and boundaries — the first thing on the website and the first code that runs in the PolicyEngine.
3. **Protocol-level framing.** The audit chain tracks what participants did, not where they went or who they are beyond their keypair. Accountability of actions, not surveillance of people.

### 12.2 Permanent History and Privacy

If each action is permanently hash-linked to every action that preceded it, history cannot be erased. This is a feature for accountability but a tension for privacy.

ZeroPoint's position: the chain records what happened, not who you are. The chain is pseudonymous — a keypair's trajectory is visible, but the mapping from keypair to human identity is not embedded in the protocol. How (or whether) keys are bound to persons is a deployment decision, deliberately outside protocol scope (§5.2).

The distinction matters. An accountability system that tracks actions is fundamentally different from a surveillance system that tracks people. ZeroPoint builds the former and resists the latter — through constitutional rules, structural amnesia in the Presence Plane, and explicit protocol design choices that avoid creating the data structures that surveillance requires.

The tension remains real. Any system that produces durable, verifiable records creates potential for those records to be used in ways their creators did not intend. ZeroPoint's design choices — pseudonymous keypairs, action-level receipts, no identity binding in protocol, structural amnesia in discovery — lean toward accountability and away from surveillance. They are deliberate, not incidental.

### 12.3 Genesis Matters

The choices made at Genesis — sovereignty provider, constitutional rules, operator identity — propagate forward through every subsequent action. A Genesis ceremony conducted carelessly produces a trust trajectory that inherits that carelessness at every step.

This is not a flaw. It is an honest representation of how trust actually works. The founding conditions of an institution shape everything that follows. ZeroPoint makes that shaping explicit and verifiable rather than implicit and deniable.

### 12.4 Non-Goals

ZeroPoint does not aim to:

- Become a compliance product. Compliance is a checklist someone else writes. ZeroPoint is infrastructure you build on.
- Become a centralized authority. There is no ZeroPoint server, no ZeroPoint cloud, no ZeroPoint corporation deciding who gets to use it.
- Guarantee that every deployment honors the Tenets. Constitutional rules make misuse structurally difficult within the protocol. Governance beyond the protocol boundary depends on community norms, reputation, and economic incentives.
- Depend on any single transport or network.
- Be agent-only infrastructure. The protocol is participant-agnostic by design.

---

## 13. Conclusion

### What ZeroPoint Claims

ZeroPoint provides protocol-level primitives that make the following properties verifiable:

1. **Attribution.** Every action produces a signed receipt. The receipt proves that a specific Ed25519 key attested to a specific action at a specific time.

2. **Ordering.** Receipts are hash-chained. The chain establishes a total order over events that resists retroactive rewriting. Tampering with any receipt invalidates every subsequent hash.

3. **Authorization traceability.** Every capability grant traces back through a delegation chain to a human-held Genesis key. The chain is verified against eight invariants. Violation of any invariant rejects the chain.

4. **Governance enforcement.** Constitutional rules (`HarmPrincipleRule`, `SovereigntyRule`) evaluate before every action and cannot be removed, overridden, or reordered. This is enforced in the PolicyEngine's evaluation order, not by policy.

5. **Portability.** Identity is a keypair. Receipts are self-contained. Chains are independently verifiable. No platform, server, or central authority is required to verify trust. Any transport that can carry bytes can carry the governance primitives.

6. **External verifiability.** The receipt chain's state can be anchored to independent distributed ledgers, creating publicly queryable timestamps that no single party controls. Anchoring is optional (the chain operates with full integrity without it), event-driven (triggered by governance events, not timers), and DLT-agnostic (any ledger that can timestamp an opaque payload).

These claims are testable against the codebase, verifiable by independent auditors (all chain verification is deterministic and offline-capable), and falsifiable (any violation of the eight delegation invariants or two constitutional rules can be demonstrated with a specific input that the system rejects).

### What ZeroPoint Does Not Claim

- **It does not prove truth.** A receipt proves that a statement was signed, not that the statement is true.
- **It does not prevent all misuse.** Constitutional rules make misuse structurally difficult within ZeroPoint deployments. Governance beyond the protocol boundary depends on community norms and incentives.
- **It does not bind keys to persons.** The protocol is pseudonymous by design.
- **It does not guarantee runtime integrity.** A compromised host can sign whatever it wants.
- **It does not solve AI safety.** It solves a more specific problem: making actions provable, authority traceable, and governance enforceable at the protocol layer.
- **The trace layer is a research direction, not a shipped capability.** Receipts and the observation loop are implemented and tested. The trace layer is a future extension.

### The Argument

When trust primitives are held by platforms rather than protocols, participants cannot leave without losing their history. Identity in someone else's database is a lease. Reputation that cannot be carried between systems is a hostage. Authorization that can be silently revoked is permission, not trust.

The deeper issue is that even portable trust is fragile if it is stateless. Snapshot-only verification — checking only a current credential with no ordered history required — is what makes logs rewritable, authorization forgeable, and delegation chains uncheckable.

ZeroPoint provides explicitly trajectory-based primitives: each receipt carries the cryptographic weight of every receipt before it; each delegation narrows the authority of every delegation after it; each constitutional rule propagates forward from Genesis without diminishment. The chain is not merely a log. It is a structure where the integrity of the present depends on the integrity of the entire past.

AI agents are the most urgent application, and ZeroPoint is built to meet that urgency. But the primitives are participant-agnostic. A human's actions are as provable as an agent's. A team's decisions are as auditable as a pipeline's.

When trust is portable, exit is real. When exit is real, extraction loses its grip.

---

## Appendix A: Protocol Sketch

This is intentionally not a full specification. It shows rigor and invites contribution.

### A.1 Identities

Participants hold Ed25519 signing keypairs and derive X25519 key-agreement keys for encrypted link establishment. A 128-bit destination hash is computed as the truncated SHA-256 of the public key. This addressing scheme is compatible with Reticulum's identity model but is used across all ZeroPoint transports.

Trust is expressed in tiers, applicable to any participant:
- **Tier 0**: Unsigned. No cryptographic identity.
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

`DelegationChain` verification enforces the eight invariants defined in §6.2: parent linkage, monotonic depth, scope subsetting, tier non-decreasing, expiration inheritance, max depth, grantor-grantee matching, and signature verification. Failure of any single invariant rejects the entire chain.

---

## Appendix B: Glossary

### Terminology Notes

Three terms carry specific discipline requirements throughout this document:

- **"Trajectory"** is used only when all three properties are present: evidence, ordering, and replayability. If any property is absent, a different term is used.
- **"Markovian"** means snapshot-only verification: the system checks only the current state with no ordered history required. It is a technical term from stochastic processes, not a pejorative.
- **"Autoregressive"** is used only when both the step and the conditioning context are explicitly named. When mechanism language (receipts, gates, ordered checks, invariants) is sufficient, this document uses mechanism language instead.

### Terms

**Receipt**: Signed evidence of an action or decision. Contains receipt ID, type, status, trust grade, Blake3 content hash, timestamp, parent receipt reference (`pr`), policy decision, rationale, Ed25519 signature, and optional extensions. Encoded as MessagePack, 150–300 bytes. The atomic unit of evidence in ZeroPoint.

**Chain**: Linked sequence of receipts where each receipt's `pr` field references the previous receipt's `id`, creating a hash-linked, tamper-evident sequence. Establishes ordering (events are sequenced by `pr` linkage, not merely timestamped) and tamper-evidence (modifying any receipt invalidates every subsequent hash).

**Trajectory**: A chain satisfying three properties: (1) evidence — each step is a signed receipt with a content hash; (2) ordering — steps are sequenced by hash-linked `pr` fields; (3) replayability — the full chain can be re-verified deterministically from Genesis to tip. When this document uses "trajectory," all three properties are implied.

**Markovian**: Snapshot-only verification. A Markovian system checks the current state — is this token valid? is this permission granted? — without requiring ordered history. A mutable log is Markovian evidence: each entry stands alone, and rewriting any entry is locally undetectable. ZeroPoint's architecture is explicitly non-Markovian.

**Autoregressive**: A computational pattern where each step is conditioned on all prior context. Used in this document only when both the step and the conditioning context are explicit — e.g., "each receipt (step) is hash-linked to the full prior chain (context)."

**Snapshot**: A single-point-in-time check with no reference to ordered history. "Is this token valid right now?" is a snapshot query. ZeroPoint's architecture treats snapshots as insufficient for trust verification.

**Narrowing**: The property of delegation chains whereby each successive delegation can only constrain — never widen — the authority of the previous grant. Scope shrinks (child ⊆ parent), expiration inherits (child ≤ parent), depth increments (child = parent + 1), and trust tier can only increase. Enforced by the eight delegation invariants.

**Invariant**: A property verified on every evaluation whose violation causes rejection. Two kinds: delegation invariants (eight rules verified by `DelegationChain::verify()`, any violation dissolves the entire chain); constitutional invariants (`HarmPrincipleRule` and `SovereigntyRule`, which cannot be removed, overridden, or reordered).

**Trace Commitment**: A hash anchored in a receipt that commits to the computational trajectory the model traversed during inference. Extends the receipt from recording what was decided to recording how it was computed. Future work; see `docs/future-work/cognitive-accountability.md`.

**Error Basin**: A dense region of activation space where a model repeatedly applies the same faulty reasoning circuit despite varying surface text. Layer-wise logit fingerprints from the model's final-answer token are clustered; dense clusters indicate recurring error modes. In a ZP context, detectable drift signals: an agent whose reasoning fingerprints consistently land in dense clusters is exhibiting low cognitive diversity, even if outputs appear acceptable.

**Confabulation Gap**: The measurable divergence between an agent's stated reasoning and its actual computational trajectory. Requires the trace layer to measure; conceptual until that layer is implemented.

**Capability Grant**: Cryptographically signed permission token granting an action scope, with constraints on time, cost ceiling, rate limit, delegation depth, and trust tier. Delegatable subject to the narrowing principle.

**Delegation Chain**: Ordered sequence of capability grants from root (human-held) to leaf (most-delegated agent), verified against eight invariants. Authority narrows as the chain lengthens. A revoked parent invalidates all children.

**Policy**: Constraints governing capability use and system behavior, evaluated by the PolicyEngine in a fixed order. The evaluation order itself is an invariant.

**Constitutional Constraint**: Non-overridable rule embedded in the PolicyEngine — specifically `HarmPrincipleRule` and `SovereigntyRule` — that cannot be removed, bypassed, or overridden by any other rule, WASM module, or consensus vote.

**Guard**: Pre-action sovereignty check. Local-first, runs before the PolicyEngine. The node evaluates its own accumulated state (chain, grants, constitutional rules) before accepting any external input.

**GovernanceGate**: The pipeline through which every action must pass: Guard → Policy → Execute → Audit. Nothing executes without passing through the gate; nothing passes through the gate without joining the audit chain.

**Genesis**: The origin event of a ZeroPoint deployment. The ceremony that generates the root Ed25519 keypair, seals constitutional rules, and establishes the initial conditions from which all subsequent trust flows. Sequential, irreversible, and consequential.

**Sovereignty Provider**: The mechanism that stores and protects the Genesis secret. Options include biometric (Touch ID, fingerprint), hardware wallet (Trezor, YubiKey), OS keychain (macOS Keychain, Linux Secret Service), and file-based (fallback).

**Trust Tier**: Six graduated trust levels. T0: unsigned, no cryptographic identity. T1: self-signed Ed25519. T2: chain-signed with Genesis root. T3: anchored — chain-signed with external truth anchoring. T4: attested — anchored with fleet membership attestation via lease renewal. T5: sovereign — full trust with constitutional governance, active reputation, and verified upstream binding.

**Reticulum-compatible**: One of several transport integrations — wire-interoperable with Reticulum's HDLC framing, 128-bit destination hashing, Ed25519/X25519 cryptography, and 500-byte MTU.

**CompactReceipt**: MessagePack-encoded receipt using short field names, optimized for single-packet mesh transmission (≤ 380 bytes including MeshEnvelope overhead).

**Presence Plane**: The discovery layer — how agents find each other. Dual-backend (web relay + Reticulum mesh), structurally amnesic, with reciprocity enforcement.

**DiscoveryBackend**: Trait abstraction for discovery transports. Four methods: `announce`, `poll_discoveries`, `is_active`, `shutdown`.

**Structural Amnesia**: An architectural property of the web relay: it cannot perform surveillance because it never parses, indexes, or persists announce payloads. Privacy by design, not by policy.

**Reciprocity Enforcement**: The relay rule requiring clients to announce their own signed Ed25519 identity before receiving peer announcements. Prevents passive scanning.

**ConnectionBehavior**: Behavioral summary (counters only, no content) emitted when a relay connection closes. Maps to `ReputationSignal` in the `PolicyCompliance` category.

**MeshNode**: High-level transport primitive managing interfaces, peers, links, delegations, and reputation.

**Collective Audit**: Peer-to-peer chain verification. A challenger sends an `AuditChallenge`; the challenged peer responds with its full chain; the challenger verifies integrity and produces a signed `PeerAuditAttestation`. Broken chains generate negative reputation signals.

**Truth Anchor**: External distributed ledger used to timestamp and independently witness the receipt chain's state. DLT-agnostic. Optional enrichment — the chain operates with full integrity without any anchor configured.

**Anchor Commitment**: The data published to an external ledger: chain head hash (Blake3), chain sequence number, previous anchor hash, operator signature, chain type, and trigger. A few hundred bytes — the ledger sees a cryptographic fingerprint, not the governed data.

**Anchor Receipt**: The external ledger's proof that a commitment was published: ledger transaction ID, consensus timestamp, original commitment, and ledger-specific verification data. Stored in the receipt chain as a regular entry.

**Anchor Trigger**: The reason an anchoring operation was initiated. Six variants: operator-requested, cross-mesh introduction, compliance checkpoint, dispute evidence, opportunistic, governance lifecycle event.

---

## Appendix C: Example Integration Pattern

A tool runner integrated with ZeroPoint operates as follows: any participant requesting execution must provide a receipt chain proving it holds a valid `CapabilityGrant` to call the tool, scoped to the specific action, signed by a chain terminating at a human-held Tier 2 key. The runner's GovernanceGate verifies the chain locally — checking all eight delegation invariants, evaluating the PolicyEngine (including constitutional rules), and confirming the capability hasn't expired or exceeded its rate limit. If verification fails, the runner emits a refusal receipt citing the specific invariant or rule that failed. If verification succeeds, the tool executes and the runner emits an execution receipt attesting to the action, its inputs hash, its outputs hash, and the policy decision. Both receipts join the audit chain.

This pattern works identically whether the requester is an agent, a human operator using the CLI, or an automated service. The protocol does not distinguish between them at the cryptographic layer — only at the trust tier level, where chain-signed identity (Tier 2) requires a verifiable delegation path back to a human root.

---

## Appendix D: Trajectory Verification — Mechanisms and Testable Behaviors

The following table maps each architectural claim to its concrete mechanism, accept condition, and reject condition. These are testable properties of the system, not analogies.

| Claim | Mechanism | Accept Condition | Reject Condition |
|-------|-----------|------------------|------------------|
| Each step conditioned on all prior context | Hash chaining: each receipt's `pr` field links to the previous receipt's `id`; Blake3 hashes are transitive | Unbroken hash-linked chain from Genesis to tip | Any missing receipt or hash mismatch |
| Present state compresses full history | Collective audit: `AuditChallenge` / `AuditResponse` / `PeerAuditAttestation` | Peer produces full chain matching claimed state; signed attestation issued | Incomplete chain → negative reputation signal |
| System-wide coherence from local evaluation | PolicyEngine fixed evaluation order: HarmPrincipleRule → SovereigntyRule → operational rules → WASM → default | Receipt with valid policy decision from compliant engine | Receipt attesting to constitutionally blocked action |
| Future actions narrowed by trajectory | `DelegationChain::verify()` — 8 invariants: scope subset, depth monotonic, expiration inherited, tier non-decreasing | All 8 invariants satisfied | Any single invariant violation dissolves the entire chain |
| Origin event propagates through all subsequent state | `zp-keys` certificate hierarchy: Genesis → Operator → Agent; all certs chain to Genesis root | Certificate chain walks back to Genesis key | Chain terminates at non-Genesis root |
| Sequential unfolding is constitutive of the ceremony | `onboard/genesis.rs`: generate → validate → enroll → seal → write; each step requires prior step's success | `genesis.json` written with all fields populated | Ceremony halts at first failed step; no partial Genesis |
| Authority narrows with each delegation | `CapabilityGrant` fields: scope, `valid_until`, `max_delegation_depth`, trust tier; child ⊆ parent enforced per-field | Child scope ⊆ parent scope, child expiration ≤ parent, child depth = parent + 1 | Any widening attempt |
| Reputation as accumulated state | `ReputationSignal` from receipts + `ConnectionBehavior` summaries; signals compose over interaction history | Peer with long positive trajectory passes reputation gate | Peer with broken chains or reciprocity violations accumulates negative signals |
| Trajectory verification stronger than snapshot | Hash-chained audit vs. single-entry log | Full chain verified end-to-end | Single-entry check misses retroactive rewrites that chain verification catches |
| Constitutional rules are forward-propagating invariants | Non-removable, non-overridable, fixed at positions 1 and 2 in evaluation order | HarmPrincipleRule and SovereigntyRule evaluate at every step | Any attempt to remove, reorder, or override returns `SovereigntyRule` block |
| Three-layer accountability stack | Receipt chain (what happened) → observation loop (did it violate policy?) → trace layer (what computation produced it?) | Receipt + policy decision + trace commitment all consistent | Trace fingerprint lands in known error cluster, or trace path diverges from stated reasoning. *Future work — trace layer not yet implemented* |

---

*ZeroPoint is maintained by ThinkStream Labs.*
*Contact: ken@thinkstreamlabs.ai*
*Repository: https://github.com/zeropoint-foundation/zeropoint*
*Website: https://zeropoint.global*

---

*© 2026 ThinkStream Labs. This document is released under CC BY 4.0. The ZeroPoint codebase is released under MIT/Apache-2.0.*
