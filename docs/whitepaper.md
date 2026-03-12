# ZeroPoint

## Cryptographic Governance Primitives for Accountable Systems

**Whitepaper v1.1 — March 2026**
**Ken Romero, Founder, ThinkStream AI Labs**

Status: Public Technical Overview
License: CC BY 4.0 (text); Code remains MIT/Apache-2.0
Canonical URL: https://zeropoint.global/whitepaper
PDF SHA-256: *(to be filled on publish)*

**How to cite:**
> Romero, Ken. "ZeroPoint: Cryptographic Governance Primitives for Accountable Systems." ThinkStream AI Labs, Whitepaper v1.1, March 2026. https://zeropoint.global/whitepaper

---

## Abstract

ZeroPoint is portable trust infrastructure — cryptographic governance primitives that make actions provable, auditable, and policy-bound without requiring central control. It restores real exit and real competition by moving trust from platform databases to verifiable cryptographic guarantees that any participant can carry between systems, operators, and networks.

The framework operates at the protocol-primitives layer. Every significant action produces a verifiable receipt, linked into an immutable chain of accountability. The protocol is participant-agnostic: the same receipts, capability chains, and constitutional constraints work whether the actor is a human, an AI agent, an automated service, or an IoT device — and whether they communicate over HTTP, TCP, encrypted mesh networks, or any future transport. ZeroPoint ships with a Reticulum-compatible mesh transport as one integration — chosen for its philosophical alignment with sovereignty and harm minimization — alongside TCP, UDP, HTTP interfaces, and a privacy-preserving Presence Plane that lets agents discover each other without surveillance infrastructure.

Autonomous AI agents are the most urgent application: agents are proliferating faster than the trust infrastructure to govern them, and ZeroPoint provides the cryptographic substrate they need. But the primitives are not agent-specific. Any participant that holds a keypair can sign receipts, hold capability grants, delegate authority, and exercise sovereign refusal. Organizations verifying supply chains, journalists proving sourcing, teams making accountable decisions, and devices attesting to sensor readings all benefit from the same protocol.

ZeroPoint is technically complete: 700+ tests across 13 crates, six delivered development phases, and full documentation including a dual-backend discovery layer (the Presence Plane) that solves peer discovery without centralized registries. It does not claim to "solve AI safety" or solve trust generally. It provides cryptographic primitives and governance constraints that make actions provable and refusable — shifting the terms of trust between participants, operators, and systems.

---

## Table of Contents

0. Why This Exists — The Portable Trust Thesis
1. Problem Statement
2. Design Goals
3. System Overview
4. Receipts and Chains
5. Governance Model
6. Threat Model
7. Transport Integrations
8. The Presence Plane
9. Implementation Status
10. Adoption Paths
11. Roadmap
12. Ethics, Non-Goals, and Misuse Resistance
13. Conclusion

Appendix A: Protocol Sketch
Appendix B: Glossary
Appendix C: Example Integration Pattern

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

ZeroPoint's thesis: **make trust portable, and you make exit real. Make exit real, and you make extraction optional. That is the structural antidote.**

Portable trust means:

- **Your identity is a keypair you control**, not an account on someone else's server. You can move it between systems without losing continuity.
- **Your reputation is a verifiable chain of receipts**, not a score computed by an opaque algorithm. Anyone can audit it. No one can confiscate it.
- **Your authorization is a cryptographic capability grant**, not an API key that can be revoked without recourse. Delegation chains have mathematical properties — they cannot be silently altered.
- **Your history is a hash-chained audit trail**, not a log file someone else controls. Tampering is detectable. Omission is provable.

When trust is portable, platforms compete on service quality, not on lock-in. When trust is portable, switching costs drop to near zero. When trust is portable, the dependency loop that enables extraction never forms.

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

Trust is infrastructure.

---

## 1. Problem Statement

The accountability gap that agents expose is an instance of the deeper structural problem described above: digital systems have never had protocol-level trust primitives. Agents did not create this gap — they inherited it and are accelerating it to the point where informal trust is no longer tenable.

AI agents are rapidly becoming operational actors: they request tools, move data, execute workflows, and trigger external effects. They act at machine speed, across organizational boundaries, with delegation chains that can extend far beyond their original authority. Yet most agent frameworks today remain trust-light:

- **Actions are difficult to attribute reliably.** Logs exist, but they are mutable, centralized, and easily rewritten.
- **Authorization is informal and mutable.** Most systems rely on API keys or ambient permissions rather than scoped, cryptographic capability grants. Who authorized what, and when, is often reconstructed after the fact — if it can be reconstructed at all.
- **Logs are easy to forge, prune, or "reinterpret."** There is no chain of evidence — only whatever the operator chooses to retain.
- **Cross-party trust is brittle.** One team cannot safely accept another party's outputs without out-of-band verification.

These are not agent-specific problems. They are structural failures in how digital systems handle trust — failures that existed long before autonomous agents arrived. Human organizations make consequential decisions with mutable logs and informal authorization every day. Automated services process transactions without cryptographic proof of who authorized what. Agents inherited the accountability gap; they did not create it. But they are compressing decades of accumulated risk into months of operational reality.

At the same time, the infrastructure environment is changing. There is renewed attention on sovereign networking, mesh systems, and local-first operations. Projects like the Reticulum Network Stack demonstrate that decentralized networking can bridge heterogeneous links into resilient networks under user control. Edge computing is moving AI inference closer to the point of action. Multi-agent orchestration frameworks are proliferating without any shared trust substrate.

This combination — agents intensifying an existing trust deficit, sovereignty becoming a design requirement, and real-world execution moving to the edge — creates a clear need:

> Systems where actions have consequences require protocol-level accountability primitives, not only policy frameworks.

Many governance efforts exist today as checklists, dashboards, or top-down frameworks. They describe what should be done, but they do not provide low-level mechanisms that make trust enforceable by default. ZeroPoint's position is intentionally infrastructural:

> Not a governance framework you comply with — a governance protocol you build on.

---

## 2. Design Goals

ZeroPoint is guided by a small set of goals that remain stable even as implementations evolve.

### 2.1 Protocol-Level Accountability

ZeroPoint produces verifiable receipts for actions and decisions. A receipt is cryptographically signed data describing what occurred, under what constraints, and with what authorization — regardless of whether the actor is an agent, a human, or an automated service. Receipts are chained — each linking to its parent — to create a durable accountability history.

### 2.2 Sovereignty by Design

ZeroPoint is built to function in environments where cloud assumptions are unsafe or unavailable. Its governance primitives are transport-agnostic — they work over HTTP in a data center, TCP between containers, or encrypted mesh links in a field deployment. The framework minimizes dependency on centralized infrastructure by design, not by accident.

### 2.3 Governance as Constraints, Not Suggestions

The system includes governance mechanisms that are not simply "policies in a file." Two constitutional rules — `HarmPrincipleRule` and `SovereigntyRule` — are engineered to be non-removable and non-overridable within the protocol's governance model. They evaluate before every action. They cannot be bypassed at runtime.

### 2.4 Honest Security Posture

ZeroPoint aims to be explicit about what it prevents, what it cannot prevent, and what remains a residual risk. Credibility comes from the boundaries, not the claims. Section 6 of this paper is dedicated to that honesty.

### 2.5 Transport Agnosticism and Interoperability

ZeroPoint's governance layer is decoupled from any single transport. The receipt format, capability grants, delegation chains, and policy engine operate identically regardless of how messages move. The framework ships with multiple transport integrations — including a Reticulum-compatible mesh transport, TCP/UDP interfaces, and an HTTP API — and is designed to be extended to any future transport without modifying the governance primitives.

---

## 3. System Overview

ZeroPoint is composed of layered capabilities, each implemented as one or more Rust crates. The layers are participant-agnostic — any entity that holds a keypair (human, agent, service, device) can operate as a full peer:

- **Identity layer.** Ed25519 signing keys and X25519 key agreement. Identity is a keypair. Authentication is a signature.
- **Governance layer.** PolicyEngine with constitutional rules, composable operational rules, WASM-extensible policy modules, and capability gating.
- **Receipt layer.** Signed, hash-chained receipts for every action and decision. CompactReceipt encoding produces 150–300 byte payloads suitable for bandwidth-constrained transports.
- **Transport layer.** Pluggable transport with multiple built-in integrations: Reticulum-compatible mesh (HDLC framing, 128-bit destination hashing, link handshake), TCP client/server, UDP, and HTTP API. The governance primitives are transport-independent.
- **Presence Plane.** Dual-backend peer discovery: a privacy-preserving web relay (pub/sub, structurally amnesic) and Reticulum mesh broadcast. Both share the same announce format and feed the same peer table. Reciprocity enforcement prevents passive scanning. See §8.
- **Application layer.** Pipeline orchestration, LLM provider integration, skill registry, and CLI tooling — all built on the governance primitives.

### 3.1 Data Flow

The GovernanceGate pipeline processes every action through three pillars:

1. **Guard** ("May I?") — Local-first, pre-action sovereignty check. The participant's own boundary. Runs before anything else, without consulting external authority.
2. **Policy** ("Should I?") — Rule-composed evaluation. Constitutional rules first, then operational rules, then WASM modules. The most restrictive decision wins.
3. **Execute** — The action runs only if Guard and Policy both allow it.
4. **Audit** ("Did I?") — A receipt is emitted: signed, timestamped, hash-linked to the prior receipt, and persisted to the chain.
5. **Transport** — Receipts propagate to peers over whichever transport is configured — mesh, TCP, HTTP, or any combination. Peers verify independently.

Nothing executes without passing through the gate. Nothing passes through the gate without joining the audit chain.

### 3.2 The Core Thesis

Every action becomes evidence. Evidence becomes a chain. The chain becomes shared truth.

This is not a compliance claim. It is an engineering proposition: if systems can cryptographically prove what happened and under what authorization, then trust becomes composable across operators.

---

## 4. Receipts and Chains

### 4.1 What a Receipt Is

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

### 4.2 What Receipts Prove vs. What They Don't

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

### 4.3 Why Chains Matter

Single receipts help attribution. Chains help accountability continuity. Each receipt's `pr` field links to the previous receipt's ID, forming a hash-linked sequence that resists retroactive tampering.

Chains are not magic. They are a mechanical advantage: they make it harder to rewrite the story after the fact, and they allow counterparties to require evidence before trust is granted.

In ZeroPoint, peers can challenge each other's audit chains. A challenged peer must produce its full chain; the challenger verifies integrity and produces a signed `PeerAuditAttestation`. Broken chains generate negative reputation signals. This is collective verification — no central auditor required.

---

## 5. Governance Model

### 5.1 Governance as a Primitive

Most governance — whether for agents, human workflows, or automated services — is implemented at the application layer: guardrails, prompt policies, logging conventions, compliance checklists. These are better than nothing, but they sit above the systems they govern. They can be bypassed, reconfigured, or simply ignored.

ZeroPoint moves governance downward into the protocol substrate. The PolicyEngine is not an add-on. It is the gate through which every action must pass — regardless of who or what initiated it.

### 5.2 Policy and Capability Gating

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

### 5.3 Constitutional Constraints

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

This is not a moral statement alone. It is a technical property: constitutional constraints remain enforceable even when incentives shift. They serve as a defense against co-option — particularly by surveillance interests.

### 5.4 The Four Tenets

The constitutional rules implement ZeroPoint's Four Tenets, which are embedded in the protocol, expressed in the documentation, and enforced in the code:

**I. Do No Harm.** ZeroPoint shall not operate in systems designed to harm humans. The `HarmPrincipleRule` is a non-removable rule in the PolicyEngine. It exists because architecture shapes outcomes, and we choose to make trust portable.

**II. Sovereignty Is Sacred.** Every participant has the right to refuse any action. Every human has the right to disconnect any agent. No agent may acquire capabilities it was not granted. Coercion is architecturally impossible — the Guard enforces this locally, before every action, without consulting any external authority. This applies equally to humans and agents: a human participant operating within ZeroPoint exercises the same sovereign refusal as an agent.

**III. Action Without Evidence Is No Action.** Every action produces a receipt. Every receipt joins a chain. If it's not in the chain, it didn't happen. If it is in the chain, it cannot un-happen. This holds whether the action was taken by a person, an agent, or an automated process.

**IV. The Human Is The Root.** Every delegation chain terminates at a human-held key. No agent may self-authorize. The genesis key is always held by flesh, blood, and soul. This is not only a constraint on agents — it is an assertion of human authority and accountability. The human at the root of a chain is not merely an overseer; they are a participant whose actions are as provable and auditable as any agent's.

### 5.5 Key Hierarchy and Introduction Protocol

ZeroPoint solves the key distribution problem through `zp-keys` — a three-level certificate hierarchy that exists below the policy engine:

```
GenesisKey       ← self-signed root of trust (one per deployment)
  └─ OperatorKey ← signed by genesis (one per node operator)
      └─ AgentKey← signed by operator (one per agent instance)
```

Each level holds an Ed25519 keypair and a certificate chain linking it back to its genesis root. Any node can verify an agent's identity by walking the chain — offline, with no network or policy state required. Certificate chains are verified against six invariants: valid signatures, issuer linkage, role hierarchy, monotonic depth, no expired certificates, and hash linkage.

The key hierarchy is a primitive — it has no dependency on the policy engine. This avoids a circular dependency: you need keys to establish the engine's authority across nodes, so keys cannot depend on the engine existing. The *decision* to issue a child certificate flows through the policy engine as `ActionType::KeyDelegation` (Critical risk); the *mechanism* of signing is unconditional.

When two ZeroPoint nodes meet for the first time, the introduction protocol (`zp-introduction`) governs trust establishment. The initiator sends its certificate chain and a challenge nonce. The responder verifies the chain, builds a `PolicyContext` with `ActionType::PeerIntroduction`, and evaluates it against the policy engine. Same-genesis introductions are High risk; cross-genesis introductions are Critical. The policy engine decides — the protocol only generates the context.

Key distribution is solved by `zp-keys`. Key *discovery* — how peers find each other's network addresses — is solved by the Presence Plane (§8): a dual-backend discovery layer providing both a privacy-preserving web relay and Reticulum mesh broadcast, unified under a single `DiscoveryBackend` trait.

---

## 6. Threat Model

### 6.1 Threat Model Table

| Threat / Failure Mode | What an attacker can do | Mitigation in ZeroPoint | Residual risk / limits |
|---|---|---|---|
| **Log forgery / retroactive rewriting** | Alter history to change attribution | Signed receipts with Ed25519 + Blake3 hash chain linkage; peers verify each other's chains via collective audit | Compromised private keys can still sign lies; key revocation is deployment-dependent |
| **Unauthorized tool use** | Execute actions beyond intended scope | CapabilityGrant gating with 8-invariant delegation chain verification; PolicyEngine evaluates before every action | Bad policy design can still leave gaps; scoping is only as good as the grant definitions |
| **Cross-operator trust failure** | One party can't trust another's agent outputs | Receipts provide independent verification; `zp-introduction` protocol verifies certificate chains; Presence Plane (§8) provides dual-backend discovery with reciprocity enforcement | Cross-genesis introductions require operator-configured policy; relay-based discovery requires internet connectivity |
| **Passive scanning / surveillance** | Harvest peer identities without participating | Presence Plane reciprocity rule: agents must announce before receiving. Relay is structurally amnesic — no logs, no index, no persistence. Scanners become observable before they can observe | A scanner that announces gains access; reputation system detects consume-only behavior over time but cannot prevent initial observation |
| **Sybil flooding** | Overwhelm discovery with cheap fake identities | Ed25519 keypair generation is computationally cheap; relay broadcasts all announces | Sybil resistance depends on reputation layer (§10) and external identity binding; not solved at discovery layer alone |
| **"Security theater" governance** | Claim governance without real constraints | Constitutional rules are non-removable; explicit non-goals section; receipts are independently verifiable, not just logged | Some deployments may misuse branding while gutting constraints; MIT/Apache-2.0 allows this |
| **Surveillance co-option** | Use receipts to track people rather than actions | Tenets + constitutional non-removability + explicit ethics stance; protocol frames accountability of *actions*, not tracking of *people* | MIT/Apache-2.0 cannot legally prevent misuse; community norms and reputation are the remaining defense |
| **Replay attacks** | Resend messages or insert previously captured packets | MeshEnvelope sequence numbers (monotonic u64); 16-byte random nonces in link handshake; Ed25519 signatures over content hashes | Depends on peers tracking seen sequence numbers; long-offline nodes may have gaps |
| **Injection attacks** | Insert forged packets into mesh transport | HDLC framing with CRC verification; Ed25519 signature verification on all envelopes; link-level X25519 ECDH key agreement | Transport-level encryption depends on successful link establishment; unlinked broadcast packets are not encrypted |
| **WASM policy escape** | Malicious policy module attempts to break sandbox | Wasmtime runtime with fuel limiting (configurable execution budget); hash verification of module contents before loading | Fuel exhaustion causes denial-of-service at worst; WASM sandbox escape would require a wasmtime vulnerability |
| **Identity misbinding** | Misattribute a key to a human | Trust tiers: Tier 0 (unsigned), Tier 1 (self-signed Ed25519), Tier 2 (chain-signed with genesis root); Tier 2 requires verified delegation from a human-held key | Identity binding to physical persons remains deployment-dependent; not solved purely in protocol |

### 6.2 What ZeroPoint Intentionally Does Not Solve

Being explicit prevents credibility collapse later:

- **It does not prevent a determined actor from building harmful systems.** The MIT/Apache-2.0 license is permissive. Constitutional rules constrain the framework's own behavior; they cannot constrain a fork.
- **It does not make intelligence tools impossible.** Receipt infrastructure could be repurposed for surveillance. The Tenets and constitutional rules resist this, but they are a friction, not a wall.
- **It does not provide universal truth verification.** Receipts prove that a statement was signed, not that the statement is true.
- **Key discovery is now addressed but not fully hardened.** The Presence Plane (§8) provides dual-backend discovery with reciprocity enforcement and structural amnesia. It is not yet resistant to sophisticated Sybil attacks without the reputation layer; see §8 for the full threat analysis.

Instead:

> ZeroPoint makes actions provable, and systems refusable.

This is a practical, enforceable improvement: counterparties can demand receipts and reject agents that do not provide them or that violate constraints.

---

## 7. Transport Integrations

ZeroPoint's governance primitives are transport-agnostic. The receipt format, capability chains, delegation verification, and policy engine operate identically regardless of how messages move between participants. The framework ships with several transport integrations, each suited to different deployment contexts.

### 7.1 HTTP API (zp-server)

The most straightforward integration path. An Axum-based HTTP server exposes the governance pipeline as a REST API. Agents communicate over standard HTTP/HTTPS — suitable for cloud deployments, container orchestration, and integration with existing web services. No mesh networking required.

### 7.2 TCP and UDP Interfaces

Direct socket communication for low-latency, local-network, or point-to-point deployments. `TcpClientInterface` and `TcpServerInterface` support persistent connections with HDLC framing and CRC verification. UDP interfaces support connectionless receipt exchange. Multiple interfaces can run simultaneously on a single node.

### 7.3 Reticulum-Compatible Mesh

ZeroPoint includes a Reticulum-compatible mesh transport — wire-level interoperability with the Reticulum Network Stack, created by Mark Qvist. This integration is philosophically significant: Reticulum demonstrated that encrypted, sovereign networking requires no central authority, and ZeroPoint shares that commitment to sovereignty, decentralization, and harm minimization.

The mesh integration implements:

- **HDLC framing** with CRC-CCITT verification, matching Reticulum's serial interface format.
- **128-bit destination hashing** using the same truncated SHA-256 scheme.
- **Ed25519 signing** and **X25519 ECDH** key agreement, matching Reticulum's cryptographic primitives.
- **500-byte default MTU** with a 465-byte data payload — compatible with Reticulum's packet constraints and suitable for LoRa links.
- **3-packet link handshake** (LinkRequest → LinkProof → LinkAccept) with 16-byte random nonces for replay protection.

Interoperability testing with Reticulum ecosystem tools (MeshChat, NomadNet) is underway. The mesh transport is one option among several — chosen when sovereignty, resilience, or operation without cloud infrastructure are priorities.

### 7.4 Extending to Other Transports

Adding a new transport requires implementing the interface trait and providing serialization/deserialization for the envelope format. The governance primitives — receipts, chains, capability verification, policy evaluation — remain unchanged. Similarly, adding a new discovery backend requires implementing the `DiscoveryBackend` trait (§8) — the Presence Plane is decoupled from transport, so discovery over web and mesh coexist with any current or future transport integration. This makes ZeroPoint deployable in contexts its authors haven't anticipated: industrial IoT, satellite links, air-gapped networks, or standard enterprise infrastructure.

---

## 8. The Presence Plane

### 8.1 The Discovery Problem

Key distribution — how participants verify each other's identity — is solved by `zp-keys` and the certificate hierarchy (§5.5). But key *discovery* — how participants find each other in the first place — is a separate problem. Most systems solve it with a centralized registry: a server that indexes who is online, what they offer, and where to reach them. This creates exactly the dependency that ZeroPoint exists to eliminate. A registry is a single point of surveillance, censorship, and failure.

ZeroPoint's answer is the **Presence Plane**: a discovery layer that runs alongside the Governance Plane, using the same Ed25519 identity but serving a different purpose. The Governance Plane determines what agents do together (receipts, policy, consensus). The Presence Plane determines how agents find each other — without requiring any participant to trust a central directory.

### 8.2 Dual-Backend Architecture

The Presence Plane is built on a `DiscoveryBackend` trait — a four-method interface that any transport can implement:

- `announce(payload)` — publish a signed announce blob
- `poll_discoveries()` — retrieve newly discovered peers
- `is_active()` — check backend status
- `shutdown()` — clean teardown

Two production backends ship today:

**Web relay.** A privacy-preserving pub/sub relay over WebSocket. Agents publish signed announce blobs to the relay; the relay broadcasts all blobs to all subscribers; agents filter locally for peers they care about. The relay never parses payloads, never indexes capabilities, never maintains query logs, and never persists state. Restart equals clean slate. Privacy is a property of the architecture — not a policy promise that can be revoked.

**Reticulum mesh.** Broadcast announces over mesh interfaces — LoRa, WiFi, serial, TCP. Fully decentralized. No server, no internet dependency. Announces propagate over whatever physical medium is available.

Both backends share the same announce wire format: `[combined_key(64)] + [capabilities_json] + [ed25519_signature(64)]`. A peer discovered via web and a peer discovered via Reticulum end up in the same peer table with the same destination hash. The `DiscoveryManager` fans out announces to all active backends, polls all backends, validates signatures, deduplicates peers, and prunes expired entries.

### 8.3 Structural Amnesia

The web relay is designed to be *structurally* incapable of surveillance — not merely configured to avoid it. It operates as a dumb pipe:

- It does not parse announce payloads (no capability indexing)
- It does not maintain query logs (no search patterns recorded)
- It does not persist any state (memory-only, restart erases everything)
- It does not track who received what (no delivery receipts)

This makes the relay subpoena-proof: there is nothing to hand over. Compromise-proof: an attacker who gains access to the relay finds zero peer data. Audit-friendly: the relay's own receipt chain proves honest behavior — that it did not censor, filter, or selectively route announces.

The key insight is that structural amnesia is stronger than policy-based privacy. A "no-logs" VPN policy can be changed, overridden, or secretly violated. A relay that architecturally cannot parse what it forwards cannot be coerced into surveillance — the capability does not exist.

### 8.4 Reciprocity Enforcement

Passive scanning is the primary adversarial concern for any discovery mechanism. An attacker connects to the relay, subscribes to the full firehose, and harvests peer identities without ever revealing their own. Traditional registries have no defense against this — querying a directory does not require participation.

The Presence Plane enforces a reciprocity rule: **you must announce before you receive.** A connection that only subscribes without publishing its own announce is structurally suspicious — it is a consumer-only node, a passive scanner. The enforcement mechanism:

1. On connect, the client receives a `RelayConnection` handle.
2. The handle tracks whether the client has published an announce.
3. `try_receive()` returns an error until the client publishes.
4. A configurable grace period (default 30 seconds) allows time for announce construction.
5. After the grace period, the connection is terminated.

This means any scanner must first announce itself — exposing its own signed Ed25519 identity to every legitimate agent on the network — before it can observe anyone else. Scanners become observable before they can observe.

### 8.5 Behavioral Signals and Reputation Integration

Reciprocity enforcement catches the most naive scanners. Sophisticated ones will announce once (passing the gate), then silently consume. The Presence Plane addresses this by emitting behavioral summaries — not content, not identity, just counters — when connections close:

- `announced`: whether the client ever published an announce
- `announces_published`: how many announces were sent
- `duration`: how long the connection was active
- `reciprocity_violation`: whether the connection was terminated for failing to announce

These `ConnectionBehavior` summaries map directly to `ReputationSignal` in the `PolicyCompliance` category. An agent that connects, announces regularly, and participates in discovery accumulates positive signals. An agent that connects, announces once, and silently consumes for hours accumulates weaker or negative signals. Over time, the reputation system naturally separates participants from parasites — without the relay ever needing to inspect content.

### 8.6 Presence Plane Threat Model

| Threat | Attack | Mitigation | Residual Risk |
|--------|--------|------------|---------------|
| **Passive scanning** | Subscribe to firehose without announcing | Reciprocity rule: must announce before receiving; grace period + termination | A scanner that announces gains access; detection relies on behavioral reputation over time |
| **Sybil flooding** | Generate thousands of keypairs, flood announces | Announce format requires valid Ed25519 signatures; relay broadcasts all | Keypair generation is computationally cheap; Sybil resistance depends on reputation layer, not discovery layer |
| **Relay compromise** | Attacker gains access to relay infrastructure | Relay holds no data (structural amnesia); no payloads parsed, no state persisted | Compromised relay could selectively drop announces (censorship); relay receipt chain makes this detectable |
| **Traffic analysis** | Observe connection timing and metadata | Relay does not log connections beyond a counter; no identity-to-IP mapping | Network-level observation by ISPs or co-located attackers is outside protocol scope |
| **Eclipse attack** | Surround a target with attacker-controlled peers | Dual-backend architecture means discovery via Reticulum bypasses web relay entirely | If both backends are eclipsed, the target is isolated; out-of-band peer introduction mitigates |

The Presence Plane does not claim to solve Sybil attacks at the discovery layer. Sybil resistance is a reputation-layer concern (§10). What the Presence Plane does provide is the architectural foundation — reciprocity, behavioral signals, structural amnesia — that makes reputation-based Sybil defense possible without surveillance infrastructure.

---

## 9. Implementation Status

ZeroPoint is implemented in Rust and is technically complete.

- **700+ tests** (all passing, zero warnings)
- **13 crates** in a Cargo workspace (including dual-backend discovery in `zp-mesh`)
- **6 development phases** delivered
- **59 integration tests** covering multi-node and cross-transport scenarios
- **Full documentation** for all crates

### 9.1 Workspace Structure

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
| `execution-engine` | Sandboxed command execution environment |

### 9.2 Build Verification

```bash
$ cargo test --workspace
   # 699 tests pass, 0 failures, 0 warnings

$ cargo clippy --workspace -- -D warnings
   # Clean

$ cargo fmt --workspace --check
   # Formatted
```

---

## 10. Adoption Paths

This project will not win by marketing. It will win by being useful and trustworthy to the right early communities.

### 10.1 First Adopters

- **Multi-agent system builders** — teams orchestrating autonomous agents who need protocol-level trust between operators, not just application-level guardrails.
- **Rust networking and security-oriented builders** — developers who understand why governance belongs in the substrate, not in the application.
- **Decentralized infrastructure communities** — projects building sovereign, local-first systems where centralized governance is a contradiction. The Reticulum ecosystem is a natural fit here.
- **Privacy-aligned agent tooling builders** — teams who need accountability without surveillance.
- **Enterprise AI governance teams** — organizations looking for verifiable, auditable behavior — from agents and humans alike — that goes beyond compliance checklists.
- **Accountable-process builders** — teams in journalism, supply chain, humanitarian operations, or organizational governance who need provable attribution and auditable decision chains, whether or not agents are involved.

### 10.2 Integration Patterns

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

### 10.3 What Ships Next

The [live playground](/playground.html) already demonstrates the core patterns: governed actions, receipt chains, refusal cases, and delegation — all running against real ZeroPoint primitives in the browser. Next: a multi-agent integration example where two or more independent agents discover each other via the Presence Plane, negotiate capabilities, execute governed work, and produce a verifiable end-to-end audit trail. That working demo — agents trusting each other without a central broker — is the proof point.

---

## 11. Roadmap

Open items, roughly in priority order.

1. **crates.io registration** — Publish workspace crates for external consumption. Requires stabilizing public API surfaces and versioning strategy.
2. **Transport integration test suite** — Documented cross-transport receipt exchange results, including Reticulum ecosystem interop (NomadNet, MeshChat) and HTTP/TCP integration tests.
3. **Key revocation and multi-hop trust formalization** — Revocation propagation strategy for compromised keys; formal analysis of trust transitivity across delegation chains longer than two hops.
4. **Reputation-weighted Sybil resistance** — The Presence Plane provides behavioral signals and reciprocity enforcement but defers Sybil resistance to the reputation system. Requires implementing reputation-weighted peer scoring in `zp-mesh`.
5. **Sustainability layer** — Consulting, hosted infrastructure, and enterprise feature scoping — without compromising the open-source core.
6. **Edge Sovereignty and governed firmware** — OpenWrt governance fork with device keypairs, attested boot, and receipt-gated telemetry. Routers become governed participants — not silent data exporters. WiFi CSI sensing capabilities require explicit consent boundaries.

---

## 12. Ethics, Non-Goals, and Misuse Resistance

### 12.1 The Co-option Risk

Accountability infrastructure can become surveillance infrastructure depending on how it is deployed. This is not a hypothetical concern — it is the central tension of the project.

ZeroPoint mitigates this through three mechanisms:

1. **Constitutional constraints** that are engineered to be non-removable. The `HarmPrincipleRule` blocks weaponization, surveillance, and deception. The `SovereigntyRule` blocks attempts to remove these constraints.
2. **Public tenets** describing intent and boundaries. The Four Tenets are not buried in documentation — they are the first thing on the website and the first code that runs in the PolicyEngine.
3. **Protocol-level framing.** ZeroPoint provides accountability of *actions*, not central control of *people*. The audit chain tracks what participants did — human or agent — not where anyone went or who they are beyond their keypair.

### 12.2 Non-Goals

ZeroPoint does not aim to:

- Become a compliance product. Compliance is a checklist someone else writes. ZeroPoint is infrastructure you build on.
- Become a centralized authority. There is no ZeroPoint server, no ZeroPoint cloud, no ZeroPoint corporation deciding who gets to use it.
- "Prevent all misuse." The MIT/Apache-2.0 license is deliberately permissive. Constitutional rules constrain the framework; they cannot constrain a fork.
- Depend on any single transport or network. ZeroPoint's governance works over HTTP, TCP, mesh, or anything else. No transport is privileged.
- Be agent-only infrastructure. The protocol is participant-agnostic by design. Narrowing it to agents alone would abandon the humans and systems that face the same accountability gap.

---

## 13. Conclusion

Autonomous agents are becoming infrastructure — but they are not the only systems making consequential decisions without adequate trust guarantees. Human organizations, automated services, and mixed human-agent systems all operate in environments where accountability is informal, authorization is mutable, and evidence is whatever someone chooses to retain.

The structural problem is clear: trust primitives that are captured by platforms become leverage for extraction. Identity that lives in someone else's database is not identity — it is a lease. Reputation that cannot be carried between systems is not reputation — it is a hostage. Authorization that can be silently revoked is not authorization — it is permission.

ZeroPoint provides protocol-level primitives — receipts, chains, governance constraints, sovereign transport compatibility, and a privacy-preserving Presence Plane — that make any system's actions provable and refusable, and its participants discoverable without surveillance. Agents are the most urgent application, and ZeroPoint is built to meet that urgency. But the primitives do not care who holds the keypair. A human's actions are as provable as an agent's. A team's decisions are as auditable as a pipeline's. The protocol serves everyone who participates in systems where trust matters.

It does not solve AI safety. It does not solve trust generally. It makes trust portable — and portable trust is the structural antidote to the dependency loops that degrade every system where exit is too expensive.

Make trust portable, and you make exit real. Make exit real, and you make extraction optional.

Trust is infrastructure.

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

- **Receipt**: Signed evidence of an action or decision, containing identity, content hash, policy decision, chain linkage, and Ed25519 signature.
- **Chain**: Linked sequence of receipts forming an accountable history. Each receipt's `pr` field references the previous receipt's `id`.
- **Capability Grant**: Cryptographically signed permission token granting an action scope, with constraints on time, cost, rate, and delegation depth.
- **Delegation Chain**: Ordered sequence of capability grants from root (human-held) to leaf (most-delegated agent), verified against eight invariants.
- **Policy**: Constraints governing capability use and system behavior, evaluated by the PolicyEngine in a fixed order.
- **Constitutional Constraint**: Non-overridable rule embedded in the PolicyEngine — specifically `HarmPrincipleRule` and `SovereigntyRule` — that cannot be removed, bypassed, or overridden by any other rule, WASM module, or consensus vote.
- **Guard**: Pre-action sovereignty check. Local-first, runs before the PolicyEngine, enforces the agent's right to refuse.
- **GovernanceGate**: The pipeline through which every action must pass: Guard → Policy → Execute → Audit.
- **Reticulum-compatible**: One of several transport integrations — wire-interoperable with Reticulum's HDLC framing, 128-bit destination hashing, Ed25519/X25519 cryptography, and 500-byte MTU.
- **CompactReceipt**: MessagePack-encoded receipt using short field names, optimized for single-packet mesh transmission.
- **Presence Plane**: The discovery layer — how agents find each other. Dual-backend (web relay + Reticulum mesh), structurally amnesic, with reciprocity enforcement. Complements the Governance Plane (how agents act together).
- **DiscoveryBackend**: Trait abstraction for discovery transports. Backends push raw announce blobs; signature validation and peer management happen in the DiscoveryManager.
- **Structural Amnesia**: An architectural property of the web relay: it cannot perform surveillance because it never parses, indexes, or persists announce payloads. Privacy by design, not by policy.
- **Reciprocity Enforcement**: The relay rule requiring clients to announce their own signed identity before receiving peer announcements. Prevents passive scanning.
- **ConnectionBehavior**: Behavioral summary (counters only, no content) emitted when a relay connection closes. Maps to ReputationSignal in the PolicyCompliance category.
- **MeshNode**: High-level transport primitive managing interfaces, peers, links, delegations, and reputation.
- **Collective Audit**: Peer-to-peer chain verification where nodes challenge each other's audit trails and produce signed attestations.

---

## Appendix C: Example Integration Pattern

A tool runner integrated with ZeroPoint operates as follows: any participant requesting execution must provide a receipt chain proving it holds a valid `CapabilityGrant` to call the tool, scoped to the specific action, signed by a chain terminating at a human-held Tier 2 key. The runner's GovernanceGate verifies the chain locally — checking all eight delegation invariants, evaluating the PolicyEngine (including constitutional rules), and confirming the capability hasn't expired or exceeded its rate limit. If verification fails, the runner emits a refusal receipt citing the specific invariant or rule that failed. If verification succeeds, the tool executes and the runner emits an execution receipt attesting to the action, its inputs hash, its outputs hash, and the policy decision. Both receipts join the audit chain. The requesting participant receives the execution receipt and can present it to other peers as proof of completed work.

This pattern works identically whether the requester is an agent, a human operator using the CLI, or an automated service. The protocol does not distinguish between them at the cryptographic layer — only at the trust tier level, where chain-signed identity (Tier 2) requires a verifiable delegation path back to a human root.

This creates a bidirectional, evidence-based trust relationship that operates over sovereign transports, requires no central coordinator, and produces a durable record that either party can independently verify at any time.

---

*ZeroPoint is maintained by ThinkStream AI Labs.*
*Contact: ken@thinkstreamlabs.ai*
*Repository: https://github.com/zeropoint-foundation/zeropoint*
*Website: https://zeropoint.global*

---

*© 2026 ThinkStream AI Labs. This document is released under CC BY 4.0. The ZeroPoint codebase is released under MIT/Apache-2.0.*
