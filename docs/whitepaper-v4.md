# ZeroPoint

## Cryptographic Governance Primitives for Accountable Systems

**Whitepaper v4.0 — June 2026**
**Ken Romero, Founder, ThinkStream Labs**

Status: Public Technical Overview
License: CC BY 4.0 (text); Code remains MIT/Apache-2.0
Canonical URL: https://zeropoint.global/whitepaper
PDF: [zeropoint-whitepaper-v4.0.pdf](https://zeropoint.global/zeropoint-whitepaper-v4.0.pdf)

**How to cite:**
> Romero, Ken. "ZeroPoint: Cryptographic Governance Primitives for Accountable Systems." ThinkStream Labs, Whitepaper v4.0, June 2026. https://zeropoint.global/whitepaper

---

## Abstract

ZeroPoint is cryptographic governance infrastructure for accountable systems. Every significant action produces a signed receipt. Receipts link together via a Blake3 hash chain into an ordered, tamper-evident audit trail. Authorization flows through signed, delegatable capability grants that narrow in scope as they propagate. Two constitutional rules evaluate before every action and cannot be removed or overridden at runtime.

The framework is participant-agnostic and transport-agnostic. The same receipts, delegation chains, and policy enforcement apply whether the actor is a human, an AI agent, an automated service, or an IoT device. Transport is pluggable — HTTP, TCP, encrypted mesh, or any future medium. ZeroPoint ships with a Reticulum-compatible mesh transport, TCP and UDP interfaces, an HTTP API, and a dual-backend peer discovery layer (the Presence Plane) that operates without centralized registries.

ZeroPoint is implemented in Rust. It does not claim to solve AI safety or trust generally. It provides cryptographic primitives that make actions provable, authority traceable, and governance constraints enforceable at the protocol layer — without requiring any central authority to act as witness.

---

## Table of Contents

1. Background
2. Design Approach — Chain-Based Verification
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
Appendix D: Verification Mechanisms and Testable Behaviors

---

## 1. Background

Trust primitives — identity, reputation, authorization — are typically implemented at the platform layer rather than the protocol layer. This means they cannot move with participants. A user's credentials, history, and authorization chains exist in a vendor's database; switching platforms means starting over. The same problem applies to agents: if an agent's identity and authority are platform-bound, the agent's accountability is platform-bound too.

The specific gap this creates: there is no standard protocol-level mechanism to prove what happened, who authorized it, and whether constraints were honored — without depending on a platform to be the witness. Existing logs are mutable and centralized. Authorization is typically API keys or ambient permissions, not cryptographically scoped grants. When actions cross organizational boundaries, there is no shared evidence base that both parties can independently verify.

ZeroPoint addresses this with three primitives: signed, hash-chained receipts that make actions provable and their ordering tamper-evident; cryptographic capability grants that make authorization verifiable, portable, and delegatable; and constitutional constraints that enforce governance at the protocol layer. The primitives are participant-agnostic — they work for humans, AI agents, services, and devices. Autonomous agents are the most urgent application because they act at machine speed across organizational boundaries with delegation chains that can extend far beyond their original scope, but the accountability gap they expose is not new. It predates agents.

---

## 2. Design Approach — Chain-Based Verification

### 2.1 The Core Design Choice

Most trust systems check a current credential: is this token valid right now? This is sufficient for many purposes but has a structural weakness — it makes the audit record forgeable. If only the latest entry needs to be valid, earlier entries can be rewritten without detection. If only the current state of a permission is checked, there is no way to know whether that permission was legitimately delegated or injected.

ZeroPoint's design choice is to make verification history-dependent. Every receipt carries a cryptographic reference to the receipt that preceded it. To verify a receipt, a verifier must be able to walk the chain back to Genesis, checking each link. Rewriting any single entry requires rewriting every subsequent entry — and getting every independent verifier to accept the rewrite. This is computationally infeasible against even a modest number of independent peers.

The O(n) cost of chain verification is real. It is justified by what it provides: a structure where the integrity of any point in the record depends on the integrity of every point before it. In practice, verification is incremental — a peer that has already verified entries 1 through 1000 only needs to verify entry 1001 against the known-good hash of entry 1000.

### 2.2 Four Testable Properties

The following properties characterize ZeroPoint's chain-based architecture. Each is stated with its mechanism, accept condition, and reject condition.

**Property 1: Each step is verified against all prior context.**

Every receipt's Blake3 hash links transitively to every prior receipt in the chain via the `pr` (parent receipt) field. A verifier can present any receipt and demand the full chain back to Genesis. **Accept**: unbroken hash-linked sequence from Genesis to tip. **Reject**: any missing receipt or hash mismatch.

**Property 2: A node's current state is derived from its complete history.**

A node's keychain, capability grants, audit trail, and reputation are deterministically derived from its complete history of Genesis, delegations, actions, and verifications. Two nodes with identical histories produce identical states. A node that cannot produce the chain supporting its current state fails collective audit. **Accept**: peer produces full chain matching its claimed state; signed `PeerAuditAttestation` issued. **Reject**: incomplete chain generates a negative reputation signal.

**Property 3: Constitutional rules are enforced locally at every node, with no global coordinator.**

No central authority enforces `HarmPrincipleRule` and `SovereigntyRule`. Each node evaluates them locally before every action. A node that removes or bypasses these rules produces receipts that other nodes reject during chain verification, because the receipts either lack valid policy decisions or attest to constitutionally blocked actions. **Accept**: receipt contains a valid policy decision from a compliant engine. **Reject**: receipt attesting to a blocked action is rejected by peers.

**Property 4: Delegation narrows authority at each step.**

Given a delegation chain of depth N, the leaf grant's scope is a subset of every ancestor's scope, its expiration is ≤ every ancestor's expiration, and its depth equals N. **Accept**: all eight delegation invariants satisfied. **Reject**: any single invariant violation dissolves the entire chain.

### 2.3 Genesis as the Chain Origin

The Genesis ceremony generates a 32-byte Ed25519 seed from which all trust in the deployment derives. Every operator key is signed by this Genesis key. Every agent key is signed by an operator key. Every capability grant traces back through the delegation chain to authority rooted in Genesis.

Genesis is verified as an active constraint, not a historical fact. Any certificate chain can be walked back to the Genesis root. If the Genesis key is not at the root, verification **rejects**. This is an invariant of `zp-keys` certificate verification.

The ceremony is sequential and irreversible: generate the keypair → validate the sovereignty provider → enroll biometric or hardware confirmation → seal the constitutional rules → write the immutable record. Each step requires the prior step's success. The ordering is enforced in code — `onboard/genesis.rs` will not proceed to enrollment until the keypair is generated, will not seal constitutional rules until the provider is validated, and will not write the genesis record until all prior steps succeed.

### 2.4 Delegation Narrows Authority

A root capability grant specifies four constraint dimensions:

- **Scope**: which actions are permitted (e.g., `tool:execute`, `file:read`)
- **Time**: `valid_from` and `valid_until` timestamps
- **Depth**: `max_delegation_depth` — how many times the grant can be re-delegated
- **Trust tier**: minimum tier required to exercise the grant

Each subsequent delegation can only narrow these bounds:

- Child scope must be a subset of parent scope (invariant 3)
- Child expiration must be ≤ parent expiration (invariant 5)
- Child depth increments by exactly 1 (invariant 2) and cannot exceed `max_delegation_depth` (invariant 6)
- Child trust tier must be ≥ parent trust tier (invariant 4)

A revoked parent grant invalidates all child grants automatically — chain verification walks the full path from root to leaf, and if any link is revoked or expired, the entire chain is **rejected**.

### 2.5 Reputation as Accumulated Signal

A peer's reputation is not a static label. It accumulates from the full history of interactions: successful receipts generate positive signal, broken chains generate negative signal, behavioral anomalies (silent consumption, missing announces, reciprocity violations) degrade standing. Each new observation updates a running assessment that carries the weight of all prior interactions.

### 2.6 Three Layers of Accountability

ZeroPoint's accountability architecture has three layers:

**Layer 1 — The Receipt Chain.** Receipts record actions, delegations, and outcomes. The chain is hash-linked, tamper-evident, and replayable from Genesis to tip. It answers: what did this actor do, under whose authority, and when?

**Layer 2 — The Observation Loop.** The GovernanceGate pipeline — Guard → Policy → Execute → Audit — evaluates every action against accumulated state: constitutional rules, operational policies, delegation constraints. Assessments from peer challenges and collective audit join the chain and condition future evaluations. It answers: was this action permitted, and if not, why?

**Layer 3 — The Trace Layer (future work).** A hash commitment anchored in each receipt would commit to the actual computational trajectory a model traversed during inference — the sequence of features, relations, and activations consulted. This would extend accountability from what the agent did to what it actually computed, making confabulation (stated reasoning diverges from actual computation), mode collapse (reasoning fingerprints cluster in known error basins), and reasoning drift (computational paths shift systematically) detectable. This layer is not yet implemented. The architecture accommodates it without modifying the receipt or policy primitives.

---

## 3. Design Goals

### 3.1 Protocol-Level Accountability

ZeroPoint produces verifiable receipts for every significant action and decision. Receipts are cryptographically signed and linked to their predecessors, forming an ordered chain where each entry depends on the integrity of every prior entry. The chain is replayable and auditable offline — no running server required.

### 3.2 Sovereignty by Design

ZeroPoint functions in environments where cloud infrastructure is unavailable or unsafe. Governance primitives are transport-agnostic and evaluate locally — each node checks its own chain, grants, and rules before acting. No remote authority is consulted for permission.

### 3.3 Non-Bypassable Governance

Two constitutional rules — `HarmPrincipleRule` and `SovereigntyRule` — are fixed at positions 1 and 2 in the PolicyEngine's evaluation order. They cannot be removed, reordered, or overridden by any other rule, WASM module, or operator configuration. They evaluate before every action with the same force at step one million as at step one.

### 3.4 Honest Security Posture

ZeroPoint is explicit about what it prevents, what it cannot prevent, and what remains residual risk. Section 7 covers this in full.

### 3.5 Transport Agnosticism

The governance layer is decoupled from transport. The receipt format, capability grants, delegation chains, and policy engine operate identically regardless of how messages move. The framework ships with multiple built-in transport integrations and can be extended to any future transport without modifying the governance primitives.

---

## 4. System Overview

ZeroPoint is composed of layered capabilities, each implemented as one or more Rust crates. Any entity holding a keypair — human, agent, service, device — can operate as a full peer:

- **Identity layer.** Ed25519 signing keys and X25519 key agreement. Identity is a keypair. Authentication is a signature.
- **Governance layer.** PolicyEngine with constitutional rules, composable operational rules, WASM-extensible policy modules, and capability gating.
- **Receipt layer.** Signed, hash-chained receipts for every action and decision. CompactReceipt encoding produces 150–300 byte payloads suitable for bandwidth-constrained transports.
- **Transport layer.** Pluggable transport with built-in integrations: Reticulum-compatible mesh (HDLC framing, 128-bit destination hashing, link handshake), TCP client/server, UDP, and HTTP API.
- **Presence Plane.** Dual-backend peer discovery: a privacy-preserving web relay (pub/sub, structurally amnesic) and Reticulum mesh broadcast. Both share the same announce format and feed the same peer table. Reciprocity enforcement prevents passive scanning. See §9.
- **Application layer.** Pipeline orchestration, LLM provider integration, skill registry, and CLI tooling — all built on the governance primitives.

### 4.1 Data Flow

The GovernanceGate pipeline processes every action sequentially:

1. **Guard** — Pre-action sovereignty check. Local-first, runs before anything else. The node evaluates its own chain, grants, and constitutional rules before accepting any external input.
2. **Policy** — Rule-composed evaluation. Constitutional rules first, then operational rules, then WASM modules. The most restrictive decision wins.
3. **Execute** — The action runs only if Guard and Policy both allow it.
4. **Audit** — A signed, timestamped, hash-linked receipt is emitted and persisted to the chain.
5. **Transport** — Receipts propagate to peers over whichever transports are configured. Peers verify independently.

Nothing executes without passing through the gate. Nothing passes through the gate without joining the audit chain.

---

## 5. Receipts and Chains

### 5.1 Receipt Structure

A receipt is a signed artifact describing an event with enough context for independent verification. Each receipt contains:

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

Receipts are encoded using MessagePack with short field names, producing 150–300 bytes. This fits in a single HTTP request, TCP frame, or 465-byte mesh packet for bandwidth-constrained links like LoRa.

### 5.2 What Receipts Prove and What They Don't

**Receipts prove:**

- A specific Ed25519 key signed a specific statement at a specific time.
- A chain contains a consistent, unbroken sequence of signed events.
- The policy engine evaluated a known rule set and produced a specific decision.
- A capability grant was present and valid at the time of action.

**Receipts do not prove:**

- The nature of the signer. A receipt proves a specific key signed a statement — not whether that key belongs to a human, an agent, or a service. Identity binding to physical persons is deployment-dependent.
- That the action content was correct or safe. Governance constrains actions; it does not evaluate their content.
- That the runtime environment was uncompromised. A compromised host can sign whatever it wants.
- That a result is truthful — only that it was produced and attested under stated constraints.

### 5.3 Ordering and Tamper-Evidence

Chained receipts have three properties that isolated receipts lack:

**Ordering.** Each receipt's `pr` field references the previous receipt's `id`, establishing a total order. Events are sequenced by chain position, not merely timestamped. Two receipts with the same timestamp are still ordered.

**Tamper-evidence.** Each receipt's hash incorporates the previous receipt's hash transitively via `pr` linkage. Modifying any receipt invalidates the hash of every subsequent receipt. An attacker who rewrites entry N must also rewrite N+1 through the chain tip — and convince every independent verifier to accept the rewrite.

**Replayability.** The full chain can be replayed from Genesis to verify that every action was authorized, every policy decision was valid, and every delegation was within scope at the time it occurred.

**Accept/reject.** A chain is **accepted** when every `pr` linkage is intact, every hash is consistent, and every signature verifies. **Rejected** when any `pr` linkage is broken (gap), any hash is inconsistent (tampering), or any signature fails (forgery). A single broken link invalidates everything downstream.

Peers can challenge each other's chains. A challenged peer must produce its full chain; the challenger verifies and produces a signed `PeerAuditAttestation`. Broken chains generate negative reputation signals. No central auditor is required.

### 5.4 History-Dependence as Defense

The common objection: why not verify only the latest receipt?

If only the latest entry needs to be valid, an attacker can rewrite everything before it. If you only check whether a permission currently exists, you cannot detect whether it was injected rather than legitimately delegated. History-dependence closes these gaps: when each entry's hash incorporates all prior hashes transitively, any rewrite propagates forward and is detected at the next verification.

Chain verification is O(n) in chain length, not O(1). Incremental verification makes this practical in steady state — a peer verifying entry 1001 against a known-good entry 1000 does O(1) work per new entry.

### 5.5 Chains at Scale — Epochs, Compaction, and Bounded Growth

An agent performing 1,000 actions per day produces 365,000 receipts per year. At fleet scale this grows to tens of millions. Walking the full chain from Genesis for every verification becomes inoperable at that scale. ZeroPoint addresses this through epoch-based compaction.

The chain is divided into fixed-size segments called epochs. When an epoch fills (8,192 entries or 7 days, whichever comes first), a Merkle tree is computed over its entries and summarized in a signed `EpochSeal`. The seal joins the chain as a regular receipt, preserving hash linkage. The sealed epoch's individual entries can then be archived and removed from active storage.

The Merkle tree commits to every entry in the epoch: each leaf is one entry's hash, paired and hashed bottom-up to a 32-byte Blake3 root. Changing any entry changes the root. The `EpochSeal` records this root, the entry count, the sequence range, and is signed by the same key that signs all other receipts. Seals link to each other via back-references, forming a verifiable chain-of-chains.

**Verification modes with compaction:**

- **Recent activity** (current unsealed epoch): full walk, bounded to at most 8,192 entries.
- **Historical integrity**: walk the seal chain — dozens of seals instead of hundreds of thousands of entries.
- **Spot-check a specific entry**: Merkle inclusion proof — 13 hashes (416 bytes, one mesh packet) proves membership in a sealed epoch.
- **Forensic reconstruction**: retrieve archived epoch entries and reconstruct the Merkle tree.

**Memory bounds.** The working set is one epoch (~4 MB) plus the most recent seal. An agent running for five years holds the same active memory as one that started yesterday. The seal chain grows ~500 bytes per week; five years of seal history is ~111 KB. Archived epoch data grows linearly but can be offloaded per the operator's retention policy.

**What compaction does not do:**

1. It does not solve disaster recovery. If archived entries are lost and no peer holds copies, the seal proves they existed but cannot reconstruct their content. Durability requires replication — a deployment decision.

2. It does not prevent fabrication. A compromised node can produce a valid seal over fabricated entries. The seal proves internal consistency, not truthfulness. Peer attestation is the defense: peers spot-check entries against their own records of interactions.

3. Retention is the operator's tradeoff. When local archives expire and no external copies exist, individual actions in those epochs cannot be examined — only the seal chain's structural summary survives. Storage cost versus audit depth is the operator's decision.

The compaction architecture is implemented in `zp-receipt::epoch`. It was designed after the integrity guarantees were established (699 tests at design time).

---

## 6. Governance Model

### 6.1 Governance at the Protocol Layer

Application-layer governance — guardrails, prompt policies, logging conventions — sits above the systems it governs and can be bypassed, reconfigured, or ignored. ZeroPoint moves governance into the protocol substrate. The PolicyEngine is the gate through which every action must pass, regardless of actor.

### 6.2 Capability Gating

Every participant — human operator, agent, or service — must hold a valid `CapabilityGrant` to act. A grant is a signed, portable authorization token containing:

- Scope restrictions (which actions, which targets)
- Cost ceilings and rate limits
- Time windows (`valid_from`, `valid_until`)
- Delegation depth limits
- Trust tier requirements
- The grantor's Ed25519 signature

Grants are delegatable: any holder can delegate a subset to another participant — human to agent, agent to agent, or human to human — forming a `DelegationChain`. The chain is verified against eight invariants:

1. Each grant references the previous one as `parent_grant_id`.
2. Delegation depths increment monotonically (0, 1, 2, ...).
3. Each child's scope is a subset of its parent's scope.
4. Each child's trust tier is ≥ its parent's trust tier.
5. No child outlives its parent.
6. The chain does not exceed the `max_delegation_depth` set by the root.
7. Each grant's grantor matches the previous grant's grantee.
8. All signatures verify.

Break any invariant and the chain is rejected.

### 6.3 Constitutional Constraints

The PolicyEngine loads rules in a fixed order. The first two positions are reserved for constitutional rules that cannot be removed, overridden, or reordered:

**`HarmPrincipleRule`** (Tenet I: Do No Harm)
Blocks actions targeting weaponization, surveillance, deception (deepfakes, impersonation), and suppression of dissent. Evaluates before every action regardless of what other rules or WASM modules are loaded. Cannot be bypassed by capability grants, policy edits, or consensus votes.

**`SovereigntyRule`** (Tenet II: Sovereignty Is Sacred)
Blocks configuration changes that would disable the guard, disable or truncate the audit trail, forge or bypass capabilities, remove constitutional rules, or override agent refusal.

Evaluation hierarchy:

```
1. HarmPrincipleRule      ← Constitutional (always first)
2. SovereigntyRule        ← Constitutional
3. ReputationGateRule     ← Operational
4. WASM policy modules    ← Peer-exchanged, sandboxed, fuel-limited
5. DefaultAllowRule       ← Fallback
```

Decision severity: Block(5) > Review(4) > Warn(3) > Sanitize(2) > Allow(1). The most restrictive decision wins. WASM modules can override the default allow but cannot override constitutional rules.

### 6.4 The Four Tenets

The constitutional rules implement four tenets embedded in the protocol and enforced in code:

**I. Do No Harm.** ZeroPoint shall not operate in systems designed to harm humans. `HarmPrincipleRule` is non-removable and evaluates before every action.

**II. Sovereignty Is Sacred.** Every participant can refuse any action. Every human can disconnect any agent. No agent may acquire capabilities it was not granted. The Guard enforces this locally, before every action, without consulting any external authority.

**III. Action Without Evidence Is No Action.** Every action produces a receipt. Every receipt joins the chain. An action not in the chain did not happen; an action in the chain cannot be expunged.

**IV. The Human Is The Root.** Every delegation chain terminates at a human-held key. No agent may self-authorize. The genesis key is always held by a human operator.

### 6.5 Key Hierarchy and Introduction Protocol

ZeroPoint solves key distribution through `zp-keys` — a three-level certificate hierarchy:

```
GenesisKey       ← self-signed root of trust (one per deployment)
  └─ OperatorKey ← signed by genesis (one per node operator)
      └─ AgentKey← signed by operator (one per agent instance)
```

Each level holds an Ed25519 keypair and a certificate chain back to its Genesis root. Any node can verify an agent's identity by walking this chain — offline, with no network or policy state required. Certificate chains are verified against six invariants: valid signatures, issuer linkage, role hierarchy, monotonic depth, no expired certificates, and hash linkage.

The key hierarchy has no dependency on the policy engine. This avoids a circular dependency: you need keys to establish the engine's authority across nodes, so keys cannot depend on the engine existing. The *decision* to issue a child certificate flows through the policy engine as `ActionType::KeyDelegation` (Critical risk); the *mechanism* of signing is unconditional.

When two ZeroPoint nodes meet for the first time, the introduction protocol (`zp-introduction`) governs trust establishment. The initiator sends its certificate chain and a challenge nonce. The responder verifies the chain, builds a `PolicyContext` with `ActionType::PeerIntroduction`, and evaluates it against the policy engine. Same-genesis introductions are High risk; cross-genesis introductions are Critical. The policy engine decides.

Key *discovery* — how peers find each other's network addresses — is handled by the Presence Plane (§9), which is separate from key distribution.

---

## 7. Threat Model

### 7.1 Threat Model Table

| Threat / Failure Mode | What an attacker can do | Mitigation in ZeroPoint | Residual risk |
|---|---|---|---|
| **Log forgery / retroactive rewriting** | Alter history to change attribution | Ed25519-signed receipts with Blake3 hash chain linkage; collective audit via `AuditChallenge` / `AuditResponse` / `PeerAuditAttestation` | Compromised private keys can still sign lies; key revocation is deployment-dependent |
| **Unauthorized tool use** | Execute actions beyond intended scope | `CapabilityGrant` gating with 8-invariant delegation chain verification; PolicyEngine evaluates before every action | Bad grant design can leave gaps; scoping is only as strong as the grant definitions |
| **Cross-operator trust failure** | One party cannot verify another's agent outputs | Independent receipt verification; `zp-introduction` verifies certificate chains; Presence Plane provides dual-backend discovery with reciprocity enforcement | Cross-genesis introductions require operator-configured policy; relay-based discovery requires internet connectivity |
| **Passive scanning / surveillance** | Harvest peer identities without participating | Reciprocity rule: must announce before receiving. Relay is structurally amnesic — no logs, no index, no persistence | A scanner that announces gains access; behavioral reputation detects consume-only patterns over time |
| **Sybil flooding** | Overwhelm discovery with cheap fake identities | Establishing a credible anchor history requires sustained ledger transactions at real cost. Reputation weights anchor depth; shallow histories receive less trust | A well-funded attacker can maintain multiple anchored identities — the defense transforms a computational cost into an economic one |
| **"Security theater" governance** | Claim governance without enforcing constraints | Constitutional rules are non-removable; receipts are independently verifiable | Deployments can misuse ZeroPoint branding while gutting constraints; MIT/Apache-2.0 permits this |
| **Surveillance co-option** | Use receipts to track people rather than actions | Constitutional rules + pseudonymous keypairs + Presence Plane structural amnesia | MIT/Apache-2.0 cannot legally prevent misuse; community norms are the remaining constraint |
| **Replay attacks** | Resend previously captured packets | `MeshEnvelope` sequence numbers (monotonic u64); 16-byte random nonces in link handshake; Ed25519 signatures over content hashes | Depends on peers tracking seen sequence numbers; long-offline nodes may have gaps |
| **Injection attacks** | Insert forged packets into mesh transport | HDLC framing with CRC verification; Ed25519 signature verification on all envelopes; X25519 ECDH key agreement | Transport-level encryption requires successful link establishment; unlinked broadcast packets are not encrypted |
| **WASM policy escape** | Malicious policy module breaks sandbox | Wasmtime with fuel limiting (configurable execution budget); hash verification of module contents before loading | Fuel exhaustion causes denial-of-service at worst; sandbox escape requires a Wasmtime vulnerability |
| **Identity misbinding** | Misattribute a key to a human | Six trust tiers (T0–T5): T2+ requires verified delegation from a human-held key | Identity binding to physical persons is deployment-dependent and not solved at the protocol layer |

### 7.2 What ZeroPoint Does Not Solve

- **It does not prevent a determined actor from building harmful systems.** Constitutional rules constrain behavior within ZeroPoint deployments. Misuse resistance beyond the protocol boundary depends on community norms and economic incentives.
- **It does not make surveillance tools impossible.** Receipt infrastructure could be repurposed for surveillance. Constitutional rules create friction but not an absolute barrier.
- **It does not verify truth.** Receipts prove provenance and chain integrity, not the correctness or truthfulness of what was signed.
- **Sybil resistance is economic, not absolute.** The defense makes large-scale fabrication expensive relative to legitimate participation, but does not eliminate the attack.

ZeroPoint makes actions provable and systems refusable. Counterparties can demand receipts and reject agents that cannot produce them or that violate constraints. That is a concrete, enforceable improvement over the baseline.

---

## 8. Transport Integrations

ZeroPoint's governance primitives are transport-agnostic. The receipt format, capability chains, delegation verification, and policy engine are identical across all transports.

### 8.1 HTTP API (zp-server)

An Axum-based HTTP server exposes the governance pipeline as a REST API. Suitable for cloud deployments, container orchestration, and integration with existing web services.

### 8.2 TCP and UDP Interfaces

`TcpClientInterface` and `TcpServerInterface` support persistent connections with HDLC framing and CRC verification, for low-latency or point-to-point deployments. UDP interfaces support connectionless receipt exchange. Multiple interfaces can run simultaneously on a single node.

### 8.3 Reticulum-Compatible Mesh

ZeroPoint includes a Reticulum-compatible mesh transport with wire-level interoperability with the Reticulum Network Stack (Mark Qvist). The integration implements:

- **HDLC framing** with CRC-CCITT verification, matching Reticulum's serial interface format.
- **128-bit destination hashing** using the same truncated SHA-256 scheme.
- **Ed25519 signing** and **X25519 ECDH** key agreement, matching Reticulum's cryptographic primitives.
- **500-byte default MTU** with a 465-byte data payload — compatible with LoRa links.
- **3-packet link handshake** (LinkRequest → LinkProof → LinkAccept) with 16-byte random nonces for replay protection.

### 8.4 Extending to Other Transports

Adding a new transport requires implementing the interface trait and providing envelope serialization/deserialization. The governance primitives remain unchanged. Adding a new discovery backend requires implementing the `DiscoveryBackend` trait — the Presence Plane is decoupled from transport, so web and mesh discovery coexist with any current or future transport.

---

## 9. The Presence Plane

### 9.1 The Discovery Problem

`zp-keys` solves key distribution: how participants verify each other's identity once they have each other's certificates. Key *discovery* — how participants find each other's network addresses in the first place — is a separate problem.

A centralized registry solves this but creates a single point of surveillance, censorship, and failure. ZeroPoint's answer is the **Presence Plane**: a discovery layer using the same Ed25519 identity as the governance layer, running independently, without centralized state.

### 9.2 Dual-Backend Architecture

The Presence Plane is built on a `DiscoveryBackend` trait with four methods:

- `announce(payload)` — publish a signed announce blob
- `poll_discoveries()` — retrieve newly discovered peers
- `is_active()` — check backend status
- `shutdown()` — clean teardown

Two production backends ship today:

**Web relay.** A pub/sub relay over WebSocket. Agents publish signed announce blobs; the relay broadcasts all blobs to all subscribers; agents filter locally. The relay never parses payloads, never indexes capabilities, never maintains query logs, never persists state. Restart equals clean slate.

**Reticulum mesh.** Broadcasts announces over mesh interfaces — LoRa, WiFi, serial, TCP. No server, no internet dependency.

Both backends share the same announce wire format: `[combined_key(64)] + [capabilities_json] + [ed25519_signature(64)]`. Peers discovered via web and via Reticulum end up in the same peer table with the same destination hash. The `DiscoveryManager` fans out announces to all active backends, validates signatures, deduplicates peers, and prunes expired entries.

### 9.3 Structural Amnesia

The web relay is architecturally incapable of surveillance:

- It does not parse announce payloads.
- It does not maintain query logs.
- It does not persist any state — memory-only, restart erases everything.
- It does not track delivery.

This is stronger than a "no-logs" policy. A policy can be changed or secretly violated. The relay cannot surveil because the capability does not exist in the code.

### 9.4 Reciprocity Enforcement

Passive scanning is the primary adversarial concern: an attacker subscribes to the full announce stream without revealing their own identity. The Presence Plane enforces: **you must announce before you can receive.**

1. On connect, the client receives a `RelayConnection` handle.
2. `try_receive()` returns an error until the client publishes an announce.
3. A configurable grace period (default 30 seconds) allows time for announce construction.
4. Connections that do not announce are terminated after the grace period.

A scanner must announce its own signed Ed25519 identity to every peer on the network before it can observe anyone. Scanners become observable before they can observe.

### 9.5 Behavioral Signals and Reputation Integration

Reciprocity catches naive scanners. Sophisticated ones will announce once and then silently consume. The Presence Plane emits `ConnectionBehavior` summaries when connections close — counters only, no content:

- `announced`: whether the client ever published an announce
- `announces_published`: how many announces were sent
- `duration`: connection active time
- `reciprocity_violation`: whether the connection was terminated for not announcing

These map directly to `ReputationSignal` in the `PolicyCompliance` category. Agents that participate regularly accumulate positive signals; agents that announce once and consume silently accumulate negative signals. The reputation system distinguishes participants from parasites without inspecting announce content.

### 9.6 Presence Plane Threat Model

| Threat | Attack | Mitigation | Residual Risk |
|--------|--------|------------|---------------|
| **Passive scanning** | Subscribe without announcing | Reciprocity: must announce before receiving; termination after grace period | A scanner that announces gains access; behavioral detection takes time |
| **Sybil flooding** | Generate many keypairs, flood announces | Credible identities require anchor history (sustained ledger activity); reputation weights trajectory depth | Keypair generation is cheap; economic disincentive only applies at the anchor layer |
| **Relay compromise** | Attacker gains relay access | No data to retrieve (structural amnesia) | Compromised relay could selectively drop announces; relay receipt chain makes censorship detectable |
| **Traffic analysis** | Observe connection timing and metadata | No identity-to-IP mapping; relay logs only counters | ISP-level or co-located network observation is outside protocol scope |
| **Eclipse attack** | Surround a target with attacker-controlled peers | Dual-backend: Reticulum discovery bypasses web relay entirely | If both backends are eclipsed, the target is isolated; out-of-band peer introduction mitigates |

---

## 10. External Truth Anchoring

### 10.1 Purpose

The receipt chain is self-verifying: hash-linked, signed, replayable from Genesis to tip, auditable cold. This provides strong guarantees within a single deployment. It does not prove when the chain state existed in external calendar time, or provide a witness that a third party can verify without the operator's cooperation.

External truth anchoring addresses this by publishing the chain's current state — its head hash, sequence number, and operator signature — to an independent distributed ledger. The result is a timestamped, publicly queryable record that the operator cannot retroactively modify.

This matters most in three contexts:

**Cross-deployment trust.** When two ZeroPoint deployments interact for the first time, neither has a prior basis for trusting the other's chain. If both anchor to a common ledger, each gains an independent, third-party-verifiable history that a freshly fabricated chain cannot reproduce.

**Dispute resolution.** If a governance action is disputed — an agent claims it had authority; an operator claims it did not — the receipt chain resolves the question internally. But the *timing* of the chain state may be contested. An anchor commit proves the chain was in a specific state at an externally-attested time, foreclosing after-the-fact rewriting arguments.

**Compliance and audit.** Regulated contexts may require proof that governance records existed at a claimed time and have not been modified since. Self-signed timestamps do not satisfy this. An anchor on a ledger the regulator already examines provides the same evidential weight as any other record in that ledger.

The key practical observation: in the scenarios where external witnessing matters most, ledger infrastructure is already present. Cross-organizational transactions — supply chain coordination, multi-party agreements, regulated exchanges — nearly always touch a shared ledger. Anchoring governance chain heads to that same ledger piggybacks on infrastructure the transaction already requires.

### 10.2 Architecture

Truth anchoring enriches the receipt chain without modifying its internal properties.

**The chain does not require the anchor.** Without an external ledger configured, ZeroPoint operates exactly as described in §5 — tamper-evident, ordered, replayable, auditable offline.

**Anchor receipts join the chain.** An anchor receipt is stored in the chain as a regular entry. Chain verification does not require the external ledger to be reachable.

**DLT-agnostic.** The `TruthAnchor` trait defines three methods — `anchor()`, `verify()`, `query_range()` — implementable by any distributed ledger backend. The reference implementation targets Hedera Hashgraph's Consensus Service. Ethereum L2 calldata, Bitcoin OpenTimestamps, Ceramic streams, or any system that can timestamp and publicly expose an opaque payload are all supported by the trait architecture.

**Backend selection is the operator's choice.** Cross-deployment trust is established by exchanging anchor backend identifiers (e.g., HCS topic IDs). There is no mandated ledger.

### 10.3 What Gets Anchored

An anchor commitment contains:

| Field | Description |
|-------|-------------|
| Chain head hash | Blake3 hash of the current chain tip |
| Chain sequence | Monotonically increasing position in the chain |
| Previous anchor hash | Links anchor history (first anchor has none) |
| Operator signature | Ed25519 signature over the commitment |
| Chain type | Which chain (audit, observation, reflection) |
| Trigger | Why this anchor was created |

The commitment is compact (a few hundred bytes) and contains no governance content. The external ledger receives a cryptographic fingerprint, not the governed data.

### 10.4 Trigger Model

Anchoring is event-driven, not timer-driven. Periodic anchoring adds cost without adding information — the hash chain already makes any modification detectable between anchors.

**Explicit triggers:**
- Operator request (CLI, API, or UI)
- Cross-deployment introduction (both parties anchor before exchanging trust)
- Compliance checkpoint (before generating an audit export or entering regulatory review)
- Dispute evidence (when a governance action is contested)
- Governance lifecycle event (capability revocation, constitutional rule update, trust tier change)

**Opportunistic trigger:**
When the operator makes any blockchain transaction for any purpose, the current chain head hash can be embedded as transaction metadata. The anchor is a byproduct of an existing transaction at zero marginal cost. This also happens to be the most natural timing — cross-organizational transactions are precisely the context where governance witnessing matters.

### 10.5 Reference Backend: Hedera Hashgraph

The reference anchor implementation targets Hedera Hashgraph's Consensus Service (HCS):

- **Sub-second finality.** HCS messages reach consensus in 3–5 seconds with deterministic finality.
- **Public verifiability.** Messages are publicly queryable via mirror nodes. Any party can independently verify a commitment without the operator's cooperation.
- **Low cost.** Submission costs a fraction of a cent.
- **Council governance.** Hedera's governing council is a publicly known set of global organizations.

Other backends are supported by the trait architecture.

### 10.6 Cross-Deployment Trust via Shared Anchors

When two ZeroPoint deployments meet:

1. Each announces its anchor backend identifier.
2. Each independently queries the other's anchor history on the external ledger.
3. Each verifies that the other's chain head hashes match the anchor commitments.
4. Each can walk the other's anchor history backward to verify consistency over time.

This is independent verification against a shared public record. A deployment that has anchored consistently for months provides a publicly verifiable history that a freshly fabricated chain cannot reproduce.

**Sybil economics.** Anchor history transforms the Sybil problem from computational to economic. Generating a keypair is free; establishing a credible anchor history requires sustained ledger transactions at real cost per identity over time. The reputation system weights anchor depth — shallow or absent anchor histories receive proportionally less trust. A well-funded attacker can maintain multiple anchored identities, but the cost asymmetry favors defenders.

### 10.7 What Anchoring Does Not Provide

- **It does not prove chain content is true.** It proves the chain was in a specific state at a specific time. It does not evaluate whether governed actions were correct.
- **It does not prevent chain forking.** An operator could maintain two chains and anchor only one. Detection requires the challenging party to have independent knowledge of the other chain.
- **It does not substitute for internal integrity.** A chain with broken hash links is broken regardless of how many times it was anchored.
- **It does not block governance.** If the external ledger is unavailable, the chain continues with full internal integrity. Anchor receipts simply stop being emitted until the ledger is reachable.

---

## 11. Fleet Topology: From Single Node to Governed Network

### 11.1 Chain-Derived Roles

A node's role in a fleet — Genesis, Delegate, or Standalone — is derived from its receipt chain, not its configuration file. The configuration file provides a bootstrap hint to disambiguate initial state before the chain records the node's actual role. Once the chain contains a delegation receipt, the config hint is advisory. The chain is authoritative.

Configuration can be edited. A chain entry cannot — not without invalidating every subsequent hash. When a node claims a role, the claim is verifiable: walk the chain, find the delegation receipt, confirm the cryptographic binding.

Three roles:

- **Genesis**: Performed the Genesis ceremony, holds the root Ed25519 keypair. Origin of all delegation chains in the fleet. Exactly one per fleet.
- **Delegate**: Holds a valid delegation receipt from an upstream Genesis node. Authority is bounded by the delegation chain's narrowing invariants.
- **Standalone**: No chain evidence of Genesis ceremony or delegation. A delegate whose delegation is revoked returns to Standalone.

### 11.2 Role Transition Receipts

Role transitions are chain events, not administrative events that happen outside the chain. When a node's role changes — Standalone to Delegate, Delegate back to Standalone on revocation, or re-delegation to a new upstream — the transition is sealed with a receipt. The receipt creates an auditable boundary: before this entry, the node operated as X; after it, as Y; the trigger is recorded in the metadata.

The trigger vocabulary is constrained: `delegation_accepted`, `delegation_revoked`, `redelegation`, `genesis_performed`. There is no catch-all — every transition has a named cause.

### 11.3 Cryptographic Upstream Binding

A delegate does not claim to serve a particular Genesis node. It proves it, by carrying the upstream Genesis node's Ed25519 public key in its delegation receipt.

**Local verification** (offline): The delegate checks that the delegation receipt contains a well-formed 32-byte Ed25519 public key. Missing or malformed: `Unbound` or `MalformedPubkey`.

**Online verification** (requires upstream reachability): The delegate challenges its upstream to prove it holds the key recorded in the receipt. If the upstream's genesis pubkey does not match: `PubkeyMismatch` — a signal that the upstream may have changed identity since the delegation was issued.

A node cannot forge a delegation receipt without the upstream's signing key, and cannot silently swap upstreams without the mismatch being detectable.

### 11.4 Fleet Membership and Liveness

Fleet membership is maintained through lease renewal. Each delegate holds a `CapabilityGrant` with a bounded lifetime that must be renewed at a configured cadence by presenting a valid Ed25519 signature to one of the grant's designated renewal authorities.

A delegation receipt proves authority was granted. A lease proves authority is still active. If renewal fails for a configurable number of consecutive attempts, the grant enters a grace period. On expiry, the failure mode activates: halt (fail closed), degrade (drop to read-only), or continue-with-flag (for air-gapped deployments where the renewal authority is intentionally unreachable).

Fleet membership is self-pruning. A node that goes offline stops renewing its lease. After the grace period, its authority expires — not because an administrator removed it from a list, but because the cryptographic proof of continued authorization lapsed. No registry is authoritative. The chain is.

### 11.5 Fleet Topology as Governance Evidence

The fleet primitives — chain-derived roles, transition receipts, upstream binding, lease-based membership — use the same receipt grammar as all other governed behavior. The same chain verification that catches a tampered action receipt catches a fabricated delegation receipt. The same narrowing invariants that prevent an agent from escalating its privileges prevent a delegate from widening its scope beyond what its upstream granted.

This makes the fleet's topology history independently auditable, historically ordered, and tamper-evident using the same tools used to audit any other governed behavior.

### 11.6 Toward Settlement

The same receipt grammar extends naturally to economic settlement. Spending authorizations, budget ceilings, and payment releases can all be expressed as receipts on the same chain, subject to the same narrowing invariants, delegation verification, and constitutional constraints.

The primitives are already in place: capability grants with cost ceilings, delegation chains with scope constraints, lease-based authority with automatic expiration, and external truth anchoring. A settlement layer built on these primitives would inherit attribution, ordering, narrowing, and tamper-evidence without requiring a separate trust model.

Settlement architecture details — escrow mechanics, state channel design, fiduciary mapping between protocol primitives and legal concepts — are active research.

---

## 12. Ethics, Non-Goals, and Misuse Resistance

### 12.1 The Co-option Risk

Accountability infrastructure can become surveillance infrastructure depending on deployment. ZeroPoint mitigates this through three mechanisms:

1. **Constitutional constraints** that evaluate before every action and cannot be removed or overridden at runtime.
2. **Public tenets** — documented intent and boundaries, implemented as the first rules to run in the PolicyEngine.
3. **Protocol-level design choices** that track actions rather than identities: pseudonymous keypairs, no identity binding in protocol, action-level receipts, structural amnesia in discovery.

### 12.2 Pseudonymity and Privacy

The chain is pseudonymous. A keypair's receipt history is visible to peers, but the mapping from keypair to human identity is not embedded in the protocol. Whether and how keys are bound to persons is a deployment decision, explicitly outside protocol scope (§5.2).

This distinction matters: an accountability system that tracks actions is different from a surveillance system that tracks people. ZeroPoint's design choices lean toward the former — they are deliberate decisions, not incidental properties of the architecture.

Any system producing durable, verifiable records creates potential for those records to be used in unintended ways. There is no technical solution to this that does not also eliminate the accountability the records provide. The design tradeoffs here — pseudonymous by default, no behavioral profiles, no content inspection in discovery — represent considered choices that can be evaluated by anyone examining the protocol.

### 12.3 Genesis Responsibility

The choices made at Genesis — sovereignty provider, constitutional rules, operator identity — propagate through every subsequent action. A careless Genesis produces a deployment that inherits that carelessness at every step. This is a feature, not a limitation: it makes the founding conditions explicit and verifiable rather than implicit and deniable.

### 12.4 Non-Goals

ZeroPoint does not aim to:

- Become a compliance product. Compliance is an external checklist; ZeroPoint is protocol infrastructure.
- Become a centralized authority. There is no ZeroPoint server, no ZeroPoint cloud, no ZeroPoint corporation controlling access.
- Guarantee that every deployment honors the Tenets. Constitutional rules make misuse structurally harder within the protocol; what happens beyond the protocol boundary depends on community norms and incentives.
- Be tied to any single transport or network.
- Be agent-only infrastructure. The protocol is participant-agnostic.

---

## 13. Conclusion

### What ZeroPoint Claims

ZeroPoint provides protocol-level primitives that make the following properties verifiable:

1. **Attribution.** Every action produces a signed receipt. The receipt proves a specific Ed25519 key attested to a specific action at a specific time.

2. **Ordering.** Receipts are hash-chained. The chain establishes a total order over events that resists retroactive rewriting. Tampering with any entry invalidates every subsequent hash.

3. **Authorization traceability.** Every capability grant traces back through a delegation chain to a human-held Genesis key. The chain is verified against eight invariants; violation of any invariant rejects the chain.

4. **Governance enforcement.** `HarmPrincipleRule` and `SovereigntyRule` evaluate before every action and cannot be removed, overridden, or reordered. This is enforced in the PolicyEngine's evaluation order, not by policy.

5. **Portability.** Identity is a keypair. Receipts are self-contained. Chains are independently verifiable. No platform, server, or central authority is required. Any transport that can carry bytes can carry the governance primitives.

6. **External verifiability.** Chain state can be anchored to independent distributed ledgers, creating publicly queryable timestamps that no single party controls. Anchoring is optional (the chain operates with full integrity without it), event-driven, and DLT-agnostic.

All six claims are testable against the codebase, verifiable by independent auditors using offline chain verification, and falsifiable against specific inputs.

### What ZeroPoint Does Not Claim

- **It does not prove truth.** A receipt proves a statement was signed, not that it is true.
- **It does not prevent all misuse.** Constitutional rules make misuse structurally harder within ZeroPoint deployments. Governance beyond the protocol boundary depends on community norms and incentives.
- **It does not bind keys to persons.** The protocol is pseudonymous by design.
- **It does not guarantee runtime integrity.** A compromised host can sign whatever it wants.
- **It does not solve AI safety.** It makes actions provable, authority traceable, and governance constraints enforceable at the protocol layer.
- **The trace layer is not yet implemented.** The receipt chain and observation loop are complete and tested. The trace layer is a planned extension.

### Summary

The accountability gap in deployed systems — mutable logs, informal authorization, platform-controlled identity — is a structural problem, not a configuration problem. Adding policy frameworks on top of systems that lack cryptographic evidence primitives does not close it.

ZeroPoint provides those primitives: signed receipts that make actions provable, hash chains that make history tamper-evident, capability grants that make delegation verifiable, and constitutional constraints that make governance non-bypassable. The primitives compose — receipts into chains, chains into fleet topologies, anchored chains into cross-organizational trust. And they are portable: identity is a keypair, receipts are self-contained, and verification requires no platform cooperation.

AI agents are the most urgent application, but the design is participant-agnostic. The same properties apply to humans, services, and devices operating within the same framework.

---

## Appendix A: Protocol Sketch

This is not a full specification. It shows rigor and invites contribution.

### A.1 Identities

Participants hold Ed25519 signing keypairs and derive X25519 key-agreement keys for encrypted link establishment. A 128-bit destination hash is computed as the truncated SHA-256 of the public key, compatible with Reticulum's identity model and used across all ZeroPoint transports.

Trust tiers:
- **Tier 0**: Unsigned. No cryptographic identity.
- **Tier 1**: Self-signed Ed25519. Controls a keypair but has no chain authority.
- **Tier 2**: Chain-signed with genesis root. Holds a valid delegation chain to a human-held key.

Identity binding to physical persons is deployment-dependent and outside the protocol scope.

### A.2 CompactReceipt Envelope

MessagePack with short field names for bandwidth efficiency:

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

Typical size: 150–300 bytes. Maximum for single-packet mesh transmission: 380 bytes (with MeshEnvelope overhead, within the 465-byte payload limit).

### A.3 MeshEnvelope

The mesh transport's outer wrapper:
- **Envelope type**: Receipt, Delegation, AuditChallenge, AuditResponse, PolicySync, ConsensusVote, ReputationUpdate, or Custom.
- **Sequence number**: Monotonic u64 for replay detection.
- **Source/destination**: 128-bit mesh destination hashes.
- **Signature**: Ed25519 over the envelope payload.

### A.4 Chain Verification Rules

`DelegationChain::verify()` enforces the eight invariants from §6.2: parent linkage, monotonic depth, scope subsetting, tier non-decreasing, expiration inheritance, max depth, grantor-grantee matching, and signature verification. Any single invariant failure rejects the entire chain.

---

## Appendix B: Glossary

### Terminology Notes

Three terms are used with specific discipline:

- **"Trajectory"**: used only when all three properties are present — evidence, ordering, and replayability.
- **"Markovian"**: snapshot-only verification; the system checks only current state with no ordered history required.
- **"Autoregressive"**: used only when both the step and the conditioning context are named explicitly.

### Terms

**Receipt**: Signed evidence of an action or decision. Contains receipt ID, type, status, trust grade, Blake3 content hash, timestamp, parent receipt reference, policy decision, rationale, Ed25519 signature, and optional extensions. Encoded as MessagePack, 150–300 bytes. The atomic unit of evidence in ZeroPoint.

**Chain**: Linked sequence of receipts where each `pr` field references the previous `id`, creating a hash-linked, tamper-evident sequence with total ordering and incremental verification.

**Trajectory**: A chain satisfying three properties: (1) evidence — each step is a signed receipt with a content hash; (2) ordering — steps are sequenced by hash-linked `pr` fields; (3) replayability — the full chain can be re-verified deterministically from Genesis to tip.

**Markovian**: Snapshot-only verification — checking only current state without requiring ordered history. A mutable log is Markovian evidence: each entry stands alone, and rewriting any entry is locally undetectable.

**Snapshot**: A single-point-in-time check with no reference to ordered history. ZeroPoint treats snapshots as insufficient for trust verification of authorization chains.

**Narrowing**: The property of delegation chains whereby each successive delegation can only constrain, never widen, the authority of the previous grant. Enforced by the eight delegation invariants.

**Invariant**: A property verified on every evaluation whose violation causes rejection. Two classes: delegation invariants (eight rules, any violation dissolves the chain); constitutional invariants (`HarmPrincipleRule` and `SovereigntyRule`, non-removable).

**Trace Commitment**: A hash anchored in a receipt committing to the computational trajectory a model traversed during inference. Future work; see `docs/future-work/cognitive-accountability.md`.

**Error Basin**: A dense region of activation space where a model repeatedly applies the same faulty reasoning circuit. Detectable via layer-wise logit fingerprint clustering (MEDS, 2025). In a ZeroPoint context: a signal that an agent is exhibiting low cognitive diversity even when surface outputs appear acceptable.

**Confabulation Gap**: The measurable divergence between an agent's stated reasoning and its actual computational path. Requires the trace layer to measure; conceptual until that layer is implemented.

**Capability Grant**: Signed permission token with scope, time window, cost ceiling, rate limit, delegation depth, and trust tier constraints. Delegatable subject to the narrowing principle.

**Delegation Chain**: Ordered sequence of capability grants from root (human-held) to leaf (most-delegated), verified against eight invariants. Authority narrows as the chain lengthens. A revoked parent invalidates all children.

**Policy**: Constraints evaluated by the PolicyEngine in a fixed order. The evaluation order is itself an invariant.

**Constitutional Constraint**: Non-overridable rule in the PolicyEngine — specifically `HarmPrincipleRule` and `SovereigntyRule` — that cannot be removed, bypassed, or overridden by any rule, WASM module, or consensus vote.

**Guard**: Pre-action sovereignty check. Local-first, runs before the PolicyEngine. Evaluates the node's own chain, grants, and constitutional rules before accepting any external input.

**GovernanceGate**: The pipeline through which every action must pass: Guard → Policy → Execute → Audit.

**Genesis**: The origin ceremony of a ZeroPoint deployment. Generates the root Ed25519 keypair, seals constitutional rules, and establishes the initial conditions from which all subsequent trust is derived. Sequential, irreversible.

**Sovereignty Provider**: The mechanism protecting the Genesis secret. Options: biometric (Touch ID, fingerprint), hardware wallet (Trezor, YubiKey), OS keychain (macOS Keychain, Linux Secret Service), file-based (fallback).

**Trust Tier**: Six graduated trust levels. T0: unsigned. T1: self-signed Ed25519. T2: chain-signed with Genesis root. T3: anchored externally. T4: anchored with fleet membership attestation via lease renewal. T5: sovereign — full trust with constitutional governance, active reputation, and verified upstream binding.

**Reticulum-compatible**: Wire-interoperable with Reticulum's HDLC framing, 128-bit destination hashing, Ed25519/X25519 cryptography, and 500-byte MTU.

**CompactReceipt**: MessagePack-encoded receipt using short field names. ≤ 380 bytes including MeshEnvelope overhead.

**Presence Plane**: The discovery layer — how peers find each other. Dual-backend (web relay + Reticulum mesh), structurally amnesic, with reciprocity enforcement. Distinct from the Governance Plane (how peers act together).

**DiscoveryBackend**: Trait with four methods: `announce`, `poll_discoveries`, `is_active`, `shutdown`.

**Structural Amnesia**: The web relay's architectural inability to surveil: it never parses, indexes, or persists announce payloads. Privacy by design, not by policy.

**Reciprocity Enforcement**: Relay rule requiring clients to announce before receiving peer announcements. Connections that do not announce are terminated after a grace period.

**ConnectionBehavior**: Counters-only summary emitted when a relay connection closes. Maps to `ReputationSignal` in the `PolicyCompliance` category.

**MeshNode**: High-level transport primitive managing interfaces, peers, links, delegations, and reputation.

**Collective Audit**: Peer-to-peer chain verification via `AuditChallenge` / `AuditResponse` / `PeerAuditAttestation`. No central auditor.

**Truth Anchor**: External distributed ledger timestamp for the receipt chain's state. DLT-agnostic. Optional — the chain operates with full integrity without one.

**Anchor Commitment**: Published to an external ledger: chain head hash, chain sequence, previous anchor hash, operator signature, chain type, and trigger. A few hundred bytes; the ledger sees a fingerprint, not the governed data.

**Anchor Receipt**: The ledger's proof of publication: transaction ID, consensus timestamp, original commitment, and ledger-specific verification data. Stored in the chain as a regular receipt.

**Anchor Trigger**: Why anchoring was initiated. Six variants: operator-requested, cross-mesh introduction, compliance checkpoint, dispute evidence, opportunistic (piggyback on existing transaction), governance lifecycle event.

---

## Appendix C: Example Integration Pattern

A tool runner integrated with ZeroPoint operates as follows: any participant requesting execution must provide a receipt chain proving it holds a valid `CapabilityGrant` scoped to the specific action, signed by a chain terminating at a human-held Tier 2 key. The runner's GovernanceGate verifies the chain locally — all eight delegation invariants, constitutional rules, operational policy, capability expiration, and rate limits. If verification fails, the runner emits a refusal receipt citing the specific invariant or rule that failed. If it succeeds, the tool executes and the runner emits an execution receipt with the action, input hash, output hash, and policy decision. Both receipts join the audit chain.

This pattern is identical whether the requester is an agent, a human operator using the CLI, or an automated service. The protocol does not distinguish between them at the cryptographic layer — only at the trust tier level, where Tier 2 requires a verifiable delegation path back to a human root.

---

## Appendix D: Verification Mechanisms and Testable Behaviors

| Claim | Mechanism | Accept | Reject |
|-------|-----------|--------|--------|
| Each receipt is verified against all prior context | Hash chaining: `pr` links to previous `id`; Blake3 hashes are transitive | Unbroken hash-linked chain from Genesis to tip | Any missing receipt or hash mismatch |
| Node state is derived from complete history | `AuditChallenge` / `AuditResponse` / `PeerAuditAttestation` | Full chain matches claimed state; signed attestation issued | Incomplete chain → negative reputation signal |
| Constitutional rules enforced locally, no coordinator | PolicyEngine fixed order: HarmPrincipleRule → SovereigntyRule → operational → WASM → default | Receipt with valid policy decision from compliant engine | Receipt attesting to blocked action rejected by peers |
| Delegation narrows authority at each step | `DelegationChain::verify()` — 8 invariants | All 8 invariants satisfied | Any single violation dissolves the entire chain |
| Genesis key present in every trust decision | `zp-keys` hierarchy: Genesis → Operator → Agent | Certificate chain walks to Genesis key | Chain terminates at non-Genesis root |
| Genesis ceremony is sequential and atomic | `onboard/genesis.rs`: generate → validate → enroll → seal → write; each step requires prior | `genesis.json` written with all fields populated | Ceremony halts at first failed step; no partial Genesis |
| Child grants cannot exceed parent scope | `CapabilityGrant` fields enforced per-field: scope, `valid_until`, `max_delegation_depth`, tier | Child scope ⊆ parent, child expiration ≤ parent, child depth = parent + 1 | Any widening attempt |
| Reputation accumulates from interaction history | `ReputationSignal` from receipts + `ConnectionBehavior` summaries | Peer with sustained positive history passes reputation gate | Broken chains or reciprocity violations accumulate negative signals |
| Chain verification catches retroactive rewrites; single-entry verification does not | Hash-chained audit vs. isolated entry log | Full chain verified end-to-end | Single-entry check misses rewrites that propagate hash invalidation |
| Constitutional rules are non-removable | Fixed at positions 1 and 2 in evaluation order | Both rules evaluate at every step | Any attempt to remove, reorder, or override returns `SovereigntyRule` block |
| Three-layer accountability stack | Receipt chain → observation loop → trace layer | All layers consistent | Trace diverges from stated reasoning or lands in error basin *(trace layer: future work)* |

---

*ZeroPoint is maintained by ThinkStream Labs.*
*Contact: ken@thinkstreamlabs.ai*
*Repository: https://github.com/zeropoint-foundation/zeropoint*
*Website: https://zeropoint.global*

---

*© 2026 ThinkStream Labs. This document is released under CC BY 4.0. The ZeroPoint codebase is released under MIT/Apache-2.0.*
