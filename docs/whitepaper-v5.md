# ZeroPoint

## Cryptographic Governance Primitives for Accountable Systems

**Whitepaper v5.0 — June 2026**
**ZeroPoint Open Foundation**

Status: Public Technical Overview
License: CC BY 4.0 (text); Code remains MIT/Apache-2.0
Canonical URL: https://zeropoint.global/whitepaper
PDF: [zeropoint-whitepaper-v5.0.pdf](https://zeropoint.global/zeropoint-whitepaper-v5.0.pdf)

**How to cite:**
> ZeroPoint Open Foundation. "ZeroPoint: Cryptographic Governance Primitives for Accountable Systems." Whitepaper v5.0, June 2026. https://zeropoint.global/whitepaper

---

## Abstract

ZeroPoint is a cryptographic governance framework: signed, hash-chained receipts that make actions provable; delegatable capability grants that narrow in scope as they propagate; and two non-removable constitutional rules that evaluate before every action. The framework is participant-agnostic and transport-agnostic — the same primitives apply to humans, agents, automated services, and devices over HTTP, TCP, encrypted mesh, or any future transport.

Implemented in Rust. Ships with a Reticulum-compatible mesh transport, TCP/UDP interfaces, an HTTP API, and a dual-backend peer discovery layer (the Presence Plane) that operates without centralized registries. ZeroPoint does not claim to solve AI safety. It provides the protocol-layer substrate that makes actions provable, authority traceable, and governance constraints non-bypassable without requiring any central witness.

---

## Table of Contents

1. Background
2. Design Approach
3. Design Goals
4. System Overview
5. Receipts and Chains
6. Governance Model
7. Threat Model
8. Transport Integrations
9. The Presence Plane
10. External Truth Anchoring
11. Fleet Topology
12. Ethics, Non-Goals, and Misuse Resistance
13. Conclusion

Appendix A: Protocol Sketch
Appendix B: Glossary
Appendix C: Example Integration Pattern
Appendix D: Verification Mechanisms and Testable Behaviors

---

## 1. Background

Trust primitives — identity, reputation, authorization — are typically implemented at the platform layer, not the protocol layer. That means they cannot move with participants. Credentials and history live in a vendor's database; switching platforms means starting over. Authorization is API keys or ambient permissions rather than cryptographically scoped grants. When actions cross organizational boundaries, there is no shared evidence base both parties can independently verify.

Autonomous AI agents make the problem acute. Agents act at machine speed across organizational boundaries with delegation chains that can extend far beyond their original scope. Existing infrastructure — mutable logs, informal authorization, platform-controlled identity — was designed for human-in-the-loop workflows, not autonomous operation at scale. But the accountability gap is not new; agents expose and accelerate a structural deficit that predates them.

ZeroPoint addresses this with three primitives: signed, hash-chained receipts that make actions provable and their ordering tamper-evident; cryptographic capability grants that make authorization verifiable, portable, and delegatable with enforced narrowing; and constitutional constraints that make governance non-bypassable at the protocol layer. These primitives are participant-agnostic — the same properties apply to humans, agents, services, and devices.

---

## 2. Design Approach

### 2.1 Chain-Based Verification

The central design choice: verification must be history-dependent. A system that checks only the current state of a credential — is this token valid right now? — cannot detect retroactive tampering. If only the latest log entry needs to be valid, earlier entries can be rewritten without detection. If only the current state of a permission is checked, there is no way to know whether it was legitimately delegated or injected.

ZeroPoint makes each receipt carry a cryptographic reference to its predecessor. Verifying a receipt requires walking the chain back to Genesis, checking each link. Rewriting any single entry requires rewriting every subsequent entry and convincing every independent verifier to accept the rewrite — computationally infeasible at even modest peer counts.

Chain verification is O(n) in chain length rather than O(1). In practice it is incremental: a peer that has already verified entries 1–1000 does O(1) work for entry 1001. Section 5.5 addresses long-chain bounds via epoch-based compaction.

### 2.2 Four Testable Properties

**Property 1 — Each receipt is verified against all prior context.**
Every receipt's `pr` field references its predecessor's `id`. Blake3 hashing is transitive through the chain. **Accept**: unbroken hash-linked sequence from Genesis to tip. **Reject**: any gap or hash mismatch.

**Property 2 — A node's current state is deterministic from its history.**
Keychain, capability grants, audit trail, and reputation are all derived from the complete history of Genesis, delegations, actions, and verifications. Two nodes with identical histories produce identical states. A node that cannot produce the chain supporting its claimed state fails collective audit. **Accept**: full chain produced; signed `PeerAuditAttestation` issued. **Reject**: incomplete chain generates a negative reputation signal.

**Property 3 — Constitutional rules are enforced locally at every node.**
No global coordinator enforces `HarmPrincipleRule` and `SovereigntyRule`. Each node evaluates them independently before every action. A node that removes or bypasses these rules produces receipts that peers reject during chain verification. **Accept**: receipt contains a valid policy decision from a compliant engine. **Reject**: receipt attesting to a constitutionally blocked action is rejected by peers.

**Property 4 — Delegation monotonically narrows authority.**
The leaf grant of a depth-N chain has scope ⊆ every ancestor's scope, expiration ≤ every ancestor's expiration, and depth == N. **Accept**: all eight delegation invariants satisfied. **Reject**: any single invariant violation dissolves the entire chain.

### 2.3 Genesis

The Genesis ceremony generates a 32-byte Ed25519 seed from which all trust in the deployment derives. Every operator key is signed by the Genesis key; every agent key is signed by an operator key; every capability grant traces back to Genesis. Certificate chain verification walks to the Genesis root on every trust decision — if the Genesis key is not at the root, verification **rejects**. This is an invariant of `zp-keys`, not a policy.

The ceremony is sequential and irreversible: generate keypair → validate sovereignty provider → enroll biometric or hardware confirmation → seal constitutional rules → write the immutable genesis record. Each step requires the prior step's success, enforced in `onboard/genesis.rs`.

### 2.4 Delegation Narrowing

A root capability grant specifies four constraint dimensions: **scope** (permitted actions and targets), **time** (`valid_from` / `valid_until`), **depth** (`max_delegation_depth`), and **trust tier** (minimum tier to exercise the grant). Each subsequent delegation may only narrow these bounds:

- Child scope ⊆ parent scope (invariant 3)
- Child expiration ≤ parent expiration (invariant 5)
- Child depth = parent depth + 1, ≤ `max_delegation_depth` (invariants 2, 6)
- Child trust tier ≥ parent trust tier (invariant 4)

A revoked parent invalidates all descendants: chain verification walks root to leaf, and any revoked or expired link causes full chain **rejection**.

### 2.5 Reputation

A peer's reputation accumulates from its complete interaction history: successful receipts generate positive signal, broken chains generate negative signal, behavioral anomalies (silent consumption, reciprocity violations, missing announces) degrade standing. Reputation is never a point-in-time snapshot.

### 2.6 Three Accountability Layers

**Layer 1 — Receipt Chain.** Records what happened: signed, hash-linked, replayable from Genesis to tip.

**Layer 2 — Observation Loop.** GovernanceGate pipeline (Guard → Policy → Execute → Audit) enforces what should happen at action time. Assessments from peer challenges and collective audit join the chain.

**Layer 3 — Trace Layer (planned).** A hash commitment in each receipt would commit to the model's actual computational trajectory during inference — the sequence of features, relations, and activations consulted. This would make confabulation (stated reasoning diverges from computation), mode collapse (reasoning fingerprints cluster in error basins), and reasoning drift detectable. Not yet implemented; the receipt and policy primitives accommodate it without modification.

---

## 3. Design Goals

**Protocol-level accountability.** Every significant action produces a signed receipt linked to its predecessor. The chain is offline-auditable with no running server required.

**Sovereignty by design.** Governance primitives evaluate locally — each node checks its own chain, grants, and rules before acting. No remote authority is consulted for permission. The framework runs over HTTP, TCP, or encrypted mesh with equal governance guarantees.

**Non-bypassable constraints.** Two constitutional rules are fixed at positions 1 and 2 in the PolicyEngine's evaluation order. They cannot be removed, reordered, or overridden by any rule, WASM module, or operator action.

**Honest security posture.** The framework is explicit about what it prevents and what it does not. See §7.

**Transport agnosticism.** Receipt format, capability grants, delegation chains, and policy evaluation are identical across all transports. Adding a new transport requires implementing one interface trait; the governance primitives are unchanged.

---

## 4. System Overview

ZeroPoint is a set of layered Rust crates. Any entity holding a keypair — human, agent, service, device — is a full peer.

- **Identity layer.** Ed25519 signing keys and X25519 key agreement. Identity is a keypair; authentication is a signature.
- **Governance layer.** PolicyEngine with constitutional rules, composable operational rules, WASM-extensible policy modules, and capability gating.
- **Receipt layer.** Signed, hash-chained receipts. CompactReceipt encoding: 150–300 bytes, suitable for bandwidth-constrained transports.
- **Transport layer.** Pluggable: Reticulum-compatible mesh, TCP client/server, UDP, HTTP API.
- **Presence Plane.** Dual-backend peer discovery — privacy-preserving web relay and Reticulum mesh broadcast. See §9.
- **Application layer.** Pipeline orchestration, LLM provider integration, skill registry, CLI.

### 4.1 GovernanceGate Pipeline

Every action passes through this sequence:

1. **Guard** — Pre-action sovereignty check. Evaluates the node's own chain, grants, and constitutional rules before accepting any external input. No external authority consulted.
2. **Policy** — Constitutional rules first, then operational rules, then WASM modules. Most restrictive decision wins.
3. **Execute** — Runs only if Guard and Policy both allow.
4. **Audit** — Emits a signed, hash-linked receipt and persists it to the chain.
5. **Transport** — Receipts propagate to peers. Peers verify independently.

Nothing executes without passing through the gate. Nothing passes through the gate without joining the chain.

---

## 5. Receipts and Chains

### 5.1 Receipt Structure

| Field | Wire Name | Description |
|-------|-----------|-------------|
| Receipt ID | `id` | Unique identifier |
| Receipt Type | `rt` | `execution`, `intent`, `approval`, `delegation`, `verification`, `refusal` |
| Status | `st` | `success`, `partial`, `failed`, `denied`, `timeout`, `pending` |
| Trust Grade | `tg` | `A`–`D`, determined by chain completeness and verification |
| Content Hash | `ch` | Blake3 hash of the action content |
| Timestamp | `ts` | Unix timestamp (seconds) |
| Parent Receipt | `pr` | Previous receipt ID |
| Policy Decision | `pd` | `allow`, `deny`, `escalate`, `audit` |
| Rationale | `ra` | Policy decision explanation |
| Signature | `sg` | Ed25519 signature over the content hash |
| Extensions | `ex` | Compact JSON for domain-specific fields |

Wire format: MessagePack with short field names. Typical size: 150–300 bytes. Maximum for single-packet mesh transmission: 380 bytes (within the 465-byte LoRa payload limit).

### 5.2 What Receipts Prove and What They Don't

**Prove:**
- A specific Ed25519 key signed a specific statement at a specific time.
- The chain contains a consistent, unbroken sequence of signed events.
- The PolicyEngine evaluated a known rule set and produced a specific decision.
- A capability grant was valid at the time of action.

**Do not prove:**
- The nature of the signer. A receipt attests that a key signed something, not whether that key belongs to a human or an agent. Identity binding to physical persons is deployment-dependent and out of protocol scope.
- That the action content was correct or safe. Governance constrains actions; it does not evaluate their content.
- That the runtime environment was uncompromised. A compromised host can produce arbitrary valid receipts.

### 5.3 Chain Properties

The `pr` field is what distinguishes a chain from a log. Without it, each receipt is an isolated signed fact. With it, each receipt is a step in a sequence that requires the full ordered history to verify.

A chain provides three properties isolated receipts cannot:

**Ordering.** Chain position, not timestamp, determines sequence. Two receipts with identical timestamps are still ordered by their `pr` linkage.

**Tamper-evidence.** Modifying receipt N invalidates the hash of every subsequent receipt. An attacker must rewrite N through the chain tip and convince every independent verifier to accept the rewrite.

**Replayability.** The full chain can be re-executed from Genesis to verify that every action was authorized, every policy decision was valid, and every delegation was within scope at the time.

**Accept/reject.** A chain **accepts** when every `pr` linkage is intact, every hash consistent, and every signature valid. It **rejects** on any gap, hash inconsistency, or signature failure. Rejection is binary and propagates: one broken link invalidates everything downstream.

Peers can challenge each other's chains directly. A challenged peer produces its full chain; the challenger verifies and issues a signed `PeerAuditAttestation`. Broken chains generate negative reputation signals. No central auditor is required.

### 5.4 Why History-Dependence Is Not Optional

Snapshot-only verification — checking only whether a credential is currently valid — cannot detect retroactive tampering, injected permissions, or unauthorized delegation insertions. History-dependence closes these gaps by ensuring that any modification propagates as a hash failure that every subsequent verifier catches.

### 5.5 Chain Compaction — Epochs

At scale, walking the full chain from Genesis on every verification becomes impractical. An agent doing 1,000 actions/day produces 365,000 receipts/year; a 100-agent fleet produces 36.5M. ZeroPoint uses epoch-based compaction to bound active memory regardless of total history.

**Mechanism.** When an epoch fills (8,192 entries or 7 days, whichever comes first), a Merkle tree is computed over its entries. The root — a 32-byte Blake3 hash committing to every entry — is recorded in a signed `EpochSeal`. The seal joins the chain as a regular receipt, preserving hash linkage. Individual epoch entries can then be archived and removed from active storage. Seals back-reference each other, forming a verifiable chain-of-seals.

**Verification modes after compaction:**

| Mode | What to walk | Cost |
|------|-------------|------|
| Recent activity | Current unsealed epoch | Full walk, ≤ 8,192 entries |
| Historical integrity | Seal chain | Dozens of seals, not millions of entries |
| Spot-check one entry | Merkle inclusion proof | 13 hashes (416 bytes, one mesh packet) |
| Forensic reconstruction | Full archived epoch | Retrieve entries, reconstruct Merkle tree |

**Memory bounds.** Working set: one unsealed epoch (~4 MB) plus the most recent seal. An agent running for five years holds the same active memory as a new one. The seal chain grows ~500 bytes/week; five years of seal history is ~111 KB. Archived epoch data grows linearly and can be offloaded per the operator's retention policy.

**What compaction does not do:**

- *Disaster recovery.* If archived entries are lost with no peer copies, the seal proves they existed but cannot reconstruct content. Durability requires replication — a deployment decision.
- *Fabrication prevention.* A compromised node can produce a valid seal over fabricated entries. The seal proves internal consistency, not truth. Peer attestation is the primary defense: peers spot-check entries against their own interaction records.
- *Retention policy.* When local archives expire, individual actions in those epochs become unexaminable. Only the seal chain's structural summary remains. Audit depth vs. storage cost is the operator's tradeoff.

Implemented in `zp-receipt::epoch`. Designed after integrity guarantees were established (699 tests at design time).

---

## 6. Governance Model

### 6.1 Capability Gating

Every participant — human, agent, or service — must hold a valid `CapabilityGrant` to act. A grant is a signed, portable authorization token with:

- Scope (which actions, which targets)
- Cost ceiling and rate limit
- Time window (`valid_from`, `valid_until`)
- Delegation depth limit (`max_delegation_depth`)
- Minimum trust tier
- Grantor's Ed25519 signature

Any grant holder can delegate a subset to another participant, forming a `DelegationChain`. The chain is verified against eight invariants:

1. Each grant references the previous as `parent_grant_id`.
2. Depths increment monotonically (0, 1, 2, ...).
3. Child scope ⊆ parent scope.
4. Child trust tier ≥ parent trust tier.
5. Child expiration ≤ parent expiration.
6. Chain depth ≤ `max_delegation_depth` set by the root.
7. Each grant's grantor matches the previous grant's grantee.
8. All signatures verify.

Any invariant violation rejects the entire chain.

### 6.2 PolicyEngine and Constitutional Rules

Rules evaluate in a fixed order:

```
1. HarmPrincipleRule      ← Constitutional (immovable)
2. SovereigntyRule        ← Constitutional (immovable)
3. ReputationGateRule     ← Operational
4. WASM policy modules    ← Sandboxed, fuel-limited
5. DefaultAllowRule       ← Fallback
```

Severity: Block(5) > Review(4) > Warn(3) > Sanitize(2) > Allow(1). Most restrictive wins. WASM modules can override the default allow but cannot override constitutional rules.

**`HarmPrincipleRule`** blocks actions targeting weaponization, unauthorized surveillance, deception (deepfakes, impersonation), and suppression of dissent. Cannot be bypassed by capability grants, policy configuration, or consensus votes.

**`SovereigntyRule`** blocks configuration changes that would disable the guard, truncate the audit trail, forge or bypass capabilities, remove constitutional rules, or override agent refusal.

Both rules evaluate at every step — step 1,000,000 with the same force as step 1.

### 6.3 Protocol Tenets

Four tenets are embedded in the protocol and enforced in code:

**I. Do No Harm.** `HarmPrincipleRule` is non-removable and evaluates before every action.

**II. Sovereignty Is Sacred.** Every participant can refuse any action. Every human can disconnect any agent. No agent acquires uncapabilities it was not granted. Enforced locally by the Guard, without consulting any external authority.

**III. Action Without Evidence Is No Action.** Every action produces a receipt. Every receipt joins the chain. An action absent from the chain did not happen; an action present cannot be expunged.

**IV. The Human Is The Root.** Every delegation chain terminates at a human-held key. No agent self-authorizes.

### 6.4 Key Hierarchy and Introduction Protocol

`zp-keys` implements a three-level certificate hierarchy:

```
GenesisKey       ← self-signed root (one per deployment)
  └─ OperatorKey ← signed by genesis
      └─ AgentKey← signed by operator
```

Any node verifies agent identity by walking this chain offline — no network or policy state required. Six certificate invariants: valid signatures, issuer linkage, role hierarchy, monotonic depth, no expired certs, hash linkage.

The key hierarchy is independent of the policy engine to avoid circular dependency: establishing the engine's authority across nodes requires keys; keys cannot depend on the engine existing. The *decision* to issue a child cert flows through the policy engine as `ActionType::KeyDelegation` (Critical risk); the *signing mechanism* is unconditional.

New node introductions use `zp-introduction`: the initiator sends its certificate chain and a challenge nonce; the responder verifies and evaluates `ActionType::PeerIntroduction` through the policy engine. Same-genesis introductions are High risk; cross-genesis are Critical.

Key *discovery* — finding peers' network addresses — is handled separately by the Presence Plane (§9).

---

## 7. Threat Model

| Threat | Capability | Mitigation | Residual Risk |
|--------|-----------|------------|---------------|
| **Log forgery / retroactive rewriting** | Alter history to change attribution | Ed25519 + Blake3 hash chain; collective audit via `AuditChallenge` / `PeerAuditAttestation` | Compromised keys can sign lies; revocation is deployment-dependent |
| **Unauthorized tool use** | Execute beyond intended scope | `CapabilityGrant` gating; 8-invariant delegation chain verification; PolicyEngine evaluates before every action | Gaps possible with poorly designed grants |
| **Cross-operator trust failure** | Cannot verify another party's agent outputs | Independent receipt verification; `zp-introduction` certificate exchange; dual-backend discovery | Cross-genesis introductions require operator-configured policy |
| **Passive scanning** | Harvest peer identities without announcing | Reciprocity enforcement: must announce before receiving. Structurally amnesic relay | A scanner that announces gains initial access; behavioral reputation detects parasites over time |
| **Sybil flooding** | Overwhelm discovery with cheap fake identities | Credible anchor history requires sustained ledger cost; reputation weights anchor depth | Well-funded attackers can maintain anchored identities; defense is economic, not absolute |
| **Security theater** | Claim governance without enforcing it | Constitutional rules non-removable; receipts independently verifiable | MIT/Apache-2.0 permits stripping constraints from a fork |
| **Surveillance co-option** | Use receipts to track people, not actions | Pseudonymous keypairs; action-level receipts only; Presence Plane structural amnesia | License cannot prevent misuse |
| **Replay attacks** | Resend captured packets | Monotonic u64 sequence numbers; 16-byte nonces in link handshake; Ed25519 over content hashes | Depends on peers tracking seen sequences; long-offline nodes may have gaps |
| **Mesh injection** | Insert forged packets | HDLC + CRC; Ed25519 on all envelopes; X25519 ECDH link encryption | Requires successful link establishment for encryption |
| **WASM policy escape** | Malicious module breaks sandbox | Wasmtime with fuel limiting; hash verification before loading | Fuel exhaustion is DoS at worst; escape requires a Wasmtime vulnerability |
| **Identity misbinding** | Misattribute key to wrong entity | Six trust tiers; T2+ requires verified delegation from a human-held key | Binding keys to physical persons is deployment-dependent |

**What ZeroPoint does not solve:**

- Misuse by a deployment that strips the constitutional constraints out of a fork. MIT/Apache-2.0 permits this.
- Truth verification. Receipts prove provenance and chain integrity, not the correctness of what was signed.
- Absolute Sybil resistance. The defense is economic (sustained anchor cost per identity), not mathematical.
- Runtime integrity. A compromised host produces valid-looking receipts.

---

## 8. Transport Integrations

The governance primitives — receipts, capability grants, delegation verification, PolicyEngine — are identical across all transports. Transport is an implementation detail.

### 8.1 HTTP API

Axum-based REST server. Standard HTTP/HTTPS for cloud deployments, container orchestration, and web service integration.

### 8.2 TCP and UDP

`TcpClientInterface` / `TcpServerInterface` with HDLC framing and CRC verification for persistent connections. UDP for connectionless receipt exchange. Multiple interfaces run simultaneously on one node.

### 8.3 Reticulum-Compatible Mesh

Wire-level interoperable with the Reticulum Network Stack (Mark Qvist). Implements:

- HDLC framing with CRC-CCITT verification
- 128-bit destination hashing (truncated SHA-256)
- Ed25519 signing and X25519 ECDH key agreement
- 500-byte MTU / 465-byte data payload (LoRa-compatible)
- 3-packet link handshake (LinkRequest → LinkProof → LinkAccept) with 16-byte nonces

### 8.4 Extensibility

A new transport requires implementing one interface trait and providing envelope serialization. A new discovery backend requires implementing the four-method `DiscoveryBackend` trait. The Presence Plane is decoupled from transport — web and mesh discovery coexist with any transport combination.

---

## 9. The Presence Plane

### 9.1 Problem

`zp-keys` handles key distribution — verifying identity once you have a peer's certificates. Key *discovery* — finding peers' network addresses — is separate. A centralized directory solves it but creates a surveillance and censorship point.

The **Presence Plane** provides discovery using the same Ed25519 identity as the governance layer, without centralized state.

### 9.2 Architecture

Built on the `DiscoveryBackend` trait (four methods: `announce`, `poll_discoveries`, `is_active`, `shutdown`). Two backends ship today:

**Web relay.** Pub/sub over WebSocket. Agents publish signed announce blobs; the relay broadcasts to all subscribers; agents filter locally. The relay never parses payloads, indexes capabilities, maintains query logs, or persists state. Restart erases everything.

**Reticulum mesh.** Announces propagate over mesh interfaces (LoRa, WiFi, serial, TCP). No server. No internet dependency.

Both backends share announce wire format: `[combined_key(64)] + [capabilities_json] + [ed25519_signature(64)]`. Peers discovered via either backend land in the same peer table with the same destination hash. The `DiscoveryManager` fans out announces, validates signatures, deduplicates, and prunes expired entries.

### 9.3 Structural Amnesia

The relay cannot surveil because the capability does not exist in the code. It passes bytes without parsing, indexing, or storing them. This is stronger than a no-logs policy, which can be changed or violated in secret. Subpoena-resistant by construction.

### 9.4 Reciprocity Enforcement

Passive scanning — subscribing to announce traffic without revealing your own identity — is the primary adversarial concern. Defense: **you must announce before you receive.**

1. On connect, client receives a `RelayConnection` handle.
2. `try_receive()` errors until the client has published an announce.
3. Grace period: 30 seconds (configurable).
4. Connections that haven't announced by the grace period deadline are terminated.

Any passive scanner must expose its signed Ed25519 identity to the network before it can observe anyone else.

### 9.5 Behavioral Reputation Integration

Reciprocity stops naive scanners. Sophisticated ones announce once and then silently consume. When connections close, the relay emits `ConnectionBehavior` summaries — counters only, no content:

- `announced`: ever published an announce?
- `announces_published`: how many?
- `duration`: connection lifetime
- `reciprocity_violation`: terminated for not announcing?

These map to `ReputationSignal` in the `PolicyCompliance` category. Consistent participation accumulates positive signal; announce-once-then-consume patterns accumulate negative signal.

### 9.6 Presence Plane Threat Model

| Threat | Attack | Mitigation | Residual Risk |
|--------|--------|------------|---------------|
| Passive scanning | Subscribe without announcing | Reciprocity enforcement; grace period + termination | Scanner that announces gains access; behavioral detection takes time |
| Sybil flooding | Many keypairs, many announces | Anchor history requires sustained cost; reputation weights depth | Economic disincentive only; keypair generation is free |
| Relay compromise | Attacker gains relay access | No data to retrieve (structural amnesia) | Compromised relay can censor announces; relay receipt chain makes this detectable |
| Traffic analysis | Observe connection timing / metadata | No identity-to-IP mapping; relay logs only counters | ISP-level network observation is out of scope |
| Eclipse attack | Surround target with attacker-controlled peers | Dual-backend: Reticulum discovery bypasses relay | Full eclipse (both backends) isolates the target; out-of-band introduction mitigates |

---

## 10. External Truth Anchoring

### 10.1 Purpose

The receipt chain is self-verifying: hash-linked, signed, auditable cold. This provides strong guarantees *within* a deployment. It does not establish when the chain state existed in external calendar time, or provide a witness a third party can query without operator cooperation.

External truth anchoring publishes the chain's current state — head hash, sequence number, operator signature — to an independent distributed ledger. The result is a publicly queryable, tamper-evident timestamp that the operator cannot retroactively modify.

This matters in three contexts:

- **Cross-deployment trust.** When two deployments meet for the first time, anchoring to a common ledger gives each party an independently verifiable history that a freshly fabricated chain cannot reproduce.
- **Dispute resolution.** An anchor proves the chain was in a specific state at an externally-attested time, settling disputes about whether chain state was rewritten after the fact.
- **Compliance audit.** Self-signed timestamps don't satisfy auditors. An anchor on a ledger the regulator already examines has the same evidential weight as any other record in that ledger.

In practice, cross-organizational transactions — supply chain, multi-party agreements, regulated exchanges — nearly always touch a shared ledger. Anchoring governance chain heads to that same ledger adds no infrastructure; it piggybacks on what the transaction already requires.

### 10.2 Architecture

**Optional enrichment.** Without an external ledger configured, ZeroPoint operates exactly as described in §5 — tamper-evident, ordered, offline-auditable. The anchor adds an external witness; it doesn't replace the chain's internal guarantees.

**No dependency.** Anchor receipts join the chain as regular entries. Chain verification never requires the external ledger to be reachable. If the ledger is unavailable, governance continues uninterrupted; anchor emission simply pauses.

**DLT-agnostic.** The `TruthAnchor` trait (three methods: `anchor()`, `verify()`, `query_range()`) can be implemented by any distributed ledger backend. Reference implementation: Hedera Hashgraph's Consensus Service. Also supported: Ethereum L2 calldata, Bitcoin OpenTimestamps, Ceramic streams, or any system that can timestamp and publicly expose an opaque payload.

**Backend selection is the operator's choice.** Cross-deployment trust is established by exchanging anchor backend identifiers; there is no mandated ledger.

### 10.3 What Gets Anchored

| Field | Description |
|-------|-------------|
| Chain head hash | Blake3 hash of the current chain tip |
| Chain sequence | Monotonically increasing chain position |
| Previous anchor hash | Links anchor history |
| Operator signature | Ed25519 over the commitment |
| Chain type | `audit`, `observation`, `reflection` |
| Trigger | Why this anchor was created |

The commitment is compact (~a few hundred bytes) and carries no governed content. The ledger sees a fingerprint, not the data.

### 10.4 Trigger Model

Anchoring is event-driven, not timer-driven. Periodic anchoring adds cost without adding information — the hash chain already detects any modification between anchors.

**Explicit triggers:** operator request, cross-deployment introduction, compliance checkpoint, contested governance action, governance lifecycle event (capability revocation, constitutional rule change, trust tier change).

**Opportunistic:** when the operator makes any blockchain transaction for other purposes, the current chain head hash embeds as transaction metadata at zero marginal cost. This is also the most natural timing — cross-organizational transactions are the context where external witnessing matters most.

### 10.5 Reference Backend: Hedera Hashgraph

Hedera's Consensus Service (HCS) is the reference implementation:

- **Sub-second finality.** 3–5 second deterministic consensus; no probabilistic confirmation.
- **Public verifiability.** Mirror nodes expose all HCS messages. Any party can verify a commitment without operator cooperation.
- **Low cost.** Fraction of a cent per submission.
- **Known governance.** Hedera's council is a publicly listed set of global organizations.

### 10.6 Cross-Deployment Verification

When two deployments meet: each announces its anchor backend identifier, independently queries the other's anchor history, and verifies that chain head hashes match anchor commitments. Anchor history can be walked backward for temporal consistency checks. This is independent verification against a shared public record — not mutual cooperation.

**Sybil economics.** Generating a keypair is free; establishing a credible anchor history requires sustained ledger transactions per identity. The reputation system weights anchor depth — shallow histories receive less trust. The attack becomes economic rather than computational, which structurally favors defenders, though it does not eliminate well-resourced attackers.

### 10.7 Limits

- Does not prove chain *content* is correct — only that the chain was in a specific state at a specific time.
- Does not prevent chain forking — an operator can maintain two chains and anchor only one.
- Does not substitute for internal chain integrity — a chain with broken hash links is broken regardless of anchor history.

---

## 11. Fleet Topology

### 11.1 Chain-Derived Roles

A node's role — Genesis, Delegate, or Standalone — derives from its receipt chain, not its config file. The config file provides a bootstrap hint that is advisory once the chain contains delegation evidence. Config can be edited; chain entries cannot without invalidating all subsequent hashes.

**Genesis.** Performed the Genesis ceremony, holds the root keypair. Exactly one per fleet.
**Delegate.** Holds a valid delegation receipt from an upstream Genesis node. Authority bounded by narrowing invariants.
**Standalone.** No chain evidence of Genesis or delegation. Default role; a revoked delegate returns here.

### 11.2 Role Transition Receipts

Role transitions are chain events, not out-of-band administrative acts. When a node's role changes, a receipt seals the transition: the previous role, the new role, and the cause. Cause vocabulary is constrained: `delegation_accepted`, `delegation_revoked`, `redelegation`, `genesis_performed`. No catch-all. Fleet topology history is auditable with the same tools as any other governed behavior.

### 11.3 Upstream Binding

A delegate carries the upstream Genesis node's Ed25519 public key in its delegation receipt — a cryptographic proof, not a claim.

**Local check (offline):** receipt contains a well-formed 32-byte pubkey. Absent or malformed: `Unbound` or `MalformedPubkey`.

**Remote check (online):** challenge the upstream to prove it holds the key in the receipt. Mismatch: `PubkeyMismatch` — the upstream may have changed identity since delegation. A delegate cannot forge its delegation receipt without the upstream's signing key, and cannot silently swap upstreams.

### 11.4 Liveness and Lease Renewal

Fleet membership requires lease renewal. Each delegate's `CapabilityGrant` has a bounded lifetime, renewed at a configured cadence by presenting a valid Ed25519 signature to a designated renewal authority.

A delegation receipt proves authority was granted. A valid lease proves it remains active. Renewal failure triggers a grace period; expiry activates the configured failure mode: `halt` (fail closed), `degrade` (read-only), or `continue-with-flag` (for intentionally air-gapped deployments).

Membership is self-pruning: an offline node stops renewing, and its authority expires without administrator intervention. The fleet membership is the set of nodes with active leases.

### 11.5 Reflexive Governance

Fleet infrastructure uses the same receipt grammar as all other governed behavior. Role transitions, delegation grants, upstream binding proofs, and lease renewals are all chain events verified by the same invariants as agent actions. The fleet's complete topology history is independently auditable and tamper-evident.

### 11.6 Settlement (Planned)

The receipt grammar extends naturally to economic settlement: spending authorizations, budget ceilings, and payment releases expressed as receipts with the same narrowing invariants, delegation verification, and constitutional constraints. The primitives are in place — capability grants with cost ceilings, lease-based expiry, external anchoring. Settlement architecture details (escrow mechanics, state channel design, protocol-to-legal mapping) are active research.

---

## 12. Ethics, Non-Goals, and Misuse Resistance

### 12.1 Co-option Risk

Accountability infrastructure can be repurposed as surveillance infrastructure. ZeroPoint mitigates this structurally:

- Constitutional constraints evaluate before every action and cannot be removed at runtime.
- The audit chain records *what participants did*, not behavioral profiles, movement data, or content outside the action's scope.
- The Presence Plane is structurally amnesic — the relay cannot surveil because parsing and persistence capabilities do not exist in the code.
- Keypairs are pseudonymous by default; identity binding to persons is a deployment decision, out of protocol scope.

These are architectural decisions, not policy promises. They can be evaluated by examining the code.

### 12.2 Permanent Records and Privacy

The chain is pseudonymous: a keypair's receipt history is visible to peers, but the protocol embeds no mapping from keypair to human identity. Whether and how that mapping is maintained is a deployment decision explicitly out of scope (§5.2).

Any system producing durable verifiable records creates potential for unintended use. The design choices here — action-level receipts, no behavioral profiling, no content inspection in discovery, pseudonymous identity — represent a considered position that anyone can verify by reading the protocol.

### 12.3 Genesis Responsibility

The choices made at Genesis — sovereignty provider, constitutional rules, operator identity — propagate through every subsequent action. A careless Genesis ceremony produces a deployment that inherits that carelessness at every step. This is intentional: founding conditions are explicit and auditable rather than implicit and deniable.

### 12.4 Non-Goals

- Not a compliance product. Compliance is an external checklist; ZeroPoint is protocol infrastructure.
- Not a centralized authority. No ZeroPoint server, cloud, or corporation controls access.
- Not a guarantee that deployments honor the tenets. Constitutional rules create structural friction within the protocol; governance beyond it depends on community norms.
- Not tied to any transport or network.
- Not agent-only. The protocol is participant-agnostic.

---

## 13. Conclusion

### Claims

ZeroPoint provides protocol-level primitives that make six properties verifiable:

1. **Attribution.** Every action produces a signed receipt proving a specific Ed25519 key attested to a specific action at a specific time.
2. **Ordering.** Receipts are hash-chained. The chain establishes a total order that resists retroactive rewriting; any tampering propagates as a hash failure.
3. **Authorization traceability.** Every capability grant traces to a human-held Genesis key through a chain verified against eight invariants. Any violation rejects the chain.
4. **Governance enforcement.** `HarmPrincipleRule` and `SovereigntyRule` evaluate before every action and cannot be removed, overridden, or reordered. This is structural, not configurable.
5. **Portability.** Identity is a keypair; receipts are self-contained; chains verify offline. No platform, server, or central authority required.
6. **External verifiability.** Chain state can be anchored to independent distributed ledgers — optional, event-driven, DLT-agnostic — producing publicly queryable timestamps no single party controls.

All six are testable against the codebase, auditable offline, and falsifiable against specific inputs.

### Non-Claims

- Does not prove truth. A receipt attests that something was signed, not that it is correct.
- Does not prevent all misuse. MIT/Apache-2.0 allows forking with constraints removed.
- Does not bind keys to persons. Pseudonymous by design.
- Does not guarantee runtime integrity. A compromised host produces valid-looking receipts.
- Does not solve AI safety. It provides the protocol substrate for provable actions and traceable authority.
- Trace layer is not yet implemented. Receipt chain and observation loop are complete and tested; trace commitment is planned.

### Summary

The accountability gap in existing systems — mutable logs, informal authorization, platform-controlled identity — is structural, not a configuration problem. Protocol-layer cryptographic primitives are the correct fix: signed receipts that make actions provable, hash chains that make history tamper-evident, capability grants that make delegation verifiable, constitutional constraints that make governance non-bypassable.

These primitives compose cleanly: receipts into chains, chains into fleet topologies, anchored chains into cross-organizational trust. They are participant-agnostic — the same properties apply to humans, agents, services, and devices. And they are portable: identity is a keypair, receipts are self-contained, verification requires no platform cooperation.

---

## Appendix A: Protocol Sketch

### A.1 Identities

Ed25519 signing keypairs; X25519 key-agreement keys derived for link encryption. 128-bit destination hash: truncated SHA-256 of the public key (Reticulum-compatible, used across all transports).

Trust tiers relevant to this sketch:
- **T0**: Unsigned. No cryptographic identity.
- **T1**: Self-signed Ed25519. Controls a keypair; no chain authority.
- **T2**: Chain-signed from genesis root. Valid delegation chain to a human-held key.

Identity binding to physical persons is deployment-dependent and out of scope.

### A.2 CompactReceipt Envelope

```json
{
  "id": "rcpt-a1b2c3d4",
  "rt": "execution",
  "st": "success",
  "tg": "A",
  "ch": "b3a1...hex",
  "ts": 1740000000,
  "pr": "rcpt-prev-id",
  "pd": "allow",
  "ra": "all rules passed",
  "sg": "ed25519-sig-hex",
  "ex": {}
}
```

MessagePack-encoded with short field names. Typical: 150–300 bytes. Max for single mesh packet: 380 bytes (MeshEnvelope overhead fits within 465-byte LoRa payload).

### A.3 MeshEnvelope

Wraps receipts for mesh transport (other transports use their own framing):
- **Type**: Receipt, Delegation, AuditChallenge, AuditResponse, PolicySync, ConsensusVote, ReputationUpdate, Custom
- **Sequence**: monotonic u64 (replay detection)
- **Source/destination**: 128-bit destination hashes
- **Signature**: Ed25519 over payload

### A.4 Chain Verification

`DelegationChain::verify()` enforces the eight invariants from §6.1 in order. Any single failure rejects the full chain.

---

## Appendix B: Glossary

**Receipt** — Signed evidence of an action or decision. MessagePack-encoded, 150–300 bytes. The atomic unit of evidence.

**Chain** — Linked sequence of receipts: each `pr` references the previous `id`, establishing total ordering and tamper-evidence.

**Trajectory** — A chain with all three properties: evidence (signed receipts), ordering (hash-linked `pr` fields), and replayability (deterministic re-verification from Genesis).

**Markovian** — Snapshot-only verification: checking current state without ordered history. A mutable log is Markovian evidence; each entry is independently vulnerable.

**Narrowing** — Delegation chains may only constrain authority at each step, never widen it. Enforced by the eight delegation invariants.

**Invariant** — A property verified on every evaluation; violation causes rejection. Two classes: delegation invariants (eight rules, `DelegationChain::verify()`); constitutional invariants (`HarmPrincipleRule`, `SovereigntyRule`).

**Trace Commitment** — A hash in a receipt committing to the computational trajectory a model traversed during inference. Future work; see `docs/future-work/cognitive-accountability.md`.

**Error Basin** — Dense activation-space region where a model repeatedly applies the same faulty reasoning circuit. Detectable via layer-wise logit fingerprint clustering (MEDS, 2025). A ZeroPoint signal that an agent exhibits low cognitive diversity.

**Confabulation Gap** — Measurable divergence between an agent's stated reasoning and its actual computational path. Requires the trace layer; conceptual until implemented.

**Capability Grant** — Signed permission token: action scope, time window, cost ceiling, rate limit, delegation depth, trust tier. Delegatable with narrowing.

**Delegation Chain** — Ordered sequence of capability grants, root to leaf, verified against eight invariants. Revoked parent invalidates all descendants.

**PolicyEngine** — Evaluates rules in fixed order. Evaluation order is itself an invariant.

**Constitutional Constraint** — `HarmPrincipleRule` or `SovereigntyRule`: non-removable, non-overridable, fixed in evaluation positions 1 and 2.

**Guard** — Pre-action check evaluating the node's own chain, grants, and constitutional rules before accepting any external input.

**GovernanceGate** — Guard → Policy → Execute → Audit. Every action passes through; every pass produces a chain entry.

**Genesis** — The deployment's origin ceremony: generates root keypair, seals constitutional rules, writes the immutable genesis record. Sequential and irreversible.

**Sovereignty Provider** — Protects the Genesis secret: biometric (Touch ID, fingerprint), hardware wallet (Trezor, YubiKey), OS keychain, or file-based fallback.

**Trust Tier** — T0 (unsigned) through T5 (sovereign: full constitutional governance, active reputation, verified upstream binding). Capability grants specify a minimum tier; delegation cannot lower it.

**Reticulum-compatible** — Wire-interoperable with Reticulum: HDLC framing, 128-bit destination hashing, Ed25519/X25519, 500-byte MTU.

**CompactReceipt** — MessagePack receipt with short field names. ≤ 380 bytes including MeshEnvelope overhead.

**Presence Plane** — Peer discovery layer. Dual-backend (web relay + Reticulum mesh), structurally amnesic, reciprocity-enforced. Independent from the Governance Plane.

**DiscoveryBackend** — Four-method trait: `announce`, `poll_discoveries`, `is_active`, `shutdown`.

**Structural Amnesia** — The web relay's architectural inability to surveil: no parsing, no indexing, no persistence.

**Reciprocity Enforcement** — Relay rule requiring clients to announce before receiving. Connections that don't announce are terminated after the grace period.

**ConnectionBehavior** — Counter-only summary emitted on relay connection close. Maps to `ReputationSignal / PolicyCompliance`.

**MeshNode** — High-level transport primitive managing interfaces, peers, links, delegations, and reputation.

**Collective Audit** — `AuditChallenge` / `AuditResponse` / `PeerAuditAttestation`. Peer-to-peer chain verification; no central auditor.

**Truth Anchor** — External distributed ledger timestamp for the chain's state. DLT-agnostic; optional enrichment.

**Anchor Commitment** — Published to the ledger: chain head hash, sequence, previous anchor hash, operator signature, chain type, trigger. Fingerprint only — no governed content.

**Anchor Receipt** — Ledger proof stored as a regular chain receipt: transaction ID, consensus timestamp, commitment, ledger-specific verification data.

**Anchor Trigger** — Six variants: operator-requested, cross-deployment introduction, compliance checkpoint, dispute evidence, opportunistic (piggyback), governance lifecycle event.

---

## Appendix C: Example Integration Pattern

A tool runner integrated with ZeroPoint requires any caller to present a receipt chain proving it holds a valid `CapabilityGrant` scoped to the specific action, signed by a chain terminating at a human-held T2 key. The runner's GovernanceGate verifies the chain locally — eight delegation invariants, constitutional rules, operational policy, expiration, rate limits — without consulting any external authority.

On failure: refusal receipt citing the specific invariant or rule that failed. On success: tool executes; runner emits an execution receipt with the action, input hash, output hash, and policy decision. Both receipts join the audit chain.

The pattern is identical whether the caller is an agent, a human using the CLI, or an automated service. The protocol distinguishes them only by trust tier: T2 requires a verifiable delegation path to a human root.

---

## Appendix D: Verification Mechanisms and Testable Behaviors

| Claim | Mechanism | Accept | Reject |
|-------|-----------|--------|--------|
| Receipts verified against full prior context | Hash chain: `pr` references predecessor `id`; Blake3 transitive | Unbroken hash-linked sequence from Genesis | Any gap or hash mismatch |
| Node state is deterministic from history | `AuditChallenge` / `AuditResponse` / `PeerAuditAttestation` | Full chain matches claimed state; signed attestation issued | Incomplete chain → negative reputation signal |
| Constitutional rules enforced locally | PolicyEngine: fixed positions 1 and 2; no coordinator | Valid policy decision in receipt from compliant engine | Receipt attesting to blocked action rejected by peers |
| Delegation monotonically narrows authority | `DelegationChain::verify()`: 8 invariants | All 8 satisfied | Any single violation dissolves the chain |
| Genesis key present at every trust decision | `zp-keys` hierarchy walks to Genesis root | Certificate chain reaches Genesis key | Non-Genesis root → reject |
| Genesis ceremony is atomic | `onboard/genesis.rs`: each step requires prior | `genesis.json` written with all fields | Halt at first failure; no partial Genesis |
| Child grants cannot exceed parent scope | `CapabilityGrant` fields enforced per-dimension | Child scope ⊆ parent; child expiration ≤ parent; child depth = parent + 1 | Any widening |
| Reputation accumulates from interaction history | `ReputationSignal` from receipts + `ConnectionBehavior` | Sustained positive trajectory passes reputation gate | Broken chains or reciprocity violations accumulate negative signal |
| Chain verification catches retroactive tampering | Hash propagation: tampering at entry N fails at N+1 | Full chain end-to-end valid | Any hash inconsistency anywhere |
| Constitutional rules non-removable | Fixed evaluation positions; any removal attempt blocked by `SovereigntyRule` | Both rules evaluate at every step | Attempt to remove, reorder, or override returns Block from `SovereigntyRule` |
| Three-layer accountability | Receipt chain → observation loop → trace layer | All layers consistent | Trace diverges from stated reasoning or lands in error basin *(trace layer: future work)* |

---

*ZeroPoint is maintained by the ZeroPoint Open Foundation.*
*Contact: hello@zeropoint.global*
*Repository: https://github.com/zeropoint-foundation/zeropoint*
*Website: https://zeropoint.global*

---

*© 2026 ZeroPoint Open Foundation. This document is released under CC BY 4.0. The ZeroPoint codebase is released under MIT/Apache-2.0.*
