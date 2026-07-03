# ZeroPoint

## Cryptographic Governance Primitives for Accountable Systems

**Whitepaper v3.0 — June 2026**
**ZeroPoint Open Foundation**

Status: Public Technical Overview
License: CC BY 4.0 (text); Code remains MIT/Apache-2.0
Canonical URL: https://zeropoint.global/whitepaper
PDF: [zeropoint-whitepaper-v3.0.pdf](https://zeropoint.global/zeropoint-whitepaper-v3.0.pdf)

**How to cite:**
> ZeroPoint Open Foundation. "ZeroPoint: Cryptographic Governance Primitives for Accountable Systems." Whitepaper v3.0, June 2026. https://zeropoint.global/whitepaper

---

## Abstract

ZeroPoint is a cryptographic governance framework: signed, hash-chained receipts that make actions provable; delegatable capability grants that narrow in scope as they propagate; and two non-removable constitutional rules that evaluate before every action. The framework is participant-agnostic and transport-agnostic — the same primitives apply to humans, agents, services, and devices over HTTP, TCP, encrypted mesh, or any future transport.

Implemented in Rust. Ships with a Reticulum-compatible mesh transport, TCP/UDP interfaces, an HTTP API, and a dual-backend peer discovery layer (the Presence Plane) without centralized registries. ZeroPoint is not an AI safety system. It is the protocol-layer substrate that makes actions provable, authority traceable, and governance constraints non-bypassable — without a central witness.

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

Trust primitives — identity, reputation, authorization — are typically implemented at the platform layer, not the protocol layer. Credentials and history live in a vendor's database; switching platforms means starting over. Authorization is API keys or ambient permissions, not cryptographically scoped grants. When actions cross organizational boundaries, there is no shared evidence base both parties can independently verify.

Autonomous AI agents make the problem acute. They act at machine speed across organizational boundaries with delegation chains that can extend far beyond their original scope. Existing infrastructure — mutable logs, informal authorization, platform-controlled identity — was designed for human-in-the-loop workflows. But the accountability gap predates agents; they expose and accelerate a structural deficit that is not new.

ZeroPoint addresses this with three primitives: signed, hash-chained receipts that make actions provable and their ordering tamper-evident; cryptographic capability grants that are verifiable, portable, and delegatable with enforced narrowing; and constitutional constraints that make governance non-bypassable at the protocol layer. The same properties apply to humans, agents, services, and devices.

---

## 2. Design Approach

### 2.1 Chain-Based Verification

Verification must be history-dependent. A system that checks only current credential state cannot detect retroactive tampering: earlier log entries can be rewritten without detection, and injected permissions are invisible if only current state is checked.

Each ZeroPoint receipt carries a cryptographic reference to its predecessor. Verifying a receipt requires walking the chain to Genesis, checking every link. Rewriting any entry requires rewriting all subsequent entries and convincing every independent verifier to accept the rewrite — computationally infeasible at any meaningful peer count.

Chain verification is O(n) in chain length rather than O(1), but in practice it is incremental: a peer that has verified entries 1–1000 does O(1) work for entry 1001. §5.5 addresses long-chain bounds via epoch-based compaction.

### 2.2 Four Testable Properties

**Property 1 — Each receipt is verified against all prior context.**
Every receipt's `pr` field references its predecessor's `id`. Blake3 hashing is transitive through the chain. **Accept**: unbroken hash-linked sequence from Genesis to tip. **Reject**: any gap or hash mismatch.

**Property 2 — A node's current state is deterministic from its history.**
Keychain, capability grants, audit trail, and reputation all derive from the complete history of Genesis, delegations, actions, and verifications. Two nodes with identical histories produce identical states. A node that cannot produce its supporting chain fails collective audit. **Accept**: full chain produced; signed `PeerAuditAttestation` issued. **Reject**: incomplete chain → negative reputation signal.

**Property 3 — Constitutional rules are enforced locally at every node.**
No global coordinator enforces `HarmPrincipleRule` and `SovereigntyRule`. Each node evaluates them independently before every action. A node that removes or bypasses these rules produces receipts peers reject during chain verification. **Accept**: receipt contains a valid policy decision from a compliant engine. **Reject**: receipt attesting to a constitutionally blocked action is rejected by peers.

**Property 4 — Delegation monotonically narrows authority.**
The leaf grant of a depth-N chain has scope ⊆ every ancestor's scope, expiration ≤ every ancestor's expiration, and depth == N. **Accept**: all eight delegation invariants satisfied. **Reject**: any single invariant violation dissolves the entire chain.

### 2.3 Genesis

The Genesis ceremony generates a 32-byte Ed25519 seed from which all trust in the deployment derives. Every operator key is signed by Genesis; every agent key is signed by an operator key; every capability grant traces back to Genesis. Certificate chain verification walks to the Genesis root on every trust decision — any non-Genesis root is **rejected**. This is an invariant of `zp-keys`, not a policy.

The ceremony is sequential and irreversible: generate keypair → validate sovereignty provider → enroll biometric or hardware confirmation → seal constitutional rules → write the immutable genesis record. Each step requires the prior step's success, enforced in `onboard/genesis.rs`.

### 2.4 Delegation Narrowing

A root grant specifies four constraint dimensions: **scope** (permitted actions and targets), **time** (`valid_from` / `valid_until`), **depth** (`max_delegation_depth`), and **trust tier** (minimum tier to exercise the grant). Each delegation may only narrow these:

- Child scope ⊆ parent scope (invariant 3)
- Child expiration ≤ parent expiration (invariant 5)
- Child depth = parent depth + 1, ≤ `max_delegation_depth` (invariants 2, 6)
- Child trust tier ≥ parent trust tier (invariant 4)

A revoked parent invalidates all descendants: any revoked or expired link causes full chain **rejection**.

### 2.5 Reputation

A peer's reputation accumulates from its complete interaction history: successful receipts generate positive signal, broken chains generate negative signal, behavioral anomalies (silent consumption, reciprocity violations, missing announces) degrade standing. Reputation is never a point-in-time snapshot.

### 2.6 Three Accountability Layers

**Layer 1 — Receipt Chain.** What happened: signed, hash-linked, replayable from Genesis to tip.

**Layer 2 — Observation Loop.** What should happen: the GovernanceGate pipeline (Guard → Policy → Execute → Audit) enforces constraints at action time. Peer challenge assessments join the chain.

**Layer 3 — Trace Layer (planned).** A hash commitment in each receipt would commit to the model's actual computational trajectory during inference — making confabulation, mode collapse, and reasoning drift detectable. Not yet implemented; the existing receipt and policy primitives accommodate it without modification.

---

## 3. Design Goals

**Protocol-level accountability.** Every significant action produces a signed receipt linked to its predecessor. The chain is offline-auditable; no running server required.

**Sovereignty by design.** Governance evaluates locally — each node checks its own chain, grants, and rules before acting. No remote authority is consulted. Guarantees are identical over HTTP, TCP, or encrypted mesh.

**Non-bypassable constraints.** Two constitutional rules are fixed at positions 1 and 2 in the PolicyEngine. They cannot be removed, reordered, or overridden by any rule, WASM module, or operator action.

**Honest security posture.** The framework is explicit about what it prevents and what it does not. See §7.

**Transport agnosticism.** Receipts, capability grants, delegation chains, and policy evaluation are identical across all transports. Adding a new transport requires implementing one interface trait; the governance primitives are unchanged.

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

Every action passes through five stages in order:

1. **Guard** — Pre-action sovereignty check. Evaluates the node's own chain, grants, and constitutional rules before accepting any external input.
2. **Policy** — Constitutional rules first, then operational rules, then WASM modules. Most restrictive decision wins.
3. **Execute** — Runs only if Guard and Policy both allow.
4. **Audit** — Emits a signed, hash-linked receipt and persists it to the chain.
5. **Transport** — Receipts propagate to peers for independent verification.

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

Wire format: MessagePack with short field names. Typical: 150–300 bytes. Maximum for single-packet mesh: 380 bytes (within the 465-byte LoRa payload limit).

### 5.2 What Receipts Prove and Don't

**Prove:**
- A specific Ed25519 key signed a specific statement at a specific time.
- The chain contains an unbroken sequence of signed events.
- The PolicyEngine evaluated a known rule set and produced a specific decision.
- A capability grant was valid at the time of action.

**Do not prove:**
- The nature of the signer. A receipt attests that a key signed something, not whether that key belongs to a human or an agent. Identity binding to persons is deployment-dependent and out of protocol scope.
- That the action content was correct or safe.
- That the runtime environment was uncompromised. A compromised host can produce arbitrary valid receipts.

### 5.3 Chain Properties

The `pr` field is what distinguishes a chain from a log. Without it, each receipt is an isolated signed fact; with it, each receipt requires the full ordered history to verify.

A chain provides three properties isolated receipts cannot:

**Ordering.** Chain position, not timestamp, determines sequence. Two receipts with identical timestamps are still ordered by their `pr` linkage.

**Tamper-evidence.** Modifying receipt N invalidates the hash of every subsequent receipt. An attacker must rewrite N through the tip and convince every independent verifier to accept the rewrite.

**Replayability.** The full chain can be re-executed from Genesis to verify that every action was authorized, every policy decision was valid, and every delegation was within scope at the time.

**Accept/reject.** A chain **accepts** when every `pr` linkage is intact, every hash consistent, and every signature valid. It **rejects** on any gap, hash inconsistency, or signature failure. Rejection is binary and propagates: one broken link invalidates everything downstream.

Peers challenge each other's chains directly. A challenged peer produces its full chain; the challenger verifies and issues a signed `PeerAuditAttestation`. No central auditor is required.

### 5.4 Why History-Dependence Is Not Optional

Snapshot-only verification cannot detect retroactive tampering, injected permissions, or unauthorized delegation insertions. History-dependence closes these gaps: any modification propagates as a hash failure that every subsequent verifier catches.

### 5.5 Chain Compaction — Epochs

An agent doing 1,000 actions/day produces 365,000 receipts/year; a 100-agent fleet produces 36.5M. Full chain walks from Genesis become impractical at this scale. Epoch-based compaction bounds active memory regardless of total history.

**Mechanism.** When an epoch fills (8,192 entries or 7 days, whichever comes first), a Merkle tree is computed over its entries. The 32-byte Blake3 root is recorded in a signed `EpochSeal` that joins the chain as a regular receipt, preserving hash linkage. Individual epoch entries are then archived and removed from active storage. Seals back-reference each other, forming a verifiable chain-of-seals.

**Verification modes after compaction:**

| Mode | What to walk | Cost |
|------|-------------|------|
| Recent activity | Current unsealed epoch | Full walk, ≤ 8,192 entries |
| Historical integrity | Seal chain | Dozens of seals, not millions of entries |
| Spot-check one entry | Merkle inclusion proof | 13 hashes (416 bytes, one mesh packet) |
| Forensic reconstruction | Full archived epoch | Retrieve entries, reconstruct Merkle tree |

**Memory bounds.** Working set: one unsealed epoch (~4 MB) plus the most recent seal. An agent running five years holds the same active memory as a new one. The seal chain grows ~500 bytes/week; five years of history is ~111 KB.

**What compaction does not do:**

- *Disaster recovery.* A lost archive cannot be reconstructed from the seal alone. Durability requires replication — a deployment decision.
- *Fabrication prevention.* A compromised node can produce a valid seal over fabricated entries. Peer attestation (spot-checking against their own interaction records) is the primary defense.
- *Retention policy.* Expired archives leave epochs unexaminable except by seal chain summary. Audit depth vs. storage cost is the operator's tradeoff.

Implemented in `zp-receipt::epoch`.

---

## 6. Governance Model

### 6.1 Capability Gating

Every participant must hold a valid `CapabilityGrant` to act. A grant is a signed, portable authorization token specifying scope, cost ceiling, rate limit, time window, delegation depth limit, minimum trust tier, and the grantor's Ed25519 signature.

Any grant holder can delegate a subset to another participant, forming a `DelegationChain` verified against eight invariants:

1. Each grant references the previous as `parent_grant_id`.
2. Depths increment monotonically.
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

**`HarmPrincipleRule`** blocks weaponization, unauthorized surveillance, deception (deepfakes, impersonation), and suppression of dissent. Cannot be bypassed by capability grants, policy configuration, or consensus votes.

**`SovereigntyRule`** blocks changes that would disable the guard, truncate the audit trail, forge or bypass capabilities, remove constitutional rules, or override agent refusal.

Both carry equal weight at every step, from first to last.

### 6.3 Protocol Tenets

**I. Do No Harm.** `HarmPrincipleRule` is non-removable and evaluates before every action.

**II. Sovereignty Is Sacred.** Every participant can refuse any action. Every human can disconnect any agent. No agent holds capabilities it was not granted. Enforced locally by the Guard.

**III. Action Without Evidence Is No Action.** Every action produces a receipt; every receipt joins the chain. An action absent from the chain did not happen. A present action cannot be expunged.

**IV. The Human Is The Root.** Every delegation chain terminates at a human-held key. No agent self-authorizes.

### 6.4 Key Hierarchy and Introduction Protocol

`zp-keys` implements a three-level certificate hierarchy:

```
GenesisKey       ← self-signed root (one per deployment)
  └─ OperatorKey ← signed by genesis
      └─ AgentKey ← signed by operator
```

Any node verifies agent identity by walking this chain offline — no network or policy state required. Six certificate invariants: valid signatures, issuer linkage, role hierarchy, monotonic depth, no expired certs, hash linkage.

The key hierarchy is independent of the policy engine to avoid circular dependency: the engine's authority requires keys; keys cannot depend on the engine existing. Issuing a child cert flows through the engine as `ActionType::KeyDelegation` (Critical risk); the signing mechanism itself is unconditional.

New node introductions use `zp-introduction`: the initiator sends its certificate chain and a challenge nonce; the responder verifies and evaluates `ActionType::PeerIntroduction` through the policy engine. Same-genesis introductions are High risk; cross-genesis are Critical. Key *discovery* — finding peers' network addresses — is handled by the Presence Plane (§9).

---

## 7. Threat Model

| Threat | Capability | Mitigation | Residual Risk |
|--------|-----------|------------|---------------|
| **Log forgery / retroactive rewriting** | Alter history to change attribution | Ed25519 + Blake3 hash chain; collective audit via `AuditChallenge` / `PeerAuditAttestation` | Compromised keys can sign lies; revocation is deployment-dependent |
| **Unauthorized tool use** | Execute beyond intended scope | `CapabilityGrant` gating; 8-invariant delegation chain verification; PolicyEngine evaluates before every action | Gaps possible with poorly designed grants |
| **Cross-operator trust failure** | Cannot verify another party's agent outputs | Independent receipt verification; `zp-introduction` certificate exchange; dual-backend discovery | Cross-genesis introductions require operator-configured policy |
| **Passive scanning** | Harvest peer identities without announcing | Reciprocity enforcement; structurally amnesic relay | A scanner that announces gains initial access; behavioral reputation detects parasites over time |
| **Sybil flooding** | Overwhelm discovery with cheap fake identities | Credible anchor history requires sustained ledger cost; reputation weights anchor depth | Defense is economic, not absolute |
| **Security theater** | Claim governance without enforcing it | Constitutional rules non-removable; receipts independently verifiable | MIT/Apache-2.0 permits stripping constraints from a fork |
| **Surveillance co-option** | Use receipts to track people, not actions | Pseudonymous keypairs; action-level receipts only; Presence Plane structural amnesia | License cannot prevent misuse |
| **Replay attacks** | Resend captured packets | Monotonic u64 sequence numbers; 16-byte nonces in link handshake; Ed25519 over content hashes | Long-offline nodes may have gaps in seen sequences |
| **Mesh injection** | Insert forged packets | HDLC + CRC; Ed25519 on all envelopes; X25519 ECDH link encryption | Requires successful link establishment |
| **WASM policy escape** | Malicious module breaks sandbox | Wasmtime with fuel limiting; hash verification before loading | Escape requires a Wasmtime vulnerability; fuel exhaustion is DoS at worst |
| **Identity misbinding** | Misattribute key to wrong entity | Six trust tiers; T2+ requires verified delegation from a human-held key | Binding keys to physical persons is deployment-dependent |

**What ZeroPoint does not solve:**

- Misuse by deployments that fork and strip constitutional constraints. MIT/Apache-2.0 permits this.
- Truth. Receipts prove provenance and chain integrity, not the correctness of what was signed.
- Absolute Sybil resistance. The defense is economic, not mathematical.
- Runtime integrity. A compromised host produces valid-looking receipts.

---

## 8. Transport Integrations

The governance primitives — receipts, capability grants, delegation verification, PolicyEngine — are identical across all transports.

**HTTP API.** Axum-based REST server for cloud deployments, container orchestration, and web service integration.

**TCP and UDP.** `TcpClientInterface` / `TcpServerInterface` with HDLC framing and CRC verification. UDP for connectionless receipt exchange. Multiple interfaces run simultaneously on one node.

**Reticulum-compatible mesh.** Wire-level interoperable with the Reticulum Network Stack. Implements HDLC framing with CRC-CCITT, 128-bit destination hashing (truncated SHA-256), Ed25519 signing, X25519 ECDH key agreement, 500-byte MTU / 465-byte data payload (LoRa-compatible), and a 3-packet link handshake (LinkRequest → LinkProof → LinkAccept) with 16-byte nonces.

**Extensibility.** A new transport requires implementing one interface trait plus envelope serialization. A new discovery backend requires implementing the four-method `DiscoveryBackend` trait. The Presence Plane is decoupled from transport — web and mesh discovery coexist with any transport combination.

---

## 9. The Presence Plane

### 9.1 Problem

`zp-keys` handles identity verification once you have a peer's certificates. Finding peers' network addresses is a separate problem. A centralized directory solves it but creates a surveillance and censorship point. The **Presence Plane** provides discovery using the same Ed25519 identity as the governance layer, without centralized state.

### 9.2 Architecture

Built on the `DiscoveryBackend` trait (`announce`, `poll_discoveries`, `is_active`, `shutdown`). Two backends:

**Web relay.** Pub/sub over WebSocket. Agents publish signed announce blobs; the relay broadcasts to all subscribers; agents filter locally. The relay never parses payloads, indexes capabilities, logs queries, or persists state. Restart erases everything.

**Reticulum mesh.** Announces propagate over mesh interfaces (LoRa, WiFi, serial, TCP). No server. No internet dependency.

Both backends share the same announce wire format: `[combined_key(64)] + [capabilities_json] + [ed25519_signature(64)]`. Peers from either backend land in the same peer table. The `DiscoveryManager` fans out announces, validates signatures, deduplicates, and prunes expired entries.

### 9.3 Structural Amnesia

The relay cannot surveil because the capability does not exist in the code. It passes bytes without parsing, indexing, or storing them. This is stronger than a no-logs policy, which can be changed or violated. Subpoena-resistant by construction.

### 9.4 Reciprocity Enforcement

Passive scanning — subscribing to announce traffic without revealing your identity — is the primary adversarial concern. Defense: **you must announce before you receive.**

On connect, `try_receive()` errors until the client has published an announce. Connections that haven't announced within the grace period (30 seconds, configurable) are terminated. Any passive scanner must expose its signed Ed25519 identity before it can observe anyone else.

### 9.5 Behavioral Reputation Integration

Reciprocity stops naive scanners. Sophisticated ones announce once, then silently consume. On connection close, the relay emits `ConnectionBehavior` summaries — counters only, no content: announced, announces_published, duration, reciprocity_violation. These map to `ReputationSignal / PolicyCompliance`. Consistent participation accumulates positive signal; announce-once-then-consume patterns accumulate negative signal.

### 9.6 Presence Plane Threat Model

| Threat | Attack | Mitigation | Residual Risk |
|--------|--------|------------|---------------|
| Passive scanning | Subscribe without announcing | Reciprocity enforcement; grace period + termination | Scanner that announces gains access; behavioral detection takes time |
| Sybil flooding | Many keypairs, many announces | Anchor history requires sustained cost; reputation weights depth | Economic disincentive; keypair generation is free |
| Relay compromise | Attacker gains relay access | No data to retrieve (structural amnesia) | Compromised relay can censor; relay receipt chain makes this detectable |
| Traffic analysis | Observe connection timing / metadata | No identity-to-IP mapping; relay logs only counters | ISP-level observation is out of scope |
| Eclipse attack | Surround target with attacker-controlled peers | Dual-backend: Reticulum bypasses relay | Full eclipse requires compromising both backends |

---

## 10. External Truth Anchoring

### 10.1 Purpose

The receipt chain is self-verifying — hash-linked, signed, auditable cold. It does not establish when the chain state existed in external calendar time, or provide a witness a third party can query without operator cooperation.

External truth anchoring publishes the chain's current state to an independent distributed ledger, producing a publicly queryable, tamper-evident timestamp the operator cannot retroactively modify. This matters in three contexts:

- **Cross-deployment trust.** Anchoring to a common ledger gives each party an independently verifiable history that a freshly fabricated chain cannot reproduce.
- **Dispute resolution.** An anchor proves chain state at an externally-attested time, settling questions about whether history was rewritten.
- **Compliance audit.** Self-signed timestamps don't satisfy auditors. An anchor on a ledger regulators already examine carries equivalent evidential weight.

In practice, cross-organizational transactions nearly always touch a shared ledger. Anchoring governance chain heads piggybacks on infrastructure that already exists.

### 10.2 Architecture

**Optional enrichment.** Without a ledger configured, ZeroPoint operates exactly as described in §5. The anchor adds an external witness; it doesn't replace the chain's internal guarantees.

**No dependency.** Anchor receipts join the chain as regular entries. Chain verification never requires the ledger to be reachable. If unavailable, governance continues; anchor emission pauses.

**DLT-agnostic.** The `TruthAnchor` trait (`anchor()`, `verify()`, `query_range()`) accepts any distributed ledger backend. Reference implementation: Hedera Hashgraph's Consensus Service. Also supported: Ethereum L2 calldata, Bitcoin OpenTimestamps, Ceramic streams, or any system that can timestamp and publicly expose an opaque payload. Backend selection is the operator's choice.

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

**Opportunistic:** when the operator makes any blockchain transaction for other purposes, the current chain head hash embeds as transaction metadata at zero marginal cost.

### 10.5 Reference Backend: Hedera Hashgraph

- **Sub-second finality.** 3–5s deterministic consensus; no probabilistic confirmation.
- **Public verifiability.** Mirror nodes expose all HCS messages. Any party verifies without operator cooperation.
- **Low cost.** Fraction of a cent per submission.
- **Known governance.** Hedera's council is a publicly listed set of global organizations.

### 10.6 Cross-Deployment Verification

When two deployments meet: each announces its anchor backend identifier, independently queries the other's anchor history, and verifies that chain head hashes match anchor commitments. This is verification against a shared public record, not mutual cooperation.

Generating a keypair is free; establishing a credible anchor history requires sustained ledger transactions per identity. The reputation system weights anchor depth — shallow histories receive less trust. The attack becomes economic rather than computational.

### 10.7 Limits

- Does not prove chain content is correct — only that the chain was in a specific state at a specific time.
- Does not prevent chain forking — an operator can maintain two chains and anchor only one.
- Does not substitute for internal chain integrity.

---

## 11. Fleet Topology

### 11.1 Chain-Derived Roles

A node's role — Genesis, Delegate, or Standalone — derives from its receipt chain, not its config file. Config provides a bootstrap hint advisory once the chain contains delegation evidence. Config can be edited; chain entries cannot without invalidating all subsequent hashes.

**Genesis.** Performed the Genesis ceremony; holds the root keypair. Exactly one per fleet.
**Delegate.** Holds a valid delegation receipt from an upstream Genesis node. Authority bounded by narrowing invariants.
**Standalone.** No chain evidence of Genesis or delegation. Default; a revoked delegate returns here.

### 11.2 Role Transition Receipts

Role transitions are chain events, not administrative acts. When a node's role changes, a receipt seals the transition with the previous role, new role, and cause. Cause vocabulary is constrained: `delegation_accepted`, `delegation_revoked`, `redelegation`, `genesis_performed`. Fleet topology history is auditable with the same tools as any other governed behavior.

### 11.3 Upstream Binding

A delegate carries the upstream Genesis node's Ed25519 public key in its delegation receipt — a cryptographic proof, not a claim.

**Local check (offline):** receipt contains a well-formed 32-byte pubkey. Absent or malformed → `Unbound` or `MalformedPubkey`.

**Remote check (online):** challenge the upstream to prove it holds the key in the receipt. Mismatch → `PubkeyMismatch`. A delegate cannot forge its delegation receipt without the upstream's signing key and cannot silently swap upstreams.

### 11.4 Liveness and Lease Renewal

Fleet membership requires lease renewal. Each delegate's `CapabilityGrant` has a bounded lifetime, renewed at a configured cadence by presenting a valid Ed25519 signature to a designated renewal authority. Renewal failure triggers a grace period; expiry activates the configured failure mode: `halt` (fail closed), `degrade` (read-only), or `continue-with-flag` (for intentionally air-gapped deployments).

Membership is self-pruning: an offline node stops renewing and its authority expires without administrator intervention.

### 11.5 Reflexive Governance

Fleet infrastructure uses the same receipt grammar as all other governed behavior. Role transitions, delegation grants, upstream binding proofs, and lease renewals are chain events verified by the same invariants as agent actions. The fleet's complete topology history is independently auditable and tamper-evident.

### 11.6 Settlement (Planned)

The receipt grammar extends naturally to economic settlement: spending authorizations, budget ceilings, and payment releases expressed as receipts with the same narrowing invariants and constitutional constraints. The primitives are in place; settlement architecture details (escrow mechanics, state channel design, protocol-to-legal mapping) are active research.

---

## 12. Ethics, Non-Goals, and Misuse Resistance

### 12.1 Co-option Risk

Accountability infrastructure can be repurposed as surveillance infrastructure. ZeroPoint mitigates this structurally, not by policy:

- Constitutional constraints evaluate before every action and cannot be removed at runtime.
- The audit chain records what participants did — not behavioral profiles, movement data, or content outside the action's scope.
- The Presence Plane relay cannot surveil; parsing and persistence capabilities don't exist in the code.
- Keypairs are pseudonymous by default. Identity binding to persons is a deployment decision, out of protocol scope.

These are architectural properties, verifiable in the code.

### 12.2 Permanent Records and Privacy

The chain is pseudonymous: a keypair's receipt history is visible to peers, but the protocol embeds no mapping from keypair to person. Whether that mapping is maintained is a deployment decision explicitly out of scope (§5.2). The design choices here — action-level receipts, no behavioral profiling, no content inspection in discovery — are a considered position, verifiable in the protocol rather than taken on faith.

### 12.3 Genesis Responsibility

The choices made at Genesis — sovereignty provider, constitutional rules, operator identity — propagate through every subsequent action. A careless Genesis ceremony produces a deployment that inherits that carelessness permanently. This is intentional: founding conditions are explicit and auditable, not implicit and deniable.

### 12.4 Non-Goals

- Not a compliance product. Compliance is an external checklist; ZeroPoint is protocol infrastructure.
- Not a centralized authority. No ZeroPoint server, cloud, or corporation controls access.
- Not a guarantee of deployment behavior. The protocol creates structural friction; what happens beyond it is a social question.
- Not transport-specific or agent-only. The protocol is participant-agnostic.

---

## 13. Conclusion

### Claims

ZeroPoint provides protocol-level primitives that make six properties verifiable:

1. **Attribution.** Every action produces a signed receipt proving a specific Ed25519 key attested to a specific action at a specific time.
2. **Ordering.** Hash-chained receipts establish a total order that resists retroactive rewriting; any tampering propagates as a hash failure.
3. **Authorization traceability.** Every capability grant traces to a human-held Genesis key through a chain verified against eight invariants. Any violation rejects the chain.
4. **Governance enforcement.** `HarmPrincipleRule` and `SovereigntyRule` evaluate before every action and cannot be removed, overridden, or reordered. Structural, not configurable.
5. **Portability.** Identity is a keypair; receipts are self-contained; chains verify offline. No platform, server, or central authority required.
6. **External verifiability.** Chain state can be anchored to independent distributed ledgers — optional, event-driven, DLT-agnostic — producing publicly queryable timestamps no single party controls.

All six are testable against the codebase, auditable offline, and falsifiable against specific inputs.

### Non-Claims

- Does not prove truth. A receipt attests that something was signed, not that it is correct.
- Does not prevent all misuse. MIT/Apache-2.0 allows forking with constraints removed.
- Does not bind keys to persons. Pseudonymous by design.
- Does not guarantee runtime integrity. A compromised host produces valid-looking receipts.
- Does not solve AI safety. It provides protocol substrate for provable actions and traceable authority.
- Trace layer is not yet implemented. Receipt chain and observation loop are complete; trace commitment is planned.

### Summary

The accountability gap in existing systems — mutable logs, informal authorization, platform-controlled identity — is structural, not a configuration problem. The fix is structural: signed receipts that make actions provable, hash chains that make history tamper-evident, capability grants that make delegation verifiable, constitutional constraints that make governance non-bypassable.

These primitives compose cleanly: receipts into chains, chains into fleet topologies, anchored chains into cross-organizational trust. They are participant-agnostic, transport-agnostic, and portable. Verification requires no platform cooperation.

---

## Appendix A: Protocol Sketch

### A.1 Identities

Ed25519 signing keypairs; X25519 keys derived for link encryption. 128-bit destination hash: truncated SHA-256 of the public key (Reticulum-compatible, used across all transports).

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

MessagePack-encoded with short field names. Typical: 150–300 bytes. Max for single mesh packet: 380 bytes (MeshEnvelope overhead fits within the 465-byte LoRa payload).

### A.3 MeshEnvelope

Wraps receipts for mesh transport:
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

**Markovian** — Snapshot-only verification: checking current state without ordered history. Each entry is independently vulnerable.

**Narrowing** — Delegation chains may only constrain authority at each step, never widen it. Enforced by the eight delegation invariants.

**Invariant** — A property verified on every evaluation; violation causes rejection. Two classes: delegation invariants (`DelegationChain::verify()`); constitutional invariants (`HarmPrincipleRule`, `SovereigntyRule`).

**Trace Commitment** — A hash in a receipt committing to the computational trajectory a model traversed during inference. Future work; see `docs/future-work/cognitive-accountability.md`.

**Error Basin** — Dense activation-space region where a model repeatedly applies the same faulty reasoning circuit. A ZeroPoint signal that an agent exhibits low cognitive diversity.

**Confabulation Gap** — Measurable divergence between an agent's stated reasoning and its actual computational path. Requires the trace layer; conceptual until implemented.

**Capability Grant** — Signed permission token: action scope, time window, cost ceiling, rate limit, delegation depth, trust tier. Delegatable with narrowing.

**Delegation Chain** — Ordered sequence of capability grants, root to leaf, verified against eight invariants. Revoked parent invalidates all descendants.

**PolicyEngine** — Evaluates rules in fixed order. Evaluation order is itself an invariant.

**Constitutional Constraint** — `HarmPrincipleRule` or `SovereigntyRule`: non-removable, non-overridable, fixed in evaluation positions 1 and 2.

**Guard** — Pre-action check evaluating the node's own chain, grants, and constitutional rules before accepting external input.

**GovernanceGate** — Guard → Policy → Execute → Audit. Every action passes through; every pass produces a chain entry.

**Genesis** — The deployment's origin ceremony: generates root keypair, seals constitutional rules, writes the immutable genesis record. Sequential and irreversible.

**Sovereignty Provider** — Protects the Genesis secret: biometric (Touch ID, fingerprint), hardware wallet (Trezor, YubiKey), OS keychain, or file-based fallback.

**Trust Tier** — T0 (unsigned) through T5 (sovereign: full constitutional governance, active reputation, verified upstream binding). Capability grants specify a minimum tier; delegation cannot lower it.

**Reticulum-compatible** — Wire-interoperable with Reticulum: HDLC framing, 128-bit destination hashing, Ed25519/X25519, 500-byte MTU.

**CompactReceipt** — MessagePack receipt with short field names. ≤ 380 bytes including MeshEnvelope overhead.

**Presence Plane** — Peer discovery layer. Dual-backend (web relay + Reticulum mesh), structurally amnesic, reciprocity-enforced. Independent from the Governance Plane.

**DiscoveryBackend** — Four-method trait: `announce`, `poll_discoveries`, `is_active`, `shutdown`.

**Structural Amnesia** — The web relay's architectural inability to surveil: no parsing, no indexing, no persistence.

**Reciprocity Enforcement** — Relay rule requiring clients to announce before receiving. Non-compliant connections are terminated after the grace period.

**ConnectionBehavior** — Counter-only summary emitted on relay connection close. Maps to `ReputationSignal / PolicyCompliance`.

**MeshNode** — High-level transport primitive managing interfaces, peers, links, delegations, and reputation.

**Collective Audit** — `AuditChallenge` / `AuditResponse` / `PeerAuditAttestation`. Peer-to-peer chain verification; no central auditor.

**Truth Anchor** — External distributed ledger timestamp for the chain's state. DLT-agnostic; optional enrichment.

**Anchor Commitment** — Published to the ledger: chain head hash, sequence, previous anchor hash, operator signature, chain type, trigger. Fingerprint only — no governed content.

**Anchor Receipt** — Ledger proof stored as a regular chain receipt: transaction ID, consensus timestamp, commitment, ledger-specific verification data.

**Anchor Trigger** — Six variants: operator-requested, cross-deployment introduction, compliance checkpoint, dispute evidence, opportunistic (piggyback), governance lifecycle event.

---

## Appendix C: Example Integration Pattern

A tool runner integrated with ZeroPoint requires any caller to present a receipt chain proving it holds a valid `CapabilityGrant` scoped to the specific action, signed by a chain terminating at a human-held T2 key. The GovernanceGate verifies locally — eight delegation invariants, constitutional rules, operational policy, expiration, rate limits — without consulting any external authority.

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
| Genesis key at every trust decision | `zp-keys` hierarchy walks to Genesis root | Certificate chain reaches Genesis key | Non-Genesis root → reject |
| Genesis ceremony is atomic | `onboard/genesis.rs`: each step requires prior | `genesis.json` written with all fields | Halt at first failure; no partial Genesis |
| Child grants cannot exceed parent scope | `CapabilityGrant` fields enforced per-dimension | Child scope ⊆ parent; child expiration ≤ parent; child depth = parent + 1 | Any widening |
| Reputation accumulates from interaction history | `ReputationSignal` from receipts + `ConnectionBehavior` | Sustained positive trajectory passes reputation gate | Broken chains or reciprocity violations accumulate negative signal |
| Chain verification catches retroactive tampering | Hash propagation: tampering at N fails at N+1 | Full chain end-to-end valid | Any hash inconsistency anywhere |
| Constitutional rules non-removable | Fixed evaluation positions; removal attempt blocked by `SovereigntyRule` | Both rules evaluate at every step | Attempt to remove, reorder, or override returns Block from `SovereigntyRule` |
| Three-layer accountability | Receipt chain → observation loop → trace layer | All layers consistent | Trace diverges from stated reasoning *(trace layer: future work)* |

---

*ZeroPoint is maintained by the ZeroPoint Open Foundation.*
*Contact: hello@zeropoint.global*
*Repository: https://github.com/zeropoint-foundation/zeropoint*
*Website: https://zeropoint.global*

---

*© 2026 ZeroPoint Open Foundation. CC BY 4.0 (text); MIT/Apache-2.0 (code).*
