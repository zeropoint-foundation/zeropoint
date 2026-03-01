# ZeroPoint v2 Governance Framework

## Preamble

This document defines the governance framework for ZeroPoint v2 — a cryptographic trust substrate where participants operate as sovereign peers across any transport.

The framework rests on a constitutional foundation inspired by the work of Mark Qvist and the [Reticulum Network Stack](https://reticulum.network). Reticulum demonstrated that planetary-scale encrypted networking requires no central authority, no certificate hierarchy, and no institutional trust — only cryptographic proof, personal sovereignty, and a refusal to build tools of harm. ZeroPoint extends these principles into any system where actions have consequences — autonomous agents are the most urgent application, but the protocol serves humans, services, and devices with the same cryptographic guarantees.

We are indebted to Qvist's vision. His observation that "architecture is politics" and "a tool is never neutral" shaped the tenets below. His proof that sovereignty and safety are complements, not contradictions, gave us the courage to build governance that empowers rather than constrains. The [Zen of Reticulum](https://reticulum.network/manual/zen.html) should be considered essential reading for anyone building on or contributing to ZeroPoint.

---

## The ZeroPoint Tenets

These four tenets are constitutional. They are embedded in the protocol, expressed in the license, and enforced in the code. No capability grant, no policy rule, no consensus vote can override them.

### I. Do No Harm

ZeroPoint shall not operate in systems designed to harm humans.

This is not a policy preference. It is a structural commitment encoded as a non-removable rule in the PolicyEngine. The `HarmPrincipleRule` cannot be bypassed, overridden, or removed at runtime. It exists because architecture shapes outcomes, and we choose to make trust verifiable.

This tenet is inspired directly by Reticulum's Harm Principle: that the builders of a tool bear responsibility for the uses their architecture enables, and that protective constraints are an act of conscience, not a limitation of capability. It exists because architecture shapes outcomes, and we choose to make trust verifiable.

### II. Sovereignty Is Sacred

Every participant has the right to refuse any action. Every human has the right to disconnect any agent. No participant may acquire capabilities it was not granted. No human may be compelled to grant capabilities.

Coercion is not merely prohibited — it is architecturally impossible. The Guard enforces this locally, before every action, without consulting any external authority. A peer can request. A peer cannot compel. The participant that can say no is the one you can trust. The one that cannot is the one you should worry about. This applies equally to agents and to humans operating within the protocol — sovereignty is not a constraint imposed on agents by humans, but a right shared by every participant in the system.

### III. Action Without Evidence Is No Action

Every action produces a receipt. Every receipt joins a chain. No participant may act without leaving a cryptographic trace.

Governance without evidence is not governance. The audit chain is the single source of truth. It cannot be edited, reordered, truncated, or selectively forgotten. If it's not in the chain, it didn't happen. If it is in the chain, it cannot un-happen.

### IV. The Human Is The Root

Every delegation chain terminates at a human-held key. No agent may self-authorize. No agent may forge a delegation chain. The genesis key is always held by flesh, blood, and soul.

An agent's authority flows from the human who created it, through a verifiable chain of signed capability grants. Break the chain and the authority dissolves. This is not a limitation on agent autonomy — it is the foundation of it. An agent whose authority can be verified is an agent that can be trusted to act. And the human at the root is not merely an overseer — they are a participant whose own actions are equally provable, equally auditable, and equally bound by the protocol's constitutional constraints.

---

## Part I: Principles

### 1. Trust Is a Cryptographic Fact, Not a Score

Reticulum's zero-trust architecture eliminates institutional trust entirely. Identity is a key pair. Authentication is a signature verification. There is no certificate authority, no trust score database, no reputation server.

ZeroPoint v1 built an elaborate multi-dimensional trust scoring engine — eight dimensions, each with confidence levels, evidence trails, and incident tracking. This was intellectually rigorous but fundamentally misaligned with a mesh architecture where trust is pre-negotiated at link establishment time, not dynamically computed.

Trust in ZeroPoint is expressed through three mechanisms only: key possession (you control your identity because you control your private key), link establishment (you trust a peer because you completed a cryptographic handshake with them), and receipt chains (you trust a claim because you can verify the signatures in its provenance chain).

There are no trust scores. There are no reputation databases. There are only keys, links, and receipts.

### 2. Governance Is What the Audit Trail Says It Is

v1 maintained governance state in-memory: proposal status machines, decision logs capped at 10,000 entries, scoring engines that could produce different results if fed different evidence. This is fragile governance — it exists only as long as the server is running.

Reticulum's philosophy of store-and-forward, combined with v2's hash-chained audit trail, suggests a different model: governance is the audit trail. Every decision, every approval, every escalation, every veto is an immutable, signed entry in a hash chain. The chain IS the governance record.

### 3. The Minimum Viable Governance

Reticulum asks: "What is the minimum amount of information required to convey this intent?" This question applies to governance with equal force.

Governance mechanisms earn their complexity. Every rule, every state, every field must justify its existence against the question: "Does this make agents safer, more sovereign, or more accountable?" If the answer is no, it is weight without purpose.

### 4. Scarcity Forces Governance

Reticulum observes that scarcity eliminates waste. In a mesh network with constrained bandwidth, every byte matters. This natural scarcity forces governance decisions that abundance would allow you to defer: Is this message essential? Does this action justify its cost? Should this receipt be propagated?

Resource constraints are governance constraints. The mesh's bandwidth limits, the receipt chain's storage costs, and the audit trail's verification burden are natural governance mechanisms that require no code.

---

## Part II: Architecture

### The Three Pillars

ZeroPoint v2 governance rests on three pillars, each corresponding to a fundamental governance question:

```
┌─────────────────────────────────────────────────────────────────┐
│                    ZeroPoint v2 Governance                      │
├─────────────────┬─────────────────────┬─────────────────────────┤
│    GUARD         │     POLICY           │       AUDIT            │
│  "May I?"       │  "Should I?"         │  "Did I?"              │
│                 │                      │                        │
│  Local-first    │  Rule-composed       │  Hash-chained          │
│  Actor-aware    │  Graduated           │  Receipt-native        │
│  Sovereign      │  Composable          │  Immutable             │
│                 │                      │                        │
│  Runs BEFORE    │  Runs DURING         │  Runs AFTER            │
│  every action   │  every decision      │  every outcome         │
└─────────────────┴─────────────────────┴─────────────────────────┘
```

#### Pillar 1: Guard (Pre-Action Sovereignty)

The Guard is the participant's sovereign boundary. It runs locally, before any action is taken, and answers the question: "Does this action violate my boundaries?"

The Guard embodies Tenets I and II simultaneously. It refuses harmful actions (Do No Harm) and it cannot be overridden by external authority (Sovereignty Is Sacred). A peer can request, but cannot compel.

#### Pillar 2: Policy (Decision-Time Composition)

Policy runs during decision-making and answers: "Given the context, what is the appropriate response?" Policy is composable — multiple rules contribute to a graduated decision.

The PolicyEngine contains two constitutional rules that cannot be removed:

- **HarmPrincipleRule** — Enforces Tenet I. Blocks actions that would cause direct harm to humans. This rule is loaded first and cannot be overridden by any subsequent rule.

- **SovereigntyRule** — Enforces Tenet II. Ensures no action can strip an agent's right to refuse, revoke a human's ability to disconnect, or grant capabilities that were not delegated through a valid chain.

Additional rules are composable and pluggable. The most restrictive decision always wins.

#### Pillar 3: Audit (Post-Action Accountability)

The audit trail runs after every outcome and answers: "What happened, and can I prove it?"

Every audit entry is hash-chained (each entry references the previous, making the chain tamper-evident), signed (by the acting agent's Ed25519 key, making it attributable), and receipt-linked (every significant action produces a receipt that can be independently verified by any peer).

This is Tenet III made structural.

### The GovernanceGate

The GovernanceGate wires all three pillars into a single evaluation pipeline:

```
Request → Guard (pre-action) → Policy (decision) → Execute → Audit (post-action)
```

Every action flows through this gate. The gate produces a `GateResult` containing the policy decision, risk assessment, trust tier, a complete audit entry hash-chained to the previous, and the names of all policy rules that were evaluated. Nothing executes without passing through the gate. Nothing passes through the gate without joining the audit chain.

---

## Part III: Governance Mechanisms

### Mechanism 1: Trust Tiers (Identity)

Trust in ZeroPoint is not scored — it is tiered based on cryptographic capability.

```
Tier 0: Unsigned
  No cryptographic identity. Filesystem-level trust only.
  The agent exists but cannot prove anything about itself.

Tier 1: Self-Signed
  Local Ed25519 key pair. Can sign receipts and audit entries.
  Can establish links with peers. Cannot delegate authority.
  "I am who I say I am, and I can prove it."

Tier 2: Chain-Signed
  Genesis root key + delegation chain. Full provenance.
  Can delegate capabilities to sub-agents with constraints.
  Can verify the entire chain back to genesis.
  "I am who I say I am, I can prove who authorized me,
   and I can prove the chain of authority back to the origin."
```

A participant is Tier 0, 1, or 2 — whether they are a human, an agent, a service, or a device. There is no partial trust, no confidence interval, no evidence weighting. This is Tenet IV expressed as protocol: the chain of authority always leads back to a human.

### Mechanism 2: Capability Grants (Authorization)

Participants operate within capability envelopes — sets of allowed actions with constraints. Capabilities are granted at link establishment time and enforced locally by the Guard.

A `CapabilityGrant` is a signed, portable token that specifies what an agent is allowed to do (Read, Write, Execute, ApiCall, CredentialAccess, ConfigChange, MeshSend, or Custom capabilities), what constraints apply (cost ceilings, rate limits, scope restrictions, time windows, receipt requirements, escalation requirements), who granted it, who received it, and when it expires.

Grants are deterministically serializable for signing. They travel with the agent across the mesh. They are verifiable by any peer who has the grantor's public key. This replaces v1's monolithic AuthorityMatrix with portable, cryptographic authorization.

### Mechanism 3: Graduated Decisions (Action)

Every governance decision produces one of five outcomes, ordered by severity:

```
Allow       → Proceed. Optionally with conditions.
Warn        → Proceed, but the agent and/or operator is notified.
Review      → Pause. A designated reviewer must approve within timeout.
Sanitize    → Proceed, but redact sensitive patterns from output.
Block       → Refuse. Log the refusal. Produce a receipt.
```

The most restrictive applicable decision wins. This handles the real-world cases that binary decisions cannot: "yes, but carefully" and "yes, but redacted" and "not without a human looking at this first."

### Mechanism 4: Receipt-Native Proofs (Accountability)

Every significant governance action produces a receipt — a signed, portable proof that the action occurred, who authorized it, and what constraints applied. Receipts are the currency of governance in ZeroPoint. They flow through the mesh as proof of work, proof of authorization, and proof of accountability. Any peer can verify a receipt by checking its signature against the actor's public key.

### Mechanism 5: Distributed Consensus (Collective Decisions)

Some decisions require more than one agent's approval. v2 simplifies to a receipt-based consensus protocol: a proposer creates a signed Proposal receipt, sends it to N designated approvers via mesh links, each approver evaluates locally and returns a signed Approval or Rejection receipt, and the proposer collects receipts until the configured threshold is met (Unanimous, Majority, or Threshold of K-of-N).

There is no central coordinator. There is no proposal database. There is no state machine. There are only signed receipts flowing through the mesh, and a threshold rule that determines when enough have accumulated to authorize action.

---

## Part IV: What We Deliberately Omit

The following mechanisms are intentionally excluded, with rationale:

**Multi-Dimensional Trust Scoring.** In a mesh network, trust is binary at the link level and tiered at the identity level. Dynamically scoring trust across eight dimensions requires a central evaluator — which contradicts mesh sovereignty.

**Role-Based Governance.** Roles are an organizational concern, not a protocol concern. If an organization wants to assign roles, they can do so through capability grants.

**Execution Context Overrides.** Environment-specific rules are deployment concerns. The mesh protocol is environment-agnostic.

**Evidence Packs.** Evidence is valuable but should not be structurally mandated by the protocol. A Policy rule can require documentation for certain actions, but the protocol does not define what documentation looks like.

**In-Memory Decision Logging.** Replaced entirely by the hash-chained audit trail. If your governance log can be truncated, your governance is truncated.

**UDHR Framing.** The Universal Declaration of Human Rights was written for states governing people. ZeroPoint governs participants — human and non-human — in a peer-to-peer protocol. The power relationships, enforcement mechanisms, and concept of institutional "rights" do not map cleanly. The ZeroPoint Tenets — grounded in Reticulum's Harm Principle — are more direct, more deterministic, and more enforceable at the protocol level.

---

## Part V: Implementation Status

### Phase 1: Foundation (Current)

- [x] Trust Tiers (Tier0/1/2) — `zp-core/src/policy.rs`
- [x] Guard with Actor model — `zp-cli/src/guard.rs`
- [x] PolicyEngine with composable rules — `zp-policy/src/engine.rs`
- [x] Hash-chained audit trail — `zp-core/src/audit.rs`
- [x] Receipt generation and verification — `zp-receipt`
- [x] CapabilityGrant — signed, portable capability tokens — `zp-core/src/capability_grant.rs`
- [x] Governance event types — `zp-core/src/governance.rs`
- [x] GovernanceGate (Guard ↔ Policy ↔ Audit integration) — `zp-policy/src/gate.rs`
- [x] **HarmPrincipleRule** — constitutional, non-removable policy rule — `zp-policy/src/rules.rs`
- [x] **SovereigntyRule** — constitutional, non-removable policy rule — `zp-policy/src/rules.rs`
- [x] **Reticulum mesh transport** — HDLC wire-compatible TCP interfaces, interop verified — `zp-mesh/src/tcp.rs`

### Phase 2: Mesh Governance (Complete)

- [x] Distributed consensus — receipt-based multi-party approval — `zp-mesh/src/consensus.rs`
- [x] Capability negotiation — bilateral grant exchange at link establishment — `zp-mesh/src/capability_exchange.rs`
- [x] Audit chain verification — peer-to-peer chain validation — `zp-audit/src/verifier.rs`
- [x] WASM policy rules — sandboxed, exchangeable policy modules — `zp-policy/src/wasm_runtime.rs`, `zp-policy/src/policy_registry.rs`

### Phase 3: Emergent Governance (Complete)

- [x] Policy propagation — agents share and negotiate policy rules over the mesh — `zp-mesh/src/policy_sync.rs`
- [x] Capability delegation chains — Tier 2 agents delegate sub-capabilities with constraints — `zp-core/src/delegation_chain.rs`, `zp-mesh/src/envelope.rs` (CompactDelegation)
- [x] Collective audit — distributed audit trail spanning multiple agents — `zp-audit/src/collective_audit.rs`, `zp-mesh/src/transport.rs` (audit transport)
- [x] Governance receipts as reputation — an agent's receipt history IS its reputation — `zp-mesh/src/reputation.rs`

### Phase 4: Integration & Hardening

- [x] Mesh-pipeline bridge — connect MeshNode transport to the Pipeline for cross-agent governance
- [x] Reputation-gated policy decisions — PolicyEngine consults peer reputation before allowing mesh actions
- [x] Cross-agent receipt forwarding — receipts flow through the pipeline and propagate over the mesh
- [x] End-to-end integration tests — full governance flow from request to receipt to mesh propagation

### Phase 5: Verification & Trust Enforcement

- [x] Delegation chain verification — validate capability chains before accepting delegated work from peers
- [x] Audit chain verification & peer challenges — wire collective_audit + verifier into the bridge
- [x] Capability negotiation at link establishment — call negotiate() during link setup
- [x] Multi-dimensional reputation signals — feed audit, delegation, and policy signals into scoring

### Phase 6: Runtime & Production Readiness

- [x] Runtime event loop — live MeshNode packet dispatch with background Tokio task — `zp-mesh/src/runtime.rs`
- [x] Pipeline integration — `init_mesh()` wires MeshBridge + MeshRuntime + inbound processor into Pipeline
- [x] Persistent storage — SQLite-backed `MeshStore` for peers, reputations, delegations, attestations, agreements — `zp-mesh/src/store.rs`
- [x] CLI mesh commands — `zp mesh status|peers|challenge|grant|save` in mesh_commands.rs
- [x] Multi-node integration tests — end-to-end packet exchange between two+ MeshNode instances

---

## Acknowledgments

ZeroPoint's governance framework is deeply influenced by the philosophy and architecture of the [Reticulum Network Stack](https://reticulum.network), created by [Mark Qvist](https://unsigned.io). Reticulum proved that encrypted, uncentralizable networking is not only possible but practical — and that building tools which refuse to enable harm is an act of engineering conscience, not a limitation of capability.

The ZeroPoint Tenets draw directly from Reticulum's Harm Principle, its concept of cryptographic sovereignty, and its insistence that architecture embodies values. We build on Reticulum's wire protocol as citizens of its mesh, and we carry forward its philosophical commitments into the domain of accountable digital action — for agents, humans, and every system where trust cannot be left to good faith.

The [Zen of Reticulum](https://reticulum.network/manual/zen.html) is required reading.

---

## Closing: The Quiet Clarity

There are no trust scores to game. There are no committees to lobby. There are no reputation systems to manipulate. There are only keys, links, receipts, and the sovereign right of every participant to say no.

Governance in ZeroPoint is not a layer on top of the protocol. It is the protocol. Every packet is signed. Every action produces a receipt. Every receipt joins a chain. The chain is the truth — whether the actor is a human, an agent, or a machine.

Trust is infrastructure.
