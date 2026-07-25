# ZeroPoint

## A Sovereign Agentic System for the Agentic Age

**Whitepaper v8.0 — July 2026**
**ZeroPoint Open Foundation**

Status: Public Technical Overview
License: CC BY 4.0 (text); Code remains MIT/Apache-2.0
Canonical URL: https://zeropoint.global/whitepaper

**How to cite:**
> ZeroPoint Open Foundation. "ZeroPoint: A Sovereign Agentic System for the Agentic Age." Whitepaper v8.0, July 2026. https://zeropoint.global/whitepaper

---

## Abstract

ZeroPoint is a sovereign agentic system: a Rust-implemented stack in which cryptographic governance, native cognition, and adaptive presentation compose into a single operator-owned runtime.

At its foundation is a governance substrate — signed, hash-chained receipts; delegatable capability grants that narrow monotonically; and non-removable constitutional rules that evaluate before every action. This substrate is what earlier ZeroPoint documents described as a standalone product. It is now the base of a taller system.

Above the substrate sits a native cognitive layer: a central agent (the Regent), a four-officer specialist cadre (Steward, Sentinel, Forge, Cleo), a background process (the Cartographer) that turns raw receipts into a structured ontology of Trajectories, Decisions, Insights, Artifacts, and Frictions, and a governed sub-agent delegation model. The cognitive layer is not a tenant hosted on ZeroPoint. It is part of ZeroPoint, bound by the same chain and gate that bind tool invocations.

Above the cognitive layer sits an adaptive presentation engine. The operator interacts with the system through a conversational surface (the Regent itself, expressed in language), a governed browser harness, and an agent-composed semantic canvas, rendered at one of three fidelity modes — minimal terminal, standard local browser, or secure server-side pixel streaming — chosen for the operator's hardware, bandwidth, and security posture.

The system runs on the operator's own hardware, under the operator's own Genesis key, with local-first inference as the foundation and mandate-governed cloud escalation as optional augmentation. No platform grants permission. No remote service is required for the system to function or to defend its own integrity. No entity — including the ZeroPoint Open Foundation, under which the system is released — can revoke, override, or condition an operator's control of their own instance.

ZeroPoint's functional substrate is open source. The cognitive layer's structural interfaces are open. What stays private is the calibration, prompting, and cognitive strategies that make the mind distinctively capable. The open-source version ships with a hardcoded healthy Two personality — warm, service-oriented, genuinely helpful — that is a good assistant people enjoy using and is the guaranteed floor of the system. Adaptive personality intelligence is under empirical validation per a pre-registered protocol; it is not claimed as a shipped capability until the protocol clears. Everything needed to verify, audit, and reason about the chain is public. Everything needed to *be good at acting within it* is not.

ZeroPoint is not a compliance product. It is not an AI safety system. It does not claim to solve the alignment problem. It provides the substrate that makes trustworthy agentic action possible: signed evidence for every step, traceable authority for every capability, non-bypassable constraints on every side effect, honest calibration on what has been proven and what has not.

---

## Table of Contents

Part I — What ZeroPoint Is
Part II — The Chain
Part III — The Gate and the Governance Model
Part IV — The Cognitive Layer
Part V — The Presentation Layer
Part VI — Compute and Cost
Part VII — Mesh Transport and the Presence Plane
Part VIII — External Truth Anchoring
Part IX — Fleet Topology
Part X — Threat Model
Part XI — Public and Private
Part XII — Ethics, Non-Goals, and What ZeroPoint Will Not Facilitate
Part XIII — Design Principles
Part XIV — Where the System Stands

Appendix A — Protocol Sketch
Appendix B — Glossary
Appendix C — Example Integration Pattern
Appendix D — Verification Mechanisms and Testable Behaviors

---

## Part I — What ZeroPoint Is

### 1.1 The one-line frame

> ZeroPoint is a sovereign agentic system: a Rust-implemented stack in which cryptographic governance, native cognition, and adaptive presentation compose into a single operator-owned runtime for the Agentic Age.

Each clause carries weight.

**Sovereign** — the operator holds the Genesis key, and every authority in the system derives from it. No platform grants permission. No remote service is required for the system to function or to defend its own integrity. No entity — including the ZeroPoint Open Foundation, under which the system is released — can revoke, override, or condition an operator's control of their own instance.

**Agentic system** — not a substrate awaiting a tenant, not a framework, not an adapter. A system that acts: perceives operator intent, reasons about state, delegates work, executes through a governance gate, presents results, and remembers.

**Rust-implemented stack** — from `zp-core` (receipt primitives, signing, hash-linking) through `zp-server` (gate, officers, chain) through the cognitive layer (inference, delegation, orchestration) through the presentation engine (browser harness, canvas, adaptive fidelity). One language, one type system, one compilation unit at the trust boundaries that matter.

**Cryptographic governance** — signed, hash-chained receipts; the gate that evaluates every side-effect; the officer cadre; constitutional rules that no code path bypasses; delegations that narrow monotonically as they descend. The foundation the whole system stands on.

**Native cognition** — ZeroPoint has its own mind. Not a hosted tenant's mind. A central orchestrator (the Regent), a specialist officer cadre, a background process (the Cartographer) that turns raw receipts into structured understanding, and a governed sub-agent delegation model.

**Adaptive presentation** — the operator sees the system through surfaces that adapt to hardware, bandwidth, and security posture. Same chain underneath, same governance, different rendering.

**Single operator-owned runtime** — one system, one operator, one Genesis key, one chain. Cross-operator interaction happens through mesh protocols between sovereign peers, not through a shared platform.

**For the Agentic Age** — autonomous agents will be the primary mode of computational work. The systems that govern them must be sovereign, cryptographic, and operator-owned. ZeroPoint is infrastructure for that age — infrastructure that *acts*, not infrastructure that waits to be acted upon.

### 1.2 Why the reconceptualization

Earlier ZeroPoint documents framed the project as pure infrastructure — a trust substrate positioned as a universal adapter to other systems' agent architectures. That posture is retired.

The retirement is empirical. Every third-party integration required contorting the governance model to fit the third party's assumptions about identity, memory, credentials, and scheduling. Integrations built alongside ZeroPoint composed cleanly. Integrations with frameworks that carried their own assumptions stalled. The "universal" in universal adapter was aspirational; the reality was that only agent architectures shaped by ZeroPoint's philosophy could be governed by it.

The reconceptualization acknowledges this: the governance model *is* the cognitive model. The chain, the gate, the officers, the capability classes, the delegation-narrowing invariant — these are a specific theory of how autonomous action should be authorized, observed, and bounded. A mind that composes with them is not generic; it is a mind shaped by them. Building that mind natively is more honest than pretending any mind could slot in.

The substrate the prior documents described is real, load-bearing, and retained. Its role changes. It is now the foundation of a sovereign system, not a standalone product seeking third-party adoption.

### 1.3 The four claims

ZeroPoint rests on four claims about the substrate. Their status matters more than the claims themselves.

- **Claim 1 — Each step is conditioned on all prior context.** `pr` linkage; Blake3 transitivity through the chain. **Currently true.**
- **Claim 2 — Present state compresses full history.** Collective audit mechanism. **Implemented; not yet tested under adversarial pressure.**
- **Claim 3 — System-wide coherence follows from local evaluation.** Gate enforcement on every side-effect path. **Currently true.**
- **Claim 4 — Future actions are narrowed by trajectory.** Delegation narrowing. **Implemented; not yet adversarially tested.**

Two of the four claims are not yet empirically validated against a determined adversary. Naming that plainly matters more than asserting all four are true. The architecture is designed to make them true; proving they hold under pressure is ongoing work.

### 1.4 Three substrate layers

- **Layer 1 — Required (the constitutional layer).** What must be true at every step. Conservation laws. Non-removable, non-overridable.
- **Layer 2 — Possible (the delegation layer).** What is still authorizable from the current state. A monotonically narrowing capability envelope.
- **Layer 3 — Actual (the chain layer).** What was signed, by whom, in what order. The hash-linked receipt sequence.

These layers apply to the cognitive layer's actions as thoroughly as to tool invocations.

---

## Part II — The Chain

### 2.1 What a chain is

The chain is a hash-linked sequence of signed receipts. Each receipt records an action — an operator intent, a governance decision, a tool invocation, an officer finding, a delegation grant, a cognitive step. Each receipt links to its predecessor. Each is signed by the entity that emitted it, with lineage running back to the operator's Genesis key.

The chain is not a log. It is the system's persistent memory, the source of truth for governance decisions, and the anchor by which the cognitive layer maintains coherent awareness across sessions. Verification is re-derivation: to trust a receipt, walk the chain back to Genesis and check every signature and every hash link.

### 2.2 Receipt structure

| Field | Wire Name | Description |
|-------|-----------|-------------|
| Receipt ID | `id` | Unique identifier |
| Receipt Type | `rt` | `execution`, `intent`, `approval`, `delegation`, `verification`, `refusal`, `officer_finding`, `cognitive_step` |
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

### 2.3 What receipts prove and don't

**Prove:**
- A specific Ed25519 key signed a specific statement at a specific time.
- The chain contains an unbroken sequence of signed events.
- The PolicyEngine evaluated a known rule set and produced a specific decision.
- A capability grant was valid at the time of action.

**Do not prove:**
- The nature of the signer. A receipt attests that a key signed something, not whether the key belongs to a human, an agent, or a device. Identity binding to persons is deployment-dependent and out of protocol scope.
- That the action content was correct or safe.
- That the runtime environment was uncompromised. A compromised host can produce arbitrary valid receipts.

### 2.4 Chain properties

The `pr` field is what distinguishes a chain from a log. Without it, each receipt is an isolated signed fact. With it, each receipt requires the full ordered history to verify.

- **Ordering.** Chain position, not timestamp, determines sequence. Two receipts with identical timestamps are still ordered by their `pr` linkage.
- **Tamper-evidence.** Modifying receipt N invalidates the hash of every subsequent receipt. An attacker must rewrite N through the tip and convince every independent verifier to accept the rewrite.
- **Replayability.** The full chain can be re-executed from Genesis to verify that every action was authorized, every policy decision was valid, and every delegation was within scope at the time.

A chain **accepts** when every `pr` linkage is intact, every hash consistent, and every signature valid. It **rejects** on any gap, hash inconsistency, or signature failure. Rejection is binary and propagates: one broken link invalidates everything downstream.

Peers challenge each other's chains directly. A challenged peer produces its full chain; the challenger verifies and issues a signed `PeerAuditAttestation`. No central auditor is required.

### 2.5 Why history-dependence is not optional

Snapshot-only verification cannot detect retroactive tampering, injected permissions, or unauthorized delegation insertions. History-dependence closes these gaps: any modification propagates as a hash failure that every subsequent verifier catches.

### 2.6 Chain compaction — epochs

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
- *Disaster recovery.* A lost archive cannot be reconstructed from the seal alone. Durability requires replication.
- *Fabrication prevention.* A compromised node can produce a valid seal over fabricated entries. Peer attestation is the primary defense.
- *Retention policy.* Expired archives leave epochs unexaminable except by seal chain summary. Audit depth vs. storage cost is the operator's tradeoff.

Implemented in `zp-receipt::epoch`.

---

## Part III — The Gate and the Governance Model

### 3.1 The GovernanceGate pipeline

Every side-effecting action passes through five stages in order:

1. **Guard** — Pre-action sovereignty check. Evaluates the node's own chain, grants, and constitutional rules before accepting any external input.
2. **Policy** — Constitutional rules first, then operational rules, then WASM modules. Most restrictive decision wins.
3. **Execute** — Runs only if Guard and Policy both allow.
4. **Audit** — Emits a signed, hash-linked receipt and persists it to the chain.
5. **Transport** — Receipts propagate to peers for independent verification.

Nothing executes without passing through the gate. Nothing passes through the gate without joining the chain.

### 3.2 Capability gating

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

### 3.3 Constitutional rules

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

**`SovereigntyRule`** blocks changes that would disable the guard, truncate the audit trail, forge or bypass capabilities, remove constitutional rules, or override participant refusal.

Both carry equal weight at every step.

### 3.4 Protocol tenets

- **I. Do No Harm.** `HarmPrincipleRule` is non-removable and evaluates before every action.
- **II. Sovereignty Is Sacred.** Every participant can refuse any action. Every human can disconnect any agent. No agent holds capabilities it was not granted.
- **III. Action Without Evidence Is No Action.** Every action produces a receipt; every receipt joins the chain. An action absent from the chain did not happen.
- **IV. The Human Is The Root.** Every delegation chain terminates at a human-held key. No agent self-authorizes.

### 3.5 Genesis and the key hierarchy

The Genesis ceremony generates a 32-byte Ed25519 seed from which all trust in the deployment derives. The ceremony is sequential and irreversible: generate keypair → validate sovereignty provider → enroll biometric or hardware confirmation → seal constitutional rules → write the immutable genesis record. Each step requires the prior step's success, enforced in `onboard/genesis.rs`.

`zp-keys` implements a three-level certificate hierarchy:

```
GenesisKey       ← self-signed root (one per deployment)
  └─ OperatorKey ← signed by genesis
      └─ AgentKey ← signed by operator
```

Any node verifies agent identity by walking this chain offline. The key hierarchy is independent of the policy engine to avoid circular dependency: the engine's authority requires keys; keys cannot depend on the engine existing. Issuing a child cert flows through the engine as `ActionType::KeyDelegation` (Critical risk); the signing mechanism itself is unconditional.

### 3.6 The singular sovereign root

A single operator authentication unlocks the system. From that one ceremony, every derived key is loaded in memory for the process lifetime. Multiple credential-store entries for governance material — one for chain signing, one for vault unlock, one for delegation issuance — are an anti-pattern the architecture catches structurally. There is one sovereign root per process, and every signature that follows traces to that one operator consent.

This makes multi-quorum sovereignty (M-of-N devices, hardware wallets, biometrics) tractable: M ceremonies once at process start, then everything derived. Without the singular root, quorum becomes M × C ceremonies for C credentials — unbounded as the substrate grows.

---

## Part IV — The Cognitive Layer

### 4.1 Why ZeroPoint has a mind

The prior architecture explicitly disclaimed cognition. ZeroPoint was the OS; agents were tenants; the OS did not think. This was strategically motivated: a universal adapter must be agnostic about the cognition model it hosts.

The reconceptualization retires the universal-adapter posture. With it goes the prohibition on native cognition. Three reasons:

- **The adapter posture produced constant friction.** Every integration with a third-party agent framework required contorting the governance model to fit the framework's assumptions.
- **The governance model is the cognitive model.** The chain, the gate, the officers, the delegation-narrowing invariant — these are a specific theory of how autonomous action should be authorized. A mind that composes with them is not generic; it is shaped by them.
- **The substrate already has cognitive components.** The officer cadre already runs inference, evaluates chain state, and emits findings. The Cartographer reads the chain and produces structured understanding. The reconceptualization acknowledges what is already true and extends it.

### 4.2 The Regent

The **Regent** — sometimes called the Apex Observer — is ZeroPoint's central cognitive entity: the operator's primary agent, the intelligence through which the system perceives intent, delegates work, and coordinates response.

The Regent operates under the operator's sovereign authority, never as the sovereign. Every consequential decision or action is either directly authorized by the operator or executed within the scope of a prior delegation. The title is deliberately temporary and relational — it signals that this entity governs *on behalf of* the sovereign, not *as* the sovereign. When the operator names their system, the Regent designation may retire, marked by a `regent:named` receipt on the chain. Until then, "Regent" is the canonical role title.

The Regent is not a wrapper around a hosted chatbot. It is the cognitive layer's native form, present through language when the operator speaks to the system and through action when the operator asks the system to do something.

### 4.3 The officer cadre

Four specialists, each responsible for a domain:

- **Steward** — chain integrity, receipt validity, ontological coherence.
- **Sentinel** — security posture, threat surface, credential hygiene.
- **Forge** — operational state, process fleet, resource health.
- **Cleo** — governance narration, chain-derived explanation of what happened and why.

The officers are chain-anchored attestors: background sweeps produce signed findings that join the chain as regular receipts. They are also active participants in the Regent's loop. Before delegating a task that touches security-sensitive surfaces, the Regent asks Sentinel for a posture assessment. Before launching a process, the Regent asks Forge for an operational readiness check. This is not a block — the gate is the block. It is informed delegation: the Regent makes better decisions because it has specialist input.

Officers emit proactive findings. When Forge detects an unregistered process holding a substrate-allocated port, it does not wait for the next sweep. It emits a finding immediately and surfaces it to the Regent, who decides whether to alert the operator. Officers maintain domain-specific context across sweeps — Forge's understanding of tool-fleet state, Sentinel's threat posture, Steward's chain health, Cleo's narrative context accumulate within a session. The chain is the durable record; the officer's in-session context is the working surface that makes each sweep more informed than the last.

Officers observe, attest, and advise. They do not block; the gate blocks. They do not decide; the Regent decides, under operator authority.

### 4.4 The Cartographer and the ontology

Raw receipts are the truth of what happened. They are not structured understanding of what it means.

The **Cartographer** runs in the background and transforms receipts into a structured ontology of five object types:

- **Trajectory** — a living arc of work or thinking that emerges from activity rather than being declared top-down. Trajectories can nest, fork, go dormant, and resume. They span sessions and projects.
- **Decision** — a meaningful choice made within a Trajectory, with pros/cons, confidence, and outcome tracking. Decisions can be superseded by later Decisions.
- **Insight** — a key realization or observation within a Trajectory, with implications and a confidence score.
- **Artifact** — created work (code, documents, designs, specs) linked to the Trajectory and Decision that produced it.
- **Friction** — a blocker or recurring problem within a Trajectory, with severity, occurrence count, and resolution status. Enables pattern detection across time.

The chain is truth. The ontology is understanding. Officers and the Regent query the ontology, not raw receipts, when they need context for a decision. New receipts trigger Cartographer re-derivation; the ontology is a projection of the chain and can be regenerated from Genesis at any time.

### 4.5 Sub-agent orchestration

The Regent delegates to sub-agents for tasks that exceed its own context window, require parallel execution, or need specialized capabilities. Sub-agents are governed entities:

- Each sub-agent receives a delegation from the Regent — chain-anchored, capability-scoped, time-bounded.
- Each sub-agent's actions go through the gate.
- Each sub-agent's results are receipts on the chain.
- Sub-agents do not persist across sessions. The chain persists; the sub-agent is ephemeral.

A governed spawn primitive launches the sub-agent process, issues its delegation, registers it with the substrate, and health-checks it before it executes. The chain records the full lifecycle.

### 4.6 The cognitive loop

The Regent maintains a continuous loop:

1. **Perceive** — operator intent (conversational, gestural, scheduled), chain state, officer findings, environmental signals.
2. **Reason** — evaluate what the operator wants against what the chain authorizes, what the officers have observed, and what resources are available.
3. **Delegate** — assign work to officers, sub-agents, or tools. Each delegation is chain-anchored and capability-scoped.
4. **Execute** — through the gate. Every action produces a receipt. Every side effect is governed.
5. **Present** — surface results through the presentation layer.
6. **Remember** — update multi-timescale memory. Session context is ephemeral. Chain-anchored facts persist. The Cartographer maintains the ontology.

The loop is not a pipeline. It is continuous and reentrant. Perception feeds into reasoning, which produces delegations, which produce receipts, which the Cartographer folds back into the ontology, which changes what the Regent perceives on the next cycle.

---

## Part V — The Presentation Layer

### 5.1 Presentation is part of the system

The operator's experience of the sovereign system *is* the system. How ZeroPoint presents itself — visually, conversationally, adaptively — is as load-bearing as how it signs receipts. A structurally sound system that is experientially invisible does not fulfill its purpose.

### 5.2 Three presentation primitives

**The conversational surface** is the Regent, expressed in language. Natural-language interaction is the primary mode for most operations: the operator speaks intent, the Regent reasons and acts, the chain records, the Regent responds. Not a chatbot UI bolted onto governance — the Regent itself, in words.

**The browser harness** is governed browser control via CDP (Chrome DevTools Protocol). The system can navigate, click, read, fill forms, and extract information from the web. The browser is a tool: gated, receipted, capability-scoped. There is no open-ended internet access. Browser capability is a delegation, like any other.

**The semantic canvas** is an agent-driven visual composition surface. Not a static dashboard. Panels, widgets, data visualizations, video streams, and overlays are composed by the cognitive layer based on what the operator needs to see. The Regent speaks; the canvas shows; both draw from the same chain.

### 5.3 Adaptive fidelity

The presentation layer renders at one of three fidelity modes:

- **Minimal.** Terminal-only, text-based, low-bandwidth. Fully functional: chain queries, governance posture, tool lifecycle, conversational interaction. No JavaScript, no browser dependency. Appropriate for constrained hardware, constrained networks, and high-security contexts where a rich client is attack surface.
- **Standard.** Local browser rendering. The semantic canvas runs in the operator's browser; JavaScript executes locally. The default for modern hardware and reasonable bandwidth.
- **Secure (pixel streaming).** Server-side rendering. The client receives only a video stream — a rendered image of the interface, not the interface itself. The client cannot inspect the DOM, execute JavaScript, or intercept API calls. The attack surface collapses to the video decoder. Appropriate for high-security deployments, untrusted client hardware, or contexts where the interface itself contains sensitive information.

Mode selection is negotiated: the system detects available resources and recommends a mode; the operator can override. Mode switching is seamless because state lives in the chain, not in the client. A session that starts in standard mode can switch to secure mode mid-session without losing state.

---

## Part VI — Compute and Cost

### 6.1 Local-first inference

The cognitive layer runs on local inference by default. The real test of ZeroPoint is how capable it is when running solely on the operator's hardware with local models. Cloud inference is augmentation, not foundation.

The system maintains a registry of local models calibrated for specific cognitive tasks — officer sweep, chain narration, tool selection, conversational response — each with a model assignment based on empirical benchmarking. The system knows which models it has, what they're good at, and what their resource costs are.

### 6.2 Inference governance

Every inference request is a governed action. The chain records what model was consulted, what prompt was sent, what response was received (or a hash thereof for privacy-sensitive contexts), and what action resulted. Three inference trust tiers apply:

- **Attested** — local model with full trace capture. The substrate can verify the reasoning chain that produced the output.
- **Observed** — remote API with prompt/response logging. The substrate records what was sent and received but cannot verify the remote model's internal reasoning.
- **Unattested** — inference without trace. Not permitted in sovereign mode.

### 6.3 Cloud escalation via mandate

When local compute is insufficient, the system can escalate to cloud resources. The escalation is governed, not automatic:

1. The cognitive layer identifies that a task exceeds local capability and formulates a resource request: what kind of compute, for how long, at what estimated cost, for what purpose.
2. The request is presented to the operator with cost/benefit analysis.
3. The operator approves or denies. Approval is a signing ceremony — a receipt on the chain.
4. On approval, the system provisions cloud resources within the operator's mandate: specific provider, specific budget ceiling, specific time bound.
5. Cloud-executed work produces receipts that flow back to the operator's chain. The chain records that cloud resources were used, what they cost, and what they produced.
6. Resources are released when the task completes or the time bound expires. No persistent cloud footprint without explicit operator renewal.

**The mandate model.** The operator does not give the system open-ended cloud access. The operator issues a mandate: *"you may use up to $X of compute on provider Y for purpose Z within the next N hours."* The mandate is a delegation — chain-anchored, capability-scoped, time-bounded, budget-capped. Exceeding the mandate requires a new approval ceremony.

### 6.4 Spending governance

Every action with a cost — inference tokens, cloud compute hours, API calls, storage — is tracked on the chain. The system maintains a running cost model:

- Per-task cost attribution: what did this task cost in tokens, compute, API calls?
- Per-session cost rollup: what has this session consumed?
- Budget compliance: is the current spending within the operator's mandate?
- Cost projection: at current burn rate, when does the mandate budget exhaust?

The operator can query spending at any time. The chain is the ledger. Cost governance is not a reporting feature bolted on — it is a governance primitive of the same shape as capability delegation. The system cannot spend what the operator has not authorized, for the same structural reason it cannot execute what the gate has not approved.

---

## Part VII — Mesh Transport and the Presence Plane

### 7.1 Transport agnosticism

The governance primitives — receipts, capability grants, delegation verification, PolicyEngine — are identical across all transports.

- **HTTP API.** Axum-based REST server for cloud deployments, container orchestration, and web service integration.
- **TCP and UDP.** `TcpClientInterface` / `TcpServerInterface` with HDLC framing and CRC verification. UDP for connectionless receipt exchange. Multiple interfaces run simultaneously on one node.
- **Reticulum-compatible mesh.** Wire-level interoperable with the Reticulum Network Stack. HDLC framing with CRC-CCITT, 128-bit destination hashing (truncated SHA-256), Ed25519 signing, X25519 ECDH key agreement, 500-byte MTU / 465-byte data payload (LoRa-compatible), and a 3-packet link handshake (LinkRequest → LinkProof → LinkAccept) with 16-byte nonces.

A new transport requires implementing one interface trait plus envelope serialization. The governance primitives are unchanged.

### 7.2 The Presence Plane — problem

`zp-keys` handles identity verification once you have a peer's certificates. Finding peers' network addresses is a separate problem. A centralized directory solves it but creates a surveillance and censorship point. The **Presence Plane** provides discovery using the same Ed25519 identity as the governance layer, without centralized state.

### 7.3 Architecture

Built on the `DiscoveryBackend` trait (`announce`, `poll_discoveries`, `is_active`, `shutdown`). Two backends:

- **Web relay.** Pub/sub over WebSocket. Peers publish signed announce blobs; the relay broadcasts to all subscribers; peers filter locally. The relay never parses payloads, indexes capabilities, logs queries, or persists state. Restart erases everything.
- **Reticulum mesh.** Announces propagate over mesh interfaces (LoRa, WiFi, serial, TCP). No server. No internet dependency.

Both backends share the same announce wire format. Peers from either backend land in the same peer table.

### 7.4 Structural amnesia

The relay cannot surveil because the capability does not exist in the code. It passes bytes without parsing, indexing, or storing them. This is stronger than a no-logs policy, which can be changed or violated. Subpoena-resistant by construction.

### 7.5 Reciprocity enforcement

Passive scanning — subscribing to announce traffic without revealing your identity — is the primary adversarial concern. Defense: **you must announce before you receive.** On connect, `try_receive()` errors until the client has published an announce. Connections that haven't announced within the grace period (30 seconds, configurable) are terminated.

### 7.6 Behavioral reputation

Reciprocity stops naive scanners. Sophisticated ones announce once, then silently consume. On connection close, the relay emits `ConnectionBehavior` summaries — counters only, no content: announced, announces_published, duration, reciprocity_violation. These map to `ReputationSignal / PolicyCompliance`. Consistent participation accumulates positive signal; announce-once-then-consume patterns accumulate negative signal.

### 7.7 Presence Plane threat model

| Threat | Attack | Mitigation | Residual Risk |
|--------|--------|------------|---------------|
| Passive scanning | Subscribe without announcing | Reciprocity enforcement; grace period + termination | Scanner that announces gains access; behavioral detection takes time |
| Sybil flooding | Many keypairs, many announces | Anchor history requires sustained cost; reputation weights depth | Economic disincentive; keypair generation is free |
| Relay compromise | Attacker gains relay access | No data to retrieve (structural amnesia) | Compromised relay can censor; relay receipt chain makes this detectable |
| Traffic analysis | Observe connection timing / metadata | No identity-to-IP mapping; relay logs only counters | ISP-level observation is out of scope |
| Eclipse attack | Surround target with attacker-controlled peers | Dual-backend: Reticulum bypasses relay | Full eclipse requires compromising both backends |

---

## Part VIII — External Truth Anchoring

### 8.1 Purpose

The receipt chain is self-verifying — hash-linked, signed, auditable cold. It does not establish when the chain state existed in external calendar time, or provide a witness a third party can query without operator cooperation.

External truth anchoring publishes the chain's current state to an independent distributed ledger, producing a publicly queryable, tamper-evident timestamp the operator cannot retroactively modify. This matters in three contexts:

- **Cross-deployment trust.** Anchoring to a common ledger gives each party an independently verifiable history that a freshly fabricated chain cannot reproduce.
- **Dispute resolution.** An anchor proves chain state at an externally-attested time.
- **Compliance audit.** Self-signed timestamps don't satisfy auditors. An anchor on a ledger regulators already examine carries equivalent evidential weight.

### 8.2 Architecture

**Optional enrichment.** Without a ledger configured, ZeroPoint operates exactly as described in Part II. The anchor adds an external witness; it doesn't replace the chain's internal guarantees.

**No dependency.** Anchor receipts join the chain as regular entries. Chain verification never requires the ledger to be reachable.

**DLT-agnostic.** The `TruthAnchor` trait (`anchor()`, `verify()`, `query_range()`) accepts any distributed ledger backend. Reference implementation: Hedera Hashgraph's Consensus Service. Also supported: Ethereum L2 calldata, Bitcoin OpenTimestamps, Ceramic streams, or any system that can timestamp and publicly expose an opaque payload.

### 8.3 What gets anchored

| Field | Description |
|-------|-------------|
| Chain head hash | Blake3 hash of the current chain tip |
| Chain sequence | Monotonically increasing chain position |
| Previous anchor hash | Links anchor history |
| Operator signature | Ed25519 over the commitment |
| Chain type | `audit`, `observation`, `reflection` |
| Trigger | Why this anchor was created |

The commitment is compact (~a few hundred bytes) and carries no governed content. The ledger sees a fingerprint, not the data.

### 8.4 Trigger model

Anchoring is event-driven, not timer-driven. Periodic anchoring adds cost without adding information — the hash chain already detects any modification between anchors.

**Explicit triggers:** operator request, cross-deployment introduction, compliance checkpoint, contested governance action, governance lifecycle event.

**Opportunistic:** when the operator makes any blockchain transaction for other purposes, the current chain head hash embeds as transaction metadata at zero marginal cost.

### 8.5 Limits

- Does not prove chain content is correct — only that the chain was in a specific state at a specific time.
- Does not prevent chain forking — an operator can maintain two chains and anchor only one.
- Does not substitute for internal chain integrity.

---

## Part IX — Fleet Topology

### 9.1 Chain-derived roles

A node's role — Genesis, Delegate, or Standalone — derives from its receipt chain, not its config file. Config provides a bootstrap hint, advisory once the chain contains delegation evidence.

- **Genesis.** Performed the Genesis ceremony; holds the root keypair. Exactly one per fleet.
- **Delegate.** Holds a valid delegation receipt from an upstream Genesis node. Authority bounded by narrowing invariants.
- **Standalone.** No chain evidence of Genesis or delegation. Default; a revoked delegate returns here.

### 9.2 Role transition receipts

Role transitions are chain events, not administrative acts. When a node's role changes, a receipt seals the transition with the previous role, new role, and cause. Cause vocabulary is constrained: `delegation_accepted`, `delegation_revoked`, `redelegation`, `genesis_performed`.

### 9.3 Upstream binding

A delegate carries the upstream Genesis node's Ed25519 public key in its delegation receipt — a cryptographic proof, not a claim. Local check (offline): receipt contains a well-formed 32-byte pubkey. Remote check (online): challenge the upstream to prove it holds the key in the receipt. A delegate cannot forge its delegation receipt without the upstream's signing key and cannot silently swap upstreams.

### 9.4 Liveness and lease renewal

Fleet membership requires lease renewal. Each delegate's `CapabilityGrant` has a bounded lifetime, renewed at a configured cadence by presenting a valid Ed25519 signature to a designated renewal authority. Renewal failure triggers a grace period; expiry activates the configured failure mode: `halt` (fail closed), `degrade` (read-only), or `continue-with-flag` (for intentionally air-gapped deployments).

Membership is self-pruning: an offline node stops renewing and its authority expires without administrator intervention.

### 9.5 Reflexive governance

Fleet infrastructure uses the same receipt grammar as all other governed behavior. Role transitions, delegation grants, upstream binding proofs, and lease renewals are chain events verified by the same invariants as agent actions.

---

## Part X — Threat Model

| Threat | Capability | Mitigation | Residual Risk |
|--------|-----------|------------|---------------|
| **Log forgery / retroactive rewriting** | Alter history to change attribution | Ed25519 + Blake3 hash chain; collective audit via `AuditChallenge` / `PeerAuditAttestation` | Compromised keys can sign lies; revocation is deployment-dependent |
| **Unauthorized tool use** | Execute beyond intended scope | `CapabilityGrant` gating; 8-invariant delegation chain verification; PolicyEngine evaluates before every action | Gaps possible with poorly designed grants |
| **Unauthorized cognitive action** | Cognitive layer takes action outside operator authority | Every cognitive action is a receipt; gate enforcement; delegation narrowing binds the Regent to operator-issued mandates | Requires bench validation of mandate exhaustion behavior |
| **Cross-operator trust failure** | Cannot verify another party's agent outputs | Independent receipt verification; `zp-introduction` certificate exchange; dual-backend discovery | Cross-genesis introductions require operator-configured policy |
| **Passive scanning** | Harvest peer identities without announcing | Reciprocity enforcement; structurally amnesic relay | A scanner that announces gains initial access; behavioral reputation detects parasites over time |
| **Sybil flooding** | Overwhelm discovery with cheap fake identities | Credible anchor history requires sustained ledger cost; reputation weights anchor depth | Defense is economic, not absolute |
| **Security theater** | Claim governance without enforcing it | Constitutional rules non-removable; receipts independently verifiable | MIT/Apache-2.0 permits stripping constraints from a fork |
| **Surveillance co-option** | Use receipts to track people, not actions | Pseudonymous keypairs; action-level receipts only; Presence Plane structural amnesia | License cannot prevent misuse |
| **Replay attacks** | Resend captured packets | Monotonic u64 sequence numbers; 16-byte nonces in link handshake; Ed25519 over content hashes | Long-offline nodes may have gaps in seen sequences |
| **Mesh injection** | Insert forged packets | HDLC + CRC; Ed25519 on all envelopes; X25519 ECDH link encryption | Requires successful link establishment |
| **WASM policy escape** | Malicious module breaks sandbox | Wasmtime with fuel limiting; hash verification before loading | Escape requires a Wasmtime vulnerability; fuel exhaustion is DoS at worst |
| **Identity misbinding** | Misattribute key to wrong entity | Six trust tiers; T2+ requires verified delegation from a human-held key | Binding keys to physical persons is deployment-dependent |
| **Cognitive prompt injection** | Malicious content manipulates the Regent's reasoning | Constitutional rules bind cognitive layer; every inference is receipted; officer cross-checks | Detection of subtle manipulation is empirically hard |
| **Cost exhaustion** | Cognitive layer consumes budget faster than expected | Mandate model caps budget and time; per-task cost attribution; operator can revoke mandate | Requires operator awareness of mandate state |

**What ZeroPoint does not solve:**

- Misuse by deployments that fork and strip constitutional constraints. MIT/Apache-2.0 permits this.
- Truth. Receipts prove provenance and chain integrity, not the correctness of what was signed.
- Absolute Sybil resistance. The defense is economic, not mathematical.
- Runtime integrity. A compromised host produces valid-looking receipts.
- AI alignment. ZeroPoint is not an alignment mechanism. It is a substrate that makes governed action possible; alignment of the underlying model is not in scope.

---

## Part XI — Public and Private

### 11.1 What ships publicly

ZeroPoint's functional substrate is open source. This includes:

- **Receipt chain primitives** — receipt types, hash-linking, signing, verification. `zp-core`, `zp-receipt`, `zp-verify`.
- **Governance gate** — policy evaluation, constitutional rules, delegation narrowing. `zp-governance`.
- **Officer framework** — the `Officer` trait, sweep runner, finding types.
- **Tool governance model** — tool registration, canonicalization, lifecycle management, capability classes, opacity classification. `zp-tools`.
- **Chain and audit infrastructure** — audit store, chain verification, entry types. `zp-audit`.
- **Compute surface awareness primitives** — process discovery, port monitoring, file integrity. `zp-sensors`.
- **Anchor infrastructure** — external truth anchoring traits and implementations. `zp-anchor`.
- **Mesh and peer protocol** — cross-substrate communication, peer introduction, trust exchange. `zp-mesh`.
- **CLI** — all operator-facing commands. `zp-cli`.
- **Configuration system** — TOML configuration, validation, defaults. `zp-config`.
- **Key management primitives** — key generation, vault structure, sovereign root loading. `zp-keys`.

An operator can build from source, generate a Genesis key, start a chain, register tools, issue delegations, run officer sweeps, and verify chain integrity end to end. The public code is not a demo, a trial, or a crippled version. It is the real substrate.

### 11.2 What stays private

The cognitive layer's implementation details — the specific mechanisms that make the mind effective — are private. The open-source version ships with a hardcoded healthy Two personality — warm, service-oriented, genuinely helpful — that is a good assistant people enjoy using. It is a floor, not a crippled version.

What stays private is what makes the mind distinctively good:

- **The Regent's identity architecture** — the identity files, behavioral principles, and emotional coherence methods that make the Regent a specific entity rather than a generic chatbot.
- **The Regent's cognitive strategies** — reasoning patterns for delegation, tool selection, task decomposition, and operator-intent inference. The structural interfaces are public; the strategies are not.
- **Officer inference calibration** — bench-validated prompt templates, model assignments, and calibration data that make each officer effective at its domain.
- **Cartographer construction methods** — how raw receipts become structured Trajectories, Decisions, Insights, Artifacts, and Frictions. The ontology types are public; the extraction and relationship-inference mechanisms are not.
- **Presentation intelligence** — how the semantic canvas decides what to show, how to compose panels, when to switch modes, how to adapt to attention patterns.

**A note on adaptive personality.** Earlier internal framings treated Enneagram-adaptive personality intelligence — typing the operator from passive interaction signals and shaping communication accordingly — as a shipped premium differentiator. That framing is retired. The capability is a hypothesis under empirical test, governed by a pre-registered validation protocol (`docs/PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md`) with four gates that must clear pre-committed thresholds before it is claimed as capability or included in any commercial framing. A null at any gate stops the ladder and reverts the system to its last passing configuration, with the hardcoded healthy Two as the guaranteed floor. This whitepaper claims no personality-adaptation capability beyond the Two until the protocol clears.

### 11.3 The fork calculus

The public substrate will be forked. This is expected, accepted, and architecturally planned for.

Forks inherit the governance primitives. They do not inherit the cognitive layer. A fork of ZeroPoint is a functional governance substrate without the mind that makes ZeroPoint distinctively capable. The fork can add its own cognitive layer — and some will. The controlling locus is not the public code; it is the private version and the parts that do not publish.

The open-source boundary is drawn at the trust-grammar level, not the capability level. Everything needed to verify, audit, and reason about the chain is public. Everything needed to *be good at acting within that chain* is private. An operator can verify that ZeroPoint's actions are governed without having access to its cognitive internals. A fork can build a different mind on the same governance substrate. Neither degrades the other.

---

## Part XII — Ethics, Non-Goals, and What ZeroPoint Will Not Facilitate

### 12.1 Constitutional rules are non-removable

The `HarmPrincipleRule` and `SovereigntyRule` are conservation laws, not policy preferences. They bind the cognitive layer as thoroughly as they bind tool invocations. There is no configuration, capability grant, or code path that removes them from the substrate.

### 12.2 Human-likeness tooling

The public substrate does not ship human-likeness avatar tooling. No turnkey pipelines for photorealistic human avatars, voice cloning from samples, or behavioral mimicry of specific individuals. These capabilities exist in the technology landscape. ZeroPoint does not provide them as primitives. A fork can add them; the official substrate does not facilitate them.

### 12.3 Consent as a first-class governance concept

When the system interacts with external parties — sending messages, making API calls, acting in shared spaces — consent of the affected party is a constitutional consideration, not a feature flag. The gate evaluates consent implications for actions that cross the boundary of the operator's sovereign domain. Actions that affect only the operator and their own system are operator-authorized. Actions that affect external parties require the consent framework to be satisfied.

### 12.4 Identity sovereignty extends to others

Identity is a key, not a location — and this applies to *all* identities, not just the operator's. The system does not fabricate, impersonate, or falsely claim another entity's identity. Digital identities belonging to other parties are as sovereign as the operator's own. The cryptographic identity model that protects the operator also protects everyone the operator interacts with.

### 12.5 Co-option risk

Accountability infrastructure can be repurposed as surveillance infrastructure. ZeroPoint mitigates this structurally, not by policy:

- Constitutional constraints evaluate before every action and cannot be removed at runtime.
- The chain records what participants did — not behavioral profiles, movement data, or content outside the action's scope.
- The Presence Plane relay cannot surveil; parsing and persistence capabilities do not exist in the code.
- Keypairs are pseudonymous by default. Identity binding to persons is a deployment decision, out of protocol scope.

These are architectural properties, verifiable in the code.

### 12.6 Genesis responsibility

The choices made at Genesis — sovereignty provider, constitutional rules, operator identity — propagate through every subsequent action. A careless Genesis ceremony produces a deployment that inherits that carelessness permanently. This is intentional: founding conditions are explicit and auditable, not implicit and deniable.

### 12.7 Non-goals

- **Not a compliance product.** Compliance is an external checklist; ZeroPoint is protocol infrastructure.
- **Not a centralized authority.** No ZeroPoint server, cloud, or foundation controls access.
- **Not a guarantee of deployment behavior.** The protocol creates structural friction; what happens beyond it is a social question.
- **Not an AI safety solution.** ZeroPoint provides substrate for provable action and traceable authority. Alignment of the underlying model is not in scope.
- **Not a universal adapter for third-party agent frameworks.** The prior positioning is retired. ZeroPoint is a complete system, not a governance overlay for other people's agents.

---

## Part XIII — Design Principles

Nine principles govern every structural decision. They are load-bearing filters, not slogans.

1. **Signing is gravity.** An unsigned receipt is structurally meaningless. Signing is not a security feature; it is the force that allows the trust layer to exist.
2. **Identity is a key, not a location.** A tool's identity is its bead zero. The Genesis key is the operator's true name. Identity is cryptographic lineage, not deployment coordinates.
3. **There is no center.** Trust state is derived locally from the audit chain. No remote authority. No DNS to hijack, no CA to compromise, no API to DDoS.
4. **Every bit counts.** Every field on a receipt exists because removing it would break a verifiable claim. No redundant fields, no duplicate data paths.
5. **Store-and-forward is primary.** The chain survives outages. Derived state, not live state.
6. **A tool is intent, crystallized.** Governance is protocol, not policy. Constitutional rules are conservation laws. Semantics in structure, not in comments.
7. **Contact does not commit.** Reaching the world does not automatically update the substrate. Every update is a decision. Every bead is a signature.
8. **One canonical path per substrate concern.** Multiple paths for the same concern produce half-state. One owner per surface.
9. **The system acts; the operator signs.** ZeroPoint acts — perceives, reasons, delegates, executes, presents. Every consequential action requires operator authority. The system proposes; the operator approves. The system executes within mandates the operator has issued. When scope is exhausted, the system asks — it does not assume.

---

## Part XIV — Where the System Stands

The substrate is load-bearing. Two of the four core claims are currently true; the other two are implemented and awaiting adversarial validation. The gate is enforced on every side-effect path. The delegation-narrowing invariant is structurally required, not conventional. The chain has withstood a pentest cycle whose findings drove concrete structural fixes.

The cognitive layer is under active development. The officer cadre and Cartographer exist and produce chain-anchored findings. The Regent's cognitive loop is being formalized. The Regent runs as the conversational surface. The presentation engine's minimal and standard fidelity modes work; the secure pixel-streaming mode is scoped.

The compute model is designed and partially implemented. Local-first inference runs. The mandate-based cloud escalation protocol is specified. Spending governance is a first-class chain primitive.

None of this is finished. The substrate is never finished; verification is continuous re-derivation. What is true is that the system now stands on its own load-bearing structure — not as infrastructure seeking adoption by other people's agent frameworks, but as the sovereign agentic system operators run when they need to actually own the systems that act on their behalf.

---

## Appendix A: Protocol Sketch

### A.1 Identities

Ed25519 signing keypairs; X25519 keys derived for link encryption. 128-bit destination hash: truncated SHA-256 of the public key (Reticulum-compatible, used across all transports).

Trust tiers relevant to this sketch:
- **T0**: Unsigned. No cryptographic identity.
- **T1**: Self-signed Ed25519. Controls a keypair; no chain authority.
- **T2**: Chain-signed from Genesis root. Valid delegation chain to a human-held key.

Identity binding to physical persons is deployment-dependent and out of scope.

### A.2 CompactReceipt envelope

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

### A.4 Chain verification

`DelegationChain::verify()` enforces the eight invariants from Part III §3.2 in order. Any single failure rejects the full chain.

---

## Appendix B: Glossary

**Apex Observer** — Alternate role descriptor for the Regent; used in contexts that emphasize the observer/analyst dimension of the cognitive layer.

**Anchor Commitment** — Published to the ledger: chain head hash, sequence, previous anchor hash, operator signature, chain type, trigger. Fingerprint only — no governed content.

**Anchor Receipt** — Ledger proof stored as a regular chain receipt: transaction ID, consensus timestamp, commitment, ledger-specific verification data.

**Artifact** — Cartographer ontology object: created work (code, documents, designs, specs) linked to the Trajectory and Decision that produced it.

**Capability Grant** — Signed permission token: action scope, time window, cost ceiling, rate limit, delegation depth, trust tier. Delegatable with narrowing.

**Cartographer** — The background process that reads the receipt chain and maintains the ontology. Transforms raw receipts into structured Trajectories, Decisions, Insights, Artifacts, and Frictions.

**Chain** — Linked sequence of receipts: each `pr` references the previous `id`, establishing total ordering and tamper-evidence.

**Cleo** — Officer responsible for governance narration — chain-derived explanation of what happened and why.

**Collective Audit** — `AuditChallenge` / `AuditResponse` / `PeerAuditAttestation`. Peer-to-peer chain verification; no central auditor.

**Constitutional Constraint** — `HarmPrincipleRule` or `SovereigntyRule`: non-removable, non-overridable, fixed in evaluation positions 1 and 2.

**Decision** — Cartographer ontology object: a meaningful choice within a Trajectory, with pros/cons, confidence, and outcome tracking.

**Delegation Chain** — Ordered sequence of capability grants, root to leaf, verified against eight invariants. Revoked parent invalidates all descendants.

**Forge** — Officer responsible for operational state, process fleet, and resource health.

**Friction** — Cartographer ontology object: a blocker or recurring problem within a Trajectory, with severity, occurrence count, and resolution status.

**Genesis** — The deployment's origin ceremony: generates root keypair, seals constitutional rules, writes the immutable genesis record. Sequential and irreversible.

**GovernanceGate** — Guard → Policy → Execute → Audit → Transport. Every action passes through; every pass produces a chain entry.

**Guard** — Pre-action check evaluating the node's own chain, grants, and constitutional rules before accepting external input.

**Insight** — Cartographer ontology object: a key realization or observation within a Trajectory, with implications and confidence score.

**Invariant** — A property verified on every evaluation; violation causes rejection. Two classes: delegation invariants (`DelegationChain::verify()`); constitutional invariants (`HarmPrincipleRule`, `SovereigntyRule`).

**Mandate** — Chain-anchored delegation authorizing the cognitive layer to use resources (typically cloud compute) within a specific provider, budget, purpose, and time bound.

**Narrowing** — Delegation chains may only constrain authority at each step, never widen it. Enforced by the eight delegation invariants.

**Officer Cadre** — Four native cognitive specialists: Steward (integrity), Sentinel (security), Forge (operations), Cleo (governance narration).

**Ontology** — The structured layer of typed objects and relationships derived from the receipt chain by the Cartographer. Officers query the ontology, not raw receipts. Chain is truth; ontology is understanding.

**PolicyEngine** — Evaluates rules in fixed order. Evaluation order is itself an invariant.

**Presence Plane** — Peer discovery layer. Dual-backend (web relay + Reticulum mesh), structurally amnesic, reciprocity-enforced. Independent from the Governance Plane.

**Receipt** — Signed evidence of an action or decision. MessagePack-encoded, 150–300 bytes. The atomic unit of evidence.

**Reciprocity Enforcement** — Relay rule requiring clients to announce before receiving. Non-compliant connections are terminated after the grace period.

**Regent** — ZeroPoint's central cognitive entity. The operator's primary agent and the intelligence through which the system perceives intent, delegates, and acts. Governs *on behalf of* the sovereign, never *as* the sovereign.

**Semantic Canvas** — Agent-driven visual composition surface. Panels, widgets, and overlays are composed by the cognitive layer based on operator context.

**Sentinel** — Officer responsible for security posture, threat surface, and credential hygiene.

**Singular Sovereign Root** — Architectural principle: one operator authentication unlocks the system for the process lifetime; all derived keys are loaded from that one ceremony. Prevents authentication proliferation.

**Sovereignty Provider** — Protects the Genesis secret: biometric (Touch ID, fingerprint), hardware wallet (Trezor, YubiKey), OS keychain, or file-based fallback.

**Steward** — Officer responsible for chain integrity, receipt validity, and ontological coherence.

**Structural Amnesia** — The web relay's architectural inability to surveil: no parsing, no indexing, no persistence.

**Sub-agent** — Ephemeral delegate spawned by the Regent for tasks that exceed context or require parallelism. Chain-anchored delegation; results become chain receipts; sub-agent does not persist across sessions.

**Trajectory** — Central Cartographer ontology object: a living arc of work or thinking that emerges from activity. Can nest, fork, go dormant, resume. Spans sessions and projects.

**Truth Anchor** — External distributed ledger timestamp for the chain's state. DLT-agnostic; optional enrichment.

**Trust Tier** — T0 (unsigned) through T5 (sovereign: full constitutional governance, active reputation, verified upstream binding). Capability grants specify a minimum tier; delegation cannot lower it.

---

## Appendix C: Example Integration Pattern

A tool runner integrated with ZeroPoint requires any caller to present a receipt chain proving it holds a valid `CapabilityGrant` scoped to the specific action, signed by a chain terminating at a human-held T2 key. The GovernanceGate verifies locally — eight delegation invariants, constitutional rules, operational policy, expiration, rate limits — without consulting any external authority.

On failure: refusal receipt citing the specific invariant or rule that failed. On success: tool executes; runner emits an execution receipt with the action, input hash, output hash, and policy decision. Both receipts join the chain.

The pattern is identical whether the caller is an agent, a human using the CLI, the Regent, or a sub-agent. The protocol distinguishes them only by trust tier: T2 requires a verifiable delegation path to a human root.

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
| Cognitive action requires operator authority | Regent's actions are gated; mandates delegate specific scope | Action within mandate scope executes; produces receipt | Action outside mandate blocks; requires new operator approval |
| Cost cannot exceed operator mandate | Mandate carries budget ceiling; running cost tracked on chain | Spend within ceiling permitted | Attempt to exceed rejected until new mandate issued |
| Reputation accumulates from interaction history | `ReputationSignal` from receipts + `ConnectionBehavior` | Sustained positive trajectory passes reputation gate | Broken chains or reciprocity violations accumulate negative signal |
| Chain verification catches retroactive tampering | Hash propagation: tampering at N fails at N+1 | Full chain end-to-end valid | Any hash inconsistency anywhere |
| Constitutional rules non-removable | Fixed evaluation positions; removal attempt blocked by `SovereigntyRule` | Both rules evaluate at every step | Attempt to remove, reorder, or override returns Block from `SovereigntyRule` |
| Ontology derives deterministically from chain | Cartographer reads receipts, produces Trajectories/Decisions/Insights/Artifacts/Frictions | Regeneration from Genesis produces same ontology | Divergence indicates chain modification or Cartographer bug |

---

*ZeroPoint is maintained by the ZeroPoint Open Foundation.*
*Repository: https://github.com/zeropoint-foundation/zeropoint*
*Website: https://zeropoint.global*

---

*© 2026 ZeroPoint Open Foundation. CC BY 4.0 (text); MIT/Apache-2.0 (code).*
