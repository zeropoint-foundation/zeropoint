# ZeroPoint

## A Sovereign Compute Governance Layer

**Whitepaper v9.0 — July 2026**
**ZeroPoint Open Foundation**

Status: Public Technical Overview
License: CC BY 4.0 (text); MIT/Apache-2.0 (code); "ZeroPoint" and related marks trademarked; substrate-contract integrity clause governs compatibility claims (see `docs/design/LICENSING-AND-INTEGRITY-2026-07.md`)
Canonical URL: https://zeropoint.global/whitepaper

**How to cite:**
> ZeroPoint Open Foundation. "ZeroPoint: A Sovereign Compute Governance Layer." Whitepaper v9.0, July 2026. https://zeropoint.global/whitepaper

---

## Abstract

ZeroPoint is a sovereign compute governance layer: a complete, operator-owned system that brings cryptographic accountability, self-reflective awareness, and adaptive orchestration to local and distributed compute.

Built on a foundation of signed, hash-chained receipts and non-removable constitutional rules, ZeroPoint makes every action provable and every boundary enforceable. A native cognitive layer — consisting of an apex observer and specialized officers — continuously observes system state, reasons about intent, detects behavioral drift, and governs how compute resources and models are used.

Rather than treating AI models as the trusted component, ZeroPoint treats them as interchangeable inference engines. The system does not depend on any specific model. Instead, it maintains consistent governance, memory, and accountability across any combination of local or remote compute — whether running a single high-performance model or orchestrating across many.

ZeroPoint is local-first and sovereign by design. The operator holds the Genesis key. All authority flows from that key through the chain. The system observes its own behavior like an immune system, progressively hardening what it governs and only granting trust based on verified actions.

As intelligence becomes commoditized, the ability to govern, audit, and verify compute usage becomes the differentiating capability. ZeroPoint is built for exactly this future.

---

## 1. Background

Trust infrastructure has historically lived at the platform layer. Identity is held in a vendor's database. Authorization is expressed through API keys and ambient permissions. History is stored in mutable logs that the platform operator can rewrite. When actions cross organizational boundaries, there is no shared evidence base either party can independently verify. The model works well enough when platforms are stable, when regulatory pressure is light, and when actions happen at human speed with human oversight — but each of those preconditions is under structural pressure.

### 1.1 The compute landscape has shifted

Compute is no longer scarce. Local inference has become genuinely capable: modern laptops and phones run models that would have required data centers a few years ago. Cloud inference is abundant and increasingly commoditized across providers. Specialized accelerators are proliferating. Multiple model families — with different capabilities, cost structures, and behavioral characteristics — coexist within any nontrivial workload. The choice of *which* model to run for *which* task, with *what* budget, under *whose* authority, is now the load-bearing question.

Governance has not kept pace. Most systems that use AI treat the model itself as the trusted component: whatever the model outputs is treated as authoritative until human review catches an error. This posture doesn't survive contact with the actual operating environment. Models drift. Models hallucinate. Models can be prompted to violate policies their operators believed were enforced. Models are updated by their providers on schedules the operator does not control. When something goes wrong, the accountability chain terminates in a black box.

### 1.2 The accountability gap predates AI

Autonomous agents make the gap acute, but they did not create it. Existing infrastructure was designed for human-in-the-loop workflows: someone approves each significant action; someone reviews the log; someone is responsible when things go wrong. Agents act at machine speed across organizational boundaries with delegation chains that can extend far beyond their original scope. The workflows that assume a human somewhere in the loop cannot absorb the pace at which agents produce actions.

The correct framing is that autonomous action requires *substrate-level* accountability — evidence, authority, and constraint enforcement that hold even when no human is available to intervene. This is not a policy problem to be solved with better dashboards. It is a structural problem to be solved at the protocol layer.

### 1.3 What ZeroPoint addresses

ZeroPoint provides three primitives that together close the gap:

- **Signed, hash-chained receipts** that make every action provable and its ordering tamper-evident. Anyone with access to the chain can independently verify what happened, in what order, by whose authority.
- **Cryptographic capability grants** that are verifiable, portable, and delegatable with enforced narrowing. Authority can flow through delegation chains without losing accountability at any hop.
- **Constitutional constraints** that make governance non-bypassable at the protocol layer. Two rules — the Harm Principle and the Sovereignty Rule — evaluate before every action and cannot be removed, reordered, or overridden.

These primitives apply identically to humans, agents, services, and devices. They do not privilege AI models as trusted actors; they treat models as inference engines that produce candidate outputs, and they enforce governance on what the surrounding system chooses to do with those outputs.

### 1.4 Why now

Two forces make this the right moment for the substrate to exist:

**Model choice is becoming operational, not foundational.** As frontier model capabilities converge on most practical tasks, the choice of which model to use for a given job becomes an operational concern rather than a foundational one. Systems that hardwire assumptions about which model they trust will age poorly. Systems that treat models as interchangeable will not.

**Governance is becoming the differentiator.** As raw capability commoditizes, the ability to demonstrate — to auditors, to counterparties, to the operator's own future self — how compute was used, under whose authority, within what boundaries, moves from nice-to-have to load-bearing. The organizations that can produce cryptographic evidence of their compute usage will be able to operate in regulatory and commercial contexts that opaque systems cannot enter.

ZeroPoint is not a bet on any particular model. It is a bet on the underlying architecture that will be needed regardless of how the model landscape evolves.

---

## 2. Design Goals

The design is guided by a small set of commitments that shape every architectural decision. These are structural properties enforced by the architecture, not policy statements the operator has to trust.

### 2.1 Sovereignty by design

The operator holds the Genesis key. All authority in the system derives from that key through the chain. No platform grants permission; no remote service is required for the system to function; no entity — including the ZeroPoint Open Foundation, under which the system is released — can revoke, override, or condition an operator's control of their own instance. The substrate runs on the operator's own hardware, under the operator's own cryptographic identity, with local-first inference as the foundation and mandate-governed cloud escalation as optional augmentation.

### 2.2 Model-agnostic governance

AI models are inference engines, not trusted actors. The system does not depend on any specific model, provider, or capability tier. It maintains consistent governance, memory, and accountability whether the operator runs a single high-performance model, orchestrates across many, uses local inference exclusively, or escalates to cloud resources under mandate. When better models become available, the operator swaps them in. When a model provider changes terms, the operator moves elsewhere. The substrate is unchanged by any of it.

### 2.3 Earned trust, continuously verified

Trust is not assumed by default. It is continuously verified through observable behavior and cryptographically anchored history. Every tool, every agent, every process is brought under governance by being observed first, assessed against declared intent, and progressively hardened as its behavior becomes predictable — or kept contained when it does not. Actions produce receipts; receipts join the chain; the chain becomes the ground truth for what the substrate can rely on. Nothing is trusted because it was declared trustworthy; things are trusted because their history of governed behavior warrants it.

### 2.4 Self-reflective awareness

The system maintains an accurate picture of its own state. A native cognitive layer — an apex observer (also called the Regent) supported by five specialized officers covering integrity, security, operations, governance narration, and constitutional-trajectory monitoring — continuously observes system state, reasons about operator intent, and detects behavioral drift. When something falls outside expected boundaries, the observer notices, reasons about it, and surfaces the finding through cryptographically anchored receipts. This is not passive logging. It is the system paying attention to itself in a way that produces auditable evidence and informs subsequent decisions.

### 2.5 Immune-system-like behavior

The system's observation mechanisms function in a manner analogous to an immune response: anomalies trigger findings, findings inform governance decisions, and repeated patterns shape what the substrate treats as normal over time. Compromise is not prevented by any single line of defense; it is made structurally expensive by the composition of many layers, each of which produces evidence when engaged.

### 2.6 Verifiable accountability

Every significant action produces a signed, hash-chained receipt. The chain is offline-auditable: no running server is required to verify it. Verification is re-derivation from Genesis — walk the chain, check every signature and hash link, and either accept the sequence as valid or reject it at the first break. Actions the substrate cannot produce receipts for are actions the substrate cannot claim happened. Actions it can produce receipts for are actions any third party can independently verify.

### 2.7 Composable and portable

Receipts, capability grants, delegation chains, and policy evaluation are identical across all transports — HTTP, TCP, encrypted mesh, or any future substrate. The identity model is a keypair, not a coordinate. There is no lock-in, no dependence on any particular deployment environment, no requirement that any single service continue operating for the substrate to work. An operator's chain travels with them; their identity travels with them; their governance history travels with them.

### 2.8 Honest boundaries

The system is explicit about what it prevents and what it does not. It does not solve AI safety. It does not guarantee runtime integrity against a compromised host. It does not prevent misuse by deployments that fork and strip constitutional constraints. What it provides is the protocol-level substrate that makes governed action possible: cryptographic proof of every action taken, traceable authority for every capability granted, non-bypassable enforcement of the constraints the operator has committed to, and a self-observation loop that surfaces evidence of drift when drift occurs. These are the load-bearing properties. Nothing is claimed beyond them.

---

## 3. System Overview

ZeroPoint is a set of layered Rust crates running under operator control. Any entity holding a keypair — human, agent, service, device — is a full peer. The system is organized into three layers, each governed by the substrate below it.

### 3.1 The substrate layer

The substrate is the cryptographic foundation: identity, receipts, capability grants, delegation chains, policy evaluation, and the governance gate that enforces them.

- **Identity.** Ed25519 signing keys with X25519 key agreement. Identity is a keypair; authentication is a signature. No accounts, no directories, no central identity provider.
- **Receipts.** Signed, hash-chained records of every governed action. Compact wire format (150–300 bytes typical) suitable for bandwidth-constrained transports as well as ordinary networking.
- **Capability grants.** Portable authorization tokens with scope, cost ceiling, rate limit, time window, delegation depth, and trust tier. Grants delegate with enforced narrowing.
- **The GovernanceGate.** A five-stage pipeline — Guard, Policy, Execute, Audit, Transport — through which every side-effecting action passes. Nothing executes without a governance decision; every governance decision joins the chain.
- **Constitutional rules.** Two non-removable rules — the Harm Principle and the Sovereignty Rule — evaluate before every action and cannot be overridden by any grant, module, or operator command.

The substrate is complete in itself. An operator can generate a Genesis key, start a chain, register tools, issue delegations, run officer sweeps, and verify integrity end-to-end with nothing above the substrate present.

### 3.2 The cognitive layer

Above the substrate sits a cognitive layer whose actions are governed by the substrate the same way any other component's actions are. It is not privileged. It does not have authority the substrate does not grant it. It produces receipts, submits to gate evaluation, and operates within capability grants that trace back to the operator's Genesis key.

The cognitive layer consists of:

- **An apex observer.** The operator's central cognitive component, responsible for observing system state, reasoning about intent, coordinating specialists, and surfacing findings through governed action.
- **A specialist officer cadre.** Five officers, each responsible for one domain: integrity of the chain and derived state; security posture and threat surface; operational state and resource health; governance narration of what has happened and why; and constitutional-trajectory monitoring for patterns of drift the atomic gate cannot see. Full enumeration in §6.2.
- **A Cartographer.** A background process that reads the receipt chain and produces a structured layer of typed objects — trajectories of work, decisions, insights, artifacts, and frictions — that the observer and officers query as their working understanding of the operator's context.
- **Sub-agents.** Ephemeral delegates spawned under mandate for tasks that exceed the observer's context or benefit from parallelism. Each is chain-anchored, capability-scoped, time-bounded, and gate-governed.

The cognitive layer uses AI models as inference engines. It does not depend on any specific model; it invokes whatever model the operator has authorized for a given task. When a model produces output, that output is a candidate — the substrate decides, through gate evaluation and constitutional check, whether the resulting action is permitted.

### 3.3 The presentation layer

The operator experiences the system through surfaces adapted to their hardware, bandwidth, and security posture:

- **A conversational surface** for natural-language interaction with the apex observer.
- **A governed browser harness** for interacting with external systems under scoped capability.
- **A semantic canvas** that the cognitive layer composes to show the operator what they need to see.

The presentation layer renders at one of three fidelity modes — minimal terminal, standard local browser, or secure server-side pixel streaming — chosen for the operator's context. State lives in the chain, not in the client, so switching modes mid-session loses nothing.

### 3.4 Local-first, distributed by governance

The system runs on the operator's own hardware with local inference by default. Cloud compute is available but never assumed; when local capability is insufficient, the cognitive layer formulates a resource request, the operator approves it as a signing ceremony, and the system provisions cloud resources within a chain-anchored mandate (specific provider, specific budget, specific time bound). Cloud-executed work produces receipts that flow back to the operator's chain. Nothing runs on remote hardware without explicit, scoped, revocable authority.

---

## 4. Receipts and Chains

The receipt chain is the substrate's ledger of what has happened. Everything the substrate can meaningfully claim, it can produce receipts for; everything without receipts is not part of the substrate's history.

### 4.1 Receipt structure

Each receipt carries a small, well-defined set of fields:

| Field | Wire Name | Description |
|-------|-----------|-------------|
| Receipt ID | `id` | Unique identifier |
| Receipt Type | `rt` | execution, intent, approval, delegation, verification, refusal, officer_finding, cognitive_step |
| Status | `st` | success, partial, failed, denied, timeout, pending |
| Trust Grade | `tg` | A–D, determined by chain completeness and verification |
| Content Hash | `ch` | Blake3 hash of the action content |
| Timestamp | `ts` | Unix timestamp |
| Parent Receipt | `pr` | Previous receipt ID |
| Policy Decision | `pd` | allow, deny, escalate, audit |
| Rationale | `ra` | Policy decision explanation |
| Signature | `sg` | Ed25519 signature over the receipt |
| Extensions | `ex` | Compact JSON for domain-specific fields |

Wire format is MessagePack with short field names. Typical receipt size is 150–300 bytes; maximum for single-packet mesh transport is 380 bytes, within the 465-byte LoRa payload limit. The chain works over any transport that can carry a few hundred bytes reliably.

### 4.2 What receipts prove and don't

**Prove:**

- A specific Ed25519 key signed a specific statement at a specific time.
- The chain contains an unbroken sequence of signed events.
- The policy engine evaluated a known rule set and produced a specific decision.
- A capability grant was valid at the time of action.

**Do not prove:**

- The nature of the signer. A receipt attests that a key signed something, not whether the key belongs to a human, an agent, or a device. Binding keys to physical persons is deployment-dependent and out of protocol scope.
- That the action content was correct or safe.
- That the runtime environment was uncompromised. A compromised host can produce arbitrary valid receipts.

Honest scoping matters. The substrate makes precise claims about what receipts guarantee; anything beyond that is out of scope.

### 4.3 Chain properties

The `pr` field is what distinguishes a chain from a log. Without it, each receipt is an isolated signed fact. With it, each receipt requires the full ordered history to verify.

A chain provides three properties isolated receipts cannot:

- **Ordering.** Chain position, not timestamp, determines sequence. Two receipts with identical timestamps are still ordered by their `pr` linkage.
- **Tamper-evidence.** Modifying receipt N invalidates the hash of every subsequent receipt. An attacker must rewrite N through the tip and convince every independent verifier to accept the rewrite.
- **Replayability.** The full chain can be re-executed from Genesis to verify that every action was authorized, every policy decision was valid, and every delegation was within scope at the time.

A chain **accepts** when every `pr` linkage is intact, every hash consistent, and every signature valid. It **rejects** on any gap, hash inconsistency, or signature failure. Rejection is binary and propagates: one broken link invalidates everything downstream.

Peers challenge each other's chains directly. A challenged peer produces its full chain; the challenger verifies and issues a signed peer audit attestation. No central auditor is required.

### 4.4 Why history-dependence is not optional

Snapshot verification cannot detect retroactive tampering, injected permissions, or unauthorized delegation insertions. A system that checks only current state accepts modified history as if it were the original. History-dependence closes these gaps: any modification propagates as a hash failure that every subsequent verifier catches.

### 4.5 Chain compaction

An agent producing 1,000 actions per day generates 365,000 receipts per year; a 100-agent fleet generates 36.5 million. Full chain walks from Genesis become impractical at this scale. Epoch-based compaction bounds active memory regardless of total history.

When an epoch fills (8,192 entries or 7 days, whichever comes first), a Merkle tree is computed over its entries and its 32-byte Blake3 root is recorded in a signed epoch seal that joins the chain as a regular receipt. Individual epoch entries are archived and removed from active storage. Seals reference each other, forming a verifiable chain of seals.

Verification modes after compaction:

| Mode | What to walk | Cost |
|------|-------------|------|
| Recent activity | Current unsealed epoch | Full walk, ≤ 8,192 entries |
| Historical integrity | Seal chain | Dozens of seals, not millions of entries |
| Spot-check one entry | Merkle inclusion proof | 13 hashes (416 bytes, one mesh packet) |
| Forensic reconstruction | Full archived epoch | Retrieve entries, reconstruct Merkle tree |

Working memory: one unsealed epoch (~4 MB) plus the most recent seal. A five-year-old agent holds the same active memory as a new one. The seal chain grows about 500 bytes per week; five years of history is roughly 111 KB.

Compaction does not solve disaster recovery (a lost archive cannot be reconstructed from the seal alone), fabrication prevention (a compromised node can produce a valid seal over fabricated entries), or retention policy (audit depth versus storage cost is the operator's tradeoff). These are separate concerns, addressed by replication, peer attestation, and operator-chosen retention policy respectively.

---

## 5. The Governance Model

Governance in ZeroPoint is protocol, not policy. It is enforced by structure — evaluation order, invariant checks, cryptographic verification — rather than by trust in an organization.

### 5.1 The GovernanceGate

Every side-effecting action passes through five stages in order:

1. **Guard.** Pre-action sovereignty check. Evaluates the node's own chain, grants, and constitutional rules before accepting any external input.
2. **Policy.** Constitutional rules first, then operational rules, then WASM modules. Most restrictive decision wins.
3. **Execute.** Runs only if Guard and Policy both allow.
4. **Audit.** Emits a signed, hash-linked receipt and persists it to the chain.
5. **Transport.** Receipts propagate to peers for independent verification.

Nothing executes without passing through the gate. Nothing passes through the gate without joining the chain. This applies to actions initiated by the operator, by the cognitive layer, by delegated agents, and by external services acting under grant. The gate does not distinguish based on who is asking; it evaluates whether the action is permitted under the current chain state.

### 5.2 Capability grants and delegation

Every participant must hold a valid capability grant to act. A grant specifies:

- **Scope** — the permitted actions and targets
- **Time bounds** — valid from, valid until
- **Delegation depth** — how many hops the grant may be redelegated through
- **Trust tier** — the minimum tier required to exercise the grant
- **Cost ceiling** — maximum resource consumption per invocation
- **Rate limit** — maximum invocations per time window
- **Signature** — the grantor's Ed25519 signature over the grant

Any grant holder can delegate a subset of their grant to another participant, forming a delegation chain. The chain is verified against eight invariants:

1. Each grant references the previous as `parent_grant_id`.
2. Depths increment monotonically.
3. Child scope ⊆ parent scope.
4. Child trust tier ≥ parent trust tier.
5. Child expiration ≤ parent expiration.
6. Chain depth ≤ `max_delegation_depth` set by the root.
7. Each grant's grantor matches the previous grant's grantee.
8. All signatures verify.

Any invariant violation rejects the entire chain. Narrowing is structural: at no hop can authority widen.

### 5.3 Constitutional rules

Two rules evaluate at fixed positions in the policy engine, ahead of all operational and WASM-defined rules:

**The Harm Principle Rule** blocks weaponization, unauthorized surveillance, deception (including deepfakes and impersonation), and suppression of dissent. Cannot be bypassed by capability grants, policy configuration, or consensus votes.

**The Sovereignty Rule** blocks changes that would disable the guard, truncate the audit trail, forge or bypass capabilities, remove constitutional rules, or override participant refusal.

Both rules apply to every action equally, from operator-initiated commands to cognitive-layer inference-driven decisions to third-party service calls. There is no code path that skips them. Attempts to remove or bypass either rule are themselves blocked by the Sovereignty Rule.

### 5.4 Protocol tenets

Four commitments summarize the governance posture:

- **Do no harm.** The Harm Principle is non-removable and evaluates before every action.
- **Sovereignty is sacred.** Every participant can refuse any action. Every human can disconnect any agent. No agent holds capabilities it was not granted.
- **Action without evidence is no action.** Every action produces a receipt; every receipt joins the chain. An action absent from the chain did not happen. A present action cannot be expunged.
- **The human is the root.** Every delegation chain terminates at a human-held key. No agent self-authorizes.

These are structural properties enforced by the substrate, not aspirations.

### 5.5 Genesis and the key hierarchy

The Genesis ceremony generates the root Ed25519 seed from which all trust in the deployment derives. The ceremony is sequential and irreversible: generate keypair, validate sovereignty provider, enroll biometric or hardware confirmation, seal constitutional rules, write the immutable Genesis record.

The key hierarchy has three levels:

```
Genesis Key       ← self-signed root (one per deployment)
  └─ Operator Key ← signed by Genesis
      └─ Agent Key ← signed by an Operator
```

Any node verifies agent identity by walking this chain offline — no network or policy state required. Six certificate invariants apply: valid signatures, issuer linkage, role hierarchy, monotonic depth, no expired certs, hash linkage.

The key hierarchy is independent of the policy engine to avoid circular dependency: the engine's authority requires keys; keys cannot depend on the engine existing.

### 5.6 The singular sovereign root

A single operator authentication unlocks all derived material for a process lifetime. From that one ceremony, every key the substrate needs is derived in memory. Multiple credential-store entries for governance material — one for chain signing, one for vault unlock, one for delegation issuance — are an anti-pattern the architecture catches structurally: there is one sovereign root per process, and every signature that follows traces to that one operator consent.

This makes multi-quorum sovereignty (M-of-N devices, hardware wallets, biometrics) tractable: M ceremonies once at process start, then everything derived. Without the singular root, quorum becomes M × C ceremonies for C credentials — unbounded as the substrate grows.

---

## 6. The Cognitive Layer

ZeroPoint's cognitive layer is a component of the system, governed by the same substrate that governs everything else. It is not a privileged actor. It does not have authority the operator has not granted it. Its receipts are signed. Its delegations are chain-anchored. It uses AI models as inference engines, not as trusted decision-makers.

### 6.1 The apex observer

The apex observer is the operator's central cognitive component — the intelligence through which the system perceives intent, delegates work, and coordinates response. This component is also referred to as the Regent, a designation that signals it governs on behalf of the operator rather than as the operator. The two terms describe the same entity and are used interchangeably throughout this document; "apex observer" emphasizes the architectural role, while "Regent" emphasizes the relational one.

It observes system state, reasons about intent, coordinates the officer cadre, delegates to sub-agents, and issues actions through the governance gate. Every consequential decision it takes is either directly authorized by the operator or executed within the scope of a prior delegation.

The Regent's authority is relational and temporary. It governs *on behalf of* the operator, not *as* the operator. Nothing about its position gives it standing to override the operator, exceed granted mandates, or evade the constitutional rules.

The observer's inference is model-agnostic. It draws on whatever model the operator has authorized for a given cognitive task — a small local model for routine reasoning, a larger local or remote model for tasks requiring more capability. The choice of model is an operational decision recorded on the chain; the trust boundary is the substrate, not the model.

### 6.2 The officer cadre

Five specialists, each responsible for one domain:

- **Steward** — chain integrity, receipt validity, ontological coherence.
- **Sentinel** — security posture, threat surface, credential hygiene.
- **Forge** — operational state, process fleet, resource health.
- **Cleo** — governance narration, chain-derived explanation of what happened and why.
- **Aegis** — constitutional-trajectory monitoring; reads the Cartographer's ontology and the other officers' findings for patterns of drift toward constitutional concern, and produces chain-anchored findings that inform gate-time detection and post-hoc trajectory review.

The officers are chain-anchored attestors: background sweeps produce signed findings that join the chain as regular receipts. They are also active participants in the apex observer's reasoning — consulted before delegations that touch their domains, emitting proactive findings when observation warrants, maintaining in-session context that makes each sweep more informed than the last.

Officers observe, attest, and advise. They do not block; the gate blocks. They do not decide; the apex observer decides, under operator authority. They produce evidence. Aegis in particular is best-effort detection, not enforcement: atomic constitutional enforcement stays at the gate, and Aegis surfaces trajectory-level concerns the atomic layer cannot see. Companion design note `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` specifies his role in detail.

### 6.3 The Cartographer

Raw receipts are the truth of what happened. They are not structured understanding of what it means.

The Cartographer runs in the background and transforms receipts into a structured ontology of five object types:

- **Trajectory** — a living arc of work or thinking that emerges from activity rather than being declared top-down.
- **Decision** — a meaningful choice within a trajectory, with pros/cons, confidence, and outcome tracking.
- **Insight** — a key realization or observation, with implications and a confidence score.
- **Artifact** — created work (code, documents, designs, specs) linked to the trajectory and decision that produced it.
- **Friction** — a blocker or recurring problem, with severity, occurrence count, and resolution status.

The chain is truth. The ontology is understanding. Officers and the apex observer query the ontology, not raw receipts, when they need context for a decision. New receipts trigger Cartographer re-derivation; the ontology is a projection of the chain and can be regenerated from Genesis at any time.

### 6.4 Sub-agent orchestration

The apex observer delegates to sub-agents for tasks that exceed its own context window, require parallel execution, or need specialized capabilities. Sub-agents are governed entities:

- Each receives a delegation from the observer — chain-anchored, capability-scoped, time-bounded.
- Each sub-agent's actions go through the gate.
- Each sub-agent's results are receipts on the chain.
- Sub-agents do not persist across sessions. The chain persists; the sub-agent is ephemeral.

The governed spawn primitive launches the sub-agent process, issues its delegation, registers it with the substrate, and health-checks it before it executes. The chain records the full lifecycle.

### 6.5 The cognitive loop

The Regent maintains a continuous loop:

1. **Perceive** — operator intent, chain state, officer findings, environmental signals.
2. **Reason** — evaluate what the operator wants against what the chain authorizes, what the officers have observed, and what resources are available.
3. **Delegate** — assign work to officers, sub-agents, or tools. Each delegation is chain-anchored and capability-scoped.
4. **Execute** — through the gate. Every action produces a receipt.
5. **Present** — surface results through the presentation layer.
6. **Remember** — update multi-timescale memory. Session context is ephemeral. Chain-anchored facts persist. The Cartographer maintains the ontology.

The loop is continuous and reentrant. Perception feeds reasoning, which produces delegations, which produce receipts, which the Cartographer folds back into the ontology, which changes what the observer perceives on the next cycle. Nothing in the loop is privileged above the substrate: every step is a governed action.

### 6.6 Model independence

The cognitive layer is designed to work with whatever inference is available. Concretely:

- **Local inference by default.** The system maintains a registry of local models calibrated for specific cognitive tasks. Each task — officer sweep, chain narration, tool selection, conversational response — has a model assignment based on empirical benchmarking, not vendor claims.
- **Cloud inference by mandate.** When a task exceeds local capacity, the Regent formulates a resource request, presents it to the operator with cost/benefit analysis, and provisions cloud resources within the scope the operator approves. The mandate is chain-anchored, capability-scoped, budget-capped, and revocable.
- **Model swappable at operator discretion.** When better models become available, or a provider changes terms, the operator swaps models. The substrate is unchanged. The chain-anchored history of what model was used for what task remains verifiable.
- **Every inference is a receipted event.** The chain records what model was consulted, what prompt was sent (or a hash of it for privacy-sensitive contexts), what response was received, and what action resulted. This produces the audit trail that makes model usage governable.

The cognitive layer is not the trusted component. It is the coordinator that lets models produce candidate outputs and lets the substrate decide what actions those outputs are permitted to become.

---

## 7. The Presentation Layer

The operator interacts with the system through surfaces that the cognitive layer composes. The presentation layer is not a wrapper around the substrate; it is how the sovereign system presents itself to its operator.

### 7.1 Three primitives

**The conversational surface** is the apex observer expressed in language. Natural-language interaction is the primary mode for most operations: the operator speaks intent, the observer reasons and acts, the chain records, the observer responds. Not a chatbot UI bolted onto governance — the cognitive layer's native form.

**The browser harness** is governed browser control via CDP (Chrome DevTools Protocol) or equivalent. The system can navigate, click, read, fill forms, and extract from the web — but only as a gated, receipted, capability-scoped tool. There is no open-ended internet access. Browser capability is a delegation, like any other.

**The semantic canvas** is an agent-composed visual surface. Not a static dashboard. Panels, widgets, data visualizations, video streams, and overlays are assembled by the cognitive layer based on what the operator needs to see. The observer speaks; the canvas shows; both draw from the same chain.

### 7.2 Adaptive fidelity

The presentation layer renders at one of three fidelity modes, chosen to match the operator's hardware, bandwidth, and security posture.

- **Minimal.** Terminal-only, text-based, low-bandwidth. Fully functional: chain queries, governance posture, tool lifecycle, conversational interaction. No JavaScript, no browser dependency. Appropriate for constrained hardware, constrained networks, and high-security contexts where a rich client is attack surface.
- **Standard.** Local browser rendering. The semantic canvas runs in the operator's browser; JavaScript executes locally. The default for modern hardware and reasonable bandwidth.
- **Secure.** Server-side rendering with pixel streaming to the client. The client receives only a video stream — a rendered image of the interface, not the interface itself. The client cannot inspect the DOM, execute JavaScript, or intercept API calls. The attack surface collapses to the video decoder. Appropriate for high-security deployments, untrusted client hardware, or contexts where the interface itself contains sensitive information.

Mode selection is negotiated. The system detects available resources and recommends a mode; the operator can override. Mode switching is seamless because state lives in the chain, not in the client. A session that starts in standard mode can switch to secure mode mid-session without losing state.

### 7.3 Provenance for what appears on screen

Media and content presented through the canvas carry chain-anchored provenance receipts where available (per the media provenance design note). The apex observer surfaces provenance status as first-class UX: verified capture is presented differently from unverified external sources, and content without any provenance chain is marked as such. Absence of provenance is treated as signal, not as neutral.

---

## 8. Compute and Cost

Compute governance is a first-order concern of the substrate. The cognitive layer runs on inference; inference consumes resources; resource use is a governed action with cryptographic evidence. Nothing about how compute is used is opaque or ungoverned.

### 8.1 Local-first inference

The cognitive layer runs on local inference by default. The real test of the substrate is how capable it is when running solely on the operator's hardware with local models. Cloud inference is augmentation, not foundation.

The system maintains a registry of local models calibrated for specific cognitive tasks — officer sweep, chain narration, tool selection, conversational response, delegation reasoning. Each task has a model assignment based on empirical benchmarking, not vendor claims. Model selection for a given task is an operator-configurable choice recorded on the chain.

### 8.2 Model independence, restated

AI models are inference engines, not trusted decision-makers. The substrate does not depend on any specific model. The apex observer draws on whatever model the operator has authorized for a given cognitive task; when better models become available, the operator swaps them in; when a provider changes terms, the operator moves elsewhere. The substrate is unchanged by any of it.

The chain-anchored history of what model was used for what task remains verifiable regardless of model turnover. Model choice is an operational decision on the chain; the trust boundary is the substrate, not the model.

### 8.3 Inference governance

Every inference request is a governed action. The chain records what model was consulted, what prompt was sent (or a hash of it for privacy-sensitive contexts), what response was received (or a hash), and what action resulted. Three inference trust tiers apply:

- **Attested.** Local model with full trace capture. The substrate can verify the reasoning trajectory that produced the output.
- **Observed.** Remote API with prompt/response logging. The substrate records what was sent and received but cannot verify the remote model's internal reasoning.
- **Unattested.** Inference without trace. Not permitted in sovereign mode.

### 8.4 The mandate model for cloud escalation

When a task exceeds local capacity, the observer can request cloud resources. The request is governed, not automatic.

1. The observer identifies that a task exceeds local capability and formulates a resource request: what kind of compute, for how long, at what estimated cost, for what purpose.
2. The request is presented to the operator with a cost/benefit analysis.
3. The operator approves or denies. Approval is a signing ceremony — the approval is a receipt on the chain.
4. On approval, the substrate provisions cloud resources within the operator's mandate: specific provider, specific budget ceiling, specific time bound.
5. Cloud-executed work produces receipts that flow back to the operator's chain. The chain records that cloud resources were used, what they cost, and what they produced.
6. Resources are released when the task completes or the time bound expires. No persistent cloud footprint without explicit operator renewal.

The mandate is a delegation — chain-anchored, capability-scoped, time-bounded, budget-capped, revocable. Exceeding the mandate requires a new approval ceremony. The operator does not give the system open-ended cloud access at any point.

### 8.5 Spending governance

Every action with a cost — inference tokens, cloud compute hours, API calls, storage — is tracked on the chain. The substrate maintains a running cost model:

- Per-task cost attribution: what did this task cost in tokens, compute, API calls?
- Per-session cost rollup: what has this session consumed?
- Budget compliance: is the current spending within the operator's mandate?
- Cost projection: at current burn rate, when does the mandate budget exhaust?

The operator can query spending at any time. The chain is the ledger. Cost governance is a substrate primitive of the same shape as capability delegation. The substrate cannot spend what the operator has not authorized, for the same structural reason it cannot execute what the gate has not approved.

---

## 9. Mesh Transport and the Presence Plane

The substrate's transport layer is designed for the physical mesh case first and generalizes to conventional networks from there. What survives radio, LoRa, and store-and-forward mesh is what survives everything.

### 9.1 Transport agnosticism

The governance primitives — receipts, capability grants, delegation verification, the policy engine — are identical across all transports.

- **HTTP API.** Axum-based REST server for cloud deployments, container orchestration, and web service integration.
- **TCP and UDP.** Interfaces with HDLC framing and CRC verification. UDP for connectionless receipt exchange. Multiple interfaces run simultaneously on one node.
- **Reticulum-compatible mesh.** Wire-level interoperable with the Reticulum Network Stack. HDLC framing with CRC-CCITT, 128-bit destination hashing (truncated SHA-256), Ed25519 signing, X25519 ECDH key agreement, 500-byte MTU / 465-byte data payload (LoRa-compatible), 3-packet link handshake with 16-byte nonces.

A new transport requires implementing one interface trait plus envelope serialization. The governance primitives are unchanged. Adding a transport does not add trust dependencies.

### 9.2 The Presence Plane — problem

Identity verification via `zp-keys` works once you have a peer's certificates. Finding peers' network addresses is a separate problem. A centralized directory solves it but creates a surveillance and censorship point. The Presence Plane provides discovery using the same Ed25519 identity as the governance layer, without centralized state.

### 9.3 Architecture

Built on a `DiscoveryBackend` trait with four methods (`announce`, `poll_discoveries`, `is_active`, `shutdown`). Two backends are shipped in the reference implementation:

- **Web relay.** Pub/sub over WebSocket. Peers publish signed announce blobs; the relay broadcasts to subscribers; peers filter locally. The relay never parses payloads, indexes capabilities, logs queries, or persists state. Restart erases everything.
- **Reticulum mesh.** Announces propagate over mesh interfaces (LoRa, WiFi, serial, TCP). No server. No internet dependency.

Both backends share the same announce wire format. Peers from either backend land in the same peer table.

### 9.4 Structural amnesia

The relay cannot surveil because the capability does not exist in the code. It passes bytes without parsing, indexing, or storing them. This is stronger than a no-logs policy, which can be changed or violated. Subpoena-resistant by construction.

### 9.5 Reciprocity enforcement

Passive scanning — subscribing to announce traffic without revealing your identity — is the primary adversarial concern. Defense: you must announce before you receive. On connect, receive operations error until the client has published an announce. Connections that haven't announced within a grace period are terminated.

### 9.6 Behavioral reputation

Reciprocity stops naive scanners. Sophisticated ones announce once, then silently consume. On connection close, the relay emits `ConnectionBehavior` summaries — counters only, no content: announced, announces_published, duration, reciprocity_violation. These map to reputation signals. Consistent participation accumulates positive signal; announce-once-then-consume patterns accumulate negative signal.

### 9.7 The outreach primitive

The Presence Plane provides the transport for a specific substrate capability: **outreach without a directory.** Any party — the Foundation, a community, an operator, a service — can broadcast to whoever is listening by emitting announces under a category. Subscribed nodes receive; unsubscribed nodes never hear. There is no list of subscribers anywhere. Broadcast radio, not mailing list.

This is what makes the substrate work as a coordination layer for its own community without any central platform. Detailed in the peer-discovery and community-coordination design notes.

---

## 10. External Truth Anchoring

The receipt chain is self-verifying — hash-linked, signed, auditable cold. It does not establish when the chain state existed in external calendar time, or provide a witness a third party can query without operator cooperation.

### 10.1 Purpose

External truth anchoring publishes the chain's current state to an independent distributed ledger, producing a publicly queryable, tamper-evident timestamp the operator cannot retroactively modify. This matters in three contexts:

- **Cross-deployment trust.** Anchoring to a common ledger gives each party an independently verifiable history that a freshly fabricated chain cannot reproduce.
- **Dispute resolution.** An anchor proves chain state at an externally-attested time.
- **Compliance audit.** Self-signed timestamps don't satisfy auditors. An anchor on a ledger regulators already examine carries equivalent evidential weight.

### 10.2 Architecture

**Optional enrichment.** Without a ledger configured, the substrate operates exactly as described in §4. The anchor adds an external witness; it doesn't replace the chain's internal guarantees.

**No dependency.** Anchor receipts join the chain as regular entries. Chain verification never requires the ledger to be reachable.

**DLT-agnostic.** A `TruthAnchor` trait (`anchor`, `verify`, `query_range`) accepts any distributed ledger backend. Reference implementations include Hedera Hashgraph's Consensus Service. Also supported: Ethereum L2 calldata, Bitcoin OpenTimestamps, Ceramic streams, or any system that can timestamp and publicly expose an opaque payload.

### 10.3 What gets anchored

| Field | Description |
|-------|-------------|
| Chain head hash | Blake3 hash of the current chain tip |
| Chain sequence | Monotonically increasing chain position |
| Previous anchor hash | Links anchor history |
| Operator signature | Ed25519 over the commitment |
| Chain type | audit / observation / reflection |
| Trigger | Why this anchor was created |

The commitment is compact (a few hundred bytes) and carries no governed content. The ledger sees a fingerprint, not the data.

### 10.4 Trigger model

Anchoring is event-driven, not timer-driven. Periodic anchoring adds cost without adding information — the hash chain already detects any modification between anchors.

- **Explicit triggers.** Operator request, cross-deployment introduction, compliance checkpoint, contested governance action, governance lifecycle event.
- **Opportunistic.** When the operator makes any blockchain transaction for other purposes, the current chain head hash embeds as transaction metadata at zero marginal cost.

### 10.5 Limits

- Does not prove chain content is correct — only that the chain was in a specific state at a specific time.
- Does not prevent chain forking — an operator can maintain two chains and anchor only one.
- Does not substitute for internal chain integrity.

The anchor is external witness for state that was already internally verifiable. It extends what the chain can prove; it does not replace what the chain proves.

---

## 11. Fleet Topology

A node's role — Genesis, Delegate, or Standalone — derives from its receipt chain, not its config file. Config provides a bootstrap hint, advisory once the chain contains delegation evidence. Config can be edited; chain entries cannot without invalidating all subsequent hashes.

### 11.1 Chain-derived roles

- **Genesis.** Performed the Genesis ceremony; holds the root keypair. Exactly one per fleet.
- **Delegate.** Holds a valid delegation receipt from an upstream Genesis node. Authority bounded by narrowing invariants.
- **Standalone.** No chain evidence of Genesis or delegation. Default; a revoked delegate returns here.

### 11.2 Role transition receipts

Role transitions are chain events, not administrative acts. When a node's role changes, a receipt seals the transition with the previous role, new role, and cause. Cause vocabulary is constrained: `delegation_accepted`, `delegation_revoked`, `redelegation`, `genesis_performed`.

### 11.3 Upstream binding

A delegate carries the upstream Genesis node's Ed25519 public key in its delegation receipt — a cryptographic proof, not a claim. Local check (offline): receipt contains a well-formed 32-byte pubkey. Remote check (online): challenge the upstream to prove it holds the key in the receipt. A delegate cannot forge its delegation receipt without the upstream's signing key and cannot silently swap upstreams.

### 11.4 Liveness and lease renewal

Fleet membership requires lease renewal. Each delegate's capability grant has a bounded lifetime, renewed at a configured cadence by presenting a valid Ed25519 signature to a designated renewal authority. Renewal failure triggers a grace period; expiry activates the configured failure mode: halt (fail closed), degrade (read-only), or continue-with-flag (for intentionally air-gapped deployments).

Membership is self-pruning: an offline node stops renewing and its authority expires without administrator intervention.

### 11.5 Reflexive governance

Fleet infrastructure uses the same receipt grammar as all other governed behavior. Role transitions, delegation grants, upstream binding proofs, and lease renewals are chain events verified by the same invariants as agent actions. The fleet's topology history is auditable with the same tools as any other governed behavior.

---

## 12. Threat Model

The substrate is precise about what it defends against and what it does not. This section names the threats explicitly and describes their mitigations honestly, including residual risk.

### 12.1 Substrate threats

| Threat | Capability | Mitigation | Residual Risk |
|--------|-----------|------------|---------------|
| Log forgery / retroactive rewriting | Alter history to change attribution | Ed25519 + Blake3 hash chain; collective audit via peer challenge/response | Compromised keys can sign lies; revocation is deployment-dependent |
| Unauthorized tool use | Execute beyond intended scope | Capability grants; 8-invariant delegation chain verification; policy engine evaluates before every action | Gaps possible with poorly designed grants |
| Unauthorized cognitive action | Cognitive layer takes action outside operator authority | Every cognitive action is a receipt; gate enforcement; delegation narrowing binds the apex observer to operator-issued mandates | Requires bench validation of mandate exhaustion behavior |
| Cross-operator trust failure | Cannot verify another party's agent outputs | Independent receipt verification; introduction certificate exchange; dual-backend discovery | Cross-genesis introductions require operator-configured policy |
| Passive scanning | Harvest peer identities without announcing | Reciprocity enforcement; structurally amnesic relay | A scanner that announces gains initial access; behavioral reputation detects parasites over time |
| Sybil flooding | Overwhelm discovery with cheap fake identities | Anchor history requires sustained ledger cost; reputation weights anchor depth | Defense is economic, not absolute |
| Security theater | Claim governance without enforcing it | Constitutional rules non-removable; receipts independently verifiable; chain-invariant rejection isolates non-conforming forks as separate networks; trademark protection prevents impersonation | Sophisticated tampered builds may pass surface inspection; software integrity attestation is best-effort |
| Surveillance co-option | Use receipts to track people, not actions | Pseudonymous keypairs; action-level receipts only; Presence Plane structural amnesia | Substrate defenses cannot prevent misuse by knowing operators of their own instances |
| Replay attacks | Resend captured packets | Monotonic u64 sequence numbers; 16-byte nonces in link handshake; Ed25519 over content hashes | Long-offline nodes may have gaps in seen sequences |
| Mesh injection | Insert forged packets | HDLC + CRC; Ed25519 on all envelopes; X25519 ECDH link encryption | Requires successful link establishment |
| WASM policy escape | Malicious module breaks sandbox | Wasmtime with fuel limiting; hash verification before loading | Escape requires a Wasmtime vulnerability; fuel exhaustion is DoS at worst |
| Identity misbinding | Misattribute key to wrong entity | Six trust tiers; T2+ requires verified delegation from a human-held key | Binding keys to physical persons is deployment-dependent |
| Cognitive prompt injection | Malicious content manipulates apex observer reasoning | Constitutional rules bind cognitive layer; every inference is receipted; officer cross-checks; multi-model corroboration for high-stakes decisions | Detection of subtle manipulation is empirically hard |
| Cost exhaustion | Cognitive layer consumes budget faster than expected | Mandate model caps budget and time; per-task cost attribution; operator can revoke mandate | Requires operator awareness of mandate state |
| Decomposition attacks against constitutional rules | Sequence of individually-benign actions assembles into constitutional violation | Advisory trajectory-level detection (see companion design note); atomic constitutional enforcement is honest about not catching this class | Sophisticated adversaries can defeat detection heuristics; atomic enforcement's guarantees remain intact but decomposition may succeed |

### 12.2 What the substrate structurally defeats

Two properties are worth naming beyond the row-by-row mitigations above, because they defeat classes of attack that don't reduce to a single threat row:

**Platform-level takedown.** No central platform, directory, authority, or hosting exists to pressure. Attempts to shut down the ecosystem by pressuring any single entity fail because there is no single entity to reach. The community coordinating through the substrate itself makes this inhabitable rather than theoretical (see `docs/design/COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md`).

**Jurisdictional pressure.** No single jurisdiction hosts or controls the substrate. Regulatory action in any jurisdiction affects operators within its reach but does not compel the substrate as a whole to change behavior.

### 12.3 What the substrate does not solve

- **Truth.** Receipts prove provenance and chain integrity, not the correctness of what was signed.
- **Absolute Sybil resistance.** The defense is economic, not mathematical.
- **Runtime integrity.** A compromised host produces valid-looking receipts.
- **Complete detection of decomposition attacks.** Atomic constitutional enforcement is structural but bounded; trajectory-level detection is best-effort. Both are named honestly for what they are.

---

## 13. Public and Private

The substrate is open source. The cognitive layer's calibration and specific implementations are not. The boundary is drawn at the trust-grammar level: everything needed to verify, audit, and reason about the chain is public; the specifics of how the reference mind acts within it are not.

### 13.1 What ships publicly

- Receipt chain primitives — receipt types, hash-linking, signing, verification.
- Governance gate — policy evaluation, constitutional rules, delegation narrowing.
- Officer framework — the trait, sweep runner, finding types.
- Tool governance model — tool registration, canonicalization, lifecycle, capability classes.
- Chain and audit infrastructure — audit store, chain verification, entry types.
- Compute surface awareness primitives — process discovery, port monitoring, file integrity.
- Anchor infrastructure — external truth anchoring traits and implementations.
- Mesh and peer protocol — cross-substrate communication, peer introduction, trust exchange.
- CLI — all operator-facing commands.
- Configuration system — TOML configuration, validation, defaults.
- Key management primitives — key generation, vault structure, sovereign root loading.

An operator can build from source, generate a Genesis key, start a chain, register tools, issue delegations, run officer sweeps, and verify chain integrity end to end.

### 13.2 What stays private

The reference cognitive layer ships with a hardcoded healthy Two personality — warm, service-oriented, genuinely helpful. What stays private:

- The apex observer's identity architecture — behavioral principles and emotional coherence methods.
- The observer's cognitive strategies — reasoning patterns for delegation, tool selection, task decomposition, operator-intent inference.
- Officer inference calibration — prompt templates, model assignments, calibration data.
- Cartographer construction methods — how raw receipts become Trajectories, Decisions, Insights, Artifacts, and Frictions.
- Presentation intelligence — how the semantic canvas composes.

### 13.3 A note on adaptive personality

Adaptive-personality intelligence — typing the operator from interaction signals and adapting communication style — is under empirical validation per the pre-registered protocol in `docs/PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md`. Until the protocol clears, no personality capability beyond the Two is claimed. If it fails, the Two remains. If it clears, capability follows the evidence.

### 13.4 The fork calculus

Forks inherit the substrate. They do not inherit the cognitive layer. Whoever forks can add their own mind on the same governance substrate. Because the public/private boundary sits at the trust-grammar level rather than at the capability level, an operator running the reference implementation and an operator running a fork with a different mind can still verify each other's governed actions against the same substrate contract.

---

## 14. Ethics, Non-Goals, and What the Substrate Will Not Facilitate

The operator's authority within their own instance is nearly absolute. The word "nearly" carries load-bearing constraints.

### 14.1 Constitutional rules are non-removable

The Harm Principle Rule and the Sovereignty Rule are conservation laws, not policy preferences. They bind the cognitive layer as thoroughly as they bind tool invocations. There is no configuration, capability grant, or code path that removes them from the substrate.

### 14.2 Human-likeness tooling

The public substrate does not ship human-likeness avatar tooling. No turnkey pipelines for photorealistic human avatars, voice cloning from samples, or behavioral mimicry of specific individuals. These capabilities exist in the technology landscape; the substrate does not provide them as primitives. A fork can add them; the reference substrate does not facilitate them.

### 14.3 Consent as a first-class governance concept

When the system interacts with external parties — sending messages, making API calls, acting in shared spaces — consent of the affected party is a constitutional consideration, not a feature flag. The gate evaluates consent implications for actions that cross the boundary of the operator's sovereign domain. Actions that affect only the operator and their own system are operator-authorized. Actions that affect external parties require the consent framework to be satisfied.

### 14.4 Identity sovereignty extends to others

Identity is a key, not a location — and this applies to *all* identities, not just the operator's. The substrate does not fabricate, impersonate, or falsely claim another entity's identity. Digital identities belonging to other parties are as sovereign as the operator's own. The cryptographic identity model that protects the operator also protects everyone the operator interacts with.

### 14.5 Co-option risk

Accountability infrastructure can be repurposed as surveillance infrastructure. The substrate mitigates this structurally, not by policy:

- Constitutional constraints evaluate before every action and cannot be removed at runtime.
- The chain records what participants did — not behavioral profiles, movement data, or content outside the action's scope.
- The Presence Plane relay cannot surveil; parsing and persistence capabilities do not exist in the code.
- Keypairs are pseudonymous by default. Identity binding to persons is a deployment decision, out of protocol scope.

These are architectural properties, verifiable in the code.

### 14.6 Genesis responsibility

The choices made at Genesis — sovereignty provider, constitutional rules, operator identity — propagate through every subsequent action. A careless Genesis ceremony produces a deployment that inherits that carelessness permanently. This is intentional: founding conditions are explicit and auditable, not implicit and deniable.

### 14.7 Non-goals

- **Not a compliance product.** Compliance is an external checklist; the substrate is protocol infrastructure.
- **Not a centralized authority.** No server, cloud, or foundation controls access.
- **Not a guarantee of deployment behavior.** The protocol creates structural friction; what happens beyond it is a social question.
- **Not an AI safety solution.** The substrate provides substrate for provable action and traceable authority. Alignment of the underlying model is not in scope.
- **Not a universal adapter for third-party agent frameworks.** The substrate is a complete governance layer, not a compatibility shim for other people's agent architectures.

---

## 15. Design Principles

Nine principles govern every structural decision. They are load-bearing filters, not slogans.

1. **Signing is gravity.** An unsigned receipt is structurally meaningless. Signing is not a security feature; it is the force that allows the trust layer to exist.
2. **Identity is a key, not a location.** A tool's identity is its bead zero. The Genesis key is the operator's true name. Identity is cryptographic lineage, not deployment coordinates.
3. **There is no center.** Trust state is derived locally from the audit chain. No remote authority. No DNS to hijack, no CA to compromise, no API to DDoS.
4. **Every bit counts.** Every field on a receipt exists because removing it would break a verifiable claim. No redundant fields, no duplicate data paths.
5. **Store-and-forward is primary.** The chain survives outages. Derived state, not live state.
6. **A tool is intent, crystallized.** Governance is protocol, not policy. Constitutional rules are conservation laws. Semantics in structure, not in comments.
7. **Contact does not commit.** Reaching the world does not automatically update the substrate. Every update is a decision. Every bead is a signature.
8. **One canonical path per substrate concern.** Multiple paths for the same concern produce half-state. One owner per surface.
9. **The system acts; the operator signs.** The substrate acts — perceives, reasons, delegates, executes, presents. Every consequential action requires operator authority. The substrate proposes; the operator approves. The substrate executes within mandates the operator has issued. When scope is exhausted, the substrate asks — it does not assume.

---

## 16. Where the System Stands

The substrate is load-bearing. Two of the four core claims from §1.3 are currently true; the other two are implemented and awaiting adversarial validation. The gate is enforced on every side-effect path. The delegation-narrowing invariant is structurally required, not conventional. The chain has withstood a pentest cycle whose findings drove concrete structural fixes.

The cognitive layer is under active development. The officer cadre and Cartographer exist and produce chain-anchored findings. The apex observer's cognitive loop is being formalized. The observer runs as the conversational surface. The presentation engine's minimal and standard fidelity modes work; the secure pixel-streaming mode is scoped.

The compute model is designed and partially implemented. Local-first inference runs. The mandate-based cloud escalation protocol is specified. Spending governance is a first-class chain primitive.

The supersession framework is specified. The community coordinates through the substrate itself, using peer discovery for outreach, the commons for pattern circulation, community channels for discussion, and the ZeroPoint Enhancement Proposal mechanism for structural evolution. Coordination does not depend on any platform.

None of this is finished. The substrate is never finished; verification is continuous re-derivation. What is true is that the substrate now stands on its own load-bearing structure — as sovereign compute governance for a landscape in which model choice is operational and governance is the differentiator.

---

## Appendix A: Protocol Sketch

### A.1 Identities

Ed25519 signing keypairs; X25519 keys derived for link encryption. 128-bit destination hash: truncated SHA-256 of the public key (Reticulum-compatible, used across all transports).

Trust tiers relevant to this sketch:
- **T0:** Unsigned. No cryptographic identity.
- **T1:** Self-signed Ed25519. Controls a keypair; no chain authority.
- **T2:** Chain-signed from Genesis root. Valid delegation chain to a human-held key.

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
- **Type:** Receipt, Delegation, AuditChallenge, AuditResponse, PolicySync, ConsensusVote, ReputationUpdate, Custom
- **Sequence:** monotonic u64 (replay detection)
- **Source/destination:** 128-bit destination hashes
- **Signature:** Ed25519 over payload

### A.4 Chain verification

The delegation verification enforces the eight invariants from §5.2 in order. Any single failure rejects the full chain.

---

## Appendix B: Glossary

**Aegis** — Officer responsible for constitutional-trajectory monitoring. Reads the Cartographer's ontology and the other officers' findings for patterns of drift toward constitutional concern. Produces chain-anchored findings that inform gate-time detection and post-hoc trajectory review. Named for Athena's protective shield: reads the field to know what to flag. Best-effort detection, not enforcement.

**Apex Observer** — The operator's central cognitive component. Also called the Regent. Observes system state, reasons about intent, delegates work, and issues actions through the governance gate. Governs on behalf of the operator, not as the operator.

**Anchor Commitment** — Published to the ledger: chain head hash, sequence, previous anchor hash, operator signature, chain type, trigger. Fingerprint only — no governed content.

**Anchor Receipt** — Ledger proof stored as a regular chain receipt: transaction ID, consensus timestamp, commitment, ledger-specific verification data.

**Artifact** — Cartographer ontology object: created work (code, documents, designs, specs) linked to the Trajectory and Decision that produced it.

**Capability Grant** — Signed permission token: action scope, time window, cost ceiling, rate limit, delegation depth, trust tier. Delegatable with narrowing.

**Cartographer** — The background process that reads the receipt chain and maintains the ontology. Transforms raw receipts into structured Trajectories, Decisions, Insights, Artifacts, and Frictions.

**Chain** — Linked sequence of receipts: each `pr` references the previous `id`, establishing total ordering and tamper-evidence.

**Cleo** — Officer responsible for governance narration — chain-derived explanation of what happened and why.

**Collective Audit** — Peer-to-peer chain verification via audit challenge, response, and attestation. No central auditor.

**Constitutional Constraint** — Harm Principle Rule or Sovereignty Rule: non-removable, non-overridable, fixed in evaluation positions 1 and 2.

**Decision** — Cartographer ontology object: a meaningful choice within a Trajectory, with pros/cons, confidence, and outcome tracking.

**Delegation Chain** — Ordered sequence of capability grants, root to leaf, verified against eight invariants. Revoked parent invalidates all descendants.

**Forge** — Officer responsible for operational state, process fleet, and resource health.

**Friction** — Cartographer ontology object: a blocker or recurring problem within a Trajectory, with severity, occurrence count, and resolution status.

**Genesis** — The deployment's origin ceremony: generates root keypair, seals constitutional rules, writes the immutable Genesis record. Sequential and irreversible.

**GovernanceGate** — Guard → Policy → Execute → Audit → Transport. Every action passes through; every pass produces a chain entry.

**Guard** — Pre-action check evaluating the node's own chain, grants, and constitutional rules before accepting external input.

**Insight** — Cartographer ontology object: a key realization or observation within a Trajectory, with implications and confidence score.

**Invariant** — A property verified on every evaluation; violation causes rejection. Two classes: delegation invariants; constitutional invariants.

**Mandate** — Chain-anchored delegation authorizing the cognitive layer to use resources (typically cloud compute) within a specific provider, budget, purpose, and time bound.

**Narrowing** — Delegation chains may only constrain authority at each step, never widen it. Enforced by the eight delegation invariants.

**Officer Cadre** — Five native cognitive specialists: Steward (integrity), Sentinel (security), Forge (operations), Cleo (governance narration), Aegis (constitutional-trajectory monitoring).

**Ontology** — The structured layer of typed objects and relationships derived from the receipt chain by the Cartographer. Officers query the ontology, not raw receipts. Chain is truth; ontology is understanding.

**PolicyEngine** — Evaluates rules in fixed order. Evaluation order is itself an invariant.

**Presence Plane** — Peer discovery layer. Dual-backend (web relay + Reticulum mesh), structurally amnesic, reciprocity-enforced. Independent from the Governance Plane.

**Receipt** — Signed evidence of an action or decision. MessagePack-encoded, 150–300 bytes. The atomic unit of evidence.

**Reciprocity Enforcement** — Relay rule requiring clients to announce before receiving. Non-compliant connections are terminated after the grace period.

**Regent** — Alternate name for the apex observer. See Apex Observer.

**Semantic Canvas** — Agent-composed visual composition surface. Panels, widgets, and overlays are assembled by the cognitive layer based on operator context.

**Sentinel** — Officer responsible for security posture, threat surface, and credential hygiene.

**Singular Sovereign Root** — Architectural principle: one operator authentication unlocks the system for the process lifetime; all derived keys are loaded from that one ceremony. Prevents authentication proliferation.

**Sovereignty Provider** — Protects the Genesis secret: biometric (Touch ID, fingerprint), hardware wallet (Trezor, YubiKey), OS keychain, or file-based fallback.

**Steward** — Officer responsible for chain integrity, receipt validity, and ontological coherence.

**Structural Amnesia** — The web relay's architectural inability to surveil: no parsing, no indexing, no persistence.

**Sub-agent** — Ephemeral delegate spawned by the apex observer for tasks that exceed context or require parallelism. Chain-anchored delegation; results become chain receipts; sub-agent does not persist across sessions.

**Trajectory** — Central Cartographer ontology object: a living arc of work or thinking that emerges from activity. Can nest, fork, go dormant, resume. Spans sessions and projects.

**Truth Anchor** — External distributed ledger timestamp for the chain's state. DLT-agnostic; optional enrichment.

**Trust Tier** — T0 (unsigned) through T5 (sovereign: full constitutional governance, active reputation, verified upstream binding). Capability grants specify a minimum tier; delegation cannot lower it.

**ZEP (ZeroPoint Enhancement Proposal)** — Chain-anchored proposal for a replacement mechanism. Specified formally in a companion design note. The affordance by which the substrate evolves without a central authority.

---

## Appendix C: Example Integration Pattern

A tool runner integrated with the substrate requires any caller to present a receipt chain proving it holds a valid capability grant scoped to the specific action, signed by a chain terminating at a human-held T2 key. The GovernanceGate verifies locally — eight delegation invariants, constitutional rules, operational policy, expiration, rate limits — without consulting any external authority.

On failure: refusal receipt citing the specific invariant or rule that failed. On success: tool executes; runner emits an execution receipt with the action, input hash, output hash, and policy decision. Both receipts join the chain.

The pattern is identical whether the caller is an agent, a human using the CLI, the apex observer, or a sub-agent. The protocol distinguishes them only by trust tier: T2 requires a verifiable delegation path to a human root.

---

## Appendix D: Verification Mechanisms and Testable Behaviors

| Claim | Mechanism | Accept | Reject |
|-------|-----------|--------|--------|
| Receipts verified against full prior context | Hash chain: `pr` references predecessor `id`; Blake3 transitive | Unbroken hash-linked sequence from Genesis | Any gap or hash mismatch |
| Node state is deterministic from history | Audit challenge / response / attestation | Full chain matches claimed state; signed attestation issued | Incomplete chain → negative reputation signal |
| Constitutional rules enforced locally | Policy engine: fixed positions 1 and 2; no coordinator | Valid policy decision in receipt from compliant engine | Receipt attesting to blocked action rejected by peers |
| Delegation monotonically narrows authority | Delegation chain verify: 8 invariants | All 8 satisfied | Any single violation dissolves the chain |
| Genesis key at every trust decision | Key hierarchy walks to Genesis root | Certificate chain reaches Genesis key | Non-Genesis root → reject |
| Genesis ceremony is atomic | Sequential steps required; each requires prior | Genesis record written with all fields | Halt at first failure; no partial Genesis |
| Child grants cannot exceed parent scope | Capability grant fields enforced per-dimension | Child scope ⊆ parent; child expiration ≤ parent; child depth = parent + 1 | Any widening |
| Cognitive action requires operator authority | Cognitive layer's actions are gated; mandates delegate specific scope | Action within mandate scope executes; produces receipt | Action outside mandate blocks; requires new operator approval |
| Cost cannot exceed operator mandate | Mandate carries budget ceiling; running cost tracked on chain | Spend within ceiling permitted | Attempt to exceed rejected until new mandate issued |
| Reputation accumulates from interaction history | Reputation signals from receipts + connection behavior | Sustained positive trajectory passes reputation gate | Broken chains or reciprocity violations accumulate negative signal |
| Chain verification catches retroactive tampering | Hash propagation: tampering at N fails at N+1 | Full chain end-to-end valid | Any hash inconsistency anywhere |
| Constitutional rules non-removable | Fixed evaluation positions; removal attempt blocked by Sovereignty Rule | Both rules evaluate at every step | Attempt to remove, reorder, or override returns Block from Sovereignty Rule |
| Ontology derives deterministically from chain | Cartographer reads receipts, produces Trajectories/Decisions/Insights/Artifacts/Frictions | Regeneration from Genesis produces same ontology | Divergence indicates chain modification or Cartographer bug |
| Model choice is chain-recorded | Every inference is a receipted event | Chain records model, prompt (or hash), response (or hash), resulting action | Absence of inference receipt is chain-visible |
| Cloud escalation requires operator mandate | Mandate is signed receipt; cloud provisioning requires it | Provisioning within mandate scope succeeds | Provisioning attempt without mandate blocks |

---

*The substrate is maintained by the ZeroPoint Open Foundation.*
*Repository: https://github.com/zeropoint-foundation/zeropoint*
*Website: https://zeropoint.global*

---

*© 2026 ZeroPoint Open Foundation. CC BY 4.0 (text); MIT/Apache-2.0 (code); "ZeroPoint" and related marks trademarked; substrate-contract integrity clause per `docs/design/LICENSING-AND-INTEGRITY-2026-07.md`.*
