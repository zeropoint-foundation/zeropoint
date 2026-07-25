# ZeroPoint

**Document type:** Public-facing overview draft. Not canonical and not a Tier 2 elaboration — narrative synthesis for external readers. Canonical claims live in `KEEL-2026-07.md`.

*An overview of the sovereign agentic system — July 2026.*

---

## What ZeroPoint is

ZeroPoint is a sovereign agentic system: a Rust-implemented stack in which cryptographic governance, native cognition, and adaptive presentation compose into a single operator-owned runtime for the Agentic Age.

Each clause carries weight.

**Sovereign** means the operator holds the Genesis key, and every authority in the system derives from it. No platform grants permission. No remote service is required for the system to function or to defend its own integrity. No entity — including the ZeroPoint Open Foundation, under which the system is released — can revoke, override, or condition the operator's control of their own instance.

**Agentic system** means it acts. It perceives operator intent, reasons about state, delegates work, executes through a governance gate, presents results, and remembers. It is not a substrate awaiting a tenant. It is the thing infrastructure has historically existed to enable.

**Rust-implemented stack** means one language, one type system, one compilation unit at the trust boundaries that matter. From receipt primitives through the gate and officer cadre through the cognitive layer and presentation engine, the system is built as one thing.

**Cryptographic governance** means signed, hash-chained receipts; a gate that evaluates every side-effecting call; constitutional rules that no code path can bypass; and delegations that narrow monotonically as they descend.

**Native cognition** means ZeroPoint has its own mind — not a hosted tenant's mind. A central agent (the Regent), a specialist officer cadre, a background process (the Cartographer) that turns raw receipts into structured understanding, and a sub-agent delegation model. All of it is governed by the same chain and gate that govern tools.

**Adaptive presentation** means the operator sees the system through surfaces that adapt to their hardware, bandwidth, and security posture — from a terminal at five bits per second to a pixel-streamed semantic canvas — with the same chain, gate, and cognitive layer underneath.

**Single operator-owned runtime** means one system, one operator, one Genesis key, one chain. ZeroPoint does not multi-tenant in the platform sense. Each operator runs their own. Cross-operator interaction happens through mesh protocols between sovereign peers, not through a shared host.

## Why the reconceptualization

An earlier framing of the project treated ZeroPoint as pure infrastructure — a trust substrate positioned as a universal adapter to other systems' agent architectures. That posture is retired.

The retirement is empirical, not philosophical. Every third-party integration required contorting ZeroPoint's governance model to fit the third party's assumptions about identity, memory, credentials, and scheduling. Integrations built alongside ZeroPoint composed cleanly. Integrations with frameworks that carried their own assumptions stalled. The "universal" in universal adapter was aspirational; the reality was that only agent architectures shaped by ZeroPoint's philosophy could be governed by it.

The reconceptualization acknowledges this: the governance model *is* the cognitive model. The chain, the gate, the officers, the capability classes, the delegation-narrowing invariant — these are a specific theory of how autonomous action should be authorized, observed, and bounded. A mind that composes with them is not generic; it is a mind shaped by them. Building that mind natively is more honest than pretending any mind could slot in.

The substrate the prior framing described is real, load-bearing, and retained. Its role changes. It is now the foundation of a sovereign system, not a standalone product.

## The chain

At the base of the system is a hash-linked sequence of signed receipts. Each receipt records an action — an operator intent, a governance decision, a tool invocation, an officer finding, a delegation grant, a cognitive step. Each receipt links to its predecessor, and each is signed by the entity that emitted it, with lineage running back to the operator's Genesis key.

The chain is not a log. It is the system's persistent memory, the source of truth for governance decisions, and the anchor by which the cognitive layer maintains coherent awareness across sessions. Verification is re-derivation: to trust a receipt, walk the chain back to Genesis and check every signature and every hash link.

The system rests on four claims about this substrate. They are the acceptance criteria for the whole architecture. Their status matters more than the claims themselves.

- **Each step is conditioned on all prior context.** Currently true.
- **Present state compresses full history.** Implemented; not yet tested under adversarial pressure.
- **System-wide coherence follows from local evaluation.** Currently true.
- **Future actions are narrowed by trajectory.** Implemented; not yet adversarially tested.

The two claims that are not yet adversarially validated are honest boundaries. The architecture is designed to make them true; the empirical work of proving they hold is ongoing.

## The gate

Every side-effecting action passes through a GovernanceGate. The gate evaluates constitutional rules (non-removable, non-overridable), current capability grants, delegation scope, and observed system state before allowing execution. The gate does not advise. It permits or denies.

Constitutional rules are conservation laws, not policy. They cannot be removed by configuration, overridden by capability, or bypassed by any code path. They apply to the cognitive layer as thoroughly as they apply to tool invocations. The system's own mind is bound by the same law as its tools.

Delegations narrow monotonically. A capability handed from one entity to another can only equal or reduce the granting entity's scope. There is no path by which a subordinate action gains authority its parent did not have.

## The cognitive layer

ZeroPoint has a mind. It is native — part of the system, not a tenant hosted on it.

**The Regent** is the apex cognitive entity, the operator's primary agent, the intelligence through which the system perceives intent, delegates work, and coordinates response. The title is deliberately temporary and relational: the Regent governs *on behalf of* the operator, not *as* the operator. When the operator names their system, the Regent designation may retire with a chain receipt marking the transition. Until then, "Regent" is the canonical role.

**The officer cadre** is five specialists, each responsible for a domain:

- **Steward** — chain integrity, receipt validity, ontological coherence.
- **Sentinel** — security posture, threat surface, credential hygiene.
- **Forge** — operational state, process fleet, resource health.
- **Cleo** — governance narration, chain-derived explanation of what happened and why.
- **Aegis** — constitutional-trajectory monitoring; reads the Cartographer's ontology and the other officers' findings for patterns of drift toward constitutional concern. Best-effort detection, not enforcement — atomic constitutional enforcement stays at the gate.

The officers are chain-anchored attestors — background sweeps produce signed findings. They are also active participants in the Regent's loop: consulted before delegations that touch their domains, emitting proactive findings when observation warrants, maintaining in-session context that makes each sweep more informed than the last. They observe, attest, and advise. They do not block; the gate blocks. They do not decide; the Regent decides, under operator authority.

**The Cartographer** runs in the background and turns raw receipts into structured understanding. Its output is the ontology: Trajectories (living arcs of work that emerge from activity rather than being declared top-down), Decisions (meaningful choices with tracked confidence and outcomes), Insights (realizations with implications), Artifacts (created work linked to what produced it), and Frictions (blockers and recurring problems with severity and occurrence tracking). The chain is truth; the ontology is understanding. Officers and the Regent query the ontology, not raw receipts.

**Sub-agents** are ephemeral delegations. When a task exceeds the Regent's context or benefits from parallelism, the Regent requests a sub-agent through a governed spawn primitive. The sub-agent receives a chain-anchored, capability-scoped, time-bounded delegation. Its actions go through the gate. Its results become receipts. The chain persists; the sub-agent does not.

## The cognitive loop

The Regent maintains a continuous loop:

1. **Perceive** — operator intent, chain state, officer findings, environmental signals.
2. **Reason** — evaluate what the operator wants against what the chain authorizes, what the officers observe, what resources are available.
3. **Delegate** — assign work to officers, sub-agents, or tools. Every delegation is chain-anchored and capability-scoped.
4. **Execute** — through the gate. Every action produces a receipt.
5. **Present** — surface results through the presentation layer.
6. **Remember** — update multi-timescale memory. Session context is ephemeral; chain-anchored facts persist; the Cartographer maintains the ontology.

The loop is not a pipeline. It is continuous and reentrant. Perception feeds into reasoning, which produces delegations, which produce receipts, which the Cartographer folds back into the ontology, which changes what the Regent perceives on the next cycle.

## Presentation

The operator's experience of the system is the system. How ZeroPoint presents itself — visually, conversationally, adaptively — is as load-bearing as how it signs receipts.

Three primitives compose the presentation layer:

**The conversational surface** is the Regent, expressed in language. Natural-language interaction is the primary mode for most operations: the operator speaks intent, the Regent reasons and acts, the chain records, the Regent responds. Not a chatbot UI on top of governance — the Regent itself, in words.

**The browser harness** is governed browser control. The system can navigate, click, read, fill forms, and extract from the web — but only as a gated, receipted, capability-scoped tool. There is no open-ended internet access. Browser capability is a delegation, like any other.

**The semantic canvas** is an agent-driven visual composition surface. Not a static dashboard. Panels, widgets, visualizations, video streams, and overlays are composed by the cognitive layer based on what the operator needs to see. The Regent speaks; the canvas shows; both draw from the same chain.

These primitives render at three fidelities, adaptive to the operator's context:

- **Minimal** — terminal-only, text-based, low-bandwidth. Fully functional: chain queries, governance posture, tool lifecycle, conversational interaction. Appropriate for constrained hardware, constrained networks, and high-security contexts where rich clients are attack surface.
- **Standard** — local browser rendering. The default for modern hardware and reasonable bandwidth.
- **Secure** — server-side rendering with pixel streaming to the client. The client receives only a video stream; it cannot inspect the DOM, execute JavaScript, or intercept API calls. The attack surface collapses to the video decoder.

State lives in the chain, not in the client. Switching fidelity mid-session does not lose state, because there is nothing in the client to lose.

## Compute and cost

The cognitive layer runs on local inference by default. The system maintains a registry of local models calibrated to specific cognitive tasks; each task has a model assignment based on empirical benchmarking. The real test of ZeroPoint is how capable it is running solely on the operator's hardware.

Cloud inference is augmentation, not foundation, and it is governed like every other capability. When a task exceeds local capacity, the cognitive layer formulates a resource request — what compute, for how long, at what estimated cost, for what purpose — and presents it to the operator. Approval is a signing ceremony. Resources are provisioned within a mandate: specific provider, specific budget ceiling, specific time bound. Cloud-executed work produces receipts that flow back to the operator's chain. Exceeding the mandate requires a new ceremony.

Every action with a cost — inference tokens, cloud compute hours, API calls, storage — is tracked on the chain. Cost governance is not a reporting feature. It is a governance primitive of the same shape as capability delegation: the system cannot spend what the operator has not authorized, for the same structural reason it cannot execute what the gate has not approved.

## Public and private

ZeroPoint's functional substrate is open source. The receipt primitives, the gate, the officer framework, the tool governance model, the chain and audit infrastructure, the compute-surface-awareness primitives, the mesh protocol, the CLI, the configuration system, the key management — all of it ships. An operator can build from source, generate a Genesis key, start a chain, register tools, issue delegations, run officer sweeps, and verify integrity end to end. The public code is not a demo or a trial; it is the real substrate.

The cognitive layer's implementation details stay private. The open-source version ships with a hardcoded healthy Two personality — warm, service-oriented, genuinely helpful — that is a good assistant people enjoy using. It is a floor, not a crippled version. What stays private is what makes the mind distinctively good: the Enneagram-adaptive personality intelligence that types the operator from interaction signals and adapts its communication style; the Regent's identity architecture and emotional coherence methods; its cognitive strategies for delegation, tool selection, and intent inference; officer inference calibration; the Cartographer's ontology-construction methods; the semantic canvas's composition intelligence.

The public boundary is drawn at the trust-grammar level, not the capability level. Everything needed to verify, audit, and reason about the chain is public. Everything needed to *be good at acting within that chain* is private. An operator can verify that the system's actions are governed without needing access to its cognitive internals. A fork can build a different mind on the same substrate. Neither degrades the other.

## What the system will not facilitate

The operator's authority within their own instance is nearly absolute. The word "nearly" carries the load-bearing constraints.

**Constitutional rules are non-removable.** The HarmPrinciple and Sovereignty rules bind the cognitive layer as thoroughly as they bind tool invocations. There is no configuration, capability, or code path that removes them.

**The public substrate does not ship human-likeness avatar tooling.** No turnkey pipelines for photorealistic avatars, voice cloning from samples, or behavioral mimicry of specific individuals. These capabilities exist in the technology landscape. ZeroPoint does not provide them as primitives. A fork can add them; the official substrate does not.

**Consent is a first-class governance concept.** When the system acts across the boundary of the operator's sovereign domain — sending messages, making API calls, participating in shared spaces — consent of affected parties is a constitutional consideration, not a feature flag.

**Identity sovereignty extends to others.** Identity is a key, not a location, and this applies to all identities, not just the operator's. The system does not fabricate, impersonate, or falsely claim another entity's identity. The cryptographic identity model that protects the operator also protects everyone the operator interacts with.

## The design principles

Nine principles govern every structural decision. They are load-bearing filters, not slogans.

1. **Signing is gravity.** An unsigned receipt is structurally meaningless.
2. **Identity is a key, not a location.** Cryptographic lineage, not deployment coordinates.
3. **There is no center.** Trust state is derived locally from the chain.
4. **Every bit counts.** Every field on a receipt exists because removing it would break a claim.
5. **Store-and-forward is primary.** The chain survives outages. Derived state, not live state.
6. **A tool is intent, crystallized.** Semantics live in structure, not in comments. Constitutional rules are conservation laws.
7. **Contact does not commit.** Reaching the world does not automatically update the substrate.
8. **One canonical path per substrate concern.** Multiple paths for the same concern produce half-state.
9. **The system acts; the operator signs.** ZeroPoint acts — perceives, reasons, delegates, executes, presents. Every consequential action requires operator authority. The system proposes; the operator approves. The system executes within mandates the operator has issued. When scope is exhausted, the system asks — it does not assume.

## Where the system stands

The substrate is load-bearing. Two of the four claims are currently true; the other two are implemented and awaiting adversarial validation. The gate is enforced on every side-effecting path. The delegation-narrowing invariant is structurally required, not conventional. The chain has withstood a pentest cycle whose findings drove concrete structural fixes.

The cognitive layer is under active development. The officer cadre and Cartographer exist and produce chain-anchored findings. The Regent's cognitive loop is being formalized. The Regent runs as the conversational surface. The presentation engine's minimal and standard modes work; the secure pixel-streaming mode is scoped.

The compute model is designed and partially implemented. Local-first inference runs. The mandate-based cloud escalation protocol is specified. Spending governance is a first-class primitive in the chain.

None of this is finished. The substrate is never finished; verification is continuous re-derivation. What is true is that the system now stands on its own load-bearing structure — not as infrastructure seeking adoption by other people's agent frameworks, but as the sovereign agentic system operators run when they need to actually own the systems that act on their behalf.

---

*ZeroPoint overview — July 2026. Companion to `docs/ARCHITECTURE-2026-07.md` (the canonical architecture record). This document is the readable overview; the architecture doc is the operating spec.*
