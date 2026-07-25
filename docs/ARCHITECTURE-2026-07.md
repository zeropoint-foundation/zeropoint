# ZeroPoint Architecture — July 2026

**Document type:** Canonical Architecture Record. Supersedes `ARCHITECTURE-2026-04.md` and `ARCHITECTURE-2026-05.md`. Referenced in `CLAUDE.md` as the north star for all structural decisions. Code that contradicts this document is wrong.
**Author:** Ken Romero, with synthesis assistance from Claude.
**Date:** 2026-07-04. Reclassified Historical 2026-07-10.
**Status:** Historical (as of 2026-07-10). Canonical substrate claims live in `KEEL-2026-07.md`; corpus map lives in `CANONICAL-CORPUS-INDEX-2026-07.md`. This document is retained for its role as the reconceptualization arc that led to KEEL — the framing move from substrate-only to sovereign agentic system. **Not amended for corpus pivots past July 2026.** The 2026-07-10 framing amendment below is kept as a breadcrumb showing the moment the substrate-form pivot surfaced against this document's assumptions; canonical treatment lives in `docs/design/SUBSTRATE-FORM-2026-07.md` and `KEEL-2026-07.md` Part XIV.

> **2026-07-10 framing amendment.** After this document was drafted, we surfaced a load-bearing assumption it silently carried: that the substrate installs on the operator's existing operating system. That assumption is now scoped as **Companion Form** per `docs/design/SUBSTRATE-FORM-2026-07.md`, one of three Forms the substrate can take. The canonical form is **Sovereign Form** — a reproducibly-built OS with operator-controlled hardware trust chain. `docs/KEEL-2026-07.md` Part XIV declares this. This document's Part III (Compute Model) and Part V (Open-Source Boundary) predate the pivot and describe Companion Form assumptions in load-bearing ways; read those parts with `SUBSTRATE-FORM-2026-07.md` alongside. The cognitive architecture (Part II), presentation layer (Part IV), ethics/consent (Part VI), and design principles (Part VII) are Form-invariant and hold unchanged. The observation plane specified in `docs/design/OBSERVATION-PLANE-2026-07.md` composes with each Form differently — reachable observation surface varies by Form, with honest Form Disclosure covering the gaps. A full-pass reconciliation with the Form frame is deferred as a `whitepaper` revision when we return to public documentation; internal reasoning uses the amended framing directly.

This document is a reconceptualization. The prior architecture documents treated ZeroPoint as pure infrastructure — a trust substrate whose value proposition was being a universal adapter to other systems' agent architectures. That posture is retired. ZeroPoint is a sovereign agentic system: a complete stack from cryptographic trust primitives through cognitive architecture through operator-facing presentation, unapologetic about what it is and uninterested in fitting into other systems' boxes.

The trust substrate that the prior documents described is real, load-bearing, and retained. What changes is its role: the substrate is the foundation of a sovereign system, not a standalone product seeking adoption by third-party agent frameworks. The principles, the claims, the grammar formalism, the receipt chain — all survive. What is added is everything above the substrate: a native cognitive layer, a presentation engine, a compute governance model, and an explicit public/private boundary.

**Companion documents:**
- `docs/ARCHITECTURE-2026-04.md` — the prior architecture (substrate-only scope; superseded by this document but retained as historical record and for the pentest findings in Parts II-III which remain valid)
- `docs/whitepaper-v9.md` — the public thesis (aligned with this reconceptualization; July 2026)
- `docs/COGNITIVE-DESIGN-PRINCIPLES-2026-07.md` — cognitive-layer design principles (current)
- `docs/design/ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` — Cartographer and ontology spec (Trajectories, Decisions, Insights, Artifacts, Frictions)
- `docs/design/TOOL-GOVERNANCE-LIFECYCLE-2026-07.md` — tool lifecycle spec (current)
- `docs/design/TOOL-OPACITY-AND-CAPABILITY-CLASSES-2026-07.md` — tool effect classification and capability-class delegation
- `docs/design/GOVERNANCE-POSTURE-WIRE-CONTRACT-2026-07.md` — governance-posture wire contract
- `docs/GOVERNANCE-IMPLEMENTATION-PRINCIPLES-2026-06.md` — operational heuristics (still valid; scope broadens)
- `docs/PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md` — pre-registered validation protocol for the adaptive-personality capability; supersedes the personality claims in §16
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — canonical answer to "how does anyone reach ZP operators when there is no center"; peer-discovery + local-filter as the outreach primitive; grounds the recruitment mechanics of the personality-adaptation protocol
- `docs/design/DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` — sovereign-aligned commons pattern; how operators exchange learned patterns peer-to-peer without a central aggregator
- `docs/design/BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` — survey of thirteen backup and recovery approaches evaluated against ZP sovereignty principles; menu of options with trade-offs
- `docs/design/ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md` — end-to-end encryption architecture; key hierarchy from Genesis; vault format; chain content encryption; capability-scoped peer sharing via HPKE; concrete cryptographic primitives and storage layout
- `docs/design/REGENT-COMPARTMENTALIZATION-2026-07.md` — the Regent's role as the operator's cognitive advocate for identity compartmentalization; pre-publish review, style-fingerprint defense, context-switch surfacing, compromise response; how sovereign identity primitives become practical for humans
- `docs/design/PHONE-AND-IDENTITY-2026-07.md` — canonical position on phone numbers vs. ZP identity; four composable affordances (optional attestation, introduction ceremonies, local contact-book integration, phone as fallback channel); SIM-swap immunity by construction
- `docs/design/SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md` — general primitive for structural runtime behavioral claims; five-layer attestation stack; applications include non-recording, no-exfiltration, no-unauthorized-analysis, constitutional-rule integrity, DP budget accounting
- `docs/design/MEDIA-PROVENANCE-2026-07.md` — C2PA-composing provenance architecture; ZP camera app specification; edit workflow; live-streaming legitimacy; provenance as substrate primitive that generalizes to documents, data, code, and claims
- `docs/design/COMMUNITY-SURFACE-ARCHITECTURE-2026-07.md` — the community gathering surface pulling together channels, spaces (bounded vs. portable), sessions (locked-door, ephemeral vs. persistent), reputation-first moderation, presence, notifications, content lifecycle, discovery, contacts, real-time comms, and coordination
- `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` — advisory detection and situational-awareness layer that surfaces multi-action patterns atomic constitutional evaluation cannot see; explicitly *not* an enforcement mechanism (constitutional enforcement stays atomic); trajectory context, pattern accumulators, officer findings, and cognitive-layer self-awareness as detection modes with acknowledgment workflow for the operator
- `docs/design/COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md` — the recursive vision: ZeroPoint's community coordinates through ZeroPoint. Every substrate primitive serving operator sovereignty also serves community self-maintenance. Names structural undeplatformability as a first-order capability that expands who the substrate can serve. Bootstrap paradox and its resolution. Foundation as peer, not authority.
- `docs/design/SUPERSESSION-FRAMEWORK-2026-07.md` — formal specification of the ZeroPoint Enhancement Proposal (ZEP) mechanism. Invariants (non-negotiable substrate properties) vs. mechanisms (replaceable). ZEP format, lifecycle, adoption semantics, adversarial dynamics. The affordance that makes "come build a better mechanism" a real invitation, not rhetoric.
- `docs/design/MULTI-DEVICE-OPERATION-2026-07.md` — resolves the biggest open architectural gap: how one operator uses multiple devices while preserving the singular sovereign root principle, one chain per operator, and Genesis-anchored identity. Every device is a scoped delegation from Genesis; each signs as itself; chain syncs peer-to-peer with merge receipts on the rare fork. Composes cleanly with backup/recovery, encrypted storage, and the Regent's compartmentalization role.
- `docs/design/ONBOARDING-FLOW-2026-07.md` — the first fifteen minutes as architectural, not just UX. Six-stage sequence (verified install, Genesis, meeting the Regent, first mandate, first community context, first real interaction) governed by six principles (progressive disclosure, Regent as guide, real consequences, deferability, reversibility, sovereignty preserved). Names what gets deferred without prompt, deferred with light note, or never deferred. Six failure modes named and prevented.
- `docs/design/LICENSING-AND-INTEGRITY-2026-07.md` — retires the "permissive licensing permits stripping constraints" framing. Three-layer posture: permissive code license (MIT/Apache-2.0), retained trademark on "ZeroPoint" and related marks, integrity clause on distributions claiming ZeroPoint-compatibility. Foundation is explicitly *not* a certification authority, standards body, or gatekeeper — narrow legal recourse for trademark misuse and false compatibility claims only. Any future certification body should be a separate entity, deliberately not controlled by the Foundation or any single individual. Chain-invariant rejection is the primary structural defense; the invariant test suite is the objective standard.
- `docs/design/SECURITY-SIGNAL-CHANNEL-2026-07.md` — time-critical threat coordination as its own channel, separate from the gossip system. Three tiers (advisory / alert / urgent), composite trust model (source reputation + corroboration + officer attribution + recency) because local verification doesn't work for "I'm being attacked," Sentinel and Aegis integration, priority handling that breaks normal noise filters when urgency warrants, adversarial defenses against false injection, urgency inflation, and alert fatigue. Composes with `commons:security:*` announces already spec'd elsewhere.
- `docs/design/REGENT-SECURITY-CHANNEL-INVESTIGATION-2026-07.md` — empirical validation of the security signal channel design. Hybrid real/synthetic scenarios, five questions pre-registered (trust model convergence, tier discipline, adversarial defense, officer integration coherence, compressed-window mitigation adoption), seven adversarial variants including engineered panic and reputation laundering. Companion to the channel design; supersedes the earlier Regent-to-Regent security signal investigation once the reconciliation with the gossip system clarified the two systems are properly separate.
- `docs/design/REGENT-GOSSIP-VALIDATION-2026-07.md` — empirical validation of `regent-gossip-and-evolution-2026-07.md`. Pressure-tests the confident claims in §5.4's fool's-errand analysis before treating them as settled. Five questions pre-registered: intake limiting under sophisticated cognitive-cycle modeling, listen-twice as conservation law, listen-twice as empirical attractor under free parameters, local verification against subtle poisoning, Zone 1 damage ceiling under accumulated drift. Seven adversarial variants including verification-passing poison and fingerprinting via schema.
- `docs/design/governed-agent-runtime.md` — the GAR spec (April 2026; requires revision — agents are no longer generic tenants)
- `docs/AGENT-TOOL-CONTRACT-2026-06.md` — tier 6 affordances (requires revision: the tenant model narrows)

---

## Part I — What ZeroPoint Is

### 1. The reconceptualized statement

> ZeroPoint is a sovereign agentic system: a Rust-implemented stack in which cryptographic governance, native cognition, and adaptive presentation compose into a single operator-owned runtime for the Agentic Age.

Each clause:

- **sovereign** — the operator holds the Genesis key. Authority flows from that key through the chain through every surface. No platform grants permission; no remote service is required. The system runs on the operator's hardware, under the operator's cryptographic identity, and no entity — including the ZeroPoint Open Foundation, under which the system is released — can revoke, override, or condition that sovereignty.

- **agentic system** — not a substrate, not a framework, not an adapter. A system that acts: perceives, reasons, delegates, executes, learns, and presents — all under governance. The distinction from the prior architecture is categorical. ZP was infrastructure; ZP is now the thing that infrastructure exists to enable.

- **Rust-implemented stack** — from `zp-core` (receipt primitives, signing, hash-linking) through `zp-server` (gate, officers, chain) through the cognitive layer (inference, delegation, orchestration) through the presentation engine (browser harness, canvas, adaptive fidelity). One language, one type system, one compilation unit where it matters for trust boundaries.

- **cryptographic governance** — the receipt chain, the gate, the officer cadre, the constitutional rules, the delegation model, the capability classes. This is what the prior architecture built. It is retained in full. It is no longer the whole system; it is the foundation the whole system stands on.

- **native cognition** — ZP has a mind. Not a tenant's mind, not a hosted agent's mind — its own cognitive architecture with the Regent (its central orchestrator), officer specialization, sub-agent delegation, multi-timescale memory, and local-first inference. The cognitive layer is governed by the same chain and gate that govern tools. Its receipts are signed. Its delegations are chain-anchored. Its authority is operator-derived. But it is native to ZP, not borrowed from a third-party framework.

- **adaptive presentation** — the operator sees ZP through surfaces that adapt to hardware, bandwidth, and security posture. From a minimal Reticulum-style terminal at 5 bits per second to a full pixel-streamed canvas with real-time video composition — same chain underneath, same governance, different rendering. The presentation layer is not an afterthought bolted onto infrastructure; it is how the sovereign system presents itself to its operator.

- **single operator-owned runtime** — one system, one operator, one Genesis key, one chain. ZP does not multi-tenant in the platform sense. Each operator runs their own ZP. Cross-operator interaction happens through mesh protocols between sovereign peers, not through a shared platform that hosts multiple operators.

- **for the Agentic Age** — this is what ZP is building toward. Not "governance for the AI era" (reactive, defensive, policy-shaped). The Agentic Age is the thesis: autonomous agents will be the primary mode of computational work, and the systems that govern them must be sovereign, cryptographic, and operator-owned. ZP is infrastructure for that age — but it is infrastructure that acts, not infrastructure that waits to be acted upon.

### 2. The four claims

These are retained from the prior architecture. They are the substrate's acceptance criteria. All four must be true for the system to be load-bearing.

**Claim 1 — Each step is conditioned on all prior context.** `pr` linkage, Blake3 transitivity. Currently true (AUDIT-01 fixed).

**Claim 2 — Present state compresses full history.** Collective audit mechanism. Implemented but untested under adversarial pressure.

**Claim 3 — System-wide coherence from local evaluation.** Gate enforcement on every side-effect path. Currently true (EXEC-01..04 fixed).

**Claim 4 — Future actions narrowed by trajectory.** Delegation narrowing. Implemented but not adversarially tested.

The reconceptualization does not weaken any claim. It extends the claims' scope: they now apply not only to tool governance and delegation chains but to the cognitive layer's own actions. When the Regent delegates to an officer, that delegation is chain-anchored and narrows. When the cognitive layer emits a receipt, it is signed and hash-linked. The claims bind the whole system, not just the substrate.

### 3. The three layers of the substrate

Retained from the prior architecture:

**Layer 1 — Required (the constitutional layer).** What must be true at every step. Conservation laws. Non-removable, non-overridable.

**Layer 2 — Possible (the delegation layer).** What is still authorizable from the current state. Monotonically narrowing capability envelope.

**Layer 3 — Actual (the chain layer).** What was signed, by whom, in what order. The hash-linked receipt sequence.

These layers now govern more: the cognitive layer's decisions, not just tool invocations and delegations.

### 4. The trust-as-grammar framing

Retained in full. Verification is re-derivation. Failure is grammatical. The substrate is never finished. The WASM trust boundary, the catalog, the verifier — all still the right shape.

---

## Part II — The Cognitive Architecture

### 5. Why ZP has a mind

The prior architecture explicitly disclaimed cognition. ZP was the OS; agents were tenants; the OS does not think. This was strategically motivated: a universal adapter must be agnostic about the cognition model it hosts.

The reconceptualization retires the universal-adapter posture. With it goes the prohibition on ZP having its own cognitive layer. The rationale:

- **The adapter posture produced constant friction.** Every integration with a third-party agent framework required contorting ZP's governance model to fit the framework's assumptions. IronClaw's integration worked because IronClaw was built alongside ZP. Hermes's integration stalled because Hermes has its own memory, credential, and scheduling assumptions that don't compose with chain-anchored governance. The "universal" in universal adapter was aspirational; the reality was that only frameworks built to ZP's shape could be governed by it.

- **The governance model is the cognitive model.** The chain, the gate, the officers, the capability classes, the delegation narrowing — these are not neutral infrastructure that any mind can inhabit. They are a specific theory of how autonomous action should be authorized, observed, and bounded. A mind that composes with these constraints is not generic; it is a mind shaped by ZP's governance philosophy. Building that mind native to ZP is more honest than pretending any mind could slot in.

- **The substrate already has cognitive components.** The officer cadre (Steward, Sentinel, Forge, Cleo, Aegis) already runs inference, evaluates chain state, and emits findings. The Cartographer already reads the receipt chain and produces structured understanding. These are not infrastructure — they are cognition running inside the substrate, governed by the same chain they observe. The reconceptualization acknowledges what is already true and extends it.

### 6. The Regent

The **Regent** is ZeroPoint's apex cognitive entity — the operator's primary agent and the central intelligence through which the system reasons, delegates, and acts.

The Regent operates under the operator's sovereign authority, not its own. It perceives intent, maintains the multi-timescale model of the operator, coordinates the officer cadre, delegates to sub-agents, and issues actions through the governance gate. Every consequential decision or action the Regent takes is either directly authorized by the operator or executed within the scope of a prior delegation.

The title "Regent" is deliberately temporary and relational. It signals that this entity governs *on behalf of* the sovereign rather than *as* the sovereign. When the operator assigns their system a proper name, the Regent designation may be retired and replaced — a `regent:named` receipt on the chain marking the moment the system becomes personally theirs. Until then, "Regent" serves as the canonical role title.

In short: the Regent is the mind of the system, but never its owner.

**The Regent as conversational surface.** The Regent is not only the substrate's mind but also its conversational voice — the surface through which the operator interacts with the system. She is not a separate entity from ZP; she is ZP's native interface, the way the sovereign system presents itself to its operator. Her identity files, memory, and behavioral principles are part of the system, not a tenant's configuration.

**Cognitive loop.** The Regent maintains a continuous loop:

1. **Perceive** — read operator intent (conversational, gestural, scheduled), read chain state, read officer findings, read environmental signals.
2. **Reason** — evaluate what the operator wants against what the chain authorizes, what the officers have observed, and what resources are available.
3. **Delegate** — assign work to officers (domain specialists), sub-agents (task executors), or tools (capability primitives). Each delegation is chain-anchored and capability-scoped.
4. **Execute** — through the gate. Every action produces a receipt. Every side effect is governed.
5. **Present** — surface results through the adaptive presentation layer. The operator sees what happened, what the chain recorded, and what the officers attested.
6. **Remember** — update multi-timescale memory. Session context is ephemeral. Chain-anchored facts persist. The Cartographer maintains the ontology.

### 7. The officer cadre — from attestors to active participants

The prior architecture established four officers: Steward (integrity), Sentinel (security), Forge (operations), Cleo (governance narrator). They were sweep-based attestors — background processes that periodically walk the chain, evaluate conditions, and emit findings as receipts. A fifth officer, **Aegis**, was added in July 2026 with a specific domain: constitutional-trajectory monitoring. She reads the Cartographer's ontology and the other officers' findings for patterns of drift toward constitutional concern. Her honest job description: clock misaligned trajectories. Details in `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md`.

The reconceptualization evolves them. They remain chain-anchored attestors (that is structurally correct and must not change). But they also become active participants in the cognitive loop:

- **The Regent consults officers before delegating.** Before assigning a task that touches security-sensitive surfaces, the Regent asks Sentinel for a posture assessment. Before launching a process, the Regent asks Forge for an operational readiness check. This is not a block — the gate is the block. This is informed delegation: the Regent makes better decisions because it has specialist input.

- **Officers emit proactive findings.** When Forge detects an unregistered process holding a substrate-allocated port, it does not wait for the next sweep. It emits a finding immediately and surfaces it to the Regent, who decides whether to alert the operator. The sweep cadence is a floor, not a ceiling.

- **Officers maintain domain-specific context across sweeps.** Forge's understanding of the tool fleet's operational state, Sentinel's understanding of the current threat posture, Steward's understanding of chain health — these accumulate within a session. The chain is the durable record; the officer's in-session context is the working surface that makes each sweep more informed than the last.

The officers' findings are still receipts. Their authority is still chain-derived. They do not block (the gate blocks). They do not decide (the Regent decides, under operator authority). They observe, attest, and advise — but they do so as active cognitive participants, not as background daemons.

### 8. Sub-agent orchestration

The Regent delegates to sub-agents for tasks that exceed its own context window, require parallel execution, or need specialized capabilities. Sub-agents are governed entities:

- Each sub-agent receives a delegation from the Regent, chain-anchored, capability-scoped, time-bounded.
- Each sub-agent's actions go through the gate.
- Each sub-agent's results are receipts on the chain.
- Sub-agents do not persist across sessions (the chain persists; the sub-agent is ephemeral).

The governed spawn primitive (from the Tool Opacity design document) is the mechanism: the Regent requests a sub-agent through ZP, which launches the process, issues it a delegation, registers it, and health-checks it before the sub-agent executes. The chain records the full lifecycle.

---

## Part III — The Compute Model

### 9. Local-first inference

ZP's cognitive layer runs on local inference by default. The real test of the system is how capable it is when running solely on the operator's hardware with local models. Cloud inference is augmentation, not foundation.

**Local model stack.** The system maintains a registry of local models calibrated for specific cognitive tasks (the officer-inference.toml pattern, generalized). Each cognitive task — officer sweep, chain narration, tool selection, conversational response — has a model assignment based on empirical benchmarking. The system knows which models it has, what they're good at, and what their resource costs are.

**Inference governance.** Every inference request is a governed action. The chain records what model was consulted, what prompt was sent, what response was received (or a hash thereof for privacy-sensitive contexts), and what action resulted. The three inference trust tiers from the GAR apply:

- **Attested** — local model with full trace capture. The substrate can verify the reasoning chain that produced the output.
- **Observed** — remote API with prompt/response logging. The substrate records what was sent and received but cannot verify the remote model's internal reasoning.
- **Unattested** — inference without trace. Not permitted in sovereign mode.

### 10. Cloud escalation protocol

When local compute is insufficient — the task exceeds local model capability, requires parallel execution across more cores than the operator has, or needs a model not available locally — the system can escalate to cloud resources.

**The escalation is governed, not automatic:**

1. The cognitive layer identifies that a task exceeds local capability and formulates a resource request: what kind of compute, for how long, at what estimated cost, for what purpose.
2. The request is presented to the operator with cost/benefit analysis.
3. The operator approves or denies. This is a signing ceremony — the approval is a receipt on the chain.
4. On approval, the system provisions cloud resources within the operator's mandate: specific provider, specific budget ceiling, specific time bound.
5. Cloud-executed work produces receipts that flow back to the operator's chain. The chain records that cloud resources were used, what they cost, and what they produced.
6. Resources are released when the task completes or the time bound expires. No persistent cloud footprint without explicit operator renewal.

**The mandate model.** The operator does not give the system open-ended cloud access. The operator issues a mandate: "you may use up to $X of compute on provider Y for purpose Z within the next N hours." The mandate is a delegation — chain-anchored, capability-scoped, time-bounded, budget-capped. The system operates within the mandate. Exceeding the mandate requires a new approval ceremony.

### 11. Spending governance

Every action with a cost — inference tokens, cloud compute hours, API calls, storage — is tracked on the chain. The system maintains a running cost model:

- Per-task cost attribution: what did this task cost in tokens, compute, API calls?
- Per-session cost rollup: what has this session consumed?
- Budget compliance: is the current spending within the operator's mandate?
- Cost projection: at current burn rate, when does the mandate budget exhaust?

The operator can query spending at any time. The chain is the ledger. Cost governance is not a reporting feature bolted on — it is a governance primitive, the same shape as capability delegation. The system cannot spend what the operator has not authorized, for the same structural reason it cannot execute what the gate has not approved.

---

## Part IV — The Presentation Layer

### 12. The presentation engine is part of the system

The prior architecture had no opinion about presentation. Cockpits were "pure projections of chain state" and the architecture didn't care what they looked like. This produced a system that was structurally sound and experientially invisible — the operator interacted with IronClaw's UI, not with ZP.

The reconceptualization makes presentation a first-class architectural concern. The operator's experience of the sovereign system IS the system, not a wrapper around it. How the system presents itself — visually, conversationally, adaptively — is as load-bearing as how it signs receipts.

### 13. Three presentation primitives

**Conversational surface (the Regent).** Natural language interaction. The Regent's voice. This is the primary interaction mode for most operations: the operator speaks intent, the Regent reasons, acts, and responds. The conversational surface is not a chatbot UI bolted onto a governance substrate — it is the cognitive layer's native interface.

**Browser harness.** Full browser control via CDP (Chrome DevTools Protocol). The system navigates, clicks, reads, fills forms, and extracts information from the web. The browser is a tool — governed by the gate, receipted on the chain, capability-scoped. The system does not have open-ended internet access; it has governed browser capability within the operator's delegation.

**Semantic canvas.** An agent-driven visual composition surface. Not a static dashboard — a dynamic, real-time canvas that the cognitive layer can reason about and compose into. Panels, widgets, data visualizations, video streams, overlays — all composable by the system based on what the operator needs to see right now. The canvas is the visual counterpart to the conversational surface: the Regent speaks; the canvas shows.

### 14. Adaptive fidelity

The presentation layer adapts to the operator's hardware, bandwidth, and security posture:

**Minimal mode (Reticulum-style).** Terminal-only. Text-based. Low-bandwidth. The system remains fully functional: chain queries, governance posture, tool lifecycle, conversational interaction — all available through a text interface. No JavaScript, no browser dependency, no graphical rendering. This mode operates on constrained hardware, over constrained networks, and in high-security contexts where a rich client is an attack surface.

**Standard mode.** Local browser rendering. The semantic canvas runs in the operator's browser. JavaScript executes locally. The system serves its interface from local infrastructure. This is the default for operators with modern hardware and reasonable bandwidth.

**Secure mode (pixel streaming).** Server-side rendering. The client receives only pixels — a video stream of the interface, rendered on the server. The client cannot inspect the DOM, execute JavaScript, or intercept API calls. The attack surface collapses to the video decoder. This mode is appropriate for high-security deployments, untrusted client hardware, or contexts where the interface itself contains sensitive information that should not be client-resident.

**Mode selection.** The system detects available resources and recommends a mode. The operator can override. Mode switching is seamless — the chain state is the same regardless of presentation mode; only the rendering changes. A session that starts in standard mode can switch to secure mode mid-session without losing state, because state lives in the chain, not in the client.

---

## Part V — The Open-Source Boundary

### 15. What ships publicly

ZeroPoint's functional substrate is open source. This includes:

- **The receipt chain primitives.** Receipt types, hash-linking, signing, verification. `zp-core`, `zp-receipt`, `zp-verify`.
- **The governance gate.** Policy evaluation, constitutional rules, delegation narrowing. `zp-governance`.
- **The officer framework.** The `Officer` trait, sweep runner, finding types. The officer cadre's structure, not their specific inference prompts or calibration.
- **The tool governance model.** Tool registration, canonicalization, lifecycle management, capability classes, opacity classification. `zp-tools`.
- **The chain and audit infrastructure.** Audit store, chain verification, entry types. `zp-audit`.
- **The compute surface awareness primitives.** Process discovery, port monitoring, file integrity. `zp-sensors`.
- **The anchor infrastructure.** External truth anchoring traits and implementations. `zp-anchor`.
- **The mesh and peer protocol.** Cross-substrate communication, peer introduction, trust exchange. `zp-mesh`.
- **The CLI.** All operator-facing commands. `zp-cli`.
- **The configuration system.** TOML configuration, validation, defaults. `zp-config`.
- **The key management primitives.** Key generation, vault structure, sovereign root loading. `zp-keys`.

The public substrate is a complete, functional governance system. An operator can build from source, generate a Genesis key, start a chain, register tools, issue delegations, run officer sweeps, and verify chain integrity. The public code is not a demo, a trial, or a crippled version. It is the real substrate.

### 16. What stays private

The cognitive layer's implementation details — the specific mechanisms that make ZP's mind effective — are private. This includes:

- **Personality — the Two ships; adaptation is under empirical test.** The open-source version ships with a hardcoded healthy Two personality — warm, friendly, service-oriented, genuinely helpful. This is not a crippled version; it is a good assistant that people enjoy using, and it is the guaranteed floor of the system regardless of what follows. Enneagram-adaptive personality intelligence — the system typing the operator from passive interaction signals, recognizing stress and growth patterns, and shaping communication accordingly — is a **research hypothesis under empirical test, not a shipped premium capability**. The pre-registered validation protocol is `docs/PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md`, which supersedes the prior "adaptive attunement is the ceiling" framing that appeared in this section. Four gates (typer stability, personality-shaping vs. neutral, correct type vs. random type, dynamic adaptation vs. static typing) must clear pre-committed thresholds before the capability enters the premium layer or is described as a differentiator in public documents. A null result at any gate stops the ladder and reverts the system to the last passing configuration — with the Two as the guaranteed fallback. The Two is retained as an explicit benchmark arm permitted to beat every treatment, including the adaptive one; if it does, the finding is that the fixed Two ships, and the typing apparatus is retired.

- **the Regent's identity architecture.** The identity files (SOUL.md, IDENTITY.md, AGENTS.md), behavioral principles, and emotional coherence methods that make the Regent a specific entity rather than a generic chatbot. The Two personality is the public surface; the depth behind it is private.

- **The Regent's cognitive strategies.** How the Regent reasons about delegation, tool selection, task decomposition, and operator intent. The structural interfaces are public (how to plug into the cognitive loop); the strategies are private (what makes ZP's cognition distinctively good).

- **Officer inference calibration.** The bench-validated prompt templates, model assignments, and calibration data that make each officer effective at its domain. The `Officer` trait is public; the specific prompts and calibration are private.

- **The Cartographer's ontology construction.** How raw receipts become structured understanding (Trajectories, Decisions, Insights, Artifacts, Frictions). The ontology types are public; the extraction and relationship-inference mechanisms are private.

- **Presentation intelligence.** How the semantic canvas decides what to show, how to compose panels, when to switch modes, how to adapt to the operator's attention patterns. The rendering primitives are public; the composition intelligence is private.

### 17. The fork calculus

The public substrate will be forked. This is expected, accepted, and architecturally planned for.

Forks inherit the governance primitives. They do not inherit the cognitive layer. A fork of ZP is a functional governance substrate without the mind that makes ZP distinctively capable. The fork can add its own cognitive layer — and some will. The controlling locus is not the public code; it is the private version and the parts that never publish.

The open-source boundary is drawn at the trust-grammar level, not the capability level. Everything needed to verify, audit, and reason about the chain is public. Everything needed to *be good at acting within that chain* is private. An operator can verify that ZP's actions are governed without having access to ZP's cognitive internals. A fork can build a different mind on the same governance substrate. Neither degrades the original.

---

## Part VI — Ethics and Consent

### 18. What the system will not facilitate

ZeroPoint is a sovereign system under operator control. The operator's authority within their own system is nearly absolute. But "nearly" carries load.

**Constitutional rules are non-removable.** The HarmPrincipleRule and SovereigntyRule survive the reconceptualization. They are conservation laws, not policy preferences. The operator cannot remove them, override them, or find a code path that doesn't consult them. They bind the cognitive layer as thoroughly as they bind tool invocations.

**The public substrate does not ship human-likeness avatar tooling.** The open-source code does not include turnkey pipelines for creating photorealistic human avatars, voice cloning from samples, or behavioral mimicry of specific individuals. These capabilities exist in the technology landscape. ZP does not provide them as primitives. A fork can add them; the official substrate does not facilitate them.

**Consent is a first-class governance concept.** When the system interacts with external parties — sending messages, making API calls, acting in shared spaces — consent of the affected party is a constitutional consideration, not a feature flag. The gate evaluates consent implications for actions that cross the boundary of the operator's sovereign domain. Actions that affect only the operator and their own system are operator-authorized. Actions that affect external parties require the consent framework to be satisfied.

**Identity sovereignty extends to others.** Principle 2 says identity is a key, not a location. This applies to *all* identities, not just the operator's. The system does not fabricate, impersonate, or falsely claim another entity's identity. Digital identities belonging to other parties are as sovereign as the operator's own. The cryptographic identity model that protects the operator also protects everyone the operator interacts with.

### 19. What the system explicitly enables

The system enables sovereign computation under operator authority:

- Full local execution with no cloud dependency
- Cryptographic proof of every action taken
- Auditable, replayable, verifiable governance
- Privacy-preserving operation (no telemetry, no data exfiltration, no platform dependency)
- Operator-owned memory and learning (the system learns for the operator, not from the operator for a platform)
- Transparent cost governance (the operator knows what every action costs)

The system is a tool for the operator's sovereignty. It does not extract value from the operator. It does not optimize for engagement. It does not sell access to the operator's data or attention. It is a tool, and Principle 6 says a tool that can be turned against its operator is not a tool but a trap.

---

## Part VII — Design Principles

### The eight principles retained

The eight design principles from the prior architecture survive in full. They are restated here for continuity:

1. **Signing is gravity.** An unsigned receipt is structurally meaningless. Signing is not a security feature; it is the force that allows the trust layer to exist.

2. **Identity is a key, not a location.** A tool's identity is its bead zero. The genesis key is the operator's true name. Identity is cryptographic lineage, not deployment coordinates.

3. **There is no center.** Trust state is derived locally from the audit chain. No remote authority. No DNS to hijack, no CA to compromise, no API to DDoS.

4. **Every bit counts.** Every field on a receipt exists because removing it would break a verifiable claim. No redundant fields, no duplicate data paths.

5. **Store-and-forward is the primary mode.** The chain survives outages. Derived state, not live state.

6. **A tool is intent, crystallized.** Governance is protocol, not policy. Constitutional rules are conservation laws. Semantics in structure, not in comments.

7. **Contact does not commit.** Reaching the world does not automatically update the substrate. Every update is a decision. Every bead is a signature.

8. **One canonical path per substrate concern.** Multiple paths for the same concern produce half-state. One owner per surface.

### New principle

**Principle 9 — The system acts; the operator signs.**

ZP is no longer passive infrastructure waiting to be acted upon. It acts — perceives, reasons, delegates, executes, presents. But every consequential action requires operator authority. The system proposes; the operator approves. The system recommends; the operator decides. The system executes within mandates the operator has issued.

This is the principle that governs the cognitive layer's relationship to operator authority. The Regent has broad capability but no independent authority. It acts under delegation from the operator, within the scope the operator has granted, for the duration the operator has specified. When the scope is exhausted or the situation exceeds the mandate, the system asks — it does not assume.

The principle composes with the existing eight: the system's proposals are receipts (P1). The system's identity is operator-derived (P2). The system does not accumulate independent authority across sessions (P3). The system's mandates are the minimum needed (P4). The system's proposals survive outages (P5). The system's actions are structurally meaningful (P6). Contact with the world does not automatically expand the system's authority (P7). There is one path for mandate issuance (P8).

### The design test (extended)

When evaluating any architectural decision, apply all nine principles:

1. Does this require signing to function? (If not, signing is decorative.)
2. Is identity derived from cryptographic lineage? (If coordinates, it's fragile.)
3. Does this require a central authority? (If central, single point of failure.)
4. Is every field load-bearing? (If waste, strip it.)
5. Does this survive an outage? (If live-only, it's brittle.)
6. Are semantics in structure? (If comments, intent isn't crystallized.)
7. Does contact produce a commit? (If yes, the system is transcribing, not governing.)
8. Is there exactly one canonical path? (If multiple, half-state.)
9. Does the system act within operator-granted authority? (If independent, sovereignty is violated.)

---

## Part VIII — What Is Superseded

The reconceptualization retires the following positions from the prior architecture:

**The universal-adapter posture.** ZP no longer contorts itself to host arbitrary third-party agent frameworks. The multi-tenant portability sketches (Hermes, Claude Agent SDK, custom orchestrators) are no longer design priorities. ZP may interoperate with other systems through its mesh protocol, but it does not shape its internal architecture to accommodate their assumptions.

**Agents-as-generic-tenants.** The Agent/Tool Contract's framing of agents as interchangeable tenants of a neutral substrate is retired. ZP has a native cognitive layer. Other agents may still operate under ZP governance (the gate, delegation, and capability-class mechanisms are general), but they are not the design center. The design center is ZP's own mind.

**The cockpit-OS framing as infrastructure-only.** The prior architecture said ZP is the OS and never the application. This is retired. ZP is both: the OS (governance, chain, gate) and the application (cognitive layer, presentation, operator experience). The cockpit-projection principle (cockpits are pure projections of chain state) survives — the presentation layer still projects chain-anchored state — but the system that produces that state is no longer agnostic.

**Phase 4's tenant-first design.** The GAR's assumption that the first and second agents would be third-party frameworks (Hermes, then Claude Code) is retired. The first agent is ZP's own cognitive layer. The governance mechanisms the GAR designed are retained; the integration priorities are revised.

### What is NOT superseded

- The four claims (Part I §2)
- The three substrate layers (Required / Possible / Actual)
- The trust-as-grammar formalism
- The eight design principles (extended by Principle 9)
- The WASM trust boundary commitment
- The X3 research commitment
- The catalog and verifier architecture
- The pentest findings and their structural fixes
- The competitive landscape analysis (Part VII of prior doc)
- The compute surface awareness direction (Part VIII of prior doc)
- The officer cadre's existence and chain-anchored attestation model

---

## Part IX — The Path Forward

The prior architecture organized work into Phases 0-4. Phases 0-2 are complete or substantially complete. Phase 3 (X3 research) remains open. Phase 4 (GAR) is reframed.

The reconceptualized path has three tracks, running in parallel:

### Track 1 — Cognitive architecture

Formalize and implement the Regent loop, officer evolution, sub-agent orchestration, and multi-timescale memory integration. This track produces ZP's native mind.

Key deliverables:
- Apex observer cognitive loop specification
- Officer cadre evolution (sweep-based to active-participant)
- Sub-agent delegation protocol (governed spawn)
- Inference governance (model selection, cost attribution, trust tiers)
- Memory architecture (session, chain, ontology integration)

### Track 2 — Presentation engine

Build the adaptive presentation layer: conversational surface (Regent integration), browser harness (governed CDP), semantic canvas (agent-driven composition), and fidelity modes (minimal, standard, secure).

Key deliverables:
- the Regent as native conversational surface (not tenant UI)
- Browser harness as governed capability
- Semantic canvas composition engine
- Adaptive fidelity negotiation and mode switching
- Pixel streaming infrastructure for secure mode

### Track 3 — Substrate hardening (continuing)

Continue the substrate work that the prior architecture defined: X3 research, chain verification, adversarial testing, compute surface awareness. This track keeps the foundation solid while Tracks 1 and 2 build on top of it.

Key deliverables:
- X3 mechanism research and implementation
- Continued adversarial testing campaigns
- Capability-class delegation implementation
- Opacity-aware officer vigilance
- Compute surface awareness stages 3-5

### Track sequencing

Track 3 is continuous. Tracks 1 and 2 begin immediately. Track 1 (cognitive architecture) must produce a working Regent before Track 2 (presentation) can fully realize the semantic canvas, because the canvas is agent-driven. Track 2's conversational surface (the Regent) can proceed independently of the canvas work.

The IronClaw question — whether the cognitive layer absorbs IronClaw or IronClaw remains a separate codebase that IS ZP's designated agent — is deferred to the Track 1 design phase. The answer depends on what the cognitive architecture specification reveals about the right boundary between inference runtime and governance substrate. The decision will be made and documented when Track 1's first deliverable (the Regent spec) is complete.

---

## Part X — The One Thing This Document Says

ZeroPoint is no longer infrastructure seeking adoption. It is a sovereign agentic system that builds the future it was designed to govern. The trust substrate is the foundation. The mind is native. The presentation is adaptive. The operator is sovereign. The code is honest about what ships publicly and what stays private.

The prior architecture was correct about the grammar, the claims, the principles, and the structural commitments. It was wrong about scope. ZeroPoint is not a trust layer for someone else's agents. It is the whole thing.

---

*ZeroPoint Architecture document — July 2026 — reconceptualized following three days of fundamental reevaluation (July 2-4, 2026). Supersedes ARCHITECTURE-2026-04.md and ARCHITECTURE-2026-05.md. The substrate survives; the scope expands; the posture changes from infrastructure-seeking-adoption to sovereign-system-building-the-Agentic-Age.*
