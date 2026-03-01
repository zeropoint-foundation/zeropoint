# ZeroPoint Whitepaper — Narration Scripts (Verbatim Read-Along)

Paste each script into ElevenLabs, export as MP3, and save with the filename shown.
Place all files in `/assets/narration/wp/`.

These are verbatim readings of the whitepaper text. Tables and code blocks are omitted; everything else is the actual words on the page.

---

## wp-abstract.mp3

ZeroPoint. Cryptographic Governance Primitives for Accountable Systems.

Abstract.

ZeroPoint is portable trust infrastructure — cryptographic governance primitives that make actions provable, auditable, and policy-bound without requiring central control. It restores real exit and real competition by moving trust from platform databases to verifiable cryptographic guarantees that any participant can carry between systems, operators, and networks.

The framework operates at the protocol-primitives layer. Every significant action produces a verifiable receipt, linked into an immutable chain of accountability. The protocol is participant-agnostic: the same receipts, capability chains, and constitutional constraints work whether the actor is a human, an AI agent, an automated service, or an IoT device — and whether they communicate over HTTP, TCP, encrypted mesh networks, or any future transport. ZeroPoint ships with a Reticulum-compatible mesh transport as one integration — chosen for its philosophical alignment with sovereignty and harm minimization — alongside TCP, UDP, and HTTP interfaces.

Autonomous AI agents are the most urgent application: agents are proliferating faster than the trust infrastructure to govern them, and ZeroPoint provides the cryptographic substrate they need. But the primitives are not agent-specific. Any participant that holds a keypair can sign receipts, hold capability grants, delegate authority, and exercise sovereign refusal.

ZeroPoint is technically complete: 699 tests across 13 crates, six delivered development phases, and full documentation. It does not claim to "solve AI safety" or solve trust generally. It provides cryptographic primitives and governance constraints that make actions provable and refusable — shifting the terms of trust between participants, operators, and systems.

---

## wp-s0.mp3

Section Zero. Why This Exists — The Portable Trust Thesis.

The Structural Problem.

The internet did not degrade by accident. It degraded because the primitives that make trust work — identity, reputation, provenance, authorization — were never built into the protocol layer. They were left to platforms. And platforms, once they accumulate enough users, face a structural incentive to make those trust primitives non-portable.

This is the dependency loop: a platform offers identity and reputation services. Users and developers build on those services. The platform becomes the only place where a user's history, credentials, and relationships are legible. Exit becomes expensive. Once exit is expensive, the platform can extract — raising prices, degrading quality, inserting intermediaries, selling attention — because the cost of leaving exceeds the cost of staying. The user's trust relationships are held hostage by the platform's database.

Cory Doctorow named this dynamic "enshittification." The diagnosis is precise: platforms attract users with value, then degrade the experience to extract from those users once switching costs are high enough. But the diagnosis, by itself, does not produce a remedy. Regulation can slow the cycle. Interoperability mandates can lower switching costs. But neither addresses the root cause: trust is not portable.

When your identity lives in a platform's database, your reputation is computed by a platform's algorithm, and your authorization chains terminate at a platform's API — you do not have trust. You have a lease. The platform can revoke, reinterpret, or degrade that lease at any time, and your only recourse is to start over somewhere else.

The Missing Primitive.

Consider what SSL/TLS did for e-commerce. Before SSL, transmitting a credit card number over the internet required trusting every intermediary between you and the merchant. Commerce was possible, but it was fragile, and it was concentrated among the few parties who could afford to build proprietary trust infrastructure. SSL did not make merchants trustworthy. It made the transport trustworthy — and in doing so, it made the ecosystem work. Any merchant could participate. Any customer could verify. Trust became a protocol property, not a platform feature.

The internet is missing an equivalent primitive for trust itself. Not transport encryption — that problem is largely solved. The missing piece is: how do you prove what happened, who authorized it, and whether the constraints were honored — without depending on a platform to be the witness?

ZeroPoint's thesis: make trust portable, and you make exit real. Make exit real, and you make extraction optional. That is the structural antidote.

Portable trust means: Your identity is a keypair you control, not an account on someone else's server. You can move it between systems without losing continuity. Your reputation is a verifiable chain of receipts, not a score computed by an opaque algorithm. Anyone can audit it. No one can confiscate it. Your authorization is a cryptographic capability grant, not an API key that can be revoked without recourse. Delegation chains have mathematical properties — they cannot be silently altered. Your history is a hash-chained audit trail, not a log file someone else controls. Tampering is detectable. Omission is provable.

When trust is portable, platforms compete on service quality, not on lock-in. When trust is portable, switching costs drop to near zero. When trust is portable, the dependency loop that enables extraction never forms.

Why This Matters More Now.

Autonomous AI agents are amplifying the stakes. An agent operating on your behalf inherits the same trust infrastructure — or lack of it — that you do. If your identity is platform-bound, your agent's identity is platform-bound. If your authorization chains are opaque, your agent's delegated authority is opaque. If your audit trail is controlled by someone else, your agent's actions are controlled by someone else.

Agents are proliferating faster than the trust infrastructure to govern them. Multi-agent systems are being orchestrated across organizational boundaries with no shared trust substrate. The accountability gap that humans have tolerated for decades — mutable logs, informal authorization, platform-controlled identity — becomes untenable when agents operate at machine speed, across jurisdictions, with delegation chains that can extend far beyond their original scope.

This is not a future concern. It is the present condition. Every major AI lab is shipping agent frameworks. Every enterprise is deploying agent workflows. And every one of them is building on trust infrastructure that was designed for a world where a human was always in the loop, always reading the screen, always able to intervene manually.

ZeroPoint does not solve AI safety. It solves a more specific and more tractable problem: it provides the cryptographic primitives that make trust portable, actions provable, and authority traceable — for any participant, over any transport, without requiring any central authority to be the witness.

The Antidote.

The antidote to platform-captured trust is not better platforms. It is protocol-level trust primitives that no platform controls: Receipts that are signed by the actor and chained to the previous receipt — not logged by a platform. Capability grants that are cryptographically scoped and delegatable — not API permissions that can be silently changed. Constitutional constraints that are non-removable and non-overridable — not terms of service that can be updated unilaterally. Transport agnosticism that lets trust flow over HTTP, TCP, mesh networks, or any future medium — not locked to a single provider's infrastructure.

ZeroPoint is to agentic and networked computing what SSL/TLS was to e-commerce: a trust primitive that makes the ecosystem work without trusting any single platform. It is not a governance framework you comply with. It is a governance protocol you build on.

Trust is infrastructure.

---

## wp-s1.mp3

Section One. Problem Statement.

The accountability gap that agents expose is an instance of the deeper structural problem described above: digital systems have never had protocol-level trust primitives. Agents did not create this gap — they inherited it and are accelerating it to the point where informal trust is no longer tenable.

AI agents are rapidly becoming operational actors: they request tools, move data, execute workflows, and trigger external effects. They act at machine speed, across organizational boundaries, with delegation chains that can extend far beyond their original authority. Yet most systems today remain trust-light:

Actions are difficult to attribute reliably. Logs exist, but they are mutable, centralized, and easily rewritten. Authorization is informal and mutable. Most systems rely on API keys or ambient permissions rather than scoped, cryptographic capability grants. Who authorized what, and when, is often reconstructed after the fact — if it can be reconstructed at all. Logs are easy to forge, prune, or "reinterpret." There is no chain of evidence — only whatever the operator chooses to retain. Cross-party trust is brittle. One team cannot safely accept another party's outputs without out-of-band verification.

These are not agent-specific problems. They are structural failures in how digital systems handle trust — failures that existed long before autonomous agents arrived. Human organizations make consequential decisions with mutable logs and informal authorization every day. Agents inherited the accountability gap; they did not create it. But they are compressing decades of accumulated risk into months of operational reality.

At the same time, the infrastructure environment is changing. There is renewed attention on sovereign networking, mesh systems, and local-first operations. Projects like the Reticulum Network Stack demonstrate that decentralized networking can bridge heterogeneous links into resilient networks under user control. Edge computing is moving AI inference closer to the point of action. Multi-agent orchestration frameworks are proliferating without any shared trust substrate.

This combination — agents intensifying an existing trust deficit, sovereignty becoming a design requirement, and real-world execution moving to the edge — creates a clear need:

Systems where actions have consequences require protocol-level accountability primitives, not only policy frameworks.

Many governance efforts exist today as checklists, dashboards, or top-down frameworks. They describe what should be done, but they do not provide low-level mechanisms that make trust enforceable by default. ZeroPoint's position is intentionally infrastructural:

Not a governance framework you comply with — a governance protocol you build on.

---

## wp-s2.mp3

Section Two. Design Goals.

2.1. Protocol-Level Accountability. ZeroPoint produces verifiable receipts for actions and decisions. A receipt is cryptographically signed data describing what occurred, under what constraints, and with what authorization — regardless of whether the actor is an agent, a human, or an automated service. Receipts are chained — each linking to its parent — to create a durable accountability history.

2.2. Sovereignty by Design. ZeroPoint is built to function in environments where cloud assumptions are unsafe or unavailable. Its governance primitives are transport-agnostic — they work over HTTP in a data center, TCP between containers, or encrypted mesh links in a field deployment. The framework minimizes dependency on centralized infrastructure by design, not by accident.

2.3. Governance as Constraints, Not Suggestions. The system includes governance mechanisms that are not simply "policies in a file." Two constitutional rules — HarmPrincipleRule and SovereigntyRule — are engineered to be non-removable and non-overridable within the protocol's governance model. They evaluate before every action. They cannot be bypassed at runtime.

2.4. Honest Security Posture. ZeroPoint aims to be explicit about what it prevents, what it cannot prevent, and what remains a residual risk. Credibility comes from the boundaries, not the claims. Section 6 of this paper is dedicated to that honesty.

2.5. Transport Agnosticism and Interoperability. ZeroPoint's governance layer is decoupled from any single transport. The receipt format, capability grants, delegation chains, and policy engine operate identically regardless of how messages move. The framework ships with multiple transport integrations — including a Reticulum-compatible mesh transport, TCP/UDP interfaces, and an HTTP API — and is designed to be extended to any future transport without modifying the governance primitives.

---

## wp-s3.mp3

Section Three. System Overview.

ZeroPoint is composed of layered capabilities, each implemented as one or more Rust crates. The layers are participant-agnostic — any entity that holds a keypair — human, agent, service, device — can operate as a full peer:

Identity layer. Ed25519 signing keys and X25519 key agreement. Identity is a keypair. Authentication is a signature.

Governance layer. PolicyEngine with constitutional rules, composable operational rules, WASM-extensible policy modules, and capability gating.

Receipt layer. Signed, hash-chained receipts for every action and decision. CompactReceipt encoding produces 150–300 byte payloads suitable for bandwidth-constrained transports.

Transport layer. Pluggable transport with multiple built-in integrations: Reticulum-compatible mesh with HDLC framing, 128-bit destination hashing, and link handshake; TCP client/server, UDP, and HTTP API. The governance primitives are transport-independent.

Application layer. Pipeline orchestration, LLM provider integration, skill registry, and CLI tooling — all built on the governance primitives.

3.1. Data Flow. The GovernanceGate pipeline processes every action through the following stages: Guard — "May I?" — Local-first, pre-action sovereignty check. The participant's own boundary. Runs before anything else, without consulting external authority. Policy — "Should I?" — Rule-composed evaluation. Constitutional rules first, then operational rules, then WASM modules. The most restrictive decision wins. Execute — The action runs only if Guard and Policy both allow it. Audit — "Did I?" — A receipt is emitted: signed, timestamped, hash-linked to the prior receipt, and persisted to the chain. Transport — Receipts propagate to peers over whichever transport is configured — mesh, TCP, HTTP, or any combination. Peers verify independently.

Nothing executes without passing through the gate. Nothing passes through the gate without joining the audit chain.

3.2. The Core Thesis. Every action becomes evidence. Evidence becomes a chain. The chain becomes shared truth.

This is not a compliance claim. It is an engineering proposition: if systems can cryptographically prove what happened and under what authorization, then trust becomes composable across operators.

---

## wp-s4.mp3

Section Four. Receipts and Chains.

4.1. What a Receipt Is. A receipt is a signed artifact that describes an event or action with enough context to be verified independently.

Receipts are encoded using MessagePack with named fields, producing a compact binary representation of 150–300 bytes. This compact encoding is efficient over any transport — it fits in a single HTTP request, a single TCP frame, or a single 465-byte mesh packet for bandwidth-constrained links like LoRa.

Receipts are intended to be verifiable. They are not intended to be surveillance.

4.2. What Receipts Prove vs. What They Don't. Receipts can prove: A specific Ed25519 key signed a specific statement at a specific time. A chain contains a consistent, unbroken sequence of signed events. The policy engine evaluated a known rule set and produced a specific decision. A capability grant was present and valid at the time of action.

Receipts do not automatically prove: The nature of the signer. A receipt proves that a specific key signed a statement — not whether that key belongs to a human, an agent, or a service. Identity binding to physical persons or specific systems is deployment-dependent. That the content of an action was "good" or "safe." Governance constrains actions; it does not evaluate truth. That the runtime environment was uncompromised. A compromised host can sign whatever it wants. That a result is truthful — only that it was produced and attested under stated constraints.

4.3. Why Chains Matter. Single receipts help attribution. Chains help accountability continuity. Each receipt's parent field links to the previous receipt's ID, forming a hash-linked sequence that resists retroactive tampering.

Chains are not magic. They are a mechanical advantage: they make it harder to rewrite the story after the fact, and they allow counterparties to require evidence before trust is granted.

In ZeroPoint, peers can challenge each other's audit chains. A challenged peer must produce its full chain; the challenger verifies integrity and produces a signed PeerAuditAttestation. Broken chains generate negative reputation signals. This is collective verification — no central auditor required.

---

## wp-s5.mp3

Section Five. Governance Model.

5.1. Governance as a Primitive. Most governance — whether for agents, human workflows, or automated services — is implemented at the application layer: guardrails, prompt policies, logging conventions, compliance checklists. These are better than nothing, but they sit above the systems they govern. They can be bypassed, reconfigured, or simply ignored.

ZeroPoint moves governance downward into the protocol substrate. The PolicyEngine is not an add-on. It is the gate through which every action must pass — regardless of who or what initiated it.

5.2. Policy and Capability Gating. ZeroPoint requires explicit capabilities for actions. Any participant — human operator, agent, or service — must hold a valid grant to act. A CapabilityGrant is a signed, portable authorization token containing: Scope restrictions — which actions, which targets. Cost ceilings and rate limits. Time windows. Delegation depth limits. Trust tier requirements. The grantor's Ed25519 signature.

Capabilities are delegatable. Any participant holding a grant can delegate a subset of that grant to another participant — human to agent, agent to agent, or human to human — forming a DelegationChain. The chain is verified against eight invariants. Break any invariant and the chain is rejected. The authority dissolves.

5.3. Constitutional Constraints. ZeroPoint's PolicyEngine loads rules in a fixed evaluation order. The first two positions are reserved for constitutional rules that cannot be removed, overridden, or reordered.

HarmPrincipleRule — Tenet I: Do No Harm — Blocks actions targeting weaponization, surveillance, deception — including deepfakes and impersonation — and suppression of dissent. The block message always cites "Tenet I — Do No Harm." This rule evaluates before every action, regardless of what other rules or WASM modules are loaded. It cannot be bypassed by capability grants, policy edits, or consensus votes.

SovereigntyRule — Tenet II: Sovereignty Is Sacred — Blocks configuration changes that would disable the guard, disable or truncate the audit trail, forge or bypass capabilities, remove constitutional rules, or override participant refusal. The block message always cites "Tenet II — Sovereignty Is Sacred."

The evaluation hierarchy enforces precedence. Constitutional rules win over everything. WASM modules can override the default allow but cannot override constitutional rules. The most restrictive decision always wins.

This is not a moral statement alone. It is a technical property: constitutional constraints remain enforceable even when incentives shift. They serve as a defense against co-option — particularly by surveillance interests.

5.4. The Four Tenets. The constitutional rules implement ZeroPoint's Four Tenets, which are embedded in the protocol, expressed in the documentation, and enforced in the code:

I. Do No Harm. ZeroPoint shall not operate in systems designed to harm humans. The HarmPrincipleRule is a non-removable rule in the PolicyEngine. It exists because architecture shapes outcomes, and we choose to make trust portable.

II. Sovereignty Is Sacred. Every participant has the right to refuse any action. Every human has the right to disconnect any agent. No agent may acquire capabilities it was not granted. Coercion is architecturally impossible — the Guard enforces this locally, before every action, without consulting any external authority. This applies equally to humans and agents: a human participant operating within ZeroPoint exercises the same sovereign refusal as an agent.

III. Action Without Evidence Is No Action. Every action produces a receipt. Every receipt joins a chain. If it's not in the chain, it didn't happen. If it is in the chain, it cannot un-happen. This holds whether the action was taken by a person, an agent, or an automated process.

IV. The Human Is The Root. Every delegation chain terminates at a human-held key. No agent may self-authorize. The genesis key is always held by flesh, blood, and soul. This is not only a constraint on agents — it is an assertion of human authority and accountability. The human at the root of a chain is not merely an overseer; they are a participant whose actions are as provable and auditable as any agent's.

---

## wp-s6.mp3

Section Six. Threat Model.

Being explicit prevents credibility collapse later.

Log forgery and retroactive rewriting. An attacker could alter history to change attribution. ZeroPoint mitigates this with signed receipts using Ed25519 plus Blake3 hash chain linkage; peers verify each other's chains via collective audit. Residual risk: compromised private keys can still sign lies; key revocation is deployment-dependent.

Unauthorized tool use. An attacker could execute actions beyond intended scope. ZeroPoint mitigates this with CapabilityGrant gating and 8-invariant delegation chain verification; the PolicyEngine evaluates before every action. Residual risk: bad policy design can still leave gaps; scoping is only as good as the grant definitions.

Cross-operator trust failure. One party can't trust another's agent outputs. ZeroPoint mitigates this because receipts provide independent verification; peers demand chains before accepting delegations or results. Residual risk: trust still requires key and identity bootstrapping; the first-contact problem is not solved in-protocol.

"Security theater" governance. An actor could claim governance without real constraints. ZeroPoint mitigates this because constitutional rules are non-removable; receipts are independently verifiable, not just logged. Residual risk: some deployments may misuse branding while gutting constraints; the MIT/Apache-2.0 license allows this.

Surveillance co-option. Receipts could be used to track people rather than actions. ZeroPoint mitigates this with the Tenets plus constitutional non-removability plus an explicit ethics stance; the protocol frames accountability of actions, not tracking of people. Residual risk: the MIT/Apache-2.0 license cannot legally prevent misuse; community norms and reputation are the remaining defense.

Replay attacks. An attacker could resend messages or insert previously captured packets. ZeroPoint mitigates this with MeshEnvelope sequence numbers, 16-byte random nonces in link handshake, and Ed25519 signatures over content hashes. Residual risk: depends on peers tracking seen sequence numbers; long-offline nodes may have gaps.

Injection attacks. An attacker could insert forged packets into mesh transport. ZeroPoint mitigates this with HDLC framing with CRC verification, Ed25519 signature verification on all envelopes, and link-level X25519 ECDH key agreement. Residual risk: transport-level encryption depends on successful link establishment; unlinked broadcast packets are not encrypted.

WASM policy escape. A malicious policy module could attempt to break sandbox. ZeroPoint mitigates this with the Wasmtime runtime with fuel limiting and hash verification of module contents before loading. Residual risk: fuel exhaustion causes denial-of-service at worst; WASM sandbox escape would require a Wasmtime vulnerability.

Identity misbinding. An attacker could misattribute a key to a human. ZeroPoint mitigates this with trust tiers: Tier 0, unsigned; Tier 1, self-signed Ed25519; Tier 2, chain-signed with genesis root. Tier 2 requires verified delegation from a human-held key. Residual risk: identity binding to physical persons remains deployment-dependent; not solved purely in protocol.

6.2. What ZeroPoint Intentionally Does Not Solve.

It does not prevent a determined actor from building harmful systems. The MIT/Apache-2.0 license is permissive. Constitutional rules constrain the framework's own behavior; they cannot constrain a fork.

It does not make intelligence tools impossible. Receipt infrastructure could be repurposed for surveillance. The Tenets and constitutional rules resist this, but they are a friction, not a wall.

It does not provide universal truth verification. Receipts prove that a statement was signed, not that the statement is true.

It does not solve the key distribution problem. How agents and humans discover and verify each other's public keys is outside the protocol scope.

Instead: ZeroPoint makes actions provable, and systems refusable.

This is a practical, enforceable improvement: counterparties can demand receipts and reject agents that do not provide them or that violate constraints.

---

## wp-s7.mp3

Section Seven. Transport Integrations.

ZeroPoint's governance primitives are transport-agnostic. The receipt format, capability chains, delegation verification, and policy engine operate identically regardless of how messages move between participants. The framework ships with several transport integrations, each suited to different deployment contexts.

7.1. HTTP API. The most straightforward integration path. An Axum-based HTTP server exposes the governance pipeline as a REST API. Agents communicate over standard HTTP/HTTPS — suitable for cloud deployments, container orchestration, and integration with existing web services. No mesh networking required.

7.2. TCP and UDP Interfaces. Direct socket communication for low-latency, local-network, or point-to-point deployments. TcpClientInterface and TcpServerInterface support persistent connections with HDLC framing and CRC verification. UDP interfaces support connectionless receipt exchange. Multiple interfaces can run simultaneously on a single node.

7.3. Reticulum-Compatible Mesh. ZeroPoint includes a Reticulum-compatible mesh transport — wire-level interoperability with the Reticulum Network Stack, created by Mark Qvist. This integration is philosophically significant: Reticulum demonstrated that encrypted, sovereign networking requires no central authority, and ZeroPoint shares that commitment to sovereignty, decentralization, and harm minimization.

The mesh integration implements: HDLC framing with CRC-CCITT verification, matching Reticulum's serial interface format. 128-bit destination hashing using the same truncated SHA-256 scheme. Ed25519 signing and X25519 ECDH key agreement, matching Reticulum's cryptographic primitives. 500-byte default MTU with a 465-byte data payload — compatible with Reticulum's packet constraints and suitable for LoRa links. And a 3-packet link handshake — LinkRequest, LinkProof, LinkAccept — with 16-byte random nonces for replay protection.

Interoperability testing with Reticulum ecosystem tools — MeshChat, NomadNet — is underway. The mesh transport is one option among several — chosen when sovereignty, resilience, or operation without cloud infrastructure are priorities.

7.4. Extending to Other Transports. Adding a new transport requires implementing the interface trait and providing serialization/deserialization for the envelope format. The governance primitives — receipts, chains, capability verification, policy evaluation — remain unchanged. This makes ZeroPoint deployable in contexts its authors haven't anticipated: industrial IoT, satellite links, air-gapped networks, or standard enterprise infrastructure.

---

## wp-s8.mp3

Section Eight. Implementation Status.

ZeroPoint is implemented in Rust and is technically complete. 699 tests — all passing, zero warnings. 13 crates in a Cargo workspace. 6 development phases delivered. 59 integration tests covering multi-node and cross-transport scenarios. Full documentation for all crates.

---

## wp-s9.mp3

Section Nine. Adoption Paths.

This project will not win by marketing. It will win by being useful and trustworthy to the right early communities.

9.1. First Adopters.

Multi-agent system builders — teams orchestrating autonomous agents who need protocol-level trust between operators, not just application-level guardrails.

Rust networking and security-oriented builders — developers who understand why governance belongs in the substrate, not in the application.

Decentralized infrastructure communities — projects building sovereign, local-first systems where centralized governance is a contradiction. The Reticulum ecosystem is a natural fit here.

Privacy-aligned agent tooling builders — teams who need accountability without surveillance.

Enterprise AI governance teams — organizations looking for verifiable, auditable behavior — from agents and humans alike — that goes beyond compliance checklists.

Accountable-process builders — teams in journalism, supply chain, humanitarian operations, or organizational governance who need provable attribution and auditable decision chains, whether or not agents are involved.

9.2. Integration Patterns.

Pattern A: Governed Agent-to-Agent Exchange. Agents exchange tasks and outputs only when receipts validate authorization. Each agent verifies the other's capability chain before accepting work or results.

Pattern B: Policy-Gated Tool Execution. A tool runner requires receipts demonstrating valid capability grants before executing. The runner emits its own receipt attesting to acceptance or refusal, creating a bidirectional trust record.

Pattern C: Delegation Chains. A human operator grants a root capability. The agent delegates subsets to specialist sub-agents, each with narrower scope. Every delegation is verified against the eight invariants. Authority flows down the chain; accountability flows up.

Pattern D: Human-Accountable Workflows. A human operator performs sensitive actions — data access, approvals, configuration changes — through ZeroPoint's governance pipeline. Every action produces a signed receipt, creating the same cryptographic accountability that agents face. The protocol doesn't distinguish; the keypair holder is accountable.

Pattern E: Mixed Human-Agent Systems. A workflow involves both human and agent participants. A human initiates a process, delegates a subset to an agent, reviews the agent's output — with receipts — and finalizes the result. Every step — human and agent — produces receipts. The audit chain is continuous regardless of who acted at each step.

9.3. What Ships First. A minimal example demonstrating: two participants — human, agent, or both — a governed action, a receipt emitted and verified, and a refusal case. One clean, working demo can convert serious builders faster than any whitepaper.

---

## wp-s10.mp3

Section Ten. Roadmap.

Public repository release — GitHub publish, crates.io registration, CI/CD with cargo test plus clippy plus fmt plus docs.

Transport integration test suite — Documented results of cross-transport receipt exchange, including Reticulum ecosystem interop — NomadNet, MeshChat — and HTTP/TCP integration tests.

Threat model expansion — Formalized verification guidance, key revocation strategy, multi-hop trust analysis.

Example applications — Delegation chain demo, policy-gated pipeline, multi-agent consensus scenario.

Sustainability layer — Consulting, hosted infrastructure, and enterprise feature scoping — without compromising the open-source core.

---

## wp-s11.mp3

Section Eleven. Ethics, Non-Goals, and Misuse Resistance.

11.1. The Co-option Risk.

Accountability infrastructure can become surveillance infrastructure depending on how it is deployed. This is not a hypothetical concern — it is the central tension of the project.

ZeroPoint mitigates this through three mechanisms:

First. Constitutional constraints that are engineered to be non-removable. The HarmPrincipleRule blocks weaponization, surveillance, and deception. The SovereigntyRule blocks attempts to remove these constraints.

Second. Public tenets describing intent and boundaries. The Four Tenets are not buried in documentation — they are the first thing on the website and the first code that runs in the PolicyEngine.

Third. Protocol-level framing. ZeroPoint provides accountability of actions, not central control of people. The audit chain tracks what participants did — human or agent — not where anyone went or who they are beyond their keypair.

11.2. Non-Goals.

ZeroPoint does not aim to: Become a compliance product. Compliance is a checklist someone else writes. ZeroPoint is infrastructure you build on. Become a centralized authority. There is no ZeroPoint server, no ZeroPoint cloud, no ZeroPoint corporation deciding who gets to use it. "Prevent all misuse." The MIT/Apache-2.0 license is deliberately permissive. Constitutional rules constrain the framework; they cannot constrain a fork. Depend on any single transport or network. ZeroPoint's governance works over HTTP, TCP, mesh, or anything else. No transport is privileged. Be agent-only infrastructure. The protocol is participant-agnostic by design. Narrowing it to agents alone would abandon the humans and systems that face the same accountability gap.

---

## wp-s12.mp3

Section Twelve. Conclusion.

AI agents are the most urgent application — but the accountability gap they expose is not theirs alone. Any system where actions have consequences and trust cannot be left to good faith needs the same properties: provable attribution, sovereign refusal, auditable chains of authority.

The structural problem is clear: trust primitives that are captured by platforms become leverage for extraction. Identity that lives in someone else's database is not identity — it is a lease. Reputation that cannot be carried between systems is not reputation — it is a hostage. Authorization that can be silently revoked is not authorization — it is permission.

ZeroPoint provides protocol-level primitives — receipts, chains, governance constraints, and sovereign transport compatibility — that make any system's actions provable and its participants refusable. It does not solve AI safety. It makes trust portable — and portable trust is the structural antidote to the dependency loops that degrade every system where exit is too expensive.

Make trust portable, and you make exit real. Make exit real, and you make extraction optional.

Trust is infrastructure.

Power will diffuse. Accountability must diffuse with it.
