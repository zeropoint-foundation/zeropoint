#!/usr/bin/env bash
#
# generate-audio.sh — Produce all whitepaper narration via Piper TTS
# Total: 133 paragraphs across 15 sections
# Usage: cd ~/projects/zeropoint && bash generate-audio.sh
#
# Options:
#   SKIP_EXISTING=1 bash generate-audio.sh  — skip existing files
#   SECTION=s8 bash generate-audio.sh        — only generate one section
#
PIPER="/Users/kenrom/anaconda3/bin/piper"
MODEL_DIR="/Users/kenrom/projects/zeropoint/models/piper"
AUDIO_DIR="zeropoint.global/assets/narration/wp"
SKIP_EXISTING="${SKIP_EXISTING:-0}"
SECTION="${SECTION:-}"

# Preferred voice: amy
VOICE="${VOICE:-amy}"

# Find model matching voice name, fall back to any .onnx
MODEL=$(ls "$MODEL_DIR"/*"$VOICE"*.onnx 2>/dev/null | head -1)
if [ -z "$MODEL" ]; then
  MODEL=$(ls "$MODEL_DIR"/*.onnx 2>/dev/null | head -1)
  if [ -z "$MODEL" ]; then
    echo "ERROR: No .onnx model found in $MODEL_DIR"
    exit 1
  fi
  echo "WARNING: No model matching \"$VOICE\" found, using: $MODEL"
fi
echo "Using model: $MODEL"

mkdir -p "$AUDIO_DIR"

generated=0
skipped=0
failed=0

generate() {
  local filename="$1"
  local text="$2"
  local outpath="$AUDIO_DIR/$filename"

  if [ "$SKIP_EXISTING" = "1" ] && [ -f "$outpath" ]; then
    skipped=$((skipped + 1))
    return
  fi

  echo "Generating: $filename"
  echo "$text" | "$PIPER" --model "$MODEL" --length_scale 0.6993 --noise_scale 0.55 --noise_w 0.51 --sentence_silence 0.3 --output_file "$outpath" 2>/dev/null
  if [ $? -eq 0 ]; then
    generated=$((generated + 1))
  else
    echo "  FAILED: $filename"
    failed=$((failed + 1))
  fi
}

# === Abstract (wp-abstract) — 4 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "abstract" ] || [ "$SECTION" = "wp-abstract" ]; then
  generate 'wp-abstract-p01.mp3' 'ZeroPoint is portable proof infrastructure — cryptographic governance primitives that produce proof of authorization, compliance, and prov-eh-nance without requiring central control. It restores real exit and real competition by moving trust from platform databases to verifiable cryptographic guarantees that any participant can carry between systems, operators, and networks.'
  generate 'wp-abstract-p02.mp3' 'The framework operates at the protocol-primitives layer. Every significant action produces a verifiable receipt, linked into an immutable chain of accountability. The protocol is participant-agnostic: the same receipts, capability chains, and constitutional constraints work whether the actor is a human, an AI agent, an automated service, or an IoT device — and whether they communicate over HTTP, TCP, encrypted mesh networks, or any future transport. ZeroPoint ships with a Reticulum-compatible mesh transport as one integration — chosen for its philosophical alignment with sovereignty and harm minimization — alongside TCP, UDP, HTTP interfaces, and a privacy-preserving Presence Plane that lets agents discover each other without surveillance infrastructure.'
  generate 'wp-abstract-p03.mp3' 'Autonomous AI agents are the most urgent application: agents are proliferating faster than the trust infrastructure to govern them, and ZeroPoint provides the cryptographic substrate they need. But the primitives are not agent-specific. Any participant that holds a keypair can sign receipts, hold capability grants, delegate authority, and exercise sovereign refusal.'
  generate 'wp-abstract-p04.mp3' 'ZeroPoint is technically complete: 700+ tests across 13 crates, six delivered development phases, and full documentation including a dual-backend discovery layer (the Presence Plane) that solves peer discovery without centralized registries. It does not claim to "solve AI safety" or solve trust generally. It provides cryptographic primitives and governance constraints that make actions provable and refusable — shifting the terms of trust between participants, operators, and systems.'
fi

# === Why This Exists — The Portable Trust Thesis (wp-s0) — 18 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "s0" ] || [ "$SECTION" = "wp-s0" ]; then
  generate 'wp-s0-p01.mp3' 'The internet did not degrade by accident. It degraded because the primitives that make trust work — identity, reputation, prov-eh-nance, authorization — were never built into the protocol layer. They were left to platforms. And platforms, once they accumulate enough users, face a structural incentive to make those trust primitives non-portable.'
  generate 'wp-s0-p02.mp3' 'This is the dependency loop: a platform offers identity and reputation services. Users and developers build on those services. The platform becomes the only place where a user'\''s history, credentials, and relationships are legible. Exit becomes expensive. Once exit is expensive, the platform can extract — raising prices, degrading quality, inserting intermediaries, selling attention — because the cost of leaving exceeds the cost of staying. The user'\''s trust relationships are held hostage by the platform'\''s database.'
  generate 'wp-s0-p03.mp3' 'Cory Doctorow named this dynamic "enshittification." The diagnosis is precise: platforms attract users with value, then degrade the experience to extract from those users once switching costs are high enough. But the diagnosis, by itself, does not produce a remedy. Regulation can slow the cycle. Interoperability mandates can lower switching costs. But neither addresses the root cause: trust is not portable.'
  generate 'wp-s0-p04.mp3' 'When your identity lives in a platform'\''s database, your reputation is computed by a platform'\''s algorithm, and your authorization chains terminate at a platform'\''s API — you do not have trust. You have a lease. The platform can revoke, reinterpret, or degrade that lease at any time, and your only recourse is to start over somewhere else.'
  generate 'wp-s0-p05.mp3' 'Consider what SSL/TLS did for e-commerce. Before SSL, transmitting a credit card number over the internet required trusting every intermediary between you and the merchant. Commerce was possible, but it was fragile, and it was concentrated among the few parties who could afford to build proprietary trust infrastructure. SSL did not make merchants trustworthy. It made the transport trustworthy — and in doing so, it made the ecosystem work. Any merchant could participate. Any customer could verify. Trust became a protocol property, not a platform feature.'
  generate 'wp-s0-p06.mp3' 'The internet is missing an equivalent primitive for trust itself. Not transport encryption — that problem is largely solved. The missing piece is: how do you prove what happened, who authorized it, and whether the constraints were honored — without depending on a platform to be the witness?'
  generate 'wp-s0-p07.mp3' 'ZeroPoint'\''s thesis: make trust portable, and you make exit real. Make exit real, and you make extraction optional. That is the structural antidote.'
  generate 'wp-s0-p08.mp3' 'Portable trust means:'
  generate 'wp-s0-p09.mp3' 'Your identity is a keypair you control, not an account on someone else'\''s server. You can move it between systems without losing continuity. Your reputation is a verifiable chain of receipts, not a score computed by an opaque algorithm. Anyone can audit it. No one can confiscate it. Your authorization is a cryptographic capability grant, not an API key that can be revoked without recourse. Delegation chains have mathematical properties — they cannot be silently altered. Your history is a hash-chained audit trail, not a log file someone else controls. Tampering is detectable. Omission is provable.'
  generate 'wp-s0-p10.mp3' 'When trust is portable, platforms compete on service quality, not on lock-in. When trust is portable, switching costs drop to near zero. When trust is portable, the dependency loop that enables extraction never forms.'
  generate 'wp-s0-p11.mp3' 'Autonomous AI agents are amplifying the stakes. An agent operating on your behalf inherits the same trust infrastructure — or lack of it — that you do. If your identity is platform-bound, your agent'\''s identity is platform-bound. If your authorization chains are opaque, your agent'\''s delegated authority is opaque. If your audit trail is controlled by someone else, your agent'\''s actions are controlled by someone else.'
  generate 'wp-s0-p12.mp3' 'Agents are proliferating faster than the trust infrastructure to govern them. Multi-agent systems are being orchestrated across organizational boundaries with no shared trust substrate. The accountability gap that humans have tolerated for decades — mutable logs, informal authorization, platform-controlled identity — becomes untenable when agents operate at machine speed, across jurisdictions, with delegation chains that can extend far beyond their original scope.'
  generate 'wp-s0-p13.mp3' 'This is not a future concern. It is the present condition. Every major AI lab is shipping agent frameworks. Every enterprise is deploying agent workflows. And every one of them is building on trust infrastructure that was designed for a world where a human was always in the loop, always reading the screen, always able to intervene manually.'
  generate 'wp-s0-p14.mp3' 'ZeroPoint does not solve AI safety. It solves a more specific and more tractable problem: it provides the cryptographic primitives that produce portable proof — of what happened, who authorized it, and what constraints applied — for any participant, over any transport, without requiring any central authority to be the witness.'
  generate 'wp-s0-p15.mp3' 'The antidote to platform-captured trust is not better platforms. It is protocol-level trust primitives that no platform controls:'
  generate 'wp-s0-p16.mp3' 'Receipts that are signed by the actor and chained to the previous receipt — not logged by a platform. Capability grants that are cryptographically scoped and delegatable — not API permissions that can be silently changed. Constitutional constraints that are non-removable and non-overridable — not terms of service that can be updated unilaterally. Transport agnosticism that lets trust flow over HTTP, TCP, mesh networks, or any future medium — not locked to a single provider'\''s infrastructure.'
  generate 'wp-s0-p17.mp3' 'ZeroPoint is to agentic and networked computing what SSL/TLS was to e-commerce: a trust primitive that makes the ecosystem work without trusting any single platform. It is not a governance framework you comply with. It is a governance protocol you build on.'
  generate 'wp-s0-p18.mp3' 'Trust is infrastructure.'
fi

# === Problem Statement (wp-s1) — 9 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "s1" ] || [ "$SECTION" = "wp-s1" ]; then
  generate 'wp-s1-p01.mp3' 'The accountability gap that agents expose is an instance of the deeper structural problem described above: digital systems have never had protocol-level trust primitives. Agents did not create this gap — they inherited it and are accelerating it to the point where informal trust is no longer tenable.'
  generate 'wp-s1-p02.mp3' 'AI agents are rapidly becoming operational actors: they request tools, move data, execute workflows, and trigger external effects. They act at machine speed, across organizational boundaries, with delegation chains that can extend far beyond their original authority. Yet most systems today remain trust-light:'
  generate 'wp-s1-p03.mp3' 'Actions are difficult to attribute reliably. Logs exist, but they are mutable, centralized, and easily rewritten. Authorization is informal and mutable. Most systems rely on API keys or ambient permissions rather than scoped, cryptographic capability grants. Who authorized what, and when, is often reconstructed after the fact — if it can be reconstructed at all. Logs are easy to forge, prune, or "reinterpret." There is no chain of evidence — only whatever the operator chooses to retain. Cross-party trust is brittle. One team cannot safely accept another party'\''s outputs without out-of-band verification.'
  generate 'wp-s1-p04.mp3' 'These are not agent-specific problems. They are structural failures in how digital systems handle trust — failures that existed long before autonomous agents arrived. Human organizations make consequential decisions with mutable logs and informal authorization every day. Agents inherited the accountability gap; they did not create it. But they are compressing decades of accumulated risk into months of operational reality.'
  generate 'wp-s1-p05.mp3' 'At the same time, the infrastructure environment is changing. There is renewed attention on sovereign networking, mesh systems, and local-first operations. Projects like the Reticulum Network Stack demonstrate that decentralized networking can bridge heterogeneous links into resilient networks under user control. Edge computing is moving AI inference closer to the point of action. Multi-agent orchestration frameworks are proliferating without any shared trust substrate.'
  generate 'wp-s1-p06.mp3' 'This combination — agents intensifying an existing trust deficit, sovereignty becoming a design requirement, and real-world execution moving to the edge — creates a clear need:'
  generate 'wp-s1-p07.mp3' 'Systems where actions have consequences require protocol-level accountability primitives, not only policy frameworks.'
  generate 'wp-s1-p08.mp3' 'Many governance efforts exist today as checklists, dashboards, or top-down frameworks. They describe what should be done, but they do not provide low-level mechanisms that make trust enforceable by default. ZeroPoint'\''s position is intentionally infrastructural:'
  generate 'wp-s1-p09.mp3' 'Not a governance framework you comply with — a governance protocol you build on.'
fi

# === Design Goals (wp-s2) — 5 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "s2" ] || [ "$SECTION" = "wp-s2" ]; then
  generate 'wp-s2-p01.mp3' 'ZeroPoint produces verifiable receipts for actions and decisions. A receipt is cryptographically signed data describing what occurred, under what constraints, and with what authorization — regardless of whether the actor is an agent, a human, or an automated service. Receipts are chained — each linking to its parent — to create a durable accountability history.'
  generate 'wp-s2-p02.mp3' 'ZeroPoint is built to function in environments where cloud assumptions are unsafe or unavailable. Its governance primitives are transport-agnostic — they work over HTTP in a data center, TCP between containers, or encrypted mesh links in a field deployment. The framework minimizes dependency on centralized infrastructure by design, not by accident.'
  generate 'wp-s2-p03.mp3' 'The system includes governance mechanisms that are not simply "policies in a file." Two constitutional rules — HarmPrincipleRule and SovereigntyRule — are engineered to be non-removable and non-overridable within the protocol'\''s governance model. They evaluate before every action. They cannot be bypassed at runtime.'
  generate 'wp-s2-p04.mp3' 'ZeroPoint aims to be explicit about what it prevents, what it cannot prevent, and what remains a residual risk. Credibility comes from the boundaries, not the claims. Section 6 of this paper is dedicated to that honesty.'
  generate 'wp-s2-p05.mp3' 'ZeroPoint'\''s governance layer is decoupled from any single transport. The receipt format, capability grants, delegation chains, and policy engine operate identically regardless of how messages move. The framework ships with multiple transport integrations — including a Reticulum-compatible mesh transport, TCP/UDP interfaces, and an HTTP API — and is designed to be extended to any future transport without modifying the governance primitives.'
fi

# === System Overview (wp-s3) — 7 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "s3" ] || [ "$SECTION" = "wp-s3" ]; then
  generate 'wp-s3-p01.mp3' 'ZeroPoint is composed of layered capabilities, each implemented as one or more Rust crates. The layers are participant-agnostic — any entity that holds a keypair (human, agent, service, device) can operate as a full peer:'
  generate 'wp-s3-p02.mp3' 'Identity layer. Ed25519 signing keys and X25519 key agreement. Identity is a keypair. Authentication is a signature. Governance layer. PolicyEngine with constitutional rules, composable operational rules, WASM-extensible policy modules, and capability gating. Receipt layer. Signed, hash-chained receipts for every action and decision. CompactReceipt encoding produces 150–300 byte payloads suitable for bandwidth-constrained transports. Transport layer. Pluggable transport with multiple built-in integrations: Reticulum-compatible mesh (HDLC framing, 128-bit destination hashing, link handshake), TCP client/server, UDP, and HTTP API. The governance primitives are transport-independent. Presence Plane. Dual-backend discovery layer (web relay + Reticulum mesh) that lets agents find each other without centralized registries. Same Ed25519 identity anchors both discovery and governance. Privacy is structural: the relay never parses, indexes, or persists announce payloads. Application layer. Pipeline orchestration, LLM provider integration, skill registry, and CLI tooling — all built on the governance primitives.'
  generate 'wp-s3-p03.mp3' 'The GovernanceGate pipeline processes every action through three pillars:'
  generate 'wp-s3-p04.mp3' 'Guard ("May I?") — Local-first, pre-action sovereignty check. The participant'\''s own boundary. Runs before anything else, without consulting external authority. Policy ("Should I?") — Rule-composed evaluation. Constitutional rules first, then operational rules, then WASM modules. The most restrictive decision wins. Execute — The action runs only if Guard and Policy both allow it. Audit ("Did I?") — A receipt is emitted: signed, timestamped, hash-linked to the prior receipt, and persisted to the chain. Transport — Receipts propagate to peers over whichever transport is configured — mesh, TCP, HTTP, or any combination. Peers verify independently.'
  generate 'wp-s3-p05.mp3' 'Nothing executes without passing through the gate. Nothing passes without producing proof.'
  generate 'wp-s3-p06.mp3' 'Every action becomes proof. Proof becomes a chain. The chain becomes shared truth.'
  generate 'wp-s3-p07.mp3' 'This is not a compliance claim. It is an engineering proposition: if systems can produce cryptographic proof of what happened and under what authorization, then trust becomes composable across operators.'
fi

# === Receipts and Chains (wp-s4) — 10 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "s4" ] || [ "$SECTION" = "wp-s4" ]; then
  generate 'wp-s4-p01.mp3' 'A receipt is a signed artifact that describes an event or action with enough context to be verified independently. In ZeroPoint'\''s implementation, a receipt contains:'
  generate 'wp-s4-p02.mp3' 'Receipts are encoded using MessagePack with named fields, producing a compact binary representation of 150–300 bytes. This compact encoding is efficient over any transport — it fits in a single HTTP request, a single TCP frame, or a single 465-byte mesh packet for bandwidth-constrained links like LoRa.'
  generate 'wp-s4-p03.mp3' 'Receipts are intended to be verifiable. They are not intended to be surveillance.'
  generate 'wp-s4-p04.mp3' 'Receipts can prove:'
  generate 'wp-s4-p05.mp3' 'A specific Ed25519 key signed a specific statement at a specific time. A chain contains a consistent, unbroken sequence of signed events. The policy engine evaluated a known rule set and produced a specific decision. A capability grant was present and valid at the time of action.'
  generate 'wp-s4-p06.mp3' 'Receipts do not automatically prove:'
  generate 'wp-s4-p07.mp3' 'The nature of the signer. A receipt proves that a specific key signed a statement — not whether that key belongs to a human, an agent, or a service. Identity binding to physical persons or specific systems is deployment-dependent. That the content of an action was "good" or "safe." Governance constrains actions; it does not evaluate truth. That the runtime environment was uncompromised. A compromised host can sign whatever it wants. That a result is truthful — only that it was produced and attested under stated constraints.'
  generate 'wp-s4-p08.mp3' 'Single receipts help attribution. Chains help accountability continuity. Each receipt'\''s pr field links to the previous receipt'\''s ID, forming a hash-linked sequence that resists retroactive tampering.'
  generate 'wp-s4-p09.mp3' 'Chains are not magic. They are a mechanical advantage: they make it harder to rewrite the story after the fact, and they allow counterparties to require evidence before trust is granted.'
  generate 'wp-s4-p10.mp3' 'In ZeroPoint, peers can challenge each other'\''s audit chains. A challenged peer must produce its full chain; the challenger verifies integrity and produces a signed PeerAuditAttestation. Broken chains generate negative reputation signals. This is collective verification — no central auditor required.'
fi

# === Governance Model (wp-s5) — 23 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "s5" ] || [ "$SECTION" = "wp-s5" ]; then
  generate 'wp-s5-p01.mp3' 'Most governance — whether for agents, human workflows, or automated services — is implemented at the application layer: guardrails, prompt policies, logging conventions, compliance checklists. These are better than nothing, but they sit above the systems they govern. They can be bypassed, reconfigured, or simply ignored.'
  generate 'wp-s5-p02.mp3' 'ZeroPoint moves governance downward into the protocol substrate. The PolicyEngine is not an add-on. It is the gate through which every action must pass — regardless of who or what initiated it.'
  generate 'wp-s5-p03.mp3' 'ZeroPoint requires explicit capabilities for actions. Any participant — human operator, agent, or service — must hold a valid grant to act. A CapabilityGrant is a signed, portable authorization token containing:'
  generate 'wp-s5-p04.mp3' 'Scope restrictions (which actions, which targets) Cost ceilings and rate limits Time windows (valid_from, valid_until) Delegation depth limits Trust tier requirements The grantor'\''s Ed25519 signature'
  generate 'wp-s5-p05.mp3' 'Capabilities are delegatable. Any participant holding a grant can delegate a subset of that grant to another participant — human to agent, agent to agent, or human to human — forming a DelegationChain. The chain is verified against eight invariants:'
  generate 'wp-s5-p06.mp3' 'Each grant references the previous one as parent_grant_id. Delegation depths increment monotonically (0, 1, 2, ...). Each child'\''s scope is a subset of its parent'\''s scope. Each child'\''s trust tier is ≥ its parent'\''s trust tier. No child outlives its parent (expiration inheritance). The chain doesn'\''t exceed the max_delegation_depth set by the root. Each grant'\''s grantor matches the previous grant'\''s grantee. All signatures verify.'
  generate 'wp-s5-p07.mp3' 'Break any invariant and the chain is rejected. The authority dissolves.'
  generate 'wp-s5-p08.mp3' 'ZeroPoint'\''s PolicyEngine loads rules in a fixed evaluation order. The first two positions are reserved for constitutional rules that cannot be removed, overridden, or reordered:'
  generate 'wp-s5-p09.mp3' 'HarmPrincipleRule (Tenet I: Do No Harm) — Blocks actions targeting weaponization, surveillance, deception (deepfakes, impersonation), and suppression of dissent. The block message always cites "Tenet I — Do No Harm." This rule evaluates before every action, regardless of what other rules or WASM modules are loaded. It cannot be bypassed by capability grants, policy edits, or consensus votes.'
  generate 'wp-s5-p10.mp3' 'SovereigntyRule (Tenet II: Sovereignty Is Sacred) — Blocks configuration changes that would disable the guard, disable or truncate the audit trail, forge or bypass capabilities, remove constitutional rules, or override participant refusal. The block message always cites "Tenet II — Sovereignty Is Sacred."'
  generate 'wp-s5-p11.mp3' 'The evaluation hierarchy enforces precedence. Constitutional rules win over everything. WASM modules can override the default allow but cannot override constitutional rules. The decision severity hierarchy is: Block(5) > Review(4) > Warn(3) > Sanitize(2) > Allow(1). The most restrictive decision always wins.'
  generate 'wp-s5-p12.mp3' 'This is not a moral statement alone. It is a technical property: constitutional constraints remain enforceable even when incentives shift. They serve as a defense against co-option — particularly by surveillance interests.'
  generate 'wp-s5-p13.mp3' 'The constitutional rules implement ZeroPoint'\''s Four Tenets, which are embedded in the protocol, expressed in the documentation, and enforced in the code:'
  generate 'wp-s5-p14.mp3' 'I. Do No Harm. ZeroPoint shall not operate in systems designed to harm humans. The HarmPrincipleRule is a non-removable rule in the PolicyEngine. It exists because architecture shapes outcomes, and we choose to make trust portable.'
  generate 'wp-s5-p15.mp3' 'II. Sovereignty Is Sacred. Every participant has the right to refuse any action. Every human has the right to disconnect any agent. No agent may acquire capabilities it was not granted. Coercion is architecturally impossible — the Guard enforces this locally, before every action, without consulting any external authority. This applies equally to humans and agents: a human participant operating within ZeroPoint exercises the same sovereign refusal as an agent.'
  generate 'wp-s5-p16.mp3' 'III. Action Without Proof Is No Action. Every action produces a receipt. Every receipt is a cryptographic proof. Every proof joins a chain. If it'\''s not in the chain, it didn'\''t happen. If it is in the chain, it cannot un-happen. This holds whether the action was taken by a person, an agent, or an automated process.'
  generate 'wp-s5-p17.mp3' 'IV. The Human Is The Root. Every delegation chain terminates at a human-held key. No agent may self-authorize. The genesis key is always held by flesh, blood, and soul. This is not only a constraint on agents — it is an assertion of human authority and accountability. The human at the root of a chain is not merely an overseer; they are a participant whose actions are as provable and auditable as any agent'\''s.'
  generate 'wp-s5-p18.mp3' 'ZeroPoint solves the key distribution problem through zp-keys — a three-level certificate hierarchy that exists below the policy engine:'
  generate 'wp-s5-p19.mp3' 'GenesisKey — self-signed root of trust, one per deployment. OperatorKey — signed by genesis, one per node operator. AgentKey — signed by operator, one per agent instance.'
  generate 'wp-s5-p20.mp3' 'Each level holds an Ed25519 keypair and a certificate chain linking it back to its genesis root. Any node can verify an agent'\''s identity by walking the chain — offline, with no network or policy state required. Certificate chains are verified against six invariants: valid signatures, issuer linkage, role hierarchy, monotonic depth, no expired certificates, and hash linkage.'
  generate 'wp-s5-p21.mp3' 'The key hierarchy is a primitive — it has no dependency on the policy engine. This avoids a circular dependency: you need keys to establish the engine'\''s authority across nodes, so keys cannot depend on the engine existing. The decision to issue a child certificate flows through the policy engine as ActionType::KeyDelegation (Critical risk); the mechanism of signing is unconditional.'
  generate 'wp-s5-p22.mp3' 'When two ZeroPoint nodes meet for the first time, the introduction protocol (zp-introduction) governs trust establishment. The initiator sends its certificate chain and a challenge nonce. The responder verifies the chain, builds a PolicyContext with ActionType::PeerIntroduction, and evaluates it against the policy engine. Same-genesis introductions are High risk; cross-genesis introductions are Critical. The policy engine decides — the protocol only generates the context.'
  generate 'wp-s5-p23.mp3' 'Key distribution is solved by zp-keys. Key discovery — how peers find each other'\''s network addresses — is solved by the Presence Plane (§8), a dual-backend discovery layer that uses the same Ed25519 identity but serves a different purpose: finding peers without requiring a centralized registry.'
fi

# === Threat Model (wp-s6) — 5 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "s6" ] || [ "$SECTION" = "wp-s6" ]; then
  generate 'wp-s6-p01.mp3' 'Being explicit prevents credibility collapse later:'
  generate 'wp-s6-p02.mp3' 'It does not prevent a determined actor from building harmful systems. The MIT/Apache-2.0 license is permissive. Constitutional rules constrain the framework'\''s own behavior; they cannot constrain a fork. It does not make intelligence tools impossible. Receipt infrastructure could be repurposed for surveillance. The Tenets and constitutional rules resist this, but they are a friction, not a wall. It does not provide universal truth verification. Receipts prove that a statement was signed, not that the statement is true. Key discovery is now addressed but not fully hardened. The Presence Plane (§8) provides dual-backend discovery with reciprocity enforcement and structural amnesia. It is not yet resistant to sophisticated Sybil attacks without the reputation layer; see §8 for the full threat analysis.'
  generate 'wp-s6-p03.mp3' 'Instead:'
  generate 'wp-s6-p04.mp3' 'ZeroPoint produces proof. Proof makes systems refusable.'
  generate 'wp-s6-p05.mp3' 'This is a practical, enforceable improvement: counterparties can demand receipts and reject agents that do not provide them or that violate constraints.'
fi

# === Transport Integrations (wp-s7) — 8 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "s7" ] || [ "$SECTION" = "wp-s7" ]; then
  generate 'wp-s7-p01.mp3' 'ZeroPoint'\''s governance primitives are transport-agnostic. The receipt format, capability chains, delegation verification, and policy engine operate identically regardless of how messages move between participants. The framework ships with several transport integrations, each suited to different deployment contexts.'
  generate 'wp-s7-p02.mp3' 'The most straightforward integration path. An Axum-based HTTP server exposes the governance pipeline as a REST API. Agents communicate over standard HTTP/HTTPS — suitable for cloud deployments, container orchestration, and integration with existing web services. No mesh networking required.'
  generate 'wp-s7-p03.mp3' 'Direct socket communication for low-latency, local-network, or point-to-point deployments. TcpClientInterface and TcpServerInterface support persistent connections with HDLC framing and CRC verification. UDP interfaces support connectionless receipt exchange. Multiple interfaces can run simultaneously on a single node.'
  generate 'wp-s7-p04.mp3' 'ZeroPoint includes a Reticulum-compatible mesh transport — wire-level interoperability with the Reticulum Network Stack, created by Mark Qvist. This integration is philosophically significant: Reticulum demonstrated that encrypted, sovereign networking requires no central authority, and ZeroPoint shares that commitment to sovereignty, decentralization, and harm minimization.'
  generate 'wp-s7-p05.mp3' 'The mesh integration implements:'
  generate 'wp-s7-p06.mp3' 'HDLC framing with CRC-CCITT verification, matching Reticulum'\''s serial interface format. 128-bit destination hashing using the same truncated SHA-256 scheme. Ed25519 signing and X25519 ECDH key agreement, matching Reticulum'\''s cryptographic primitives. 500-byte default MTU with a 465-byte data payload — compatible with Reticulum'\''s packet constraints and suitable for LoRa links. 3-packet link handshake (LinkRequest → LinkProof → LinkAccept) with 16-byte random nonces for replay protection.'
  generate 'wp-s7-p07.mp3' 'Interoperability testing with Reticulum ecosystem tools (MeshChat, NomadNet) is underway. The mesh transport is one option among several — chosen when sovereignty, resilience, or operation without cloud infrastructure are priorities.'
  generate 'wp-s7-p08.mp3' 'Adding a new transport requires implementing the interface trait and providing serialization/deserialization for the envelope format. The governance primitives — receipts, chains, capability verification, policy evaluation — remain unchanged. The same decoupling principle extends to discovery: the DiscoveryBackend trait (§8) allows new discovery mechanisms without touching the governance stack. This makes ZeroPoint deployable in contexts its authors haven'\''t anticipated: industrial IoT, satellite links, air-gapped networks, or standard enterprise infrastructure.'
fi

# === The Presence Plane (wp-s8) — 20 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "s8" ] || [ "$SECTION" = "wp-s8" ]; then
  generate 'wp-s8-p01.mp3' 'Key distribution — how participants verify each other'\''s identity — is solved by zp-keys and the certificate hierarchy (§5.5). But key discovery — how participants find each other in the first place — is a separate problem. Most systems solve it with a centralized registry: a server that indexes who is online, what they offer, and where to reach them. This creates exactly the dependency that ZeroPoint exists to eliminate. A registry is a single point of surveillance, censorship, and failure.'
  generate 'wp-s8-p02.mp3' 'ZeroPoint'\''s answer is the Presence Plane: a discovery layer that runs alongside the Governance Plane, using the same Ed25519 identity but serving a different purpose. The Governance Plane determines what agents do together (receipts, policy, consensus). The Presence Plane determines how agents find each other — without requiring any participant to trust a central directory.'
  generate 'wp-s8-p03.mp3' 'The Presence Plane is built on a DiscoveryBackend trait — a four-method interface that any transport can implement:'
  generate 'wp-s8-p04.mp3' 'announce(payload) — publish a signed announce blob poll_discoveries() — retrieve newly discovered peers is_active() — check backend status shutdown() — clean teardown'
  generate 'wp-s8-p05.mp3' 'Two production backends ship today:'
  generate 'wp-s8-p06.mp3' 'Web relay. A privacy-preserving pub/sub relay over WebSocket. Agents publish signed announce blobs to the relay; the relay broadcasts all blobs to all subscribers; agents filter locally for peers they care about. The relay never parses payloads, never indexes capabilities, never maintains query logs, and never persists state. Restart equals clean slate. Privacy is a property of the architecture — not a policy promise that can be revoked.'
  generate 'wp-s8-p07.mp3' 'Reticulum mesh. Broadcast announces over mesh interfaces — LoRa, WiFi, serial, TCP. Fully decentralized. No server, no internet dependency. Announces propagate over whatever physical medium is available.'
  generate 'wp-s8-p08.mp3' 'Both backends share the same announce wire format: [combined_key(64)] + [capabilities_json] + [ed25519_signature(64)]. A peer discovered via web and a peer discovered via Reticulum end up in the same peer table with the same destination hash. The DiscoveryManager fans out announces to all active backends, polls all backends, validates signatures, deduplicates peers, and prunes expired entries.'
  generate 'wp-s8-p09.mp3' 'The web relay is designed to be structurally incapable of surveillance — not merely configured to avoid it. It operates as a dumb pipe:'
  generate 'wp-s8-p10.mp3' 'It does not parse announce payloads (no capability indexing) It does not maintain query logs (no search patterns recorded) It does not persist any state (memory-only, restart erases everything) It does not track who received what (no delivery receipts)'
  generate 'wp-s8-p11.mp3' 'This makes the relay subpoena-proof: there is nothing to hand over. Compromise-proof: an attacker who gains access to the relay finds zero peer data. Audit-friendly: the relay'\''s own receipt chain proves honest behavior — that it did not censor, filter, or selectively route announces.'
  generate 'wp-s8-p12.mp3' 'The key insight is that structural amnesia is stronger than policy-based privacy. A "no-logs" VPN policy can be changed, overridden, or secretly violated. A relay that architecturally cannot parse what it forwards cannot be coerced into surveillance — the capability does not exist.'
  generate 'wp-s8-p13.mp3' 'Passive scanning is the primary adversarial concern for any discovery mechanism. An attacker connects to the relay, subscribes to the full firehose, and harvests peer identities without ever revealing their own. Traditional registries have no defense against this — querying a directory does not require participation.'
  generate 'wp-s8-p14.mp3' 'The Presence Plane enforces a reciprocity rule: you must announce before you receive. A connection that only subscribes without publishing its own announce is structurally suspicious — it is a consumer-only node, a passive scanner. The enforcement mechanism:'
  generate 'wp-s8-p15.mp3' 'On connect, the client receives a RelayConnection handle. The handle tracks whether the client has published an announce. try_receive() returns an error until the client publishes. A configurable grace period (default 30 seconds) allows time for announce construction. After the grace period, the connection is terminated.'
  generate 'wp-s8-p16.mp3' 'This means any scanner must first announce itself — exposing its own signed Ed25519 identity to every legitimate agent on the network — before it can observe anyone else. Scanners become observable before they can observe.'
  generate 'wp-s8-p17.mp3' 'Reciprocity enforcement catches the most naive scanners. Sophisticated ones will announce once (passing the gate), then silently consume. The Presence Plane addresses this by emitting behavioral summaries — not content, not identity, just counters — when connections close:'
  generate 'wp-s8-p18.mp3' 'announced: whether the client ever published an announce announces_published: how many announces were sent duration: how long the connection was active reciprocity_violation: whether the connection was terminated for failing to announce'
  generate 'wp-s8-p19.mp3' 'These ConnectionBehavior summaries map directly to ReputationSignal in the PolicyCompliance category. An agent that connects, announces regularly, and participates in discovery accumulates positive signals. An agent that connects, announces once, and silently consumes for hours accumulates weaker or negative signals. Over time, the reputation system naturally separates participants from parasites — without the relay ever needing to inspect content.'
  generate 'wp-s8-p20.mp3' 'The Presence Plane does not claim to solve Sybil attacks at the discovery layer. Sybil resistance is a reputation-layer concern (§10). What the Presence Plane does provide is the architectural foundation — reciprocity, behavioral signals, structural amnesia — that makes reputation-based Sybil defense possible without surveillance infrastructure.'
fi

# === Implementation Status (wp-s9) — 2 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "s9" ] || [ "$SECTION" = "wp-s9" ]; then
  generate 'wp-s9-p01.mp3' 'ZeroPoint is implemented in Rust and is technically complete.'
  generate 'wp-s9-p02.mp3' '700+ tests (all passing, zero warnings) 16 crates in a Cargo workspace (including dual-backend discovery in zp-mesh, key hierarchy in zp-keys, and the introduction protocol in zp-introduction) 6 development phases delivered 59 integration tests covering multi-node and cross-transport scenarios Full documentation for all crates'
fi

# === Adoption Paths (wp-s10) — 8 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "s10" ] || [ "$SECTION" = "wp-s10" ]; then
  generate 'wp-s10-p01.mp3' 'This project will not win by marketing. It will win by being useful and trustworthy to the right early communities.'
  generate 'wp-s10-p02.mp3' 'Multi-agent system builders — teams orchestrating autonomous agents who need protocol-level trust between operators, not just application-level guardrails. Rust networking and security-oriented builders — developers who understand why governance belongs in the substrate, not in the application. Decentralized infrastructure communities — projects building sovereign, local-first systems where centralized governance is a contradiction. The Reticulum ecosystem is a natural fit here. Privacy-aligned agent tooling builders — teams who need accountability without surveillance. Enterprise AI governance teams — organizations looking for verifiable, auditable behavior — from agents and humans alike — that goes beyond compliance checklists. Accountable-process builders — teams in journalism, supply chain, humanitarian operations, or organizational governance who need cryptographic proof of attribution and auditable decision chains, whether or not agents are involved.'
  generate 'wp-s10-p03.mp3' 'Pattern A: Governed Agent-to-Agent Exchange. Agents exchange tasks and outputs only when receipts validate authorization. Each agent verifies the other'\''s capability chain before accepting work or results.'
  generate 'wp-s10-p04.mp3' 'Pattern B: Policy-Gated Tool Execution. A tool runner requires receipts demonstrating valid capability grants before executing. The runner emits its own receipt attesting to acceptance or refusal, creating a bidirectional trust record.'
  generate 'wp-s10-p05.mp3' 'Pattern C: Delegation Chains. A human operator grants a root capability. The agent delegates subsets to specialist sub-agents, each with narrower scope. Every delegation is verified against the eight invariants. Authority flows down the chain; accountability flows up.'
  generate 'wp-s10-p06.mp3' 'Pattern D: Human-Accountable Workflows. A human operator performs sensitive actions — data access, approvals, configuration changes — through ZeroPoint'\''s governance pipeline. Every action produces a signed receipt, creating the same cryptographic accountability that agents face. The protocol doesn'\''t distinguish; the keypair holder is accountable.'
  generate 'wp-s10-p07.mp3' 'Pattern E: Mixed Human-Agent Systems. A workflow involves both human and agent participants. A human initiates a process, delegates a subset to an agent, reviews the agent'\''s output (with receipts), and finalizes the result. Every step — human and agent — produces receipts. The audit chain is continuous regardless of who acted at each step.'
  generate 'wp-s10-p08.mp3' 'A minimal example demonstrating: two participants (human, agent, or both), a governed action, a receipt emitted and verified, and a refusal case. One clean, working demo can convert serious builders faster than any whitepaper.'
fi

# === Roadmap (wp-s11) — 2 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "s11" ] || [ "$SECTION" = "wp-s11" ]; then
  generate 'wp-s11-p01.mp3' 'The public repository, CI/CD pipeline, expanded threat model, and Presence Plane are shipped. The following items remain.'
  generate 'wp-s11-p02.mp3' 'crates.io registration — Publish workspace crates for external consumption. Requires stabilizing public API surfaces and versioning strategy. Transport integration test suite — Documented cross-transport receipt exchange results, including Reticulum ecosystem interop (NomadNet, MeshChat) and HTTP/TCP integration tests. Key revocation and multi-hop trust formalization — Revocation propagation strategy for compromised keys; formal analysis of trust transitivity across delegation chains longer than two hops. Reputation-weighted Sybil resistance — The Presence Plane provides behavioral signals and reciprocity enforcement but defers Sybil resistance to the reputation system. Requires implementing reputation-weighted peer scoring in zp-mesh. Sustainability layer — Consulting, hosted infrastructure, and enterprise feature scoping — without compromising the open-source core.'
fi

# === Ethics, Non-Goals, and Misuse Resistance (wp-s12) — 5 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "s12" ] || [ "$SECTION" = "wp-s12" ]; then
  generate 'wp-s12-p01.mp3' 'Accountability infrastructure can become surveillance infrastructure depending on how it is deployed. This is not a hypothetical concern — it is the central tension of the project.'
  generate 'wp-s12-p02.mp3' 'ZeroPoint mitigates this through three mechanisms:'
  generate 'wp-s12-p03.mp3' 'Constitutional constraints that are engineered to be non-removable. The HarmPrincipleRule blocks weaponization, surveillance, and deception. The SovereigntyRule blocks attempts to remove these constraints. Public tenets describing intent and boundaries. The Four Tenets are not buried in documentation — they are the first thing on the website and the first code that runs in the PolicyEngine. Protocol-level framing. ZeroPoint provides accountability of actions, not central control of people. The audit chain tracks what participants did — human or agent — not where anyone went or who they are beyond their keypair.'
  generate 'wp-s12-p04.mp3' 'ZeroPoint does not aim to:'
  generate 'wp-s12-p05.mp3' 'Become a compliance product. Compliance is a checklist someone else writes. ZeroPoint is infrastructure you build on. Become a centralized authority. There is no ZeroPoint server, no ZeroPoint cloud, no ZeroPoint corporation deciding who gets to use it. "Prevent all misuse." The MIT/Apache-2.0 license is deliberately permissive. Constitutional rules constrain the framework; they cannot constrain a fork. Depend on any single transport or network. ZeroPoint'\''s governance works over HTTP, TCP, mesh, or anything else. No transport is privileged. Be agent-only infrastructure. The protocol is participant-agnostic by design. Narrowing it to agents alone would abandon the humans and systems that face the same accountability gap.'
fi

# === Conclusion (wp-s13) — 7 paragraphs ===
if [ -z "$SECTION" ] || [ "$SECTION" = "s13" ] || [ "$SECTION" = "wp-s13" ]; then
  generate 'wp-s13-p01.mp3' 'AI agents are the most urgent application — but the accountability gap they expose is not theirs alone. Any system where actions have consequences and trust cannot be left to good faith needs the same properties: cryptographic proof of attribution, sovereign refusal, auditable chains of authority.'
  generate 'wp-s13-p02.mp3' 'The structural problem is clear: trust primitives that are captured by platforms become leverage for extraction. Identity that lives in someone else'\''s database is not identity — it is a lease. Reputation that cannot be carried between systems is not reputation — it is a hostage. Authorization that can be silently revoked is not authorization — it is permission.'
  generate 'wp-s13-p03.mp3' 'ZeroPoint provides protocol-level primitives — receipts, chains, governance constraints, sovereign transport compatibility, and a privacy-preserving Presence Plane — that make any system'\''s actions provable and refusable, and its participants discoverable without surveillance. Agents are the most urgent application, and ZeroPoint is built to meet that urgency. But the primitives do not care who holds the keypair. A human'\''s actions are as provable as an agent'\''s. A team'\''s decisions are as auditable as a pipeline'\''s. The protocol serves everyone who participates in systems where trust matters.'
  generate 'wp-s13-p04.mp3' 'It does not solve AI safety. It does not solve trust generally. It makes trust portable — and portable trust is the structural antidote to the dependency loops that degrade every system where exit is too expensive.'
  generate 'wp-s13-p05.mp3' 'Make trust portable, and you make exit real. Make exit real, and you make extraction optional.'
  generate 'wp-s13-p06.mp3' 'Trust is infrastructure.'
  generate 'wp-s13-p07.mp3' 'Power will diffuse. Accountability must diffuse with it.'
fi

echo ""
echo "Done. Generated: $generated, Skipped: $skipped, Failed: $failed"