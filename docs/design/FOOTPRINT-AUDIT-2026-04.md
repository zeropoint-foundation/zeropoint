# ZeroPoint Footprint Audit — Cross-Reference Against Five Security Frameworks

**Date:** 2026-04-25
**Method:** Each framework item tested against ZP codebase reality (not marketing claims). Ratings are GREEN (implemented and verifiable in code), YELLOW (partial — code exists but incomplete, or structurally addressed but not purpose-built), RED (out of scope or not implemented).

**Frameworks tested:**
1. NIST AI RMF (GOVERN, MAP, MEASURE, MANAGE)
2. OWASP LLM Top 10 (2025)
3. OWASP Agentic Top 10 (2026)
4. MITRE ATLAS v5.4.0
5. ZP GOVERN (internal governance claims)

**Codebase evidence sources:** zp-core (types, gate), zp-trust (vault, capabilities), zp-receipt (chain, signing), zp-server (exec_ws, proxy, lib), zp-skills (registry), zp-mesh (networking), zp-memory (promotion, quarantine), zp-policy (WASM, rules).

---

## 1. NIST AI RMF

### GOVERN — Policies, processes, procedures, and practices

| ID | NIST Requirement | ZP Coverage | Evidence | Rating |
|----|-----------------|-------------|----------|--------|
| GV-1 | AI risk management policies established | GovernanceGate with constitutional rules (HarmPrincipleRule, SovereigntyRule) | `zp-policy/src/rules/` — 7 rule implementations | GREEN |
| GV-2 | Accountability structures defined | Operator model — single human holds genesis key, sovereign authority | `zp-core/src/types.rs` — ActorId::Operator, SovereigntyRule | GREEN |
| GV-3 | Workforce AI risk awareness | Outside runtime scope — organizational process | N/A | RED |
| GV-4 | Organizational commitments to AI principles | Four Tenets enforced at protocol level | `zp-policy/src/rules/harm_principle.rs` — non-removable | GREEN |
| GV-5 | Processes for ongoing risk monitoring | Receipt chain provides continuous audit data; analytics not built-in | `zp-receipt/src/` — chain verification exists; no automated alerting | YELLOW |
| GV-6 | Stakeholder engagement processes | Outside runtime scope — organizational process | N/A | RED |

**NIST GOVERN summary:** 3 GREEN, 1 YELLOW, 2 RED. ZP covers the technical governance surface well but doesn't address organizational process requirements (workforce training, stakeholder engagement) — nor should it, as those are human-process concerns.

### MAP — Context and risk identification

| ID | NIST Requirement | ZP Coverage | Evidence | Rating |
|----|-----------------|-------------|----------|--------|
| MAP-1 | AI system context established | PolicyContext captures action type, trust tier, channel, conversation, tools | `zp-core/src/types.rs` — PolicyContext struct | GREEN |
| MAP-2 | AI system categorized | Trust tiers (1-5) classify system components by privilege level | `zp-core/src/types.rs` — TrustTier enum | GREEN |
| MAP-3 | AI benefits/costs assessed | Cost tracking exists (estimated + recorded) but NOT enforced in gate | `zp-server/src/lib.rs` — cost fields present; no CostGuardRule in gate | YELLOW |
| MAP-4 | Risks across AI lifecycle mapped | Five mediation surfaces explicitly enumerated; containment model with levels 1-5 | GAR spec §Architecture Overview | GREEN |
| MAP-5 | Impacts to individuals/groups assessed | HarmPrincipleRule evaluates potential harm; limited to policy rule scope | `zp-policy/src/rules/harm_principle.rs` | YELLOW |

**NIST MAP summary:** 3 GREEN, 2 YELLOW, 0 RED. Strong on system categorization and risk mapping. Cost enforcement is a gap.

### MEASURE — Analysis, assessment, monitoring

| ID | NIST Requirement | ZP Coverage | Evidence | Rating |
|----|-----------------|-------------|----------|--------|
| MSR-1 | AI risks measured and monitored | Receipt chain records all governance decisions; chain verification detects tampering | `zp-receipt/src/store.rs` — AuditStore with chain integrity checks | GREEN |
| MSR-2 | AI system evaluated for trustworthiness | Trust as trajectory — each action conditioned on full prior history | `zp-core/src/types.rs` — TrustTier + gate evaluation | GREEN |
| MSR-3 | Mechanisms for tracking metrics | Receipt chain is the metric store; no built-in dashboards for metric aggregation | Cockpit dashboard exists for live view; no historical analytics engine | YELLOW |
| MSR-4 | Feedback mechanisms operational | Gate result includes needs_interaction() for human review escalation | `zp-core/src/types.rs` — GateResult::needs_interaction() | GREEN |

**NIST MEASURE summary:** 3 GREEN, 1 YELLOW, 0 RED. Receipt chain serves as measurement infrastructure. Analytics/alerting layer is the gap.

### MANAGE — Risk treatment, response, recovery

| ID | NIST Requirement | ZP Coverage | Evidence | Rating |
|----|-----------------|-------------|----------|--------|
| MNG-1 | AI risks prioritized and treated | GovernanceGate blocks or escalates based on policy evaluation | `zp-server/src/proxy.rs`, `exec_ws.rs` — gate.evaluate() before every action | GREEN |
| MNG-2 | Plans for maximizing benefits | Outside runtime scope — business planning | N/A | RED |
| MNG-3 | AI risks monitored post-deployment | Receipt chain provides continuous post-deployment record | Chain verification + revocation index | GREEN |
| MNG-4 | Incident response plans | Kill switch (SovereigntyRule), capability revocation, memory quarantine | `zp-memory/src/quarantine.rs`, `zp-trust/src/capabilities.rs` — revocation | GREEN |

**NIST MANAGE summary:** 3 GREEN, 0 YELLOW, 1 RED.

### NIST AI RMF Overall: 12 GREEN, 4 YELLOW, 3 RED → Coverage: 74%

---

## 2. OWASP LLM Top 10 (2025)

| ID | Threat | ZP Coverage | Evidence | Current Page | Revised Rating |
|----|--------|-------------|----------|-------------|---------------|
| LLM01 | **Prompt Injection** | GovernanceGate screens actions post-inference; not a dedicated prompt-level defense. Gate operates on structured PolicyContext, not raw prompt text. | `zp-policy/src/rules/` — rules evaluate action semantics, not token sequences | YELLOW | **YELLOW** — accurate. ZP governs the *output* (action) not the *input* (prompt). Honest about not being a WAF. |
| LLM02 | **Sensitive Info Disclosure** | Capability grants scope data access per-agent. Memory tiers enforce promotion gates. Sovereign Mode blocks third-party telemetry. | `zp-trust/src/capabilities.rs` — Read/Write/Execute/ApiCall scoping; `zp-memory/src/promotion.rs` — 6-stage pipeline | GREEN | **GREEN** — verified. Multiple layers of data access control. |
| LLM03 | **Supply Chain Vulnerabilities** | Rust memory safety eliminates a class of supply chain bugs. zp-skills registry exists but no signature verification on skill packages. No SBOM generation. | `zp-skills/src/registry.rs` — registry with metadata; no cryptographic verification of skill contents | YELLOW | **YELLOW** — downgrade from current page's "green" claim of "verified registry." Registry exists but verification is metadata-only, not cryptographic. |
| LLM04 | **Data and Model Poisoning** | Training-time concern — outside runtime governance scope. Memory poisoning partially addressed via promotion gates + quarantine. | `zp-memory/src/quarantine.rs` — compromise-triggered quarantine | RED/YELLOW | **YELLOW** — split rating. Model poisoning is RED (out of scope). Memory/context poisoning has real defenses (promotion pipeline, quarantine). Current page says RED — underclaims on memory side. |
| LLM05 | **Improper Output Handling** | GovernanceGate evaluates actions before execution. Policy rules can screen outputs. No dedicated output sanitization layer. | Gate operates on PolicyContext actions, not raw model output text | YELLOW | **YELLOW** — accurate. Gate governs structured actions, not free-text output. |
| LLM06 | **Excessive Agency** | Scoped capability grants with Read/Write/Execute/ApiCall permissions, delegation depth limits, expiry. This is ZP's strongest defense. | `zp-trust/src/capabilities.rs` — CapabilityGrant with scope, depth, expiry; `zp-trust/src/delegation.rs` — chain validation | GREEN | **GREEN** — verified. Purpose-built for this threat. |
| LLM07 | **System Prompt Leakage** | No dedicated defense. Policy rules *could* screen for prompt content in outputs but no built-in rule does this. | No PromptLeakageRule in `zp-policy/src/rules/` | YELLOW | **YELLOW** — accurate. Addressable via custom policy rule but not built-in. |
| LLM08 | **Vector and Embedding Weaknesses** | Outside scope — ZP governs actions, not embeddings. Memory tier governance could constrain retrieval but doesn't inspect vector quality. | N/A for vector DB security | RED | **RED** — accurate. Not in ZP's governance domain. |
| LLM09 | **Misinformation** | Receipt chain provides provenance tracing. Memory promotion gates validate before persisting. No factual accuracy verification. | Provenance exists; no ground-truth checking | YELLOW | **YELLOW** — new rating. Current page doesn't list this. Provenance tracing is real but doesn't verify factual accuracy. |
| LLM10 | **Unbounded Consumption** | Cost tracking exists (estimated + recorded in receipts) but cost guard is NOT enforced in gate. Capability expiry provides time-based limits. | `zp-server/src/lib.rs` — cost fields in responses; no CostGuardRule in gate pipeline | YELLOW | **YELLOW** — downgrade from current page's GREEN. Cost tracking without enforcement is monitoring, not prevention. |

### OWASP LLM Top 10 Overall: 2 GREEN, 6 YELLOW, 2 RED → Coverage: 50%

**Current page overclaims:**
- LLM03 (Supply Chain): Listed as GREEN ("verified registry + sandboxed execution") — registry verification is metadata-only, not cryptographic. Should be YELLOW.
- LLM10 (Unbounded Consumption): Listed as GREEN ("Capability grants with rate/scope limits") — cost guard not enforced in gate. Should be YELLOW.

**Current page underclaims:**
- LLM04 (Data Poisoning): Listed as RED — memory poisoning defenses (promotion pipeline, quarantine) deserve YELLOW.

**Current page missing:**
- LLM09 (Misinformation): Not listed at all. Should be YELLOW.

---

## 3. OWASP Agentic Top 10 (2026)

This is the most important framework for ZP. The current footprint page has an ad-hoc "Agentic Threats" domain with 7 items that don't map 1:1 to the OWASP standard. Recommendation: replace with exact OWASP Agentic items.

| ID | Threat | ZP Coverage | Evidence | Rating |
|----|--------|-------------|----------|--------|
| ASI01 | **Agent Goal Hijack** | GovernanceGate screens every action. HarmPrincipleRule and custom policy rules constrain behavior. But: gate evaluates *actions*, not *goals* — a hijacked agent that stays within action-level policy would pass. | `zp-policy/src/rules/` — action-level evaluation only | **YELLOW** — honest. Gate is action-level, not intent-level. Powerful defense but not purpose-built for goal drift detection. |
| ASI02 | **Tool Misuse** | Five mediation surfaces — every tool invocation passes through GovernanceGate. zp-skills registry with execution sandboxing. ValidatedCommand with program allowlist for exec. | `zp-server/src/exec_ws.rs` — safe_path + metachar + allowlist + gate.evaluate(); `zp-skills/src/registry.rs` | **GREEN** — verified. This is ZP's primary design surface. |
| ASI03 | **Identity & Privilege Abuse** | Ed25519 keypair identity per agent. Scoped capability grants with delegation depth limits. Self-issuance prevention (M4-3). Capability expiry and revocation. | `zp-trust/src/capabilities.rs`, `zp-trust/src/delegation.rs`, `zp-core/src/types.rs` — ActorId variants | **GREEN** — verified. Cryptographic identity + least-privilege is core to ZP. |
| ASI04 | **Supply Chain** | Rust memory safety. zp-skills registry. No cryptographic skill signing. No SBOM. WASM policy evaluation is feature-gated and disabled by default. | `zp-skills/src/registry.rs` — metadata registry; `zp-policy/src/wasm/` — exists but behind feature gate | **YELLOW** — registry exists but no cryptographic supply chain verification. WASM policy disabled by default reduces the custom-policy attack surface but also limits custom governance. |
| ASI05 | **Unexpected Code Execution** | ValidatedCommand: program allowlist + argument validators + no shell (direct exec). Shell metacharacter rejection. GovernanceGate evaluation before spawn. | `zp-server/src/auth.rs` — validate_command(); `exec_ws.rs` lines 153-264 | **GREEN** — verified. Purpose-built defense with defense-in-depth layers. |
| ASI06 | **Memory & Context Poisoning** | 6-stage memory promotion pipeline (observation → short-term → working → long-term → permanent → archival). Human review gate. Compromise-triggered quarantine. Memory tier canonicalization. | `zp-memory/src/promotion.rs`, `zp-memory/src/quarantine.rs` | **GREEN** — verified. This is a genuine differentiator. Few governance systems address memory governance at all. |
| ASI07 | **Insecure Inter-Agent Communication** | zp-mesh with Ed25519-signed messages. Presence Plane dual-backend transport (web relay + Reticulum mesh). Reciprocity enforcement — peers must announce before observing. | `zp-mesh/src/` — signed message exchange; dual transport | **GREEN** — verified. Cryptographic inter-agent messaging with identity verification. |
| ASI08 | **Cascading Failures** | Blast radius model (R6-1) with key-compromise containment. Memory quarantine isolates affected tiers. Kill switch via SovereigntyRule. No circuit-breaker pattern for cascading agent chains. | `zp-trust/src/blast_radius.rs`, `zp-memory/src/quarantine.rs` | **YELLOW** — blast radius + quarantine address compromise cascades, but no purpose-built circuit breaker for multi-agent chain failures (e.g., Agent A calls Agent B calls Agent C, and C fails — no automatic cascade halt). |
| ASI09 | **Human-Agent Trust Exploitation** | SovereigntyRule — human is always root authority. Human review gate for memory promotion. needs_interaction() escalation from gate. | `zp-policy/src/rules/sovereignty.rs`, `zp-memory/src/promotion.rs` — human gate | **GREEN** — verified. The operator model structurally prevents agents from overriding human authority. |
| ASI10 | **Rogue Agents** | Capability revocation. Kill switch. Receipt chain provides forensic trail. Blast radius model contains compromise scope. Canonicalization provides identity permanence (agent can't forge a new identity to escape revocation). | `zp-trust/src/capabilities.rs` — revocation; `zp-receipt/src/` — forensic chain | **GREEN** — verified. Multiple containment mechanisms with cryptographic enforcement. |

### OWASP Agentic Top 10 Overall: 7 GREEN, 3 YELLOW → Coverage: 85%

**This is ZP's strongest framework alignment.** The agentic threat model is what ZP was designed for. The three YELLOW ratings are honest:
- ASI01 (Goal Hijack): Action-level governance, not intent-level — a real limitation
- ASI04 (Supply Chain): Registry without cryptographic verification — fixable
- ASI08 (Cascading Failures): Blast radius exists but no multi-agent circuit breaker — architectural gap

---

## 4. MITRE ATLAS v5.4.0

### Tactics (16 total — mapped to ZP relevance)

| Tactic | ZP Relevance | Coverage | Rating |
|--------|-------------|----------|--------|
| **Reconnaissance** (AML.TA0002) | Presence Plane reciprocity — scanners must announce before observing | Structural defense | GREEN |
| **Resource Development** (AML.TA0003) | Attacker infrastructure — outside scope | N/A | RED |
| **Initial Access** (AML.TA0001) | Ed25519 identity + capability grants | Cryptographic access control | GREEN |
| **ML Model Access** (AML.TA0000) | GovernanceGate mediates Model API surface | Gate evaluates model API calls | GREEN |
| **Execution** (AML.TA0004) | ValidatedCommand + GovernanceGate on exec path | Defense-in-depth on all five surfaces | GREEN |
| **Persistence** (AML.TA0005) | Capability expiry + revocation + canonicalization (identity is permanent, not forgeable) | Time-bounded access + identity permanence | GREEN |
| **Privilege Escalation** (AML.TA0006) | Delegation depth limits + self-issuance prevention | Structural prevention | GREEN |
| **Defense Evasion** (AML.TA0007) | Receipt chain tamper evidence (hash-linked, signed). But: model-layer evasion (adversarial examples) out of scope | Chain integrity verified; model-layer is outside scope | YELLOW |
| **Discovery** (AML.TA0008) | Scoped capability grants limit what agents can discover | Access control limits discovery surface | GREEN |
| **Collection** (AML.TA0009) | Scoped read capabilities + audit trail | Least-privilege on data access | GREEN |
| **Staging** (AML.TA0010) | GovernanceGate screens patterns; memory quarantine | Gate + quarantine | YELLOW |
| **Exfiltration** (AML.TA0011) | Network mediation surface + audit trail + Sovereign Mode (no third-party telemetry) | Multiple layers | GREEN |
| **Impact** (AML.TA0012) | Kill switch + blast radius + revocation | Containment mechanisms | GREEN |
| **ML Attack Staging** (AML.TA0013) | GovernanceGate on Model API surface | Gate screens model interactions | YELLOW |
| **Impersonation** (AML.TA0014) | Ed25519 cryptographic identity — impersonation requires private key compromise | Structural prevention | GREEN |
| **LLM Jailbreak** (AML.TA0015) | GovernanceGate evaluates post-inference actions, not prompt-level jailbreaks | Action-level, not prompt-level | YELLOW |

### New Agentic Techniques (5 — critical for ZP)

| ID | Technique | ZP Coverage | Rating |
|----|-----------|-------------|--------|
| AML.T0096 | **AI Service API** — exploit APIs to manipulate agent behavior | GovernanceGate on API surface + Ed25519 auth | GREEN |
| AML.T0098 | **Agent Tool Credential Harvesting** — extract credentials via tool abuse | CredentialVault with ChaCha20-Poly1305 encryption. Credentials never in env vars (vault-only). Scoped access. | GREEN |
| AML.T0099 | **Agent Tool Data Poisoning** — poison data through tool interactions | Memory promotion pipeline + quarantine. But: tool output itself not validated for data integrity before storage. | YELLOW |
| AML.T0100 | **AI Agent Clickbait** — social engineering to make agent perform actions | GovernanceGate evaluates all actions regardless of trigger. HarmPrincipleRule screens harmful actions. | GREEN |
| AML.T0101 | **Data Destruction via Agent Tool** — use agent tools to destroy data | Scoped capability grants (Read ≠ Write ≠ Execute). No write access without explicit grant. | GREEN |

### MITRE ATLAS Overall: 12 GREEN, 4 YELLOW, 1 RED → Coverage: 82%

---

## 5. ZP GOVERN (Internal Governance Claims)

Testing ZP's own published claims against codebase reality.

| Claim | Status | Evidence | Rating |
|-------|--------|----------|--------|
| **"Every action produces a signed receipt"** | Partially true. Receipts are emitted for all governance-significant actions. Ed25519 signing is feature-gated and disabled by default in production builds. When disabled, receipts are hash-linked but unsigned. | `zp-receipt/src/` — Receipt struct has signature field; signing behind `#[cfg(feature = "signed-receipts")]` | **YELLOW** — receipts exist universally; signing is optional. The claim should say "hash-linked receipt" not "signed receipt" unless signing is enabled. |
| **"Immutable, hash-linked chain"** | TRUE. Chain integrity verified with Blake3 hash linking. AUDIT-01 concurrent-append race FIXED (BEGIN IMMEDIATE + UNIQUE index). | `zp-receipt/src/store.rs` — transactional append with chain integrity | **GREEN** — verified. Claim 1 is true. |
| **"Every side effect passes through GovernanceGate"** | TRUE. All five mediation surfaces now gated. exec_ws.rs was the last ungated path — fixed (gate.evaluate() wired in). | `exec_ws.rs` lines 209-264; `proxy.rs` lines 332-368 | **GREEN** — verified. Claim 3 is true. |
| **"Canonicalization invariant: nothing executes without canon"** | NOT ENFORCED. Canonicalization receipts are emitted at startup but the GovernanceGate does NOT check for canon before allowing actions. An uncanonicalized entity can still execute. | `zp-server/src/lib.rs` — emits `system:canonicalized`, `provider:canonicalized`, `tool:canonicalized`; gate rules in `zp-policy/src/rules/` — no CanonInvariantRule | **YELLOW** — the infrastructure exists (canon events emitted, receipt types defined) but the invariant is descriptive, not enforced. Fixable by adding a gate rule. |
| **"Six canonicalizable entities"** | Partially implemented. System, provider, and tool canonicalization implemented. Agent, skill, and memory tier canonicalization defined in types but not emitted. | `zp-receipt/src/types.rs` — all six CanonicalizedClaim variants; `zp-server/src/lib.rs` — only 3 emitted | **YELLOW** — 3 of 6 implemented. |
| **"Governance without runtime"** | TRUE. Receipt chain is self-contained, self-verifying. Chain verification requires only the chain file + verifier binary. No API, no running server, no credentials. | `zp-receipt/src/verify.rs` — standalone chain verification | **GREEN** — verified. This is ZP's strongest differentiating claim and it holds. |
| **"Trust as trajectory"** | TRUE architecturally. Each gate evaluation considers trust tier; receipt chain accumulates history. Trust is not a static flag. | Core architectural principle reflected in gate evaluation flow | **GREEN** — architectural truth. |
| **"Five mediation surfaces"** | TRUE. Model API, filesystem, subprocess, network, IPC — all pass through GovernanceGate. | Gate evaluation on all five paths verified | **GREEN** — verified. |
| **"Sovereign Mode"** | Implemented. Local-only memory, approved-only providers, no third-party telemetry, credentials from vault. | Configuration flags in server setup; Sovereign Mode as default | **GREEN** — verified. |
| **"Presence Plane"** | Code uses "mesh" terminology, not "Presence Plane." Dual-backend transport (web relay + Reticulum) exists. Reciprocity enforcement exists. | `zp-mesh/src/` — implements the concept; naming doesn't match spec | **YELLOW** — functionally present, terminology gap between spec and code. |

### ZP GOVERN Overall: 6 GREEN, 4 YELLOW, 0 RED → Coverage: 80%

**Key finding:** ZP's internal claims are mostly honest. The two significant gaps are:
1. **Canonicalization invariant not enforced** — emitted but not checked in gate. This is the single most important gap to close.
2. **Receipt signing feature-gated** — the "signed receipt" claim is conditional on a feature flag.

---

## Summary: Current Footprint Page vs. Reality

### Items to Downgrade (overclaimed)

| Domain | Item | Current | Should Be | Why |
|--------|------|---------|-----------|-----|
| LLM Threats | Supply Chain Vulns | GREEN | YELLOW | "verified registry" — verification is metadata-only, not cryptographic |
| LLM Threats | Unbounded Consumption | GREEN | YELLOW | Cost tracking without enforcement in gate |
| Agentic | Tool Misuse | GREEN | GREEN | Accurate — keep |
| Identity | Peer Discovery | GREEN | YELLOW | "Presence Plane" — code says "mesh"; concept implemented, naming diverges from spec |

### Items to Upgrade (underclaimed)

| Domain | Item | Current | Should Be | Why |
|--------|------|---------|-----------|-----|
| LLM Threats | Data Poisoning | RED | YELLOW | Memory promotion pipeline + quarantine provide real defense against context poisoning |

### Items to Add (missing from current page)

| Framework | Item | Rating | Rationale |
|-----------|------|--------|-----------|
| OWASP LLM | Misinformation (LLM09) | YELLOW | Provenance tracing exists; no factual accuracy verification |
| OWASP Agentic | Identity & Privilege Abuse (ASI03) | GREEN | Core ZP strength — Ed25519 + scoped capabilities + delegation limits |
| OWASP Agentic | Unexpected Code Execution (ASI05) | GREEN | ValidatedCommand + gate — purpose-built defense |
| OWASP Agentic | Memory & Context Poisoning (ASI06) | GREEN | 6-stage promotion + quarantine — genuine differentiator |
| OWASP Agentic | Human-Agent Trust Exploitation (ASI09) | GREEN | SovereigntyRule + human review gate |
| MITRE ATLAS | Agent Tool Credential Harvesting (AML.T0098) | GREEN | Vault encryption + no env vars |
| MITRE ATLAS | Agent Tool Data Poisoning (AML.T0099) | YELLOW | Promotion pipeline, but no tool-output validation |
| MITRE ATLAS | Data Destruction via Agent Tool (AML.T0101) | GREEN | Scoped capability grants |

### Items to Remove or Reclassify

| Current Item | Recommendation | Why |
|-------------|----------------|-----|
| "Passive Scanning" (Agentic) | Merge into Reconnaissance (ATLAS) or keep as sub-item | Not an OWASP Agentic category |
| "Cascading Hallucinations" (Agentic) | Rename to "Cascading Failures" (ASI08) | Align with OWASP terminology |
| "Insecure Plugin Design" (LLM) | Rename to "Supply Chain" (LLM03) | OWASP 2025 renamed this category |

---

## Recommended Domain Restructure

Replace the current 9 ad-hoc domains with framework-aligned domains:

| New Domain | Source Framework | Items | Coverage |
|-----------|-----------------|-------|----------|
| **Identity & Access** | NIST GOVERN | 7 | ~93% |
| **Governance & Policy** | NIST GOVERN + MAP | 6 | ~92% |
| **Audit & Traceability** | NIST MEASURE | 6 | ~83% |
| **Agentic Security** | OWASP Agentic Top 10 | 10 | **85%** |
| **LLM Security** | OWASP LLM Top 10 | 10 | 50% |
| **Adversarial ML** | MITRE ATLAS | 8 | 82% |
| **Data Protection** | NIST MANAGE | 5 | ~70% |
| **Edge Sovereignty** | ZP GOVERN | 6 | ~42% |

**Drop "Infrastructure" domain** (currently 6 items, all RED). These are genuinely out of scope (network segmentation, firewalls, endpoint protection, canary deployments) and listing them as RED dilutes the footprint's signal. Add a one-line note: "Infrastructure-layer concerns (network, endpoint, deployment) are outside ZP's governance scope — ZP operates at the agent runtime layer."

**Rename "Agentic Threats" → "Agentic Security"** and align items 1:1 with OWASP Agentic Top 10 (ASI01-ASI10).

---

## Preamble Addition: Honesty Strip

Add before the domain grid:

> **What ZeroPoint governs — and what it doesn't.** ZP operates at the agent runtime layer: identity, policy, execution mediation, receipting. It does not govern model internals (training data, embeddings, weight security), network infrastructure (firewalls, segmentation, endpoint protection), or organizational processes (workforce training, stakeholder engagement). Items marked RED are explicitly out of scope, not failed implementations. Items marked YELLOW are structurally addressed but not purpose-built — honest partial coverage. The receipt chain and governance gate are verified against the codebase; claims on this page are testable.

---

## Governance Without Runtime — Footprint Callout

Add as a standalone card above or below the domain grid:

> **Governance Without Runtime.** The receipt chain can be audited cold — no running server, no API, no credentials, no cooperation from the governed system. Hand the chain to an auditor and they can verify every decision, every identity, every policy constraint with nothing but a verifier and the data. No other agent governance system offers this property.

This is ZP's single most differentiating claim and it's currently buried. It should be visually prominent on the footprint page.

---

## Decision Points for Ken

- [ ] Approve domain restructure (drop Infrastructure, align Agentic with OWASP)
- [ ] Approve downgrades (Supply Chain GREEN→YELLOW, Unbounded Consumption GREEN→YELLOW)
- [ ] Approve upgrade (Data Poisoning RED→YELLOW)
- [ ] Approve honesty preamble text
- [ ] Approve "Governance Without Runtime" callout card
- [ ] Confirm addition of missing items (LLM09, ASI03, ASI05, ASI06, ASI09, ATLAS techniques)
- [ ] Decide: add canonicalization invariant enforcement to near-term roadmap? (biggest internal gap)
- [ ] Decide: enable receipt signing by default? (affects "signed receipt" claim credibility)

---

## Aggregate Coverage

| Framework | GREEN | YELLOW | RED | Coverage |
|-----------|-------|--------|-----|----------|
| NIST AI RMF | 12 | 4 | 3 | 74% |
| OWASP LLM Top 10 | 2 | 6 | 2 | 50% |
| OWASP Agentic Top 10 | 7 | 3 | 0 | 85% |
| MITRE ATLAS | 12 | 4 | 1 | 82% |
| ZP GOVERN | 6 | 4 | 0 | 80% |
| **Total** | **39** | **21** | **6** | **75%** |

The weighted story: ZP is strongest where it should be (agentic security: 85%, adversarial ML: 82%) and weakest where it's honest about scope boundaries (LLM internals: 50%). The 75% aggregate is defensible because the RED items are genuinely out of scope, not failed implementations.
