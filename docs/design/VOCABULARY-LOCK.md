# ZeroPoint Vocabulary Lock — Canonical Terms for Documentation Ripple-Out

**Purpose:** Binding glossary for all documentation, whitepaper, and website updates. Every ripple-out edit derives from these definitions. No synonyms, no drift, no ambiguity.

**Status:** Draft for Ken's approval. Lock before editing any external docs.

---

## Core Identity Terms

| Term | Definition | Usage Notes |
|------|-----------|-------------|
| **ZeroPoint** | Portable trust infrastructure — cryptographic governance primitives that make actions provable, auditable, and policy-bound. | Never "ZP" in public-facing prose (acceptable in code, internal docs, CLI output). Never "a framework" — it's infrastructure, a substrate. |
| **Governed Agent Runtime (GAR)** | The process-level containment and governance layer that runs autonomous AI agents as managed tenants. | Always expanded on first use per document. "GAR" acceptable after first expansion. Not "the GAR framework" — the GAR is a runtime, not a framework. |
| **Tenant** | An agent framework running inside a GAR instance as a managed process. | IronClaw is the first tenant. Hermes is the roadmap second tenant. Not "client," not "user," not "application." |
| **Operator** | The human who holds the genesis key and exercises sovereign authority over the system. | Not "admin," not "user." The operator is always human. Always singular — one operator per genesis. |

## Canonicalization Terms

| Term | Definition | Usage Notes |
|------|-----------|-------------|
| **Canonicalization** | The act of anchoring an entity to the genesis identity via a signed receipt chain. The only governance primitive that is *constitutive* — it establishes what *exists* rather than recording what happened. | The full word, not abbreviated. Verb form: "canonicalize." Past: "canonicalized." Never "canonize" (religious connotation). |
| **Canon** | The state of being canonicalized. An entity "has canon" or "has no canon." | Short form acceptable in flowing prose: "Without canon, an entity does not exist in the governance domain." Not a noun for the receipt itself — the receipt is a "canonicalization receipt." |
| **Canonical identity** | The cryptographic identity established by canonicalization. Lives in the receipt chain, not in the process. Survives restarts, upgrades, migrations. | Distinct from "configuration identity" (file on disk) or "process identity" (PID). The canonical identity is permanent; the others are ephemeral. |
| **Year Zero** | The moment an entity is first canonicalized — its origin epoch. | Use in spec prose and conceptual discussion. Avoid in diagrams and UI where neutral alternatives ("origin epoch," "genesis anchor") work without political connotation. |
| **Canonicalization invariant** | "Nothing executes in a governed context without a canon." Structural, not policy. | Always quote the full sentence when introducing the invariant. After introduction, "the invariant" or "the canon invariant" is acceptable. |
| **Canonicalization receipt** | The signed receipt that anchors an entity to the governance chain. Types: `system:canonicalized`, `agent:canonicalized`, `tool:canonicalized`, `provider:canonicalized`, `skill:canonicalized`, `memory:canonicalized`. | Not "canon receipt" (ambiguous). Not "identity receipt" (too generic). |
| **Canonicalization chain** | The specific receipt chain from genesis to an entity: `genesis → system → agent → {tools, providers, skills, memory}`. | Not "identity chain" or "trust chain" (the trust chain is broader). |
| **Six canonicalizable entities** | System, agent, tool, provider, skill, memory tier. | Always list all six when introducing the concept. Order matters: system first (closest to genesis), memory tier last (most derived). |
| **Six value propositions of canon** | Identity permanence, provenance, tamper evidence, downgrade resistance, trust portability, governance without runtime. | When listing, always in this order. When referencing one, use the exact phrase. |

## Receipt and Chain Terms

| Term | Definition | Usage Notes |
|------|-----------|-------------|
| **Receipt** | A signed, hash-linked, timestamped record of a governance event. The atomic unit of the audit chain. | Not "log entry," not "event," not "record." A receipt is cryptographic proof, not a log line. |
| **Receipt chain** | The immutable, hash-linked sequence of all receipts. The chain *is* the state — not a record of the state. | Always "receipt chain," not "audit chain" (audit is what you do with the chain, not what the chain is). Exception: "audit trail" is acceptable in compliance/marketing contexts where the audience expects it. |
| **Wire** | A logical partition of the receipt chain scoped to a specific governance domain (e.g., `cognition:inference:ironclaw`, `gate:tool:start:ironclaw`). | Technical term for the abacus visualization. Not "stream," not "channel." |
| **Bead** | A receipt's position on a wire. The visual metaphor — beads on a wire. | Only in visualization/UI contexts. In governance prose, use "receipt." |
| **Claim** | A receipt's assertion about what happened. The semantic content of a receipt. | "A receipt makes a claim." Not interchangeable with "receipt" — the receipt is the envelope; the claim is the content. |

## Architecture Terms

| Term | Definition | Usage Notes |
|------|-----------|-------------|
| **Dispatch gate** | The governance gate that evaluates every action before execution. Also "governance gate" or "the gate." | Not "firewall," not "filter," not "guard" (guard is the Rust struct name but too generic for prose). |
| **Five mediation surfaces** | Model API, filesystem, subprocess, network, IPC — the five places where an agent touches the outside world. | Always five. Always in this order. If listing, name all five. |
| **Containment level** | The isolation tier (1–5) from bare process + gate through container/VM. | Not "security level" — containment is orthogonal to trust. Level 1 with a robust gate is more trustworthy than Level 5 with a bypassed gate. |
| **Sovereign Mode** | The hardened default configuration: local-only memory, approved-only providers, no third-party telemetry, all credentials from ZP vault. | Capital S, capital M. Always two words. Not "sovereign deployment" or "sovereign instance." |

## Protocol Terms

| Term | Definition | Usage Notes |
|------|-----------|-------------|
| **MCP** | Model Context Protocol. Agents↔tools. ZP both consumes (as a tool provider) and exposes (as a governance server). | Never expand after first use — the abbreviation is industry-standard. |
| **MCP Apps** | The MCP extension pattern where tools declare `_meta.ui.resourceUri` for interactive HTML rendering. | Always "MCP Apps" (two words, capital A). Not "MCP UI" or "MCP widgets." |
| **AG-UI** | Agent-UI protocol for streaming real-time events to frontends. | Hyphenated. Not "AGUI" or "ag-ui." |
| **A2UI** | Declarative UI-as-data protocol. Structured JSON-L component assembly. | Not "A2-UI" or "a2ui." |
| **Component catalog** | `zp-governance-catalog.json`. The Layer 2 contract between receipt chain data and transport adapters. | "Governance component catalog" on first use, then "the catalog" or "component catalog." Not "UI catalog." |

## Thesis Terms

| Term | Definition | Usage Notes |
|------|-----------|-------------|
| **Portable trust** | Trust that lives in the protocol layer, not in a platform database. Carried by the participant, verified by anyone. | The founding thesis. Every ZP document should connect back to this. |
| **Trust as trajectory** | Trust is not a state to be checked but a trajectory to be verified. Each moment conditioned on the full prior history. Autoregressive. | The theoretical foundation. Not a marketing tagline — it's the computational principle. |
| **Autorecursive trust substrate** | ZP's self-description in technical contexts. Autorecursive because the system improves by governing itself. | "Autorecursive," not "autoregressive" when describing the *system* (the system recurses on its own governance). "Autoregressive" when describing the *computational principle* (sequential unfolding conditioned on prior context). |
| **Receipts are canonical, protocols are projections** | The receipt chain is the single source of truth. All UI protocols project from it. | Architectural principle. Use when discussing the three-layer UI architecture. |
| **Governance without runtime** | The receipt chain can be audited cold — no running process, no API, no credentials, no cooperation from the governed system. An external auditor with nothing but the chain and a verifier can confirm the governance posture of the entire system. This is governance as data, not governance as software. | See expanded treatment below. This is ZP's single most differentiating claim and should be named explicitly in every public-facing document. |

---

## Governance Without Runtime — Expanded Treatment

Every other agent governance system on the market today is governance-as-software. The governance exists only while the software is running. Turn it off and the governance disappears. Want to know whether an agent was governed last Tuesday at 3am? Check the logs — if they exist, if they haven't been rotated, if the logging service was running, if the database is accessible, if you have credentials to query it. The answer to "was this governed?" depends on the availability of an entire software stack.

ZeroPoint's receipt chain inverts this. The chain is a self-contained, self-verifying cryptographic artifact. Every receipt is signed. Every receipt is hash-linked to its predecessor. Every signature traces back to the operator's genesis key. The chain carries its own proof. You can copy it to a USB drive, hand it to an auditor who has never seen your system, and that auditor can — with nothing but the chain file and a verifier binary — confirm: which entities were canonicalized, what policy decisions were made, whether the chain is intact or tampered with, and whether every action traces back to a legitimate authority. No API calls. No running server. No network access. No cooperation from anyone.

This is the property that makes the other five value propositions of canonicalization durable. Identity permanence means nothing if the identity is only queryable while a server is up. Provenance means nothing if the provenance database can be wiped. Tamper evidence means nothing if the evidence requires the tampered system to serve it. Governance without runtime is what makes all of these properties *unconditional* — they survive the shutdown, the migration, the bankruptcy, the acquisition, the infrastructure failure, and the adversarial compromise of the governed system itself.

The connection to the broader thesis is direct. "Trust as trajectory" says trust is the accumulated history, not a snapshot. Governance without runtime says that accumulated history is a portable, self-proving artifact — not a database query. "Receipts are canonical, protocols are projections" says the receipt chain is the source of truth. Governance without runtime says that source of truth doesn't need software to be true. The chain *is* the governance. The runtime is just how you add to it.

**For public-facing use,** the claim should be stated plainly:

> Other systems are governed while they're running. ZeroPoint is governed while it exists. The receipt chain can be audited cold — no server, no API, no credentials, no cooperation. Hand the chain to an auditor and they can verify every decision, every identity, every policy constraint, with nothing but a verifier and the data. Governance as data, not governance as software.

**Where this should appear:**

- **Whitepaper abstract:** Name it. "The receipt chain can be audited without a running system" in the first paragraph.
- **Website hero or value props:** One of the three cards. "Governed even when it's off."
- **Footprint:** This is a coverage claim no competitor can match — call it out in the preamble.
- **README:** Add to the architecture section.
- **llms.txt:** Add as a core primitive.
- **Investor/partner conversations:** Lead with it. It's the sentence that makes people stop and think.

---

## Unified Thesis Paragraph

> ZeroPoint is portable trust infrastructure — cryptographic governance primitives that make actions provable, auditable, and policy-bound without requiring central control. Every significant action produces a signed receipt, hash-linked into an immutable chain that *is* the system's state, not a record of it. Every governed entity — agent, tool, provider, skill, memory tier — is canonicalized: cryptographically anchored to the operator's genesis identity via a signed receipt chain. Without canon, an entity does not exist in the governance domain. With canon, its identity is permanent, its provenance is verifiable, its trust is portable. The receipt chain can be audited cold — no running server, no API, no credentials, no cooperation from the governed system. Hand the chain to an auditor and they can verify every decision, every identity, and every policy constraint with nothing but the data and a verifier. This is governance as data, not governance as software. The Governed Agent Runtime enforces these primitives at the process boundary, running autonomous AI agents as managed tenants where every I/O surface is mediated, receipted, and policy-gated. Trust is not a state to be checked — it is a trajectory to be verified, and ZeroPoint makes trajectories portable, provable, and permanent.

**Usage:** This paragraph (or a subset) should appear in recognizable form in the whitepaper abstract, the README introduction, the website hero section, and the llms.txt header. Each venue adapts the length and emphasis but preserves the load-bearing claims: portable trust, signed receipts, canonicalization, governance without runtime, GAR as process-level governance, trust as trajectory.

---

## Grammar and Formal Terms

| Term | Definition | Usage Notes |
|------|-----------|-------------|
| **Grammar** | The formal specification of what constitutes a well-formed ZeroPoint system. Consists of productions (rules for extending a chain) and invariants (properties of the whole derivation). | Not "rules," not "policies." The grammar is the formal system; policies are one input to the grammar. See `docs/foundations/INVARIANT-CATALOG-v1.md`. |
| **Production** | A rule for extending a chain. Checked when a new receipt arrives. Six productions: P1 (chain extension), P2 (delegation), P3 (authorized action), P4 (introduction), P5 (discovery), P6 (canonicalization). | "Production" in the formal language sense — a rule that produces well-formed derivations. Not "rule" (ambiguous with policy rules). |
| **Invariant** | A property of the *whole* derivation that must hold at every step. Thirteen invariants (M1–M13) covering gate coverage, constitutional persistence, chain continuity, monotonicity, identity, sovereignty, refusal, genesis, amnesia, reciprocity, canonicalization, governance-without-runtime, and non-repudiation. | Always reference by number when precision matters: "M1 (gate coverage)." Not interchangeable with "constraint" or "rule" — invariants are properties of the system, not instructions to it. |
| **Well-formed** | A chain that satisfies all productions and invariants at every step. The grammar's accept condition. | Hyphenated as an adjective: "a well-formed chain." Not "valid" (too generic) or "compliant" (implies regulation). |
| **Ungrammatical** | A chain that violates any production or invariant. Binary, local-to-detect, global-in-consequence: a single broken production rejects the chain from that point forward. | The formal term for a governance failure. Not "invalid," not "corrupted." An ungrammatical chain may be intact data — it's the governance derivation that's broken, not the data structure. |
| **Falsifier** | The specific, executable test that would prove a claim false. Every claim and invariant has one. | Not "test" (too generic). A falsifier is adversarial by design — it's trying to break the claim, not confirm it. |
| **Falsification** | The act of running a falsifier. Decisive: a single falsifying result disproves a claim. Confirmation is provisional; falsification is conclusive. | The methodology term. See `docs/foundations/CLAIM-METHODOLOGY.md`. |
| **Monotonicity** | The property that a sequence is non-decreasing (timestamps) or strictly increasing (delegation depth). Invariant M4 (trajectory monotonicity). | "Trajectory monotonicity" when referring to the invariant. "Temporal monotonicity" for timestamps specifically. "Depth monotonicity" for delegation chains. Not "ordering" — monotonicity is a specific mathematical property. |
| **Constitutive** | An act that establishes what *exists* rather than recording what happened. Canonicalization is the only constitutive governance primitive. | Contrast with "regulative" (constraining behavior of things that already exist). A constitutive rule creates the entity; a regulative rule governs it. The distinction is from speech act theory (Searle). |
| **Conservation property** | A property that is preserved regardless of the process that transforms the system. "Governance without runtime" is a conservation property — governance state survives shutdown, migration, bankruptcy. | The physics analogy is intentional and precise. Not "persistence" (implies storage) or "durability" (implies infrastructure). Conservation is a property of the formal system, not of the hardware. |

## Modal Layer Terms

| Term | Definition | Usage Notes |
|------|-----------|-------------|
| **Required (☐)** | The modal layer of things that must hold in every reachable state. Constitutional rules, trajectory invariants, conservation properties. | The box operator from modal logic. Use "Required layer" in prose; ☐ in formal notation. |
| **Possible (◇)** | The modal layer of what is still reachable from the current state. The delegation envelope — the space of authorized futures, narrowed by the accumulated chain. | The diamond operator. Use "Possible layer" in prose; ◇ in formal notation. |
| **Actual** | The modal layer of what has actually been derived. The chain itself — what was signed, when, by whom, in what order. | No operator symbol. "Actual layer" in prose. The chain is the actual. |
| **Accumulated context (Γ)** | Everything derived up to now. The full chain at the moment of evaluation. Every gate decision is a function of Γ, not just the current request. | Use Γ in formal notation; "accumulated context" in prose. Not "state" — Γ is the full history, not a snapshot. |
| **Cross-layer coherence** | The requirement that Required, Possible, and Actual agree at every step. Four rules: X1 (Possible ⊆ Required), X2 (Actual ⊆ Possible at time of action), X3 (Required holds for the sequence, not just each receipt), X4 (canon precedes participation). | "Cross-layer" hyphenated. These are the hardest invariants to check — they involve relationships between layers, not properties within one layer. |

## Methodology Terms

| Term | Definition | Usage Notes |
|------|-----------|-------------|
| **Claim** (methodology sense) | A falsifiable proposition about the system's behavior. Five components: statement, mechanism, catalog rule, falsifier, status. | Distinct from "claim" in the receipt sense (a receipt's assertion about what happened). Context disambiguates. When ambiguity is possible, "whitepaper claim" or "receipt claim." |
| **Status register** | The dated, append-only log of a claim's status transitions. Never retroactively edited. Shows when a claim went TRUE → FALSE and back. | Not "changelog" (implies code). The register is evidence of intellectual honesty — it shows the history of what we thought was true and when we learned otherwise. |
| **Overclaim** | A claim that asserts more than the mechanism delivers. Identified during overclaim audits. The asymmetry rule: always acceptable to downgrade a claim, never acceptable to upgrade without evidence. | The term for the most common form of intellectual dishonesty in infrastructure projects. An overclaim is worse than a gap — a gap is honest; an overclaim is misleading. |
| **Proof obligation** | Something the catalog requires but the implementation does not yet provide. Tracked in the open obligations register. | Not "TODO" (implies it will be done). Not "gap" (too casual). A proof obligation is a formal debt — the catalog says it must be true, and the project owes the proof. |

## Truth Anchoring Terms

| Term | Definition | Usage Notes |
|------|-----------|-------------|
| **Truth anchor** | An external, independently verifiable proof that the receipt chain existed in a specific state at a specific moment. Published to a distributed ledger (Hedera, Ethereum L2, Bitcoin, etc.) or timestamp authority. Anchoring is situational — it happens when there's a reason (dispute, audit, handoff, compliance checkpoint, cross-mesh introduction), not on a schedule. | "Truth anchor" — two words, lowercase unless starting a sentence. Not "blockchain proof" (not all backends are blockchains). Not "notarization" (legal connotation). The `zp-anchor` crate implements this. |
| **Anchor commitment** | The data published to an external ledger: the chain head hash, chain sequence number, previous anchor hash (linking anchor history), operator signature, and chain type. | Not "anchor transaction" — the commitment is what ZP publishes; the transaction is what the ledger produces. |
| **Anchor receipt** | The external ledger's proof that a commitment was published: the ledger's transaction ID, consensus timestamp (from the ledger's clock), the original commitment, and opaque ledger-specific proof data. | Not "blockchain receipt" — the receipt comes from whatever backend is configured. Distinct from ZP's own receipt (governance event) — an anchor receipt is proof of external publication. |
| **TruthAnchor trait** | The pluggable interface that any DLT backend implements: `anchor()`, `verify()`, `query_range()`. DLT-agnostic by design. | In code/technical contexts. In prose: "truth anchor interface" or "anchor backend." |
| **Optional enrichment** | The design principle that truth anchoring is additive. If no anchor backend is configured, ZP operates with full local chain integrity. DLT adds external verifiability — it doesn't replace internal verification. The chain doesn't get *more true* by being externally witnessed — it's already true (M3, M12). Anchoring is for proving the chain's state to someone who doesn't have the chain yet, or creating an irrefutable timestamp that survives operator compromise. | This is important: ZP is NOT a blockchain project. Blockchain anchoring is an optional enrichment layer. |
| **Opportunistic anchoring** | When the operator makes any blockchain transaction for any purpose, the current chain head hash is embedded as metadata — creating a truth anchor at zero marginal cost. Anchoring is a natural byproduct of existing activity, not a separate scheduled concern. | The primary anchoring model. Not cadence-based, not periodic. Anchoring happens when there's a transaction happening anyway, or when there's a governance reason to anchor (audit, handoff, dispute). |
| **Cross-mesh anchor verification** | Two peers exchange anchor backend identifiers (e.g., HCS topic IDs) and each independently queries the other's anchor history on the external ledger. Trust established via shared external proof, not mutual cooperation. | The mechanism for cross-deployment trust verification. Connects to P4 (Introduction production). |

## Architecture Terms (Additions)

| Term | Definition | Usage Notes |
|------|-----------|-------------|
| **Genesis (Ω)** | The initial condition of the system. Sealed exactly once per deployment. Referenced transitively by every certificate and receipt. The Big Bang. | Use Ω in formal notation; "Genesis" (capital G) in prose. Not "initialization" — Genesis is constitutive, not procedural. |
| **Constitutional rules** | HarmPrincipleRule and SovereigntyRule. Non-removable, non-reorderable, evaluated at positions 0 and 1 of every PolicyEngine. The conservation laws of the governance system. | Always both together. Not "default rules" — constitutional rules are not configurable. Not "safety rules" — too generic. |
| **Delegation chain** | An ordered sequence of capability grants from root (operator-held) to leaf (most-delegated agent), verified against eight invariants. Authority can only narrow. | Not "permission chain" or "access chain." Delegation is the specific mechanism: the grantor delegates a subset of their authority to the grantee. |
| **Authority narrowing** | The property that delegation can only narrow scope, time, trust tier — never widen. Each step in a delegation chain is a subset of the previous step. | The defining property of P2. Not "least privilege" (which is a policy goal). Authority narrowing is a structural property — the grammar makes widening ungrammatical. |
| **Structural amnesia** | The property that the Presence Plane relay retains no logs, state, or index. Subpoena-proof by design: there is nothing to subpoena. | Not "privacy" (too broad). Structural amnesia is specific: the relay *cannot* remember, not *will not* remember. The architecture makes remembering impossible. |
| **Blast radius** | The scope of impact from a key compromise. Modeled explicitly: which entities are affected, which capabilities must be revoked, which memory tiers must be quarantined. | Not "impact assessment" (process, not model). The blast radius is a computed property of the key hierarchy — it's deterministic, not estimated. |
| **Kill switch** | The operator's ability to revoke any capability immediately via SovereigntyRule. Irrevocable within the current chain — restoring authority requires a new grant (a new receipt). | Not "emergency stop" or "circuit breaker." The kill switch is a governance primitive, not an infrastructure failsafe. |

## Anti-Patterns (Do Not Use)

| Wrong | Right | Why |
|-------|-------|-----|
| "ZP framework" | "ZeroPoint" or "ZP substrate" | It's infrastructure, not a framework |
| "canonize" | "canonicalize" | Avoids religious connotation |
| "canon receipt" | "canonicalization receipt" | Precision |
| "audit chain" | "receipt chain" | The chain is receipts; audit is an activity |
| "trust level" | "trust tier" | Tiers are graduated; levels imply hierarchy |
| "guardrail" | "governance gate" or "dispatch gate" | Guardrails are passive; the gate actively decides |
| "wrapper" | "runtime" or "containment layer" | ZP is not bolted on from outside |
| "plugin" | "governance primitive" | Plugins are optional; these are constitutive |
| "logging" | "receipting" | Logs are best-effort; receipts are cryptographic |
| "identity token" | "canonical identity" | Tokens expire; canonical identity is permanent |
| "valid chain" | "well-formed chain" | Well-formedness is a grammar property, not a data property |
| "invalid" | "ungrammatical" | The governance derivation is broken, not the data |
| "test" (for falsifiers) | "falsifier" | A falsifier is adversarial by design |
| "TODO" (for obligations) | "proof obligation" | A formal debt, not a task list item |
| "safety rules" | "constitutional rules" | Constitutional rules are non-removable; "safety" implies optional |
| "persistence" (for GWR) | "conservation" | Governance without runtime is a conservation property, not a storage feature |
| "state" (for Γ) | "accumulated context" | Γ is the full history, not a snapshot |
| "permission chain" | "delegation chain" | Delegation is authority narrowing, not permission granting |

---

## Lock Confirmation

- [ ] Ken approves vocabulary table
- [ ] Ken approves unified thesis paragraph
- [ ] Ken approves anti-patterns list
- [ ] GAR spec review complete (no pending tweaks)

Once all four boxes are checked, ripple-out begins.
