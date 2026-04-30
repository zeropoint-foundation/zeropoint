# ZeroPoint Formal Primitives

**Date:** 2026-04-25
**Purpose:** Precise statement of the four formal contributions that distinguish ZeroPoint from prior work in agent governance. Each primitive is defined, its properties stated, its relationship to established formalisms noted, and its novelty claim made explicit.

This document is for people who build on ideas — researchers, formal methods practitioners, protocol designers, and anyone who wants to know what's new here versus what's well-known restated in new vocabulary.

---

## Primitive 1: Canonicalization as Constitutive Act

### Statement

Canonicalization is the act of anchoring an entity to the genesis identity via a signed receipt chain. It is the only governance primitive that is *constitutive* — it establishes what exists rather than recording what happened.

An entity without a canonicalization receipt does not exist in the governance domain. It has no canonical identity, no provenance, no trust relationship, no governance obligations, and no governance protections. It is not "ungoverned" — it is *ontologically absent*.

### Properties

**Existence is earned, not assumed.** Most governance systems assume the existence of the entities they govern — agents, tools, credentials — and then apply policies to them. Canonicalization inverts this: nothing exists until the governance system says it does, and the act of saying so is itself a cryptographic commitment by the operator.

**Existence is permanent.** A canonicalized entity's identity survives restarts, upgrades, migrations, and infrastructure failures. The canonical identity lives in the receipt chain, not in the process, the configuration file, or the database. This distinguishes it from process identity (PID — ephemeral), configuration identity (file on disk — mutable), and session identity (token — expirable).

**Existence is ordered.** The six canonicalizable entity types form a chain: `genesis → system → agent → {tools, providers, skills, memory tiers}`. Each entity's canonicalization receipt references its parent's. System is closest to genesis; memory tier is most derived. This ordering is structural — you cannot canonicalize a tool without first canonicalizing the system and agent it belongs to.

**The invariant is constitutive, not regulatory.** "Nothing executes in a governed context without a canon" is not a policy choice. It is a structural constraint analogous to type safety: a well-typed program cannot produce a type error not because someone checked, but because the construction makes the error impossible. The canonicalization invariant, when fully enforced, will make ungoverned execution structurally impossible rather than policy-prohibited.

### Relationship to Prior Work

The closest analogue is the concept of *constitution* in speech act theory (Searle, 1995): certain acts don't describe pre-existing reality but bring new institutional facts into existence. A marriage ceremony doesn't record a marriage — it *creates* one. Canonicalization plays the same role for governance identity.

In formal systems, this is related to *introduction rules* in natural deduction: a rule that establishes the existence of a term. Canonicalization is the introduction rule for governance entities. Without it, the entity cannot appear in any derivation.

In distributed systems, the closest mechanism is *certificate issuance* in PKI. But PKI certificates assert identity claims about pre-existing entities. Canonicalization is stronger: the entity does not pre-exist the canonicalization. The receipt *is* the entity's origin.

### Novelty Claim

No existing agent governance system treats entity existence as a cryptographic commitment by the operator. Existing systems assume entities exist and apply policies. ZeroPoint requires the operator to explicitly constitute each entity, creating a signed receipt that anchors it to the genesis identity. This is a genuinely novel primitive in the agent governance domain.

---

## Primitive 2: Trust as Trajectory

### Statement

Trust is not a state to be checked but a trajectory to be verified. Each moment in the system's history is conditioned on the full prior history. The system is autoregressive: the present is a function of all prior context, not just the most recent state.

### Properties

**Non-Markovian.** Most access control systems are Markovian — they check the current state (is this token valid? does this role have this permission?) without reference to history. ZeroPoint's receipt chain makes every decision a function of the full accumulated context Γ. A receipt that would be valid in isolation can be ungrammatical in context (see cross-layer rule X3 in the Invariant Catalog).

**The chain is the state, not a record of the state.** This is the most commonly misunderstood property. In conventional systems, the audit log records what happened, and the state is stored separately (in a database, in memory, in configuration). In ZeroPoint, the receipt chain *is* the state. There is no separate state to get out of sync with the log. The chain is not evidence about the system — it is the system.

**Trust accumulates and narrows.** The delegation production (P2) ensures authority can only narrow along a delegation chain — never widen. Trust is not granted and then expanded; it is granted and then progressively constrained. The trajectory is monotonically narrowing in the authority dimension.

**Autoregressive vs. autorecursive.** Two related but distinct properties. The *computational principle* is autoregressive: sequential unfolding where each step is conditioned on all prior context, like a language model generating tokens. The *system property* is autorecursive: the system governs its own governance — the governance gate's decisions are themselves receipted into the chain, which conditions future gate decisions. The system's governance is an input to its own governance.

### Relationship to Prior Work

The autoregressive framing connects to sequential Bayesian inference: each observation updates a posterior that conditions all future inference. The receipt chain is the accumulated evidence; each new receipt is an observation; the gate evaluation is the posterior update.

The "chain is the state" property connects to event sourcing in software architecture (the event log is the source of truth, all other views are projections). ZeroPoint adds cryptographic integrity (hash-linking, signing) and a formal grammar that makes "well-formed event sequence" a precise, testable property rather than an application-level convention.

The autorecursive property is novel. Self-referential governance — where the governance system's own decisions are subject to its own governance — creates a fixed-point structure. The system is governed iff its governance of itself is governed. This is reminiscent of reflective towers in programming language theory (Smith, 1984) but applied to trust infrastructure rather than computation.

### Novelty Claim

Individual pieces exist in prior work: event sourcing (chain as state), Bayesian updating (sequential conditioning), capability-based security (narrowing authority). The novel contribution is their composition into a coherent formal model where trust is a verifiable trajectory with cryptographic integrity, autoregressive conditioning, and autorecursive self-governance.

---

## Primitive 3: Governance Without Runtime

### Statement

The receipt chain can be audited cold — no running server, no API, no credentials, no network access, no cooperation from the governed system. An external auditor with nothing but the chain file and a verifier binary can confirm: which entities were canonicalized, what policy decisions were made, whether the chain is intact or tampered with, and whether every action traces back to a legitimate authority.

### Properties

**Governance as data, not governance as software.** Every other agent governance system on the market is governance-as-software: the governance exists only while the software is running. Turn it off and the governance disappears. ZeroPoint's governance is governance-as-data: the receipt chain is a self-contained artifact that carries its own proof.

**A conservation property.** In physics, a conservation law says a quantity is preserved regardless of the process that transforms the system. Governance without runtime is the conservation law of trust: the governance state is conserved regardless of whether the system is running, migrated, acquired, destroyed, or adversarially compromised. The chain's validity does not depend on the chain's origin system continuing to exist.

**Unconditional invariants.** This property is what makes the other invariants *unconditional*. Identity permanence (M5) means nothing if identity is only queryable while a server is up. Provenance (M13) means nothing if the provenance database can be wiped. Tamper evidence (M3) means nothing if the evidence requires the tampered system to serve it. Governance without runtime is the meta-property that makes all other properties survive the worst case.

**Verifiable by adversaries.** The strongest form of the property: the auditor does not need to trust the governed system, its operator, or anyone associated with it. The chain carries its own proof. A hostile auditor produces the same verification result as a friendly one. This is analogous to the verifiability property of zero-knowledge proofs, applied to governance history rather than computation.

### Relationship to Prior Work

Blockchain systems share the "self-verifying chain" property but require consensus mechanisms, network participation, and typically a running node to verify. ZeroPoint's chain is a single-writer, single-verifier artifact — no consensus needed, no network participation, no running node.

Certificate transparency logs (Laurie et al., 2013) share the append-only, verifiable-by-anyone property. ZeroPoint extends this from certificate issuance events to the full governance history of an autonomous system.

Git's content-addressable object store is hash-linked and self-verifying. ZeroPoint adds Ed25519 signatures, a formal grammar of well-formedness, and governance semantics.

### Extension: External Truth Anchoring

Governance without runtime proves the chain is self-verifying. External truth anchoring extends this guarantee across organizational boundaries by publishing the chain's state to an independent distributed ledger. Crucially, in the deployment scenarios where this extension matters — cross-organizational transactions, regulated exchanges, multi-party trust — ledger infrastructure is already present. The parties are already paying for consensus and immutable publication as part of the transaction itself. Governance anchoring piggybacks on that existing infrastructure at effectively zero marginal cost.

**The conservation property holds.** An anchor does not change the chain — it adds an external timestamp to an existing state. The chain's internal integrity is unaffected by whether anchoring is configured, whether the ledger is reachable, or whether the anchor receipt is valid. The anchor is a *witness*, not a *dependency*. This is a strict enrichment: the set of things provable with an anchor is a superset of the set provable without one.

**The cold-auditability property extends.** Anchor receipts are stored in the chain as regular entries. An auditor who verifies the chain cold will see the anchor receipts and can *optionally* verify them against the external ledger. But the chain verification does not require the ledger to be reachable — the anchor receipts are chain entries first, ledger references second. This means the "governance without runtime" guarantee covers the anchoring layer itself: even the external witnessing proof is auditable without the external system.

**Event-driven, not cadence-based.** The chain does not get "more true" by being witnessed more often. Anchoring is triggered by governance events — operator request, cross-mesh introduction, compliance checkpoint, dispute, or opportunistically when a blockchain transaction is already in flight. This reflects the actual trust relationship: the chain's integrity is self-contained; the ledger provides a public clock and an independent witness. External witnessing is valuable when something is at stake, not on a timer.

**DLT-agnostic.** The `TruthAnchor` trait defines three methods (`anchor()`, `verify()`, `query_range()`) that any distributed ledger backend can implement. The reference implementation targets Hedera Hashgraph's Consensus Service (HCS). The trait ensures that the choice of ledger is the operator's sovereign decision, not a protocol dependency.

**Cross-mesh trust via shared anchors.** When two ZeroPoint deployments exchange anchor backend identifiers, each can independently query the other's anchor history on the external ledger. Trust between strangers is established through shared external proof — not mutual cooperation, not a central authority, not trust-on-first-use. The anchor history is itself a trajectory: ordered, timestamped, publicly verifiable.

### Novelty Claim

The property itself — governance verifiable without the governed system running — has no direct precedent in agent governance. Blockchains require running nodes. Log aggregators require running servers. Audit databases require running databases. ZeroPoint's receipt chain requires nothing but itself and a verifier. This is the project's single most differentiating claim.

The truth anchoring extension adds a second novelty: a governance system that is self-sufficient but *optionally* externally witnessed, where the witnessing proof is itself stored in the self-verifying chain. This creates a layered trust model — internal integrity is unconditional, external verifiability is available when the governance context demands it — that no other agent governance system offers.

---

## Primitive 4: Receipts Are Canonical, Protocols Are Projections

### Statement

The receipt chain is the single source of truth. All user interfaces, API responses, dashboard views, analytics, and external protocol representations are *projections* from the chain. They do not add information; they present it. If a projection contradicts the chain, the projection is wrong.

### Properties

**Three-layer architecture.** Layer 1: the receipt chain (canonical, cryptographic, immutable). Layer 2: the component catalog (`zp-governance-catalog.json` — the contract between chain data and transport adapters). Layer 3: transport protocols (AG-UI, A2UI, MCP Apps — the projections that carry chain data to human interfaces).

**Projections are lossy by design.** A dashboard showing "5 tools active" is a projection from the chain. It discards the full history (which tools, when canonicalized, by whom, with what policy decisions) to present a summary. The chain preserves what the projection discards. This is analogous to the relationship between a database and a materialized view — the view is derived, the database is primary.

**Projections are replaceable.** Because the chain is canonical, any projection can be rebuilt from scratch at any time. A corrupted dashboard, a crashed UI server, a deprecated protocol adapter — none of these affect the governed state. The state lives in the chain. The projections are conveniences.

**Protocol neutrality.** The chain doesn't care how its data reaches humans. AG-UI streams it in real time. A2UI assembles it into declarative JSON-L components. MCP Apps render it as interactive HTML. A CLI dumps it as text. All of these are projections. New protocols can be added without touching the chain. Old protocols can be removed without losing data.

### Relationship to Prior Work

This is the CQRS (Command Query Responsibility Segregation) pattern from software architecture, elevated to a governance principle. In CQRS, the write model (commands) and read model (queries) are separate, with the read model derived from the write model's event stream. ZeroPoint's chain is the write model; all UIs and APIs are read models.

The language of "projections from a canonical source" echoes database theory (views as projections from base relations) and category theory (functors mapping from a source category to target representations).

### Novelty Claim

The architectural pattern is not novel — CQRS and event sourcing are well-established. The novelty is applying it as a *governance principle* with cryptographic backing: the canonical source is not just authoritative by convention but self-verifying by construction. The projections don't just *happen* to derive from the chain — the chain's cryptographic integrity makes them *provably* derived.

---

## The Primitives as a System

These four primitives are not independent features — they form a coherent formal system where each primitive depends on and strengthens the others.

**Canonicalization (1) requires trust-as-trajectory (2):** A canonicalization receipt is meaningful because it's part of a trajectory — it has a position in the chain, a parent receipt, a signed commitment by the operator at a specific moment in the system's history. Without the trajectory, canon would be a static label. With it, canon is a historical fact.

**Trust-as-trajectory (2) requires governance-without-runtime (3):** The trajectory is meaningful because it's durable. If the trajectory could only be verified while the system is running, it would be a runtime property — useful but conditional. Governance without runtime makes the trajectory an unconditional artifact.

**Governance-without-runtime (3) requires receipts-are-canonical (4):** The chain can be audited cold *because* the chain is the single source of truth. If the governance state lived partly in the chain and partly in a database or configuration file, cold audit would be incomplete. The architectural commitment to chain-as-canonical-source is what makes governance-without-runtime possible.

**Receipts-are-canonical (4) requires canonicalization (1):** The chain is meaningful as a source of truth because it records constitutive acts — acts that establish existence, not just record behavior. A chain of behavioral logs is useful. A chain that includes constitutive canonicalization receipts is authoritative — it doesn't just say what happened, it says what *is*.

The primitives form a cycle. This is not circular reasoning — it's a coherent formal system where each property reinforces the others. Remove any one and the others weaken. This is the hallmark of a well-designed formal foundation: the primitives are load-bearing in combination, not decorative in isolation.

---

## Open Questions

These are the questions the primitives raise but do not yet answer. They are research directions, not gaps.

1. **Composability across grammars.** Two ZeroPoint deployments, each with its own Genesis, each with a well-formed chain — how does trust compose when they interact? The grammar is currently defined over a single deployment. Cross-deployment trust requires either a shared super-grammar or a composition operator on grammars. This is a formal semantics problem.

2. **Sequence-level constitutionality (X3).** Individual receipts can comply with constitutional rules while a sequence of receipts violates them. Detecting sequence-level violations requires a mechanism that maintains state across receipt evaluations — bounded lookback windows, rolling accumulators, or pattern-matching over subsequences. This is the substrate's hardest open problem.

3. **The verifier's obligations.** The primitives say what must be true. They don't say who checks, when, or with what consequences. A verifier specification — who walks the chain, with what frequency, what they do with a violation, how they communicate findings — is needed to make the formal system operational for multi-party trust.

4. **Temporal semantics.** The grammar assumes monotonic timestamps but doesn't address clock skew, NTP failures, or deliberate clock manipulation across distributed nodes. A formal treatment of time in the receipt chain is a prerequisite for multi-node deployments.

5. **The autorecursive fixed point.** The system governs itself — gate decisions are receipted and condition future gate decisions. Under what conditions does this self-referential process converge to a stable governance posture? Under what conditions does it oscillate or diverge? This is a dynamical systems question about the fixed-point behavior of autorecursive governance.

---

*These primitives are stated precisely enough that someone could disagree with them, extend them, or prove properties about them. That is the point. A primitive that cannot be argued with is not a primitive — it's a slogan.*
