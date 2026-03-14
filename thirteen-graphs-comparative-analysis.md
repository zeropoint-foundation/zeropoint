# Thirteen Graphs × ZeroPoint: Comparative Analysis

**March 2026**

Matt Searles's *Thirteen Graphs, One Infrastructure* proposes thirteen product graphs — from individual task management to species-level ecology — running on a single event graph infrastructure. ZeroPoint provides cryptographic governance primitives for accountable systems. They share a diagnosis. They diverge on where to cut.

---

## Shared Thesis

Both projects start from the same structural observation: **platforms capture trust, then extract from it.** Searles calls it "perverse incentives" — systems that profit from keeping coordination problems partially unsolved. ZeroPoint calls it "enshittification's root cause" — trust primitives that were never built into the protocol layer, leaving platforms as the only place where identity, reputation, and authorization are legible.

The convergence is precise:

| Claim | Searles | ZeroPoint |
|-------|---------|-----------|
| Platforms profit from lock-in, not from solving problems | ✓ (explicit, across all 13 graphs) | ✓ (Section 0: "The Structural Problem") |
| Trust must move to protocol/infrastructure | ✓ (unified event graph) | ✓ (cryptographic governance primitives) |
| Hash-chained, append-only event records | ✓ (core data structure) | ✓ (receipt chains, Blake3 + Ed25519) |
| Reputation should be portable, not platform-computed | ✓ (Identity Graph derived from behavior) | ✓ ("Your reputation is a verifiable chain of receipts") |
| AI agents as first-class participants | ✓ (agents as reliable graph nodes) | ✓ (participant-agnostic: human, agent, service, device) |
| Cross-system causal verification | ✓ (unified graph eliminates cross-platform blind spots) | ✓ (receipt chains + collective audit) |
| No novel technology required | ✓ (explicit: "trivial implementations of solved problems") | ✓ (Ed25519, Blake3, MessagePack, WASM — all proven) |

Both argue that the solution is *infrastructural*, not application-level. Both argue it's buildable now.

---

## Where They Diverge

### Scope vs. Depth

Searles goes wide: thirteen graphs covering work, markets, social connections, justice, research, knowledge, ethics, identity, population, governance, culture, meta-patterns, and ecosystems. Each graph is a "view" of the same underlying event data.

ZeroPoint goes deep: five protocol layers (identity, governance, receipt, transport, application) with formal invariants, constitutional constraints, threat modeling, and 699 tests across 13 crates. It doesn't name thirteen products — it provides the primitives that any of those thirteen products would need to be trustworthy.

**The relationship is complementary, not competitive.** Searles describes the applications. ZeroPoint describes the substrate. His Work Graph needs exactly the kind of verifiable causality that receipt chains provide. His Justice Graph needs exactly the kind of pre-existing evidence that audit trails create. His Governance Graph needs exactly the kind of transparent, traceable rule enforcement that the PolicyEngine delivers.

### Authority Model

This is the sharpest divergence. Searles's event graph is structurally flat — events are recorded and linked, and different graphs query them differently. Authority is implicit in the graph structure.

ZeroPoint makes authority explicit and enforceable:

- **Capability grants** with cryptographic scoping, delegation depth limits, time windows, and cost ceilings
- **Delegation chains** verified against eight formal invariants
- **Constitutional constraints** that are non-removable and non-overridable
- **The Guard** — a local-first, pre-action sovereignty check that runs before consulting any external authority

Searles's architecture records *what happened*. ZeroPoint's architecture controls *what is allowed to happen* and then records the proof. This is the difference between an event log and a governance protocol.

### Transport and Sovereignty

Searles doesn't address transport. The implicit assumption is standard web infrastructure — APIs, databases, cloud hosting.

ZeroPoint is explicitly transport-agnostic: HTTP, TCP, UDP, and Reticulum mesh. The mesh integration isn't incidental — it's philosophically central. Governance that depends on cloud infrastructure is governance that can be revoked by whoever controls the cloud. ZeroPoint's sovereignty posture means the same primitives work in a data center and over a LoRa link in a disaster zone.

### Ethics and Misuse

Searles's "authority models" are mentioned as ensuring humans remain in control loops. The treatment is brief.

ZeroPoint dedicates an entire section to misuse resistance, an honest threat model, explicit non-goals, and the co-option risk (accountability infrastructure becoming surveillance infrastructure). The Four Tenets are code, not text — constitutional rules that evaluate before every action.

---

## What ZeroPoint Can Use

### 1. The "Thirteen Views, One Infrastructure" Framing

This is immediately useful for ZeroPoint's adoption narrative. Right now, ZeroPoint describes itself as "portable trust infrastructure" — which is accurate but abstract. Searles's framing shows what that infrastructure *enables*: you don't build thirteen separate trust systems. You build one substrate, and thirteen different domains become governable.

**Concrete application:** The footprint page already shows ZeroPoint's coverage across security frameworks. An "application views" layer could show how ZeroPoint's primitives map to real coordination problems — work attribution, marketplace trust, dispute resolution, research reproducibility. Not as products ZeroPoint builds, but as categories that ZeroPoint's primitives unlock.

### 2. The "Perverse Incentive" Diagnosis as Market Positioning

Searles maps each of his thirteen graphs to a specific perverse incentive: task managers profit from ambiguity, marketplaces profit from being the sole trust arbiter, legal systems profit from evidence-reconstruction costs. This is sharper than ZeroPoint's current framing, which focuses on the structural diagnosis (trust is not portable) without always naming the specific extractors.

**Concrete application:** ZeroPoint's adoption paths (Section 9) could be strengthened by naming the perverse incentive each adopter faces. "Multi-agent system builders" becomes: "Teams whose agent orchestration is currently locked to a single vendor's trust model — and who lose all their provenance if they switch." The structural argument lands harder when the extraction is named.

### 3. The "Bootstrapping" Deployment Model

Searles proposes that layers 1–3 (Work, Market, Social) are buildable now, and each bootstraps the next. Work Graph enables marketplace features. Marketplace features enable social features. Social features enable justice infrastructure.

ZeroPoint's roadmap is currently linear: repository → test suite → threat model → example apps → sustainability. The bootstrapping insight suggests a different framing: **each ZeroPoint integration creates demand for the next.** A governed agent pipeline (Pattern B) creates receipts that enable delegation chains (Pattern C), which create the trust substrate for cross-operator exchange (Pattern A), which demands the Authority Graph we just added to the footprint page.

### 4. The Justice Graph → Authority Graph Connection

Searles's Justice Graph — dispute resolution using pre-existing event evidence rather than costly discovery — maps directly to ZeroPoint's arbitration surfaces concept. His framing makes explicit something ZeroPoint already enables but hasn't fully articulated: **if every action is already a receipt in a chain, dispute resolution becomes a graph traversal, not a reconstruction.**

**Concrete application:** The "Authority Graph" next step on the footprint page is exactly this. Searles gives us the language: delegation chains are the authority flow, and arbitration surfaces are the places where disputes resolve. The authority graph view should make both visible — who authorized what, through whom, and where the chain terminates if something goes wrong.

### 5. The "Cross-System Causality" Argument

Searles's strongest technical argument: separate platforms cannot verify cross-system causality. A client's non-payment (Market Graph) triggering a dispute (Justice Graph) looks disconnected across separate systems. Unified infrastructure makes the causal chain visible.

ZeroPoint's receipt chains already solve this — a receipt's `parent_receipt` field creates exactly the cross-action causality Searles describes. But ZeroPoint doesn't currently frame it this way. The whitepaper talks about "accountability continuity" — Searles's "cross-system causality" is the same concept, expressed as a product benefit rather than a protocol property.

### 6. The "Knowledge Graph" and Provenance Tracking

Searles's Knowledge Graph tracks information provenance so claim sourcing becomes transparent and auditable. This maps to a ZeroPoint use case that isn't prominently featured: **using receipt chains to make AI-generated content attributable.** Every LLM call through ZeroPoint's pipeline already produces a receipt. Chaining those receipts creates provenance — who asked what, which model answered, what constraints were applied, and what the output was.

---

## What ZeroPoint Already Has That Searles Doesn't Address

| Capability | ZeroPoint | Searles |
|-----------|-----------|---------|
| Formal threat model | ✓ (Section 6, with residual risks) | Not addressed |
| Constitutional constraints (non-removable) | ✓ (HarmPrincipleRule, SovereigntyRule) | Not addressed |
| Sovereign refusal | ✓ (Guard: any participant can refuse any action) | Not addressed |
| Transport sovereignty (mesh, offline, air-gapped) | ✓ (Reticulum, TCP, UDP, HTTP) | Not addressed |
| Compact encoding for constrained links | ✓ (150–300 byte receipts over LoRa) | Not addressed |
| WASM-extensible policy | ✓ (sandboxed, fuel-limited) | Not addressed |
| Implementation (running code, 699 tests) | ✓ | "Building the Work Graph" — early stage |

---

## Strategic Takeaway

Searles is building applications on the thesis that ZeroPoint provides the substrate for. His thirteen graphs describe the *demand*. ZeroPoint provides the *supply*. The relationship is: **if Searles's event graph had cryptographic governance, delegation chains, constitutional constraints, and transport sovereignty — it would be ZeroPoint.**

The most actionable thing here: Searles has articulated the *application-layer story* that ZeroPoint's *protocol-layer story* needs. ZeroPoint's whitepaper explains why portable trust matters and how it works. Searles's post explains what you *build with it* — and names the specific systems that are currently extracting value from the absence of it.

The authority graph view we just added to the footprint page is the first step toward making this visible. The next step: mapping ZeroPoint's primitives to concrete coordination problems (Searles's thirteen, or a subset of them) and showing that each one becomes tractable once the trust substrate exists.

---

*Analysis prepared for Ken Romero, ThinkStream Labs*
*Source: Matt Searles, "Thirteen Graphs, One Infrastructure" (Substack, 2026)*
