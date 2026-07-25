# Distributed Knowledge Commons — July 2026

**Document type:** Architectural note. Establishes the canonical answer to "what does an operator gain by participating in the ZeroPoint ecosystem, in a way that respects sovereignty and creates real value for participants?" Sits under `ARCHITECTURE-2026-07.md` Part I (there is no center) and Part IV (the cognitive layer). Composes with `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` (which provides the transport) and `docs/design/ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` (which provides the emission and consumption engine).

**Status:** Design note, with a substantive supersession pending. The commons emission architecture as originally designed here uses reputation as a primary trust mechanism (pattern-sharing keys per §9, reputation weighting per §16). The July 2026 corpus audit's resolution of Decision E reframes this: commons patterns are locally verifiable claims (does this configuration work on your hardware?), so reputation is redundant to verification and adds fingerprinting risk without adding trust value. Under the resolved principle — "trust in the substrate is anchored in verification where verification is available; in reputation where it isn't" — the commons should follow the fully-anonymous model from `regent-gossip-and-evolution-2026-07.md` rather than the reputation-tracked model in this doc. Specifically: §9 (pattern-sharing key derivation ceremony) and §16 (reputation weighting) should be treated as retired; §Parts I-VIII on why the commons exists and how it composes with peer-discovery remain valid. The full rewrite is deferred; the E resolution is the operative framing. Community-level reputation (per COMMUNITY-SURFACE-ARCHITECTURE §5) is orthogonal — that's reputation of *actors* in community coordination, not of *emissions* in the commons, and stays intact.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — The Problem This Document Answers

### 1. The participation question, restated

Sovereign systems have a distinctive economic problem. Conventional platforms create incentive to participate through *asymmetric value flow*: the platform captures user data, refines it into services, and returns some of the refined value back — while retaining most of it as competitive moat. Users participate because the returned value exceeds their alternatives, even though the platform is extracting far more than it returns. This works because users cannot see the asymmetry, cannot leave without losing accumulated value, and have no way to organize collective action.

ZeroPoint eliminates every mechanism that makes this dynamic work. No account, no accumulated data at the Foundation, no lock-in, no proprietary substrate the operator depends on. Which means the conventional incentive to participate is also eliminated. If the Foundation doesn't extract value from participation, and doesn't have any leverage over operators, why should any operator care about being part of the ecosystem at all?

The lazy answer is "they don't need to" — sovereignty means each operator runs their own instance and that's fine. This is technically correct and strategically inert. It leaves the ecosystem as an atomized set of isolated deployments, which forfeits the compound value that emerges when many instances share what they learn.

The right answer is the point of this document: **the incentive to participate is real, sovereign-aligned, and structural — because the collective's accumulated learning is itself the value proposition, and access to it composes with contribution to it.**

### 2. Why this is not "collect data centrally, return aggregates"

The obvious workaround — "operators send patterns to the Foundation, the Foundation aggregates and republishes wisdom" — recreates the platform pattern with new branding. The Foundation becomes the aggregator. The aggregator holds a central repository of pattern data. The central repository is a queryable, breachable, subpoenable surface with everything the architecture was designed to prevent.

Even if the Foundation promises never to misuse the aggregate, the plumbing exists and it will drift. The right architectural discipline: if the failure mode requires trusting an organization not to do the thing the plumbing enables, the plumbing is wrong.

### 3. The right frame

A commons is not an aggregator. A commons is a set of contributions that live where they were contributed, propagate peer-to-peer via a substrate everyone shares, and become part of everyone's local understanding by construction. Wikipedia is not a commons in this sense (it has a central server); traditional oral tradition is (each teller carries and re-transmits the stories). Peer-to-peer file sharing networks approximate this shape when they work.

ZeroPoint's substrate — chain-anchored, peer-discovered, mandate-scoped — is a substrate that can host a commons in the strong sense. What needs to be added is the semantic layer that turns raw peer-discovered announces into knowledge that operators can consume, weight, and act on.

---

## Part II — The Principle

### 4. Distributed by construction, not by policy

The commons is distributed *by construction*, meaning: there is no place in the system where holding a central copy is architecturally possible without violating other invariants. The Foundation cannot hold the commons even if it wanted to, because the commons is not a single artifact anywhere. It is the state that emerges from many operators each holding some portion, propagating patterns to peers, and consuming patterns from peers.

This is stronger than "distributed by policy," where a central copy could exist but the Foundation promises not to hold one. Distributed by construction means the architecture makes centralization structurally difficult in a way that a decision to centralize would require re-engineering, not just policy change.

### 5. Contribution and consumption compose

Every operator that participates in the commons does two things: **emits** patterns their Cartographer derives from their own chain (subject to k-anonymity, category, and confidence thresholds) and **consumes** patterns their subscription filter accepts from other operators (subject to source reputation and category preferences). The two directions are symmetric. An operator that only consumes and never contributes finds their reputation reflecting that; an operator that contributes broadly finds their emissions propagating more broadly and their access to niche patterns deepening.

The composition is not enforced by a central quota system. It emerges from the reputation-weighting of announces (from the peer-discovery layer) and the reciprocity property already present in the Presence Plane. Free-riders exist but their signal degrades gradually.

### 6. The Foundation's role is facilitator, not aggregator

The Foundation participates in the commons like any other operator. It runs ZeroPoint instances (for its own operations, for research studies, for reference deployments). Its Cartographer emits patterns like any other operator's. Its emissions are weighted by other operators exactly like any other source — no privileged reputation floor, no automatic trust.

Where the Foundation adds legitimate value that other operators don't provide:

- **Benchmark harnesses.** Reference datasets and evaluation methodologies that let operators verify whether a broadcast pattern is empirically sound in their own context.
- **Curated wisdom bundles.** Well-attested pattern collections bundled for onboarding new operators — starting priors, not authoritative truth.
- **Conflict resolution facilitation.** When contradictory patterns propagate (source A says X, source B says not-X), the Foundation can publish comparative analyses that help operators reason about which applies in which context.
- **Research studies with mandate-scoped access.** The pattern the personality-adaptation validation protocol uses — solicit participation, receive scoped mandates, run pre-registered analyses — generalizes.

Where the Foundation must not go:

- Holding a canonical copy of the commons.
- Gatekeeping participation.
- Monetizing access to the commons as a service tier.
- Publishing patterns as if authoritative rather than as one contributor among many.

---

## Part III — What Flows Through the Commons

### 7. Emission-eligible categories

The kinds of things that meet the four load-bearing criteria — emergent from usage, non-competitive, aggregatable, de-identifiable — form the commons' initial vocabulary. Concrete categories:

- **Tool-use patterns.** Which tool sequences complete which task types with fewest override cycles. Which capability-class combinations tend to fail together. Which tools compose well versus which shadow each other's functions.
- **Cost patterns.** Token costs per task class, per model tier. Which model choices are actually cost-effective for which cognitive roles (contradicting whatever the model vendor's marketing claims).
- **Officer tuning.** Sweep cadences, prompt calibrations, findings-per-hour by domain that correlate with actual anomaly catches vs. false-positive noise.
- **Delegation shapes.** Mandate scope patterns that lead to fewer scope corrections. Capability-class assignments that hold up under adversarial pressure. Delegation depth patterns that don't degrade over time.
- **Friction patterns.** Cartographer-derived Frictions that repeat across operators — specific configurations that reliably break at specific scales, specific tools that trigger specific failure modes.
- **Model routing preferences.** Which local models excel at which cognitive tasks, calibrated to empirical benchmarks rather than vendor claims.
- **Onboarding trajectories.** Common paths new operators take, common places they get stuck, common resolutions that unstuck them. Useful for the Regent to consult when onboarding.
- **Threat observations.** Attack patterns other operators have observed in the wild — with enough anonymization that the observation is useful without revealing which operator was targeted.

### 8. What is explicitly not shareable

The list of what does not enter the commons is at least as important as what does:

- **Content of interactions.** No conversation content, no operator intent, no task specifics that would identify what the operator is doing.
- **Operator identity in any form.** No Genesis-derived signatures on shared patterns. Patterns are attested to a *pattern-sharing key* that is derived once per operator but not linkable back to Genesis without operator disclosure.
- **Chain state.** No raw receipts, no receipt IDs, no anything that lets a receiver reconstruct any specific operator's chain history.
- **Anything below the k-anonymity threshold.** If the operator's local model estimates that fewer than K other operators would plausibly share the same pattern, it stays local. The value K is operator-configurable but has a substrate-enforced floor.

The distinction is between **pattern** (a generalized observation about system behavior) and **content** (specific data about what happened). Patterns flow; content does not.

### 9. The pattern-sharing key

Every operator that participates in the commons derives a pattern-sharing key from their Genesis via a formal separation ceremony. The ceremony produces a receipt on the operator's own chain stating "I authorize key K for use as my pattern-sharing identity, and I certify these will be treated as structurally distinct identities." Commons emissions are signed by K, not by any Genesis-derived operator identity. The Foundation and other operators see K's emissions and K's accumulated reputation, but cannot link K to the operator's Genesis without operator disclosure.

The pattern-sharing key can be rotated. It can be revoked. It can be one-per-operator or one-per-context (an operator might use different pattern-sharing keys for different domains, to prevent pattern-triangulation attacks). This is the standard cryptographic-separation pattern applied to commons participation.

---

## Part IV — The Cartographer as Emission and Consumption Engine

### 10. Why the Cartographer fits

The Cartographer (`docs/design/ONTOLOGY-AND-CARTOGRAPHER-2026-07.md`) already turns each operator's raw receipts into typed ontology objects. Some of those objects are inherently local (specific Decisions, specific Artifacts) and stay local. Others (certain Insights, certain Frictions) are inherently generalizable — their value is in the pattern, not the specific instance.

The Cartographer becomes the operator's participation surface in the commons. It has:

- The typing infrastructure to know what kind of object it just produced.
- The confidence-scoring infrastructure to know how confident the observation is.
- The chain access to derive k-anonymity estimates from historical patterns.
- The relationship-inference infrastructure to know which patterns co-occur and which are independent.

Adding commons participation to the Cartographer is a natural extension, not a new subsystem.

### 11. The emission path

When the Cartographer produces a new Insight or Friction:

1. **Evaluate against operator emission policy.** The operator has configured which categories they contribute to; the Cartographer checks whether the object's category is on that list.
2. **Estimate k-anonymity.** Based on the object's shape and the Cartographer's model of what patterns other operators tend to share, is this above the operator's configured k-anonymity threshold?
3. **Apply confidence threshold.** Is the object's confidence score high enough to warrant broadcasting? Low-confidence observations become noise if propagated.
4. **Redact.** Strip any content that could identify the operator or specific chain state. What remains is the pattern in generalized form.
5. **Sign with the pattern-sharing key.** The emission is a chain-anchored receipt on a separate emission chain, signed by K.
6. **Broadcast via peer-discovery announce.** The emission is announced under the appropriate commons category (`commons:tool-patterns:*`, `commons:cost:*`, etc.) via the same mechanism `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` establishes for outreach generally.

The operator can, at any point, inspect what their Cartographer has broadcast and modify emission policy. The audit is complete on the operator's own chain.

### 12. The consumption path

When a peer's commons announce arrives:

1. **Signature verification.** Standard announce verification from the peer-discovery layer.
2. **Category filter.** The operator has configured which commons categories they subscribe to; unaccepted categories are dropped.
3. **Source reputation check.** The emitting key's reputation must exceed the operator's configured floor. Reputation is a function of past emissions' apparent quality — see Part VI.
4. **Content sanity check.** The Cartographer scans the pattern for internal consistency; malformed patterns are dropped.
5. **Weighting.** The pattern is folded into the operator's local Cartographer state, weighted by source reputation, corroboration from other sources, and configured operator preferences.
6. **Availability to the Regent.** When the Regent is reasoning about a task, tool selection, delegation shape, or officer tuning, the Cartographer's collective-informed prior is available alongside the operator's own historical patterns.

Received patterns become priors, not commands. They inform reasoning without overriding local observation. If the operator's own chain contains evidence that contradicts a received pattern, local evidence wins.

---

## Part V — Reciprocity as the Participation Model

### 13. The Presence Plane's reciprocity, applied to knowledge

The Presence Plane already enforces reciprocity at the transport layer: a peer must announce before it can receive. This is spam resistance for peer discovery — you can't passively harvest without exposing yourself.

The commons applies the same principle at the semantic layer. To receive high-quality patterns from other operators, an operator must be a contributor. The mechanism is not a hard block ("you cannot receive without contributing"); it is a reputation-mediated gradient ("your reception quality reflects your contribution quality"). A never-contributed operator receives the widely-broadcast default commons — old, generic patterns everyone shares. A contributing operator receives increasingly niche and current patterns from peers whose contribution reputation composes with theirs.

### 14. The economic shape

The commons is a positive-sum game. Contributing a pattern does not reduce the pattern's usefulness to the contributor — the contributor already has the pattern locally and continues to. Contribution only expands who else can benefit from it. This is characteristic of information goods generally; ZeroPoint's commons inherits the property.

What differs from platform-mediated information sharing is that contribution has no strategic downside. In a platform economy, contributing raw material to the aggregator increases the aggregator's competitive advantage over you. In the ZP commons, contribution has no aggregator to advantage. Contribution is a peer-to-peer gift with a reciprocal-benefit expectation, not extracted labor for a platform.

### 15. Free-riders and their behavior

Some operators will consume without contributing. This is fine and expected. The reciprocity mechanism does not exclude them; it simply means their reception quality is bounded. The system tolerates free-riders because:

- They receive less, so they benefit less, so they are structurally motivated to contribute if they want more.
- They cannot poison the commons by not-contributing (they can only fail to add value).
- They may become contributors over time as their own patterns accumulate.
- Excluding them entirely would require a coordination mechanism that violates the "no center" property.

The reputation gradient is the incentive; it does not need to be an exclusion.

---

## Part VI — Reputation Weighting and Adversarial Resistance

### 16. Where reputation comes from

An emitting key K accumulates reputation from downstream operators' engagement with its emissions. Specifically:

- **Corroboration.** If other independent sources emit compatible patterns, K's contribution is corroborated and K's reputation increases.
- **Contradiction.** If K's patterns are consistently contradicted by patterns from other sources with strong reputation, K's reputation degrades.
- **Empirical validation.** If operators locally observe that K's patterns predict their own experience (their tool sequences work better after adopting a K-suggested pattern), receipts of validation propagate back and boost K's reputation.
- **Empirical failure.** If operators locally observe that K's patterns lead to worse outcomes, receipts of contradiction propagate back and reduce K's reputation.

Reputation is computed locally at each receiving operator, not centrally. Two operators may hold different reputations for the same key K because they subscribe to different corroborating sources. This is a feature: reputation is a function of the receiver's own graph, not a global consensus.

### 17. Adversarial patterns

Several attack modes on the commons deserve explicit handling:

**Sybil flooding.** A malicious actor spawns many pattern-sharing keys and floods the commons with false patterns designed to mislead. Defenses:

- The peer-discovery layer's reputation-weighted propagation already reduces the reach of low-reputation broadcasts (Part V §17 of the peer-discovery note).
- The commons requires cross-attestation: solo patterns from a single low-reputation source receive low weight; patterns corroborated by multiple independent high-reputation sources receive high weight.
- k-anonymity thresholds mean the attacker must produce coordinated multi-key emissions, raising the cost of the attack.
- Pattern-sharing key derivation is not free — it requires a chain-anchored ceremony that costs computational work.

**Pattern poisoning.** An operator emits patterns that are subtly wrong in ways that damage receivers' operations. Defenses:

- Empirical validation propagates back: receivers who act on a poisoned pattern and observe poor outcomes emit contradiction signals.
- The operator's own reputation degrades as contradiction accumulates.
- The Cartographer weights recent contradictions more heavily than older corroborations, so a source that starts poisoning after building reputation degrades faster than an equivalent source that was always poisoning.

**De-anonymization via pattern triangulation.** An adversary collects patterns emitted under key K and cross-references them with known operator characteristics to identify who K belongs to. Defenses:

- k-anonymity thresholds enforced at emission time.
- Operators can use context-scoped pattern-sharing keys (different key for tool patterns, cost patterns, threat observations, etc.) to prevent cross-domain correlation.
- The Cartographer can be configured to be more aggressive about k-anonymity for observations that would be strongly identifying if triangulated.

**Free-rider poisoning.** A malicious operator contributes just enough to build reputation, then uses the reputation to broadcast a poisoning payload. Defenses:

- The reputation degradation from a bad emission is proportional to reception; a widely-received bad emission generates widely-received contradiction and degrades reputation faster than the reputation was built.
- The Cartographer weights *stable* reputation more heavily than *recent* reputation; a source with long consistent history is weighted more than an equal-reputation source with short history.

None of these defenses are perfect. They are structurally sound composed: each attack requires overcoming multiple defenses simultaneously, and the cost of doing so scales super-linearly with the desired attack surface.

---

## Part VII — The Foundation's Legitimate Role

### 18. What the Foundation may do

The Foundation has legitimate contributions to make to the commons that do not require centralization:

- **Emit patterns from its own operations.** The Foundation runs ZeroPoint. Its Cartographer produces patterns. Those patterns can be contributed to the commons like any other operator's. The Foundation's emissions are weighted like any other source's — no privileged reputation floor.
- **Publish benchmark harnesses.** Reference datasets and evaluation methodologies that operators can run locally to verify whether a broadcast pattern holds in their context. Benchmark harnesses are chain-anchored receipts, not services — the operator runs them locally.
- **Curate reference wisdom bundles.** For new operator onboarding, a curated bundle of well-attested patterns bundled as a starting prior. The bundle is signed by the Foundation and includes attestation traces for each included pattern. Operators choose whether to adopt the bundle; nothing depends on the Foundation being the curator.
- **Publish conflict-resolution analyses.** When contradictory patterns are propagating, the Foundation can publish comparative analyses that help operators reason about which pattern applies in which context. The analysis is a contribution to the commons, not authoritative resolution.
- **Facilitate research studies.** Under the mandate-scoped model already established, the Foundation can run pre-registered research programs (see the personality-adaptation validation protocol as canonical example) that generate patterns as byproducts, contributed back to the commons.

### 19. What the Foundation must not do

The failure modes to guard against, stated concretely:

- **Hold a central copy of the commons.** No Foundation-side database of accumulated patterns. Caches for query performance are ephemeral and unauthoritative; if a cache goes down, nothing is lost.
- **Gatekeep participation.** No approval process to contribute to the commons. Any operator with a valid Genesis-derived pattern-sharing key can emit; reception is subject only to peer-reputation dynamics.
- **Monetize commons access.** The commons is not a Foundation service tier. The Foundation may charge for services *around* the commons (curated bundles for enterprise onboarding, benchmark harness maintenance, expert conflict analyses) but never for access to the commons itself.
- **Publish patterns as authoritative.** Foundation emissions are one contribution among many. They receive reputation like any other source's. The Foundation must not present its patterns as truth that other operators must accept.
- **Correlate contributions to identify operators.** The Foundation observes commons emissions like everyone else does. It must not use its position (as a widely-followed peer) to build correlation databases that de-anonymize contributors.

### 20. The self-imposed limits

The Foundation's charter should include explicit self-limits corresponding to the above. Concretely: a chain-anchored receipt on the Foundation's Genesis chain declaring the Foundation's non-privileged status in the commons, cross-signed by the Foundation's board, verifiable by any operator. This is analogous to the constitutional rules in the substrate — it binds the Foundation structurally in a way that would require explicit repudiation to violate.

---

## Part VIII — The Trap to Guard Against

### 21. Extraction dressed as commons

The failure mode most likely to occur in practice, five years out, is not overt betrayal. It is drift toward centralization in the name of user experience or performance. The specific patterns that will look reasonable at the time and are the failure mode:

- **"For query performance, we should hold a central index of commons emissions."** The proposal will be framed as caching for latency reduction. It will be technically defensible. Accepting it hollows out the commons — the "central index" becomes authoritative in practice even if not in name.
- **"Users are having trouble discovering high-quality patterns; we should curate a Foundation-endorsed catalog."** Foundation-endorsed catalogs are curation, which is fine — but if the catalog becomes the primary way operators find patterns, then peers who are not in the catalog effectively disappear from the commons. Curation becomes gatekeeping.
- **"For research, we need a subset of operators to send us their patterns."** This is the personality-adaptation-validation pattern, which is fine when it uses mandate-scoped queries. It becomes a failure mode when it slides toward "send us everything and we'll pick out what we need."
- **"Enterprise customers need reliability guarantees; we should offer a paid commons tier with SLA-backed pattern access."** A paid tier means non-paying operators receive worse access, which stratifies the commons and makes the Foundation an economic gatekeeper.

Each of these looks reasonable in isolation. Each of them, taken together, reproduces the platform pattern that ZP was built to prevent.

### 22. The discipline

The discipline is: **the authoritative commons is distributed; anything else is unauthoritative.** Caches are ephemeral and can be regenerated from peer emissions. Curated bundles are one contribution among many. Research studies are mandate-scoped and revocable. Foundation-emitted patterns are weighted like any other operator's. If a proposal would violate any of these properties, the proposal is the failure mode surfacing and must be rejected.

The way to make this discipline durable across time and personnel is to encode it structurally: constitutional rules in the Foundation's charter, chain-anchored receipts binding the Foundation's non-privileged status, technical architecture that makes centralization require explicit re-engineering rather than passive drift. Discipline that lives only in current stewards' judgment does not survive stewardship transitions.

---

## Part IX — Incentive Economics

### 23. Why operators contribute

The economic case for operator contribution:

- **Reciprocity.** Contributing improves reception quality — operator's substrate gets richer priors from the commons in proportion to what the operator contributes back.
- **Reputation.** Emitting keys accumulate reputation over time. High-reputation keys have influence: their patterns propagate more broadly, their attestations weigh more when corroborating others. Reputation is a form of standing in the ecosystem that has real value.
- **Consistency validation.** Emitting a pattern and observing whether peers corroborate is a way to check one's own operational assumptions. An operator whose patterns are consistently un-corroborated learns they may be operating unusually — sometimes valuably (unusual and effective), sometimes not (misconfigured and struggling).
- **Ecosystem stewardship.** For some operators, contributing to a commons is intrinsically motivating. The commons benefits from allowing this contribution rather than blocking it.

None of these depend on the Foundation providing anything. They are peer-to-peer economic properties.

### 24. Why operators consume

The economic case for operator consumption:

- **Faster onboarding.** New operators can adopt curated wisdom bundles (curated by the Foundation or by peer operators) and start from a better baseline than they could reach through their own experimentation.
- **Cheaper operation.** Cost patterns from the commons let operators identify inefficient tool/model choices without having to conduct their own comparative benchmarking.
- **Better decisions.** Delegation shapes, officer tuning, and threat observations from the commons inform local decisions with data the individual operator could not have gathered alone.
- **Adversarial awareness.** Threat patterns from peers alert operators to attack vectors they haven't yet observed themselves.

Consumption is the compound-interest of the ecosystem. Operators do not need to individually derive every insight; they inherit accumulated insights from peers who have done the work.

### 25. Why the commons compounds

The commons has the property that value flows to *all* participants when *any* participant contributes. A pattern discovered by operator A that saves 10% inference cost across the ecosystem produces 10% savings for every operator who receives and applies it. The total value of A's contribution scales with adoption. This is what makes the commons a positive-sum game rather than a zero-sum resource competition.

The compounding is bounded by:

- Reputation dynamics (bad patterns propagate less)
- Local override (operators' own chain evidence trumps received patterns)
- k-anonymity thresholds (privacy-preserving emission bounds contribution volume from any single operator)
- Category filters (operators only receive patterns they've opted into)

These bounds prevent runaway effects (a single operator's noise dominating the commons) while preserving the compound-benefit property.

---

## Part X — What Needs to Be Built

The primitives already exist. The following additions turn them into the commons this document describes:

- **Pattern-sharing key derivation.** A ceremony in `zp-keys` that produces a chain-anchored authorization receipt for a Genesis-derived pattern-sharing key K, with formal separation guarantees.
- **Emission-eligible Cartographer objects.** Extension to the Cartographer specification (`docs/design/ONTOLOGY-AND-CARTOGRAPHER-2026-07.md`) declaring which ontology object types are emission-eligible, and how they are transformed for emission (redaction, generalization, confidence encoding).
- **k-anonymity estimator.** A local component in the Cartographer that estimates, for a given candidate emission, how many other operators would plausibly share a similar pattern. Requires calibration data from initial commons operation.
- **Commons announce category taxonomy.** The `commons:*` namespace with subcategories (`commons:tool-patterns:*`, `commons:cost:*`, `commons:officer-tuning:*`, `commons:delegation:*`, `commons:friction:*`, `commons:threat:*`, etc.). Registration and evolution mechanics.
- **Reception-side pattern integration.** Extension to the Cartographer that folds received patterns into local reasoning as weighted priors, with reputation and corroboration factored in.
- **Reputation computation for emitting keys.** Local reputation aggregation from observed corroborations, contradictions, and empirical validations. Cached per receiving operator; computed from that operator's own graph.
- **Corroboration receipts.** A receipt type by which operators emit signals of corroboration or contradiction of received patterns, contributing to reputation dynamics.
- **Validation receipts.** A receipt type by which operators emit signals of empirical validation (or failure) from their local application of a received pattern.
- **Operator-facing commons policy configuration.** TOML schema and cockpit surface for the operator to configure emission categories, k-anonymity threshold, reception categories, reputation floors, blocklists.

Each of these is a discrete addition. Together they turn the existing primitives into a functioning commons.

---

## Part XI — Relationship to Other Work

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture record. This document extends the "there is no center" property (Part I §1) and the cognitive layer's ontology work (Part IV) into a mechanism for cross-operator value flow that preserves both.
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — provides the transport substrate. Commons emissions are peer-discovery announces under the `commons:*` namespace. The two documents compose: peer discovery is the transport; the commons is one use case for that transport.
- `docs/design/ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` — provides the emission and consumption engine. Commons participation extends the Cartographer with emission logic (what gets broadcast) and consumption logic (how received patterns integrate).
- `docs/PERSONALITY-ADAPTATION-VALIDATION-PROTOCOL-2026-07.md` — a specific application of commons-adjacent participation. The protocol uses mandate-scoped queries rather than commons emission because the study is confirmatory rather than continuous. The two mechanisms compose: research studies gather structured data under mandate; the commons circulates unstructured patterns continuously.
- `docs/whitepaper-v9.md` — public thesis. §7 (Mesh Transport and the Presence Plane) describes the primitives underlying commons transport. A future revision should include a section on the commons as a first-class ecosystem property.

---

## Part XII — Closing

The value proposition of participating in ZeroPoint is not that the Foundation gives you a benefit. It is that the collective's accumulated learning is available to you because you are part of the collective, and the more you contribute, the richer the flow you receive.

No one holds the commons. No one gates it. No one monetizes access to it. It exists as the emergent state of many operators each contributing and consuming through a shared substrate — a substrate whose properties make centralization structurally difficult rather than merely prohibited by policy.

The incentive to participate is real, sovereign-aligned, and unsympathetic to the extractive dynamics that platform-based information sharing has trained us to expect. The Foundation exists to facilitate — publishing benchmark harnesses, curating starting bundles, running research studies, contributing patterns from its own operations — never to accumulate, gatekeep, or monetize the commons itself.

The commons is what the ecosystem is *for*, in the same way that the chain is what the substrate is for. It is the compound-interest that emerges when many sovereign operators share what they have learned, without any of them giving up sovereignty to do so.

---

*The commons is not a platform. It is the emergent state of a substrate that made platforms structurally impossible and value-sharing structurally natural. Contribution is a gift. Reception is a gift. The reciprocity that binds them is peer-to-peer, chain-anchored, reputation-weighted, and — critically — belongs to no one.*
