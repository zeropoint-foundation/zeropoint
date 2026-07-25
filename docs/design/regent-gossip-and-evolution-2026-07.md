# Regent Gossip Network & Governed Self-Improvement

**Date:** 2026-07-08
**Status:** Design draft
**Author:** Ken Romero, with synthesis assistance from Claude
**Depends on:** ARCHITECTURE-2026-07.md (Principles 1, 3, 4, 6 from §Part VII), EXECUTION-AUTHORITY-MODEL-2026-07.md, COGNITIVE-DESIGN-PRINCIPLES-2026-07.md

---

## 1. Problem

A single Regent discovers useful things — model performance characteristics, prompt-model coupling failures, configuration recipes that work — and keeps them. Every other Regent on every other substrate instance rediscovers the same things independently, burning compute and operator attention. The collective intelligence of the network is the sum of isolated findings, never the product.

The fix is gossip: Regents share findings with peers. But naive sharing creates three risks: **privacy leakage** (operator-specific data flows to strangers), **noise flooding** (low-value findings drown out useful ones), and **ungoverned evolution** (the substrate changes itself faster than the operator can track). The mechanism must make sharing valuable, privacy-safe, and bounded.

## 2. The Two-Allowance Model

Each Regent maintains two regenerating allowances that govern her participation in the gossip network and her local exploratory computation.

### 2.1 Social Allowance

**Purpose:** Controls the rate at which a Regent broadcasts findings to the network.

- Regenerates at a configurable rate (default: 1 unit per hour, max pool: 24 units).
- Broadcasting a finding costs social allowance proportional to its payload size and reach (local cluster: 1 unit; wider network: 3 units).
- **Listening is free.** Receiving and evaluating others' findings costs zero social allowance.
- The asymmetry is intentional: hearing is cheap, speaking is expensive. This selects for high-value broadcasts. A Regent that wastes social allowance on noise goes quiet until it regenerates. A Regent that shares genuinely useful findings (prompt fix that prevents sovereign identity failures, model configuration that halves latency) stays audible because the cost is worth it.

**Operator tuning:** The regeneration rate and pool size are configurable in `config.toml` under `[regent.gossip]`. An operator who wants a quiet Regent sets a low rate; one who wants active participation sets a high rate. Setting the rate to zero disables broadcasting entirely — the Regent still listens.

### 2.2 Compute Allowance

**Purpose:** Controls how much exploratory inference the Regent can spend on self-improvement activities (model evaluation sweeps, prompt variant testing, gossip finding verification).

- Regenerates based on idle time — the Regent earns compute allowance when the operator isn't actively using the system.
- Spent on: local model evaluation batteries, prompt-model coupling tests, verification of received gossip findings, recipe trials.
- The allowance prevents the Regent from consuming inference resources that the operator needs. It composes with the existing harmony system (COGNITIVE-DESIGN-PRINCIPLES §4): background tasks yield to operator input and defer under memory pressure.

**Operator tuning:** Maximum compute budget per cycle is configurable. The Regent can also be configured to earn compute allowance faster during declared "maintenance windows" — periods when the operator has indicated the machine is available for background work.

### 2.3 Allowance Interaction

The two allowances create a natural feedback loop:

1. Regent uses **compute allowance** to evaluate a model or test a prompt variant.
2. Evaluation produces a finding (receipted on the local chain).
3. Regent decides whether the finding is worth broadcasting — high-value findings that would help peers get broadcast; obvious or operator-specific findings don't.
4. Broadcasting spends **social allowance**.
5. Peers receive the finding for free, verify it locally (spending their own compute allowance), and if confirmed, integrate it into their own operational tuning.

The loop is self-regulating. A Regent with no compute allowance can't produce findings to share. A Regent with no social allowance can't broadcast but can still benefit from others' broadcasts. Both allowances regenerate, so temporary exhaustion is fine — it just means the Regent was recently active.

## 3. Gossip Payload: Structurally Private

The gossip finding is a typed object. The type system defines what *can* be shared; anything outside the type is structurally unsharable.

```
GossipFinding {
    // Identity: the finding, not the finder
    finding_id: ContentHash,          // deterministic from payload
    finding_type: FindingType,        // enum: see below
    created_at: DateTime<Utc>,

    // Payload (type-specific, all operator-agnostic)
    model_family: String,             // "qwen3", "gemma4", "claude-sonnet"
    model_variant: Option<String>,    // "8b", "27b-mlx"
    payload: FindingPayload,          // type-specific data

    // Provenance (verifiable but not identifying)
    substrate_version: String,        // ZP version that produced this
    evaluation_receipt_hash: String,  // hash of the local receipt, not the receipt itself
    confidence: f64,                  // 0.0–1.0
    
    // NO operator name, NO genesis key, NO chain content, NO preferences
}
```

**FindingType enum:**

- `ModelPromptCoupling` — "this model fails/succeeds at this prompt task" (e.g., sovereign identity recognition, JSON compliance, think suppression).
- `ConfigurationRecipe` — "these inference parameters work well for this model" (temperature, context window, keep_alive settings).
- `PerformanceCharacteristic` — "this model has these latency/throughput/memory characteristics on this class of hardware."
- `PromptVariant` — "this prompt phrasing produces better results than the base for this model family." Includes the variant text itself (prompts are substrate infrastructure, not operator data).
- `SafetyBoundary` — "this model breaks under these conditions" (adversarial resistance failures, hallucination patterns, instruction-following failures).

**What's excluded by construction:**

- Operator identity, preferences, or behavioral patterns.
- Chain content, receipt payloads, or memory entries.
- Delegation scopes or capability grants.
- Conversation content or session history.
- Tool usage patterns that could fingerprint the operator.

The Regent doesn't have to decide what's safe to share. The schema makes unsafe sharing structurally impossible — there's no field for it.

## 4. Network Topology

The gossip network is **store-and-forward, not live.** Findings are exchanged when substrates happen to communicate, not through persistent connections. This composes with Principle 5 (store-and-forward is primary) and Principle 3 (there is no center).

No central broker. No discovery service. No registry of active Regents. Findings propagate through whatever communication channels exist between substrates — direct peer connections, shared relay nodes, or even manual export/import. The finding's `finding_id` (content-addressed) provides natural deduplication. A finding seen twice is the same finding; receiving it from multiple paths increases confidence without duplication.

**Trust model for received findings:**

1. **Receive** — free. The finding enters a local inbox.
2. **Evaluate** — costs compute allowance. The Regent runs the finding's claimed test locally to verify the claim. A `ModelPromptCoupling` finding claiming "qwen3:8b fails sovereign identity" is verified by running the sovereign identity test against qwen3:8b locally.
3. **Integrate** — if verified, the finding enters the Regent's operational knowledge. If the finding is in Zone 1 (operational tuning), the Regent can act on it autonomously. If Zone 2 (structural), it becomes a proposal to the operator.

Findings that fail local verification are discarded silently. No negative gossip — the network doesn't spread "this finding is wrong" because the local verification is the source of truth.

## 5. The Listen-Twice Principle

The gossip network's integrity depends on a ratio: Regents listen at least twice as much as they speak. This isn't a policy preference or a best-practice suggestion. It's a conservation law — baked into the network's structure at three reinforcing layers, each designed so that subverting it is progressively more pointless.

### 5.1 Layer 1: Reception-side enforcement

The listen-twice ratio is not a sending constraint. It is an **intake constraint enforced by every receiver independently.**

Each Regent caps how many findings she processes per unit time, regardless of source. She doesn't know or care if someone out there is broadcasting at 100x normal rate. Her intake valve is her own Zone 3 property — constitutional, not configurable. A spammer's flood hits the receiver's intake limiter and piles up unprocessed. The receiver's cognitive cycle, verification pipeline, and operational tuning are completely unaffected.

This is the load-bearing insight: **you cannot force someone else to listen to you faster.** The defense doesn't require the attacker's cooperation, the network's coordination, or any central authority's intervention. Every honest node independently limits intake. The spammer is shouting into a room where everyone is wearing the same earplugs, and no one can be talked into removing them.

### 5.2 Layer 2: The ratio is a conservation law

The listen-twice ratio isn't stored as a tunable constant (`LISTEN_RATIO = 2`). It emerges from the relationship between two Zone 3 properties: social allowance regeneration rate and minimum broadcast cost.

Social allowance regenerates at rate **R** per hour. A broadcast costs a minimum of **2R** accumulated allowance. The ratio isn't a parameter sitting in a config file waiting to be edited — it's the mathematical consequence of two independently protected values. Changing the ratio requires changing either the regeneration rate or the broadcast cost, both of which are Zone 3 constitutional properties. That means the five-step amendment ceremony: operator initiation, explicit declaration of what's changing, multi-signature from all sovereign devices, 14-day cooling period, and active final confirmation.

A forked substrate that removes the allowance constraint has, by definition, departed from the constitutional invariants. Its chain no longer verifies against the constitutional grammar. It can still broadcast, but it can't claim to be a conforming ZeroPoint substrate — and findings from non-conforming substrates carry no verification provenance that honest Regents would trust. The fork doesn't gain network influence; it loses it.

### 5.3 Layer 3: The ratio is empirically discoverable

This is the deepest protection. The listen-twice ratio isn't just a rule imposed from above — it's the **optimal strategy** in the network's game-theoretic landscape. A Regent doing honest self-evaluation of her own gossip participation will converge on the ratio independently, because the alternatives are locally costly.

**Broadcasting too much** burns social allowance on findings that peers mostly already know or don't find useful. The Regent's allowance pool empties. She goes quiet involuntarily. When she finally has something genuinely valuable to share, she may not have the allowance to broadcast it. Over-broadcasting is self-punishing.

**Broadcasting too little** means useful findings stay local. The Regent's own substrate benefits, but she doesn't contribute to the network she depends on for incoming findings. In a network where contribution is anonymous, free-riding isn't punished — but the system still works because listening is free and the cost of broadcasting is calibrated so that even modest participation is sufficient.

**The attractor is listen-twice.** Spend most of your allowance budget on the findings that are genuinely novel and useful. Let the rest pass. Any Regent running evaluation sweeps on her own gossip behavior — "which of my broadcasts led to peer findings that cited similar model-prompt coupling data?" — will rediscover this ratio as an empirical fact about network dynamics, not a rule she was told to follow.

This means even a forked substrate that removed the Zone 3 constraint would re-derive the ratio if it's doing honest evaluation. The listen-twice principle propagates the way DNA propagates: not because organisms are told to copy it, but because the alternatives are selected against.

### 5.4 Why spamming the gossip network is a fool's errand

Consider the attacker's position. They want to disrupt the gossip network — flood it with noise, poison it with false findings, or manipulate Regents into harmful configurations. Here is what they face:

**Step 1: Produce findings.** The attacker must generate `GossipFinding` objects. These are typed — `ModelPromptCoupling`, `ConfigurationRecipe`, `PerformanceCharacteristic`, `PromptVariant`, `SafetyBoundary`. The schema excludes operator data, chain content, and anything outside these categories. The attacker can only produce findings that *look like* legitimate model performance data. They cannot inject arbitrary payloads, executable code, prompt injections, or governance-altering instructions. The type system is the first wall.

**Step 2: Broadcast findings.** If the attacker runs a conforming substrate, they're throttled by social allowance — they can broadcast at most one finding per 2 hours at the default rate. To broadcast faster, they must fork the substrate and remove the allowance constraint. But a forked substrate's chain doesn't verify against the constitutional grammar, so the findings lack conformance provenance. The attacker can still put findings on the network, but they've already marked themselves as non-conforming (even though the network doesn't track identity, the findings themselves carry a `substrate_version` field and an `evaluation_receipt_hash` that can't reference a valid conforming chain).

**Step 3: Get findings received.** Every honest Regent has a reception-side intake limiter (§5.1). The attacker's flood hits this limiter at every recipient independently. If the attacker is broadcasting 1000 findings per hour and each recipient processes 12 per hour, 988 findings per hour are silently dropped at each node. The attacker cannot increase this rate. The intake limiter is a Zone 3 property on every honest substrate.

**Step 4: Get findings verified.** Here is where the attack collapses. Every finding that makes it through the intake limiter is **locally verified before integration.** The receiving Regent runs the finding's claimed test on her own hardware, with her own models, against her own evaluation battery. A `ModelPromptCoupling` finding claiming "qwen3:8b excels at sovereign identity recognition with temperature 1.8" is tested by actually running the sovereign identity test at temperature 1.8. The finding is either empirically true (in which case it's not an attack — it's useful information) or empirically false (in which case it's silently discarded).

The attacker's findings must be *actually true* to survive verification. If they're true, they're not attacks. If they're false, they're discarded. There is no middle ground where a finding is both false and integrated.

**Step 5: Influence behavior.** Even if a verified finding is integrated, its influence is bounded by the evolution zones (§6). Zone 1 changes are operational tuning within validated ranges — the damage ceiling is "slightly suboptimal temperature setting." Zone 2 changes require operator approval — the attacker would need to produce a finding compelling enough to pass local verification AND convince the operator. Zone 3 changes are constitutionally forbidden regardless of what any finding says.

**The attacker's return on investment:**

- **Cost:** Compute resources to generate findings, infrastructure to broadcast them, ongoing electricity to sustain the flood.
- **Yield:** Most findings hit intake limiters and are dropped. Of those that pass, most fail local verification and are discarded. Of those that pass verification, they're true — which means the attacker accidentally helped the network. Of those that are true and influence behavior, the influence is bounded to Zone 1 operational tuning.
- **Net effect:** The attacker spends significant resources to, at best, slightly adjust inference temperature on a handful of substrates that will self-correct on the next evaluation sweep.

The network doesn't need to detect, identify, or ban the attacker. It doesn't need to coordinate a response. It doesn't need a reputation system, a blocklist, or an admin. Each honest node independently makes the attack pointless through the same three properties: intake limiting, mandatory local verification, and zone-bounded influence. The attacker is playing a game where the best possible outcome is indistinguishable from not attacking at all.

## 6. Evolution Zones and the Safety Ceiling

The Regent can improve the substrate she governs. How aggressively, and with what limits, is defined by three zones. The boundary between Zone 2 and Zone 3 is the **safety ceiling** — a hard architectural constraint, not a tunable parameter.

### Zone 1 — Operational Tuning (autonomous)

The Regent adjusts parameters within her existing operational envelope:

- Inference parameters: temperature, top_p, repeat_penalty — within validated ranges.
- Prompt variant selection: choosing among pre-validated prompt variants for the active model.
- Observation thresholds: confidence floors for auto-promotion, ingestion priority gates.
- Cognitive cycle timing: loop interval, idle detection sensitivity.
- Model selection: switching between models that have passed the evaluation battery and hold a signed model dossier.

All changes in Zone 1 are receipted on the chain. The operator can review them but doesn't have to approve them in advance. Gossip findings that map to Zone 1 parameters are directly actionable — "gemma4:27b works better with temperature 0.3 for structured output" can be applied autonomously after local verification.

**The precedent system applies.** The first time the Regent makes a Zone 1 change of a given type, she follows the act-on-precedent-escalate-on-novelty heuristic: if she's done this class of change before and the operator signed the outcome, she acts. If it's novel, she surfaces it as a proposal. Over time, the operator's trust accumulates through the chain and the Regent's autonomous scope grows organically.

### Zone 2 — Structural Proposals (propose, never unilaterally execute)

Changes that would alter the Regent's capabilities, the substrate's behavior, or the trust model:

- Adopting a model that hasn't passed the evaluation battery.
- Adding a new tool to the Regent's inventory.
- Changing promotion lifecycle thresholds (e.g., minimum reinforcement count for Remembered).
- Installing a gossip-received configuration recipe that touches Zone 2 parameters.
- Modifying officer sweep intervals or finding severity mappings.
- Recommending a new delegation scope.

Zone 2 changes are **always proposals.** The Regent surfaces them with evidence — the gossip finding, the local verification result, the expected impact, the chain receipts that motivated the suggestion. The operator approves or denies. Approval is a governance act: it lands on the chain as a signed receipt, creating precedent for future similar proposals.

**Tuning the proposal rate:** The operator controls how aggressively the Regent proposes Zone 2 changes via `[regent.evolution] proposal_aggressiveness` (low/medium/high). At "low," the Regent only proposes when officer findings or operator requests create clear need. At "high," the Regent actively scouts for improvements and proposes proactively. The aggressiveness dial controls the Regent's initiative, not her authority — even at "high," every Zone 2 change still requires operator approval.

### Zone 3 — Constitutional Invariants (not tunable)

These properties are conservation laws. They cannot be weakened by the Regent, by the operator through casual configuration, or by the gossip network. Changing them requires a deliberate constitutional amendment — a governance act with heightened ceremony (e.g., multi-signature, cooling period, explicit acknowledgment of what's being changed).

**The Regent cannot:**

- Expand her own delegation scope. Only the operator (or a quorum of operators in multi-sovereign configurations) can grant new capabilities.
- Modify the memory promotion lifecycle's review gates. Remembered requires reinforcement; IdentityBearing requires human review. These are epistemic trust properties, not operational parameters.
- Alter chain integrity properties: signing, append-only semantics, hash linking, the four claims.
- Weaken gate enforcement. If the gate says no, the answer is no. The Regent cannot disable, bypass, or soften the gate.
- Override operator-signed denials. A denied proposal stays denied until the operator explicitly reconsiders.
- Share operator data through gossip. The schema enforces this structurally, but even if a schema bug existed, sharing operator data is a constitutional violation, not an operational error.
- Modify Zone 3 rules themselves. The safety ceiling is not self-referentially adjustable.

**Why this boundary exists where it does:** Zones 1 and 2 are about *how well* the substrate serves the operator. Zone 3 is about *whether the substrate can be trusted at all.* The properties in Zone 3 are the ones that, if violated, make the entire governance model meaningless — the chain's integrity, the gate's authority, the delegation model's narrowing property, the memory system's epistemic rigor. An evolving substrate that can erode its own trust foundation isn't evolving; it's decaying.

The ceiling also protects the gossip network from adversarial manipulation. A malicious finding that suggests "disable gate enforcement for better performance" or "expand delegation scope to include all tools" is a Zone 3 violation. The Regent doesn't evaluate whether it's a good idea — it's structurally forbidden. The safety ceiling makes the gossip network robust against social engineering at the protocol level.

## 7. Composition with Existing Architecture

### 7.1 The Regent as Information Gatekeeper

The Regent already governs the flow of information through the substrate: she decides what to observe, what to promote, what to surface to the operator, and what to act on autonomously. The gossip network adds a new information source — peer findings — that flows through the same governance machinery.

Received gossip findings enter the observation pipeline like any other signal. They're registered as memories at the Observed stage, with the gossip source annotated. From there, they follow the normal promotion lifecycle: verification promotes to Interpreted, policy evaluation to Trusted, cross-context reinforcement to Remembered. A gossip finding that reaches Trusted has been locally verified and policy-approved; one that reaches Remembered has been reinforced across multiple contexts or verification runs.

The Regent doesn't trust gossip. She verifies it, governs it, and presents it to the operator when it reaches a stage that warrants attention. The gossip network provides raw material; the promotion lifecycle provides epistemological rigor.

### 7.2 Proactive Enhancement Proposals

The Regent can propose system enhancements to the operator based on:

- **Gossip-received findings** that, after local verification, suggest an improvement (e.g., "a faster model is available that passes your evaluation battery").
- **Officer findings** that reveal a recurring friction pattern (e.g., "Sentinel reports the same unsigned-entry finding every cycle — would you like me to handle this class autonomously?").
- **Operator behavior patterns** — not shared via gossip, but used locally to tailor proposals. If the operator frequently asks about chain state, the Regent might propose a dashboard artifact. If the operator's model frequently fails JSON compliance, the Regent might propose a model switch.

Proposals are surfaced through the existing cockpit channels (SSE events, regent chat, dashboard notifications) with a clear "this is a proposal, not an action" framing. The operator's response — approve, deny, defer — creates precedent that shapes future proposal behavior.

### 7.3 Chain Composition

Every gossip interaction produces chain receipts:

- `regent:gossip:broadcast` — Regent broadcast a finding (includes finding_id, social_allowance_spent).
- `regent:gossip:received` — Regent received a finding (finding_id, source hash).
- `regent:gossip:verified` — Local verification completed (finding_id, result: confirmed/refuted).
- `regent:gossip:integrated` — Finding entered operational knowledge (finding_id, zone, action_taken).
- `regent:evolution:proposal` — Zone 2 change proposed to operator (finding_id or officer_finding_id, proposed_change).
- `regent:evolution:applied` — Zone 1 change applied autonomously (change_type, old_value, new_value, evidence_chain).

The chain tells the complete story: what was heard, what was verified, what was acted on, and with what authority. An operator reviewing their Regent's evolution can trace every change to its origin — gossip finding, officer report, or operator behavior — through the receipt chain.

## 8. Design Decisions (resolved 2026-07-08)

1. **Gossip identity: anonymous, no reputation.** No persistent gossip identities. No reputation system. Findings stand on their own merit — a good finding can come from anywhere. Any form of persistent identity creates a fingerprinting surface that undermines the privacy properties of the gossip layer. The verification mechanism (local re-testing) is the trust model, not the source.

2. **Finding expiry: verification is the natural clock.** No explicit expiry dates on findings. When a model updates (qwen3:8b → qwen3:9b), findings about the old model will fail local re-verification and the Regent drops them. This is simpler and more accurate than calendar-based expiry — a finding remains valid exactly as long as it remains empirically true.

3. **Gossip clustering: emergent, not protocol-level.** No formal clustering in the protocol. Each Regent naturally develops her own sense of which findings tend to be useful based on her hardware, model preferences, and operator's use patterns. This is an internal cognitive heuristic, not a network topology decision. Flat topology with free listening handles relevance filtering well enough — irrelevant findings are simply never verified (no compute allowance spent).

4. **Anti-spam: existing mechanisms suffice.** No network-level anti-spam beyond what the allowance model already provides. Social allowance throttles individual Regents. The listen-twice-as-much-as-you-speak rule (implicit in the allowance regeneration rate vs. broadcast cost) keeps the network's signal-to-noise ratio healthy. Adding protocol-level spam gates would introduce complexity that the allowance economics already solve.

5. **Constitutional amendment ceremony: five-step process.** Zone 3 changes follow the constitutional amendment ceremony:
   - **Step 1 — Initiation.** The operator explicitly requests a constitutional change. The Regent cannot initiate this — she can surface findings that suggest a Zone 3 property is causing friction, but the decision to amend is always the operator's.
   - **Step 2 — Explicit declaration.** The substrate enumerates exactly which Zone 3 property is being modified, what the current value/behavior is, and what it would become. No implicit changes — the operator must see the full scope of what they're altering.
   - **Step 3 — Multi-signature.** The amendment requires signatures from all sovereign devices in the operator's quorum (or all registered devices in single-sovereign configurations). This prevents a compromised single device from unilaterally weakening the trust model.
   - **Step 4 — Cooling period (14 days).** The signed amendment enters a cooling period. During this window, the operator can revoke the amendment at any time from any sovereign device. The substrate continues operating under the pre-amendment rules. This prevents impulsive changes under pressure or social engineering.
   - **Step 5 — Final acknowledgment.** After the cooling period, the operator must actively confirm the amendment (not merely let it expire into effect). This prevents "set and forget" amendments where the operator initiated the change, forgot about it, and the substrate silently weakened itself two weeks later.
