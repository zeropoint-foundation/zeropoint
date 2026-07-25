# Sovereign Kinship Primitives

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), Part VII (Peer-Verification Contract), §II.17 (Cognitive discipline sandwich), and §II.18 (chain-anchored commitments). Specifies the substrate primitives for cross-sovereign kinship: mutual chain-anchored relationships, per-scope sharing grants, cross-Regent narration surface, Regent-to-Regent familiarity accumulation, and the operator-authored labeling layer that turns primitives into legible categories. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `PEER-TRUST-ANCHOR-2026-07.md` (substrate-level admissions; kinship layers on top for cross-sovereign sharing), `COGNITIVE-INPUT-PLANE-2026-07.md` (cross-Regent narrations enter Regent's context at advisory tier), `CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md` (commitments coordinate cross-Regent actions), `CIRCUIT-BREAKER-2026-07.md` (kinship scope suspension as emergency response), `WIFI-SENSING-AND-RF-SURVEILLANCE-2026-07.md` (sensing findings are one class of kinship-shared data), the pending shared-space etiquette spec.

## Framing

The substrate's cross-sovereign discipline so far treats other sovereigns as peers with per-surface admission (chain admission, extension admission, observation reference, commitment endorsement, delegation federation, reputation input) per PEER-TRUST-ANCHOR. That covers the operational trust surface — enough to admit peer-signed chain segments, honor peer commitments, share reputation input. It does not cover the *relational* surface: two sovereigns who have chosen depth of mutual context, whose Regents have accumulated shared familiarity over time, who want their substrates to share sensing findings and coordinate actions when they're together.

Real relationships have this shape naturally. Old friends know each other's rhythms. Family members coordinate on shared responsibilities. Colleagues develop working shorthand. When these people carry substrate nodes, their substrates should be able to reflect that accumulated mutual context — with the same operator-authorized structural discipline the substrate applies everywhere else.

Three properties frame the primitives:

1. **Kinship is a mutual chain-anchored relationship between two sovereigns.** Not a per-surface admission (that's peer-trust-anchor's job); a paired declaration that both sovereigns have signed with per-scope sharing grants attached.
2. **Categories are operator-authored, never universalized.** The substrate provides primitives (kinship declaration, per-scope grants, bundles, labels). The operator authors their own relationship categories (their "chosen family," their "climbing partners," their "old college crew"). The substrate does not impose a taxonomy.
3. **Cross-Regent familiarity is a first-class primitive.** Familiar Regents accumulate chain-anchored precedent about their prior interactions and their operators' relationship. They draw on this shared history to serve their respective operators better when in shared context. Never merges context; never merges delegation.

## The three-layer shape

Substrate primitives (universal) support operator-authored categorization (per-sovereign) which supports Regent reasoning (per-cycle).

- **Layer 1 — Substrate primitives.** Kinship declaration, sharing scope grants, cross-Regent narration surface, Regent-to-Regent familiarity accumulation, copresence detection, revocation. Universal, chain-anchored, Genesis-derived. Same discipline as any other substrate primitive.
- **Layer 2 — Operator authoring.** Operator-declared labels applied to kinship declarations, operator-authored grant bundles, per-relationship customization. Chain-anchored per operator; not universalized across sovereigns.
- **Layer 3 — Regent reasoning.** Regent uses operator's labels for category-level reasoning, uses per-relationship grant truth for enforcement, uses cross-Regent familiarity for shared-context inference.

## Layer 1 — Substrate primitives

### Kinship declaration

Chain-anchored mutual relationship between two sovereigns. Both parties sign.

Receipt: `kinship:declared:<sovereign_a>:<sovereign_b>:<kinship_id>`. Fields:
- Both sovereign Genesis public keys
- Timestamp
- Optional operator-provided context (private per each operator; not shared)
- Cross-signed via chain-anchored ceremony (each substrate emits mirroring receipt on its own chain)

Kinship declaration itself is content-free about "what kind of relationship." No category, no tier, no depth. It names the pair.

### Sharing scope grants

Per-scope permissions granted bidirectionally within a kinship. Each scope is granted independently, signed by both parties for elevation, signed unilaterally for revocation.

**Canonical scope classes serve coordination, not oversight.** Scopes support specific, purposeful, narrow sharing for shared work. The substrate does not provide review-shaped scopes ("review my kinship graph," "review my copresence log," "review my life") — those are surveillance shapes even at explicit mutual grant, and the substrate structurally does not offer them regardless of authorization. If two operators want to share more than the coordination primitives support, they do it through conversation and context, not through substrate review surfaces. This boundary is load-bearing (see "Coordination, not oversight" below).

- `kinship:scope:copresence_awareness` — mutually acknowledge when substrates detect copresence. Ephemeral acknowledgment signal; not a logged history for later third-party review.
- `kinship:scope:household_presence` — for household kinships, mutual home-arrival/departure signal. "Home / not home" state, not full location, not activity detail.
- `kinship:scope:mood_signals` — filtered high-level mood/state findings when copresent. For sovereigns who want their kindred to be aware of their state during shared time.
- `kinship:scope:biometric_findings` — filtered biometric findings (respiration, activity level, sleep patterns) from sensing extensions during copresence. For household or care contexts where mutual biometric awareness serves shared work.
- `kinship:scope:intrusion_awareness` — mutual anomaly alerts when copresent in shared space.
- `kinship:scope:emergency_notification` — activation only under operator's declared crisis triggers (medical event, physical safety event). Silent otherwise. Not general "keep in touch" primitive.
- `kinship:scope:mutual_safety_check` — time-bounded activatable location visibility for a stated safety purpose (hiking alone, late drive, unfamiliar area). Operator activates per-encounter with declared duration; not always-on.
- `kinship:scope:commitment_coordination` — Regents can coordinate on specific shared commitments (dog-sitting, kids' pickup schedule, event responsibilities). Scoped to the committed activity, not general presence.
- `kinship:scope:coordinated_calendar` — read access to specific calendar categories the operator has tagged as shared with this kindred sovereign. Not full calendar access; only tagged shared context.
- `kinship:scope:activity_coordination` — for specific shared activities both operators do together (training partners, book club, joint household management). Scoped to the activity context.
- `kinship:scope:cross_regent_narration` — Regents can narrate to each other within the bounds of other granted scopes. Narrations MUST NOT reveal information outside the specific scope authorizations; scope compliance is verified pre-emission by Cognitive Self-Observer. Never used as a covert broader-visibility channel.
- `kinship:scope:spatial_ontology` — shared spatial context for household kinships (shared zone naming, shared spatial commitments). Serves shared home coordination; not remote-review of household state.

Grants may be extended via extension surface for domain-specific sharing classes (per EXTENSION-SURFACE-2026-07.md). Each scope grant is:

- Bidirectional at grant time (both parties sign to elevate)
- Unilaterally revocable (either party revokes; chain-visible)
- Time-bounded (permanent, ongoing, time-window, or per-encounter)
- Copresence-gated (always-on, copresence-only, or trigger-conditional)
- Revocable at scope granularity (revoking one scope doesn't dissolve the kinship)

Grant receipt: `kinship:scope:granted:<kinship_id>:<scope_class>:<grant_id>`. Revocation receipt: `kinship:scope:revoked:<kinship_id>:<scope_class>:<grant_id>`.

### Cross-Regent narration surface

Interface for one Regent to address another Regent. Requires `kinship:scope:cross_regent_narration` grant.

Narration receipt: `regent:cross_narration:<from_regent>:<to_regent>:<kinship_id>:<narration_id>`. Fields:
- Both Regents' identity
- Kinship ID (which relationship this narrates under)
- Narration content (filtered findings; never raw signals per cognitive-layer boundary)
- Optional urgency signal
- Optional operator-directive flag ("please surface to your operator")

Receiving Regent decides how/whether to surface to their own operator. Cognitive Input Plane treats cross-Regent narrations as Tier 3/4 input — advisory, not authoritative. Receiving Regent's own operator directives always outrank.

Cognitive Self-Observer verifies that Regent's cross-narrations don't leak information outside declared scope. Cross-narration attempting to leak raw sensing data or private operator context is flagged as violation.

### Regent-to-Regent familiarity accumulation

Chain-anchored history of prior cross-Regent interactions per kinship. Familiar Regents draw on this history when serving their respective operators in shared context.

Familiarity receipt: `regent:familiarity_accumulated:<kinship_id>:<accumulator_id>`. Content: chain-anchored summary of interaction patterns — communication cadence, coordination patterns, shared activity context, prior operator-preference-observations shared across.

Familiarity is not a merge of context. Each Regent maintains their own cognitive state; familiarity is a *read-only accumulated summary* that both Regents can consult for coordination. Neither Regent gains authority in the other's cognitive space through familiarity.

Familiarity is chain-anchored so it survives Regent restart, model reprovisioning, or Genesis rotation. Both parties can review accumulated familiarity via chain query.

### Copresence detection

Substrates detect copresence via short-range chain-signed proximity attestations. When kinship is declared, both substrates emit signed short-range beacons (BLE / UWB / other short-range modalities) that other kindred substrates can receive to establish copresence.

Copresence receipt: `kinship:copresence_detected:<kinship_id>:<detection_id>`. Emitted when both substrates mutually confirm proximity.

Copresence-gated grants activate only during confirmed copresence. Copresence-end receipt (`kinship:copresence_ended:<kinship_id>:<detection_id>`) deactivates.

## Layer 2 — Operator authoring

### Operator labels

Operator applies labels to kinship declarations to reason about relationships in their own categories. Labels are per-operator; not shared, not universalized.

Label receipt: `operator:kinship:label:<kinship_id>:<label_string>`. Fields:
- Kinship ID
- Label string (operator-chosen: "chosen family," "climbing crew," "old work friends," whatever)
- Operator's private context

An operator can apply multiple labels to one kinship ("close friend" + "climbing crew" + "chosen family"). Labels are queryable ("show me all my 'chosen family' kinships"). Labels are chain-anchored so they persist across substrate restart and Regent reprovisioning.

Labels are NOT visible to the other sovereign in the kinship. Each operator names their relationships in their own vocabulary. The other sovereign has their own labels for the same relationship.

### Operator bundles

Operator authors grant bundles — reusable compositions of grant scopes with time/copresence configurations — that can be applied to specific relationships.

Bundle receipt: `operator:kinship:bundle:defined:<bundle_id>`. Fields:
- Bundle name (operator-chosen)
- Included scopes with their configurations
- Optional metadata

Bundle application: applying a bundle to a kinship generates individual grant receipts (grants remain the primitive; bundles are the operator convenience). Modifying the bundle later does not modify prior applications (bundle changes affect future applications only). Modifying an individual grant post-application does not modify the bundle.

Example bundle: operator authors a "close-friends bundle" — `{presence: always, mood_signals: copresence, cross_regent_narration: shared_activities, biometric_findings: never}`. Applies to 12 relationships. Later, one friend asks to also share sleep-pattern findings; operator adds a scope grant to that specific kinship. Bundle unchanged; individual relationship customized.

### Per-relationship customization

Any grant may be added, modified, or revoked per-relationship independent of any bundle it was applied from. Kinship declarations are always the truth; bundles are convenience over the truth.

## Layer 3 — Regent reasoning

Regent uses operator's labels for category-level handles, uses per-relationship grants for enforcement truth, uses cross-Regent familiarity for shared-context inference.

- **Category-level reasoning**: "notify my close friends I'm going out of town" → Regent finds kinships labeled "close friends" → checks each kinship's active grants → narrates per what's authorized
- **Truth-level enforcement**: individual grants are the enforcement truth; Regent never assumes "friend implies scope X" unless the specific scope grant exists
- **Familiarity-informed narration**: when copresent with familiar-kinship Regent, Regent draws on accumulated familiarity to inform how to communicate ("this Regent's operator prefers gentle wake, not urgent")

Regent's reasoning about kinship goes through Cognitive Input Plane at declared tiers. Kinship-scoped findings appear as Tier 2-3 (contextual); cross-Regent narrations appear as Tier 3-4 (advisory); operator's kinship-directives appear as Tier 4 (recency-anchored, closest to output).

## Cognitive-layer boundary discipline

Load-bearing invariants for kinship, same discipline as elsewhere:

- **No raw signal sharing across sovereigns.** Cross-Regent narrations and kinship-scoped findings are always filtered high-level content. Raw CSI, raw audio, raw sensor streams never cross the sovereign boundary.
- **No delegation merge.** Kinship does not grant either Regent any authority in the other's substrate. Cross-Regent narrations are advisory only.
- **No cognitive context merge.** Each Regent maintains their own cognitive state. Familiarity is a read-only accumulated summary, not a shared context surface.
- **No operator-preference leakage without explicit grant.** Operator's preferences don't cross to kindred sovereign's Regent unless explicitly authorized via scope grant.
- **Cognitive Self-Observer verifies scope compliance.** Cross-narrations that exceed declared scope are flagged as violations.

## Composition with existing specs

- **PEER-TRUST-ANCHOR** provides substrate-level admissions (chain, extension, observation, commitment, delegation, reputation). Kinship *requires* baseline peer-trust-anchor for the kindred sovereign — chain admission at minimum. Kinship *adds* per-scope sharing not covered by the six peer-trust-anchor surfaces.
- **COGNITIVE-INPUT-PLANE** consumes cross-Regent narrations at Tier 3/4 (advisory). Priority-weighted so operator directives always outrank kindred-Regent input.
- **CHAIN-WATCHER-AND-COMMITMENTS** provides the coordination primitives that let cross-Regent commitment coordination work ("host commits to notify visitor's Regent if pattern X during their visit").
- **CIRCUIT-BREAKER** can suspend all kinship-scope sharing on emergency escalation; graduated levels (suspend specific scope → suspend all kinship-scope sharing → revoke kinship declaration → escalate to substrate-wide response).
- **WIFI-SENSING-AND-RF-SURVEILLANCE** produces sensing findings; kinship's biometric-findings scope authorizes sharing of specific finding classes with kindred sovereigns.
- **QUARANTINE-PLANE-adjacent**: cross-Regent narrations still admit through cognitive input plane at their declared tier; trust source is elevated but admission discipline still applies.
- **GENESIS-ROTATION-CEREMONY**: kindred sovereign rotates Genesis → operator reviews rotation notification → decides to accept (kinship updates to new Genesis) or reject (kinship enters degraded state pending investigation).

## Attack model

- **Attacker impersonates kindred sovereign**: chain-verified signatures prevent. Kinship receipts require both sovereigns' Genesis signatures.
- **Attacker manipulates cross-Regent narration to leak operator context**: Cognitive Self-Observer verifies scope compliance; violations chain-visible; operator can revoke narration scope.
- **Attacker exploits familiarity accumulation to build attack surface**: familiarity is read-only summary, not authority. Attacker gaining familiarity data cannot act on it; familiarity accumulation itself is chain-visible so anomalous accumulation patterns can be flagged.
- **Attacker forges copresence to activate copresence-gated scopes**: copresence detection requires mutual chain-signed short-range attestations; forging both sides requires compromising both sovereigns' Genesis.
- **Attacker uses kinship channel for exfiltration**: cross-Regent narration is chain-anchored; every narration is visible on both operators' chains; anomalous volume or content patterns detectable.
- **Attacker manipulates operator into over-broad bundle application**: bundle application is operator ceremony; substrate surfaces each grant explicitly at application time; Regent can flag "bundle application would broaden your sharing to N relationships — review each?"
- **Attacker compromises kindred sovereign's Regent to leak via cross-narration**: cross-narrations are visible; sudden pattern shifts trigger investigation. Operator can suspend narration scope pending investigation.
- **Attacker triggers false anomaly to force circuit-breaker kinship suspension**: circuit breaker requires calibrated trigger thresholds; individual kinship suspension is less severe than substrate-wide response, so DoS-scale attack is expensive.

## Failure modes

- **Relationship ends**: unilateral revocation ceremony. Chain records the revocation. Prior chain-anchored kinship receipts remain as history under the former relationship; forward sharing under revoked scopes stops. Familiarity accumulation is retained in chain history but no longer read by either Regent.
- **One party wants deeper sharing, other doesn't**: scope grants are bidirectional. If one party grants a scope but the other doesn't reciprocate, the grant remains pending (chain-visible). No unilateral sharing.
- **Kindred sovereign becomes untrustworthy**: operator revokes at appropriate scope or revokes kinship entirely. Circuit breaker can suspend during investigation.
- **Cross-Regent narration content drifts operator-attention**: receiving Regent has admission discipline via Cognitive Input Plane; operator directives outrank; Cognitive Self-Observer flags concerning patterns.
- **Bundle definition changes affect operator's mental model of past applications**: bundle changes don't modify past applications, but operator may forget which relationships got which bundle version. Dashboard shows per-relationship grant provenance.
- **Copresence detection fails (dead battery, RF interference)**: copresence-gated scopes don't activate. Operator UX surfaces "kinship active but copresence not detected" clearly.

## Coordination, not oversight

The substrate's kinship primitives serve *coordination*: specific, purposeful, narrow sharing between sovereigns whose lives include shared work. They do not serve *oversight*: broad, ongoing, categorical review of another sovereign's life. This is a load-bearing boundary. Scopes that would enable oversight — "review my kinship graph," "review my copresence log," "review my activities" — are structurally not offered as primitives, regardless of whether both parties would grant them. The substrate does not provide surveillance surfaces even at explicit mutual authorization.

Why the boundary sits here:

- **Surveillance shapes produce known harms.** Categorical mutual-review scopes, even under mutual grant, create the exact affordances that historically produce coercive relationships, jealousy amplification, and violence-adjacent dynamics. Adding "graph visibility" as a substrate primitive puts the primitive in reach; social pressure ("if you loved me you'd share") does the rest.
- **Coordination doesn't require oversight.** Households can coordinate arrivals via `household_presence` without either party reviewing the other's full location history. Safety check-ins happen via time-bounded `mutual_safety_check` activated per-encounter, not always-on tracking. Every legitimate coordination use case has a narrow-scope shape that serves the work without the oversight surface.
- **Real intimate trust often includes granted privacy.** Trust in mature relationships often means the choice *not* to know everything — respecting the other person's inner life and autonomous activity. Substrate primitives that make "review my life" a first-class scope put thumb on scale toward transparency-as-trust, which conflates two very different things.
- **If two people want to share more, they can — outside substrate primitives.** Conversation, shared context, invited disclosure. The substrate doesn't need to (and shouldn't) mediate every trust-deepening choice. Some things are richer when they happen through the operators themselves.

### Alignment incentivized, not surveilled

The consequence of coordination-not-oversight is that the substrate becomes a *fitting-shape for aligned life* rather than a *monitoring-shape for divergent life*. This is the incentive structure worth naming explicitly.

Aligned life — where stated relationships, chain-anchored commitments, and actual behavior cohere — fits the substrate primitives naturally. Coordination scopes serve their shared work. Commitment receipts land as truth. Cross-Regent narrations reflect actual relational context. Nothing requires ongoing management of divergent narratives.

Misaligned life — where stated relationships and actual behavior diverge — generates friction naturally. Not because the substrate surveils. Because chain-anchored primitives structurally record what happened, and maintaining a story that diverges from the record requires ongoing exceptions. Every commitment that must be broken, every household-presence signal that must be explained, every emergency notification that would surface something unwanted — these accumulate as cognitive load. Nobody is watching. The friction is the natural weight of trying to hold together divergent narratives across chain-anchored infrastructure.

The substrate is neutral about human choices. People will make their own choices about their lives and relationships, and they should. But the substrate is not neutral about *shape*. It's shaped for coordination between operators whose lives cohere. Aligned life fits smoothly; misaligned life generates friction proportional to the divergence. This is designed. It's the incentive structure the substrate provides: not enforcement, not surveillance — fit.

Everyone lives better in coherent lives. The substrate is shaped to reward that.

### What kinship primitives do make structural

Coordination scopes make explicit a few things that used to be implicit within families and households:

- **Which coordination surfaces are shared** — the household knows arrival/departure via `household_presence` because both parties granted it; without the grant, that coordination is implicit or verbal
- **What activities have shared commitments** — dog-sitting, kids' pickup, joint household management are chain-anchored commitments across kindred Regents rather than implicit assumptions
- **When emergency notification is authorized** — the substrate doesn't guess when to reach out to family; operator declared their crisis triggers and their emergency contacts, chain-anchored
- **What activities compose shared context** — coordinated calendar categories, activity-specific scopes, mutual safety-check activation

These are useful precisely because they're narrow. The household coordinates better because presence signaling is explicit; the safety check-in works because it's declared duration and purpose; the emergency notification activates for actual emergencies and stays silent otherwise. Coordination becomes reliable structural rather than depending on memory and ambient attention.

What kinship primitives do NOT make structural is intimate mutual visibility. That question stays where it was: between the people negotiating it, through conversation and lived context, without substrate-provided review scopes to make it a first-class transaction.

## Non-goals

- **Not a substitute for peer-trust-anchor**. Kinship layers on top; both are required. Kindred sovereign must have baseline peer-trust-anchor for substrate-level operations.
- **Not universal relationship taxonomy**. Substrate does not enumerate relationship types. All categorization is operator-authored.
- **Not automatic kinship discovery**. New kinships require explicit mutual ceremony. Substrate does not auto-suggest kinship from co-observed activity.
- **Not shared identity**. Each sovereign remains sovereign. Kinship is chosen mutual context, not identity merging.
- **Not persistent context sharing**. Familiarity is read-only summary of prior interactions, not a shared cognitive stream.
- **Not transitive**. Kinship between A-B and B-C does not imply kinship A-C. Each pair requires explicit ceremony.
- **Not universal across peers**. Some peers may be kindred; most peers are not. Kinship is opt-in per relationship.

## Open positions

- **Kinship declaration ceremony UX**. How does operator initiate kinship? Both operators must sign — how does the substrate handle the coordination? Dashboard flow? CLI verb? Both operators in-person co-signing at initial ceremony?
- **Bundle template library**. Should substrate ship with reference bundle templates (as suggestions, not defaults) that operators can adopt and customize? Trade-off: convenience vs implicit tier imposition.
- **Label discoverability**. Operator has 40 kinships and 15 labels; how do they explore? Dashboard filtering? Regent-narrated summaries?
- **Familiarity accumulation policy**. What's captured in familiarity summaries? Communication patterns, coordination successes, timing preferences? How does operator review and edit accumulated familiarity?
- **Cross-narration urgency schema**. When one Regent narrates urgently to another, how does the receiving Regent decide priority against operator's own state? Ordering discipline for urgent kindred input vs operator directive.
- **Kinship revocation UX**. Ending a relationship is emotionally significant. How does the substrate handle graceful UX around unilateral revocation? Optional notification to the other party? Silent revocation? Operator ceremony required?
- **Copresence detection modalities per Substrate Form**. Sovereign Form with full radio access vs Companion Form with vendor OS limits — copresence detection capability differs. Per-Form capability declaration.
- **Extension-defined kinship scopes**. Should extensions be able to declare new kinship scope classes? Trade-off: capability expressiveness vs core-primitive stability.
- **Shared-space kinship interactions**. When two kindred sovereigns are in a shared space with strangers, how does kinship-scope sharing interact with etiquette-spec public-space defaults? Some kinship sharing may be visible to third parties via metadata even when content is not.
- **Multi-party kinship (households)**. Household of 4 — is kinship pairwise (6 declarations) or is there a multi-party primitive? Trade-off: primitive simplicity vs household ergonomics.

## What composes from here

Immediate design work:

1. **Kinship declaration receipt schemas** — mutual signing protocol
2. **Grant scope canonical spec** — the initial set of scope classes with their default configurations
3. **Bundle authoring UX** — operator flow for defining and applying bundles
4. **Cross-Regent narration protocol** — how narrations flow between substrates
5. **Familiarity accumulation policy** — what's captured, how it's summarized
6. **Copresence detection modality** — short-range signaling implementation

Near-term implementation:

1. Kinship state manager in `crates/zp-server/src/kinship/`
2. Grant scope registry and enforcement
3. Cross-Regent narration surface
4. Familiarity accumulation runtime
5. Copresence detector (BLE / UWB integration per Substrate Form)
6. Dashboard: kinship panel (list kinships, apply/edit labels, apply/edit bundles, review familiarity summaries)
7. CLI verbs: `zp kinship declare|revoke|grant|revoke_scope|list|label|bundle|familiarity`
8. Regent cognitive input plane integration for cross-Regent narrations at Tier 3/4

## Framing note

Sovereign kinship primitives extend the substrate's structural discipline to a dimension previously implicit: the *chosen relational depth* between sovereigns whose Regents share accumulated context. Same principle as chain-anchored discipline elsewhere — extended to mutual sovereign relationships.

The load-bearing insight: **substrate primitives are universal; categories are operator-authored; Regent reasoning uses both.** Not a universal tier taxonomy (that would impose one culture's relationship model). Not pure per-grant composition (that would burden operators with per-relationship hand-crafting and leave Regent without category-level handles). Three layers: kinship declaration + per-scope grants + cross-Regent narration + familiarity as universal primitives; operator-authored labels and bundles as per-sovereign categorization; Regent reasoning across both for legible narration and appropriate enforcement.

Combined with the substrate's structural discipline across every trust boundary — actions, admissions, observations, cognition, extensions, hardware, emergency response, Genesis rotation, peer trust, build lifecycle, reproducibility, recovery UX, standing corrections, hardware compromise evidence, WiFi sensing — sovereign kinship primitives complete the cross-sovereign relational coordination surface. What becomes chain-anchored is the *coordination*: kinship is a declared mutual relationship; grants are per-scope chain-anchored consent for specific shared work; cross-Regent narration is bounded to declared scope; familiarity is read-only shared history; operator's labels are chosen from operator's own vocabulary; Regent reasoning composes primitives and labels for category-level coordination without ever universalizing what "close friend" means.

What does NOT become chain-anchored is intimate mutual review. The substrate does not offer review-shaped scopes — no kinship-graph visibility, no copresence history visibility, no life-review surfaces — even at explicit mutual grant. Categorical review of another sovereign's life is surveillance shape, not coordination shape, and the substrate structurally doesn't provide it. Real intimate trust often includes granted privacy; the substrate respects that by not making review a first-class transaction. If two operators want to share more than coordination primitives support, they do it through conversation and lived context, outside substrate mediation.

The consequence: substrate is a fitting-shape for aligned life. Aligned life — where stated relationships, chain-anchored commitments, and actual behavior cohere — fits primitives naturally. Misaligned life generates friction proportional to divergence, not because the substrate surveils, but because chain-anchored infrastructure structurally records what happened and maintaining divergent narratives requires ongoing exceptions. Nobody's watching. The friction is the natural weight of incoherence. This is the incentive structure the substrate provides: not enforcement, not surveillance — fit. Everyone lives better in coherent lives, and the substrate is shaped to reward that shape.

Sovereignty is preserved because operator authorizes every scope; safety is preserved because Cognitive Self-Observer verifies scope compliance; continuity is preserved because chain records every kinship, every grant, every familiarity accumulation, every revocation — through changes in relationships across time. The substrate doesn't prescribe how people should live. It provides coordination primitives for shared work and lets aligned lives fit naturally.


---

## External-signal note (2026-07-21) — verified-kin challenge (anti-impersonation)

Motivated by the open-model inflection signal (see `AI-LANDSCAPE-SIGNAL-2026-07.md` §4). The "family safe-word against voice/likeness clones" the wider world is reaching for is the low-tech shadow of a Genesis-rooted challenge between kin — a shared secret a clone cannot hold because it lacks the *key*, not because it sounds wrong.

**Canonical scenario — verified-kin challenge.** Kin verify a purported contact against likeness/voice impersonation via a Genesis-rooted challenge rather than recognition. The defended case is deepfake-enabled social engineering — a cloned voice or video requesting an urgent, irreversible action (classically, wire fraud targeting a cognitively-vulnerable dependent). The challenge is narrow, mutual, and purposeful: it answers "is this really my kin?" and nothing more. It is **coordination, not oversight** — it must not compose into a kinship-graph, copresence-history, or life-review surface, and produces no retained record of who challenged whom beyond the minimum. Composes with `DEPENDENT-SOVEREIGNTY` guardian scopes (a guardian may hold challenge capability for a dependent who cannot reliably self-verify).

**Open design decision (not resolved here):** whether this warrants a first-class `kinship:challenge:*` primitive, or is covered by composing existing `safety_check` + `copresence` scopes with a Genesis-rooted challenge. Recommendation leans to composition unless a concrete affordance (offline challenge, dependent-held challenge token, guardian-proxied challenge) needs its own receipt schema. Flagged for a deliberate design pass.
