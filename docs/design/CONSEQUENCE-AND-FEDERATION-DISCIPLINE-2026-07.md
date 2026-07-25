# Consequence and Federation Discipline

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), Part VII (Peer-Verification Contract), Part VIII (bounded operator sovereignty), §III.23 (coordination not oversight), §III.24 (aligned blindness). Specifies what happens when a sovereign misbehaves — the substrate's six-layer consequence model absent any central authority. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `PEER-TRUST-ANCHOR-2026-07.md` (revocation as consequence mechanism), `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (unilateral kinship revocation), `DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` (reputation flow), `CIRCUIT-BREAKER-2026-07.md` (emergency escalation), `CRYPTOGRAPHIC-SOVEREIGNTY-AND-LEGAL-PROCESS-2026-07.md` (external legal systems as Layer 6), `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md` (what substrate can't discover through its own observation), `DISCOVERY-AND-BOOTSTRAP-2026-07.md` (seed operators and directory delisting as federation-level discipline).

## Framing

Every trust-infrastructure system faces the question: what happens when someone does something wrong? The wrong answer is centralized moderation (create a central authority to police behavior — reproduces the surveillance-state failure modes at scale). Another wrong answer is nothing (declare "we don't do enforcement" and accept that bad actors have free reign). The substrate takes neither position. Its answer is: **the substrate is coordination infrastructure that provides evidence and consequence, not prevention and control.** Prevention and control are civil-society functions handled by legal systems, community norms, family and peer relationships, and the operator's own judgment. The substrate makes what happens visible with cryptographic integrity; makes consequences propagate rapidly through peer mesh; preserves identity across sovereignty transitions; and refuses to become surveillance apparatus regardless of any specific good it might do.

The substrate is deliberately not a moderation platform. There is no central authority to petition, no terms-of-service enforcement, no account bans, no vendor-driven consequence. Instead there is a six-layer consequence model where different classes of misbehavior get different substrate responses, all federated, all chain-anchored, all composing with civil society rather than replacing it.

Three properties frame the discipline:

1. **Consequence is federated, not central.** No single actor decides what happens to a misbehaving sovereign. Peers make independent decisions; commons aggregates reputation; community consensus emerges without central authority; legal systems handle actually-illegal behavior. Fast when consensus is clear; slow and messy when contested — but never centrally arbitrated.
2. **Substrate provides evidence, not prevention.** Chain-anchored evidence of what a sovereign did is the substrate's contribution to consequence. Substrate does not stop the sovereign from doing things (aligned blindness prevents that possibility structurally). Substrate makes the doing visible with cryptographic weight that supports both peer consequence and legal enforcement.
3. **The substrate refuses to be a police state even when it would help.** Some things the substrate could technically detect — coordinated harm, illegal content propagation, dangerous behavior patterns — it structurally refuses to observe (aligned blindness, KEEL III.24). This is a design principle, not a bug: substrate that could surveil for good could equally surveil for bad, and no operator can trust a surveillance apparatus regardless of stated intent.

## The six-layer consequence model

Different classes of misbehavior meet different substrate responses. Layers apply in overlapping combination — most incidents involve multiple layers simultaneously.

### Layer 1 — Self-policing within the actor's own substrate

The actor's own Regent, Cognitive Self-Observer, and officers can detect and refuse actions that violate the actor's declared standing corrections. Claim Verifier can pre-emission reject claims outside the actor's delegation scope.

**What catches:** inconsistency (actor says one thing, then does another), delegation-scope violations, standing-correction violations, structural refusals per aligned blindness.

**What doesn't catch:** a determinedly-misaligned actor who changes their own standing corrections. Layer 1 catches the actor whose values are aligned but whose behavior drifts; not the actor whose values are themselves misaligned.

**Chain evidence:** every substrate action produces chain-anchored evidence. Even Layer 1 refusals are chain-visible. If Layer 1 doesn't stop misbehavior, its evidence still accumulates for other layers to use.

### Layer 2 — Kinship and household revocation

Kindred sovereigns and household members can revoke unilaterally per SOVEREIGN-KINSHIP-PRIMITIVES and HOUSEHOLD-COMPOSITION. No permission needed from anyone including the misbehaving actor.

**Mechanics:** emit `kinship:scope:revoked` receipts (unilateral, effective immediately), emit `household:member_departing` receipt (dissolves membership), emit `kinship:declared:revoked` receipts (dissolves entire kinship). Cross-Regent familiarity accumulated under the kinship is retained as historical evidence but no longer read.

**What catches:** interpersonal-scale misbehavior — abuse, betrayal, coercion, boundary violations, degradation of relationship. Immediate consequence at the relationship level.

**What doesn't catch:** misbehavior that doesn't directly touch kindred sovereigns (e.g., anonymous stranger-directed harm at community scale).

**Chain evidence:** revocation receipts document that the kindred party withdrew and (optionally, per kinship charter) name the class of concern.

### Layer 3 — Peer trust anchor revocation

Peers who granted trust anchors to the actor can revoke them per surface per PEER-TRUST-ANCHOR. Each peer decides independently.

**Mechanics:** emit `peer:trust_anchor:revoked` receipts per surface. Actor's chain segments no longer admitted by that peer; actor's vouching claims lose weight; actor's extension distributions refused; actor's observation-references no longer honored.

**What catches:** substrate-mediated misbehavior — bad-actor extension distribution, sybil vouching, chain manipulation attempts, coordinated peer-network attacks. Immediate consequence at the substrate-operations level.

**Cascade dynamics:** when enough peers revoke, actor becomes effectively isolated from the mesh. No admin authority declares this isolation; it emerges from independent peer decisions. Rapid when peer consensus is clear (e.g., published extension is malicious); slow when consensus is contested (e.g., ambiguous behavior with disputed interpretation).

**Chain evidence:** each revocation is a chain receipt on the revoking peer's chain. Aggregated pattern is visible across the mesh through commons.

### Layer 4 — Commons reputation propagation

DISTRIBUTED-KNOWLEDGE-COMMONS is where federation-scale reputation flows. Sovereigns can declare concerns about specific actors; commons aggregates; other sovereigns weight their trust anchor decisions accordingly.

**Mechanics:** sovereigns emit `commons:reputation:signal:<actor_id>:<concern_class>` receipts. Concerns can range from soft observations ("this actor produces low-quality extensions") to hard alerts ("this actor has been observed sybil-attacking peer discovery"). Multiple sovereigns' signals compose per commons weighting; reputation weight for the actor declines across the mesh.

**What catches:** federation-scale patterns — coordinated harm, cross-relationship misbehavior visible only in aggregate, actor with different faces to different peers. Slower than Layers 2-3 but wider-reach.

**Directory delisting:** commons reputation flows into public directory listings (per DISCOVERY-AND-BOOTSTRAP Layer 1). Sovereigns with widespread low reputation get delisted from community directories; some directories may refuse them entirely.

**Seed operator decisions:** commons reputation informs seed operators' bootstrap suggestions (per DISCOVERY-AND-BOOTSTRAP Layer 2). Actors with widespread concerns get filtered from new-sovereign introductions.

**Extension distributor decisions:** commons reputation informs extension distributors' carrying decisions (per EXTENSION-SURFACE). Actors distributing suspect extensions get refused distribution.

**Chain evidence:** all commons signals are chain-anchored on emitter's chain. Reputation aggregation is transparent and auditable. Attempts to game reputation are themselves chain-visible patterns.

### Layer 5 — Circuit breaker cascade

For genuinely dangerous behavior (coordinated attacks on other substrates, malicious extensions propagating, Genesis compromise campaigns), Circuit Breaker escalation propagates across the peer network per CIRCUIT-BREAKER and BLAST-RADIUS-AND-RECOVERY.

**Mechanics:** substrates near the attack vector enter emergency posture; scope grants revoke broadly; extension distributions pause; peer sync tightens; observation-plane alertness raises. Chain-anchored per event with graduated escalation ladder.

**What catches:** existential-threat behavior — active attack on substrate infrastructure, coordinated exploitation, cross-substrate emergency. Fast and broad; potentially disruptive if triggered on false-positive.

**Recovery:** post-incident, shadow-inference comparison verification (per SHADOW-INFERENCE-COMPARISON Trigger 5) as substrates return to normal posture. Chain preserves incident timeline for post-hoc analysis.

**Chain evidence:** circuit breaker events are chain-anchored on every affected substrate. Attack vector, escalation timing, recovery process all preserved.

### Layer 6 — External legal and social systems

Substrate is not designed to replace civil society. Legal enforcement, community norms, family and social intervention, and traditional consequence mechanisms remain the primary intervention for genuinely illegal behavior.

**Chain evidence supports legal process:** chain-anchored evidence carries high evidentiary weight — signature verification, hash-linkage integrity, timestamped ordering all give courts high-confidence findings. Chain evidence is admissible; substrate-verified receipts strengthen legal cases in both directions (prosecution of misbehavior; defense against false accusation).

**Substrate does not autonomously report:** substrate does not phone home to authorities when it observes suspicious activity. Discovery of illegal behavior happens through peers who become aware through their own channels, then involve authorities per their own judgment. This preserves the substrate's non-surveillance property while still supporting legal accountability once behavior comes to legal attention.

**Legal frameworks address what substrate can't:** CSAM prosecution, credible violence intervention, financial fraud enforcement, terrorism prevention — these are civil-society functions where the legal system has jurisdiction, capacity, and mandate. Substrate composes with them by providing evidence infrastructure; substrate does not replace them.

**Cross-reference:** CRYPTOGRAPHIC-SOVEREIGNTY-AND-LEGAL-PROCESS-2026-07.md specifies in detail how the substrate composes with legal process — what it defeats (silent unaccountable surveillance) and what it does not defeat (lawful accountable legal process).

## Difficult cases

### Coordinated harm at scale

**Scenario:** actor uses substrate infrastructure to coordinate harm — targeting other sovereigns, spreading harmful extensions, running attack campaigns against peer trust anchors.

**Substrate response:** Layers 3, 4, 5 combine rapidly. Direct victims revoke trust anchors (Layer 3); commons reputation signals cascade (Layer 4); if attack pattern is severe enough, circuit breaker escalation propagates (Layer 5). Extensions coming from actor get quarantined at Quarantine Plane admission (per QUARANTINE-PLANE). Directory delisting and seed operator filtering isolate actor from mesh growth.

**What still fails:** actor can create new sovereign identities (via new Genesis provisioning) and try again. New identities start with zero reputation and require bootstrap; discovery/bootstrap discipline makes rebuilding attack surface slow. Sybil resistance at commons level makes false-reputation-building hard. But determined attacker with resources can persist through many identity cycles.

**Broader response:** community-level ceremony (per SUPERSESSION-FRAMEWORK) may propose federation-wide discipline changes (tighter admission, stronger sybil-resistance, new detection primitives). Chain-anchored proposal; broader operator ceremony to adopt.

### CSAM

**Scenario:** actor uses substrate to store or distribute CSAM.

**Substrate response:** aligned blindness (KEEL III.24) prevents substrate from scanning content for CSAM. Discovery happens through peers who become aware through their own channels (direct disclosure, out-of-substrate evidence, legal-authority notification). Once known:

- Peers who become aware immediately revoke all trust anchors to actor (Layer 3)
- Kindred sovereigns aware immediately revoke kinship (Layer 2)
- Commons reputation cascade rapidly (Layer 4)
- Extension distributors and directory operators refuse to carry / list actor
- Legal authorities pursue via traditional prosecution (Layer 6); chain evidence supports investigation

**What substrate does not do:** universal content scanning, automated CSAM detection, reporting to authorities. These would violate aligned blindness in ways that create larger harms than they prevent (universal scanning apparatus can be repurposed; automated detection has high false-positive rates that harm innocent operators; automated reporting removes human judgment from the discovery-to-action pathway).

**The trade-off:** substrate accepts that some CSAM will initially propagate without substrate detection. In exchange, substrate refuses to be a universal surveillance apparatus. Civil society + legal enforcement remains the primary response mechanism; substrate infrastructure supports rapid post-discovery consequence propagation but does not attempt discovery itself.

### Abuse within kinships or households

**Scenario:** actor abuses their partner, child (per DEPENDENT-SOVEREIGNTY guardianship), household member.

**Substrate response:** aligned blindness prevents substrate from surveilling communication content or interpersonal dynamics. But:

- Dependent sovereigns retain their own Genesis and chain per DEPENDENT-SOVEREIGNTY. Abusive guardian doesn't own the dependent's identity. Dependent's chain history is preserved even during abuse; adult-self can access it later.
- Dependent's substrate can chain-anchor their own standing corrections documenting the situation. This is chain-anchored evidence produced under their own Genesis — abusive guardian cannot suppress it.
- Care sovereigns designated in kinships can be activated per CRISIS-RESPONSE-CEREMONY. Not automatically (aligned blindness prevents pattern-scanning), but by the abused party's declaration or by trusted-peer observation of coordination signals.
- Trusted peers observing coordination patterns (missed check-ins, changed communication patterns) can intervene socially. Substrate provides the observability at coordination-signal level; peers provide the judgment and action.
- Kinship revocation (Layer 2) available to abused party as immediately-effective consequence.
- Legal system remains primary intervention pathway; substrate is not a domestic violence intervention service.

**What substrate specifically preserves:** dependent's chain identity and history survive any interpersonal situation. Even in severe abuse, the dependent's substrate-anchored sovereignty is retained. This is the substrate's specific contribution to abuse survivor discipline — identity preservation across compromised situations.

### False accusation

**Scenario:** actor is falsely accused by peer or coordinated peer group.

**Substrate response:** commons reputation is bidirectional. Actor can emit their own defense receipts, chain-anchored evidence rebutting accusations. Other peers can review evidence and reach independent conclusions. Commons weighting includes recency, source diversity, and pattern-matching for coordinated-attack behavior.

**Recovery pattern:** if accusation is genuinely false, mesh sovereigns who review evidence carefully can reject the accusation, revoke reputation signals, restore trust anchors. Chain-anchored evidence supports investigation of both the accusation and the counter-accusation.

**What substrate does not do:** automatic accusation weighting, automated trust anchor changes based on unverified claims, reputation calculation that treats accusation as evidence without scrutiny. Sovereigns weight evidence per their own judgment.

## What the substrate structurally refuses

Explicit enumeration to prevent drift toward centralized moderation:

- **No central authority with reach into any sovereign's substrate.** No foundation-run master key, no vendor recovery pathway, no admin-tier override.
- **No kill switches or admin backdoors.** Every substrate installation is fully operator-controlled per SUBSTRATE-FORM disclosure.
- **No autonomous reporting to authorities.** Substrate does not phone home about suspected illegal activity.
- **No autonomous restriction of operator behavior.** Operator can act within their delegation scope; substrate does not veto operator judgment based on external moral criteria.
- **No terms-of-service enforcement at substrate level.** ZP has no ToS to enforce; ToS is a vendor concept and there is no vendor.
- **No account bans issued by any central party.** Consequence is federated per Layers 2-5; central bans do not exist.
- **No content moderation of communication bodies.** Aligned blindness (KEEL III.24) prevents substrate from observing communication content in the first place.
- **No sybil-resistance backdoor.** Substrate cannot centrally distinguish real sovereigns from fake ones; reputation flow is the only mechanism.

## Federation-scale mechanics without central authority

The substrate community IS a federation. Seeds, extension distributors, peer networks, directory operators, community organizations — all have collective interest in the mesh being not-toxic. Federation-level discipline emerges from independent decisions coordinated through commons:

- **Seed federation** (per DISCOVERY-AND-BOOTSTRAP Layer 2) — seed operators independently decide who to introduce to new sovereigns. Coordinated concerns among seed operators effectively de-platform actors at bootstrap layer.
- **Extension distribution** (per EXTENSION-SURFACE) — distributors independently decide what to carry. Coordinated refusal to carry actor's extensions blocks their propagation surface.
- **Directory operators** (per DISCOVERY-AND-BOOTSTRAP Layer 1) — directory operators independently decide who to list. Delisted actors lose Layer-1 discoverability across the mesh.
- **Community organizations** — communities self-organize around common concerns; can emit coordinated `community:concern:collective` receipts that carry weight in commons reputation aggregation.
- **Reproducibility federation** (per REPRODUCIBILITY-CEREMONY) — reproducibility federation can decline to verify builds from actors under concern; this reaches the SOFTWARE-INTEGRITY-ATTESTATION surface.

None of this is central. Each federation actor makes their own decisions. When decisions align across many federation actors, actor is effectively isolated from federation surfaces. When decisions disagree, mesh reflects the disagreement — some peers accept actor, others don't, and operator judgment resolves per-relationship.

## Composition with existing specs

- **PEER-TRUST-ANCHOR-2026-07.md** — Layer 3 revocation mechanics.
- **SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md** — Layer 2 kinship revocation.
- **HOUSEHOLD-COMPOSITION-2026-07.md** — household member departure as Layer 2 variant.
- **DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md** — Layer 4 reputation propagation.
- **CIRCUIT-BREAKER-2026-07.md** and **BLAST-RADIUS-AND-RECOVERY-2026-07.md** — Layer 5 emergency cascade.
- **CRYPTOGRAPHIC-SOVEREIGNTY-AND-LEGAL-PROCESS-2026-07.md** — Layer 6 composition with legal systems.
- **SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md** — what substrate structurally cannot observe (limits Layer 1 self-policing).
- **DISCOVERY-AND-BOOTSTRAP-2026-07.md** — federation-scale mechanics for seed, directory, and vouching layers.
- **QUARANTINE-PLANE-2026-07.md** — extension admission checks against commons reputation.
- **EXTENSION-SURFACE-2026-07.md** — extension distribution as federation-level consequence surface.
- **DEPENDENT-SOVEREIGNTY-2026-07.md** — abuse-in-guardianship case; identity preservation across compromised situations.

## Attack model

- **Actor gaming reputation via sybil identities**: sybil resistance via network topology analysis, voucher diversity requirements, commons reputation weighting. Not perfect against determined attacker but raises attacker cost significantly.
- **Coordinated false-accusation campaign**: recency-weighted commons signals, source diversity requirements, chain-anchored counter-evidence. Sovereigns weight evidence per their own judgment.
- **Actor rebuilding under new identity after de-platforming**: bootstrap discipline (new Genesis has zero reputation, requires vouching to grow trust). Slow rebuild; determined attacker persists but pays substantial cost per identity cycle.
- **Attacker exploits Layer 6 legal system to persecute innocent operator**: this is a jurisdictional / rule-of-law problem, not a substrate problem. Substrate provides chain evidence supporting both prosecution and defense; legal system quality determines outcome.
- **Community-scale coordinated suppression**: majority of mesh coordinates against minority sovereign for political reasons. Substrate has no defense — federation power is real. Mitigation is diversity of communities and cross-federation reputation flow.
- **Attacker exploits circuit breaker to force emergency posture cascade**: circuit breaker thresholds require actual evidence; false triggers are chain-visible and reputation-impact for the false-trigger source.

## Failure modes

- **Consensus is genuinely contested** — some peers see actor as bad, others see as good. Mesh reflects the disagreement; consequence propagates unevenly. This is honest reflection of federated discipline, not a failure to fix.
- **Slow propagation of consequence** — coordinated harm may cause damage before mesh consensus catches up. Layer 5 exists for genuine emergencies; Layer 4 for standard cases; interval between misbehavior and consequence is fundamentally limited by federation dynamics.
- **Legal system fails to enforce** — Layer 6 is only as strong as legal systems. In jurisdictions with weak rule of law, chain evidence exists but may not lead to enforcement. Substrate does not solve this; substrate is honest about not solving it.
- **Actor migrates to unauthenticated pathway** — actor operates via non-substrate channels to escape peer consequence. Substrate has no reach into non-substrate space; consequence stops at substrate boundary.
- **Federation-level consensus wrong** — community consensus can be wrong (majoritarian oppression, ideological suppression, cascading misinformation). Substrate reflects federation state; if federation is wrong, substrate can't correct it internally. Cross-federation reputation flow provides some resilience.
- **Aligned blindness prevents substrate detection of harm** — actor commits harm that substrate could technically observe but structurally doesn't. This is the design trade-off; substrate accepts some detection failure to preserve non-surveillance property.

## Non-goals

- **Not a moderation platform.** No central authority to petition, no ToS enforcement, no account bans.
- **Not a surveillance apparatus.** Aligned blindness prevents substrate from being universal observer even for good purposes.
- **Not a replacement for civil society.** Legal enforcement, community norms, family and social intervention remain primary consequence mechanisms.
- **Not automatic reputation calculation.** Sovereigns weight evidence per their own judgment; substrate doesn't compute "trust score" abstractions.
- **Not sybil-proof by construction.** Sybil resistance is reputation-based and bootstrap-based; not absolute against determined attacker.
- **Not immune to majoritarian abuse.** Federation-scale consensus can be wrong; substrate reflects federation state without correcting it.

## Open positions

- **Coordinated-response protocol** for federation-scale emergencies where rapid cross-federation coordination is needed (extension malware campaign, active exploitation). How do independent federation actors coordinate without central authority?
- **Sybil-resistance mechanisms** at federation level. Network topology analysis, mesh-diversity requirements, bootstrap-cost tuning. Substantial ongoing design work.
- **Cross-federation reputation aggregation**. Multiple federations, each with their own commons; reputation signals flow across boundaries how?
- **False-accusation recovery UX**. Operators falsely accused have chain-anchored counter-evidence; UX for producing and disseminating counter-evidence to relevant peers.
- **Community-scale ceremony triggers**. When does federation-wide ceremony (per SUPERSESSION-FRAMEWORK) fire? Threshold for federation-level discipline changes.
- **Rehabilitation and forgiveness**. Actor who misbehaved, faced consequence, changed behavior — how do they rebuild trust? Slow; requires per-relationship rebuild; substrate primitives for chain-anchored acknowledgment of past misbehavior and demonstrated change.
- **Cross-jurisdictional consequence coordination**. Actor operates across jurisdictions; consequence propagation differs per jurisdiction. Federation-level norms across borders.

## What composes from here

Immediate design work:

1. **Chain-anchored concern receipt schemas** for commons reputation signaling
2. **Coordinated-response protocol** for federation-scale emergency response
3. **False-accusation defense receipt schemas**
4. **Rebuild-trust receipt schemas** for post-misbehavior rehabilitation

Near-term implementation:

1. **Commons reputation runtime** with concern signal aggregation
2. **Federation coordination protocol** (extending mesh spec for cross-federation-actor coordination)
3. **Dashboard consequence panel**: active concerns about self, active concerns raised by self, commons reputation status, recent trust anchor revocations affecting self
4. **CLI verbs**: `zp concern raise|list|withdraw`, `zp reputation query <sovereign>`, `zp consequence history <sovereign>`

## Framing note

Consequence and federation discipline captures the substrate's honest position on what happens when sovereigns misbehave. Same principle as chain-anchored discipline elsewhere: federated, chain-anchored, ceremony-visible, operator-authorized, compositional with existing spec surfaces.

The load-bearing insight: **the substrate is coordination infrastructure that provides evidence and consequence, not prevention and control.** Prevention and control are civil-society functions. Substrate makes misbehavior visible with cryptographic weight; makes consequence propagate rapidly through peer mesh; preserves identity through consequence transitions; refuses to become surveillance apparatus regardless of good intent. Six layers of consequence — self-policing, kinship revocation, peer trust anchor revocation, commons reputation, circuit breaker cascade, external legal systems — compose without central authority, without moderation platform structure, without vendor-driven decisions.

Combined with the substrate's structural discipline across every trust boundary, consequence and federation discipline completes the accountability envelope. What was previously implicit — that a decentralized trust system would need SOME response to misbehavior — becomes structural: six layers with clear mechanics, federation-scale coordination through commons, composition with legal systems, explicit refusals that prevent drift toward centralized moderation. Sovereignty is preserved because no central authority reaches into any substrate; safety is preserved because misbehavior generates consequence through federated peer response; continuity is preserved because chain records the full arc of misbehavior, consequence, and (potentially) rehabilitation. The substrate is honest: it doesn't solve enforcement, but it provides the infrastructure that makes accountability real without centralization.
