# Field Testing Discipline

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §III.22 (verify before commit), Part VIII (bounded operator sovereignty). Specifies the substrate's discipline for early pilot deployments — how to structure real-world tests that generate empirical evidence, protect pilot participants, and inform spec refinement without prematurely locking in design commitments. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `MINIMUM-VIABLE-INTERACTION-2026-07.md` (pilot tiers correspond to MVI classes), `EMPIRICAL-PROGRAM-2026-07.md` (pilot evidence feeds continuous empirical program), `SHADOW-EVALUATION-PRIMITIVE-2026-07.md` (pilot findings can drive candidate-policy proposals), `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md` (pilots respect blindness discipline for participants), `TRANSPORT-ABSTRACTION-AND-CONSTRAINED-NETWORKS-2026-07.md` (pilots may exercise constrained transports), `CONSEQUENCE-AND-FEDERATION-DISCIPLINE-2026-07.md` (pilot governance and dispute paths).

## Framing

The substrate corpus has been all-design. Every spec claims value; no spec has been tested. This is honest for the current phase — design coherence is prerequisite to implementation — but it has a shelf life. At some point spec-only work returns diminishing insight; only real people using substrate for real coordination produces the evidence that separates good-in-theory from good-in-practice. Field testing discipline is how the substrate moves from "spec'd" to "empirically validated" without either (a) over-claiming success from anecdote or (b) exposing pilot participants to poorly-designed early substrate.

Real pilots involve real people making real decisions with substrate infrastructure. That deserves specific discipline: participant consent must be informed; substrate primitives used in pilot must be substrate-defensible; failures in pilot must generate real chain-anchored evidence rather than glossed-over experience reports; exit paths for pilot participants must be smooth (they can stop using substrate without losing anything critical to their coordination); success metrics must be more meaningful than "operators kept using it."

Three properties frame the discipline:

1. **Pilots test substrate primitives at real-people scale.** Not synthetic benchmarks. Not internal team dogfooding (though that continues). Real operators with real coordination needs, real relationships, real consequences for coordination working or failing.
2. **Chain-anchored evidence is the pilot's primary output.** Anecdote is secondary. Substrate operations produce chain-anchored evidence of usage patterns, failures, coordination outcomes; pilot evidence is what feeds spec refinement.
3. **Pilot progression follows MVI tier ladder.** Solo pilots first (N=1), then small-group pilots (N=2-5), then household pilots (N=3-8), then community pilots (N=20+). Each tier's success or friction informs subsequent tier's design.

## Pilot tier ladder

Five canonical pilot tiers, each testing substrate value at a specific MVI class:

### Tier 0 — Internal dogfooding (ongoing)

Substrate developers use substrate for own work. Substrate operators within the immediate community use substrate for own coordination. Chain-anchored self-observation happens continuously. Provides evidence about substrate developer experience; less evidence about non-developer operator experience.

**Feedback loop**: continuous; findings inform spec refinement directly through corpus contributions.

**Ethical discipline**: minimal (participants are substrate creators).

### Tier 1 — Solo pilots (N=1)

Individual operators unaffiliated with substrate development use substrate for personal chain-anchored coordination. Decision-tracking, observation logging, Regent cognitive presence, legacy planning. No peers required.

**Recruit from**: operators with existing personal-knowledge-management workflows (Obsidian, Roam, org-mode users), quantified-self practitioners, professional decision-makers who value retrospection.

**What we learn**:
- Does N=1 value proposition actually feel valuable to non-developer operators?
- What onboarding friction exists at first-time substrate installation and Genesis ceremony?
- How do operators use chain-query for retrospection?
- Where does Regent cognitive presence add value vs feel intrusive?
- How does substrate compose with existing personal-knowledge tools?

**Pilot duration**: 30-90 days per participant.

**Success metrics**:
- Operator continues using substrate after pilot support ends
- Chain-anchored evidence of decision-anchoring and later retrospection
- Operator can articulate specific substrate value in their own words
- Regent cognitive presence receipts show meaningful usage patterns

**Failure signals**:
- Operator stops using substrate within first week (onboarding failure)
- Chain shows minimal decision-anchoring after first-week enthusiasm (value proposition failure)
- Operator reports substrate as "one more thing to maintain" (integration failure)

### Tier 2 — Small-group pilots (N=2-5)

Small groups of operators who have existing relationships (friend groups, professional collaborators, tightly-connected community members) use substrate for coordination between them. Mutual verification, kinship declarations, shared commitments, coordinated calendar for shared activities.

**Recruit from**: pre-existing groups with coordination needs — DnD groups, small research teams, professional collaboratives, close friend groups.

**What we learn**:
- Does N=2 value proposition feel valuable across a group?
- How do groups discover each other's substrate presence?
- Where does kinship declaration compose with existing relationship dynamics vs feel awkward?
- What commitment types groups naturally chain-anchor
- How commons reputation flows among small groups

**Pilot duration**: 60-180 days per group.

**Success metrics**:
- Group members chain-anchor commitments they'd have made verbally otherwise
- Group members reference substrate history in later coordination discussions
- Kinship declarations remain active beyond pilot end
- No pilot-scope-abandonment (nobody leaves substrate before pilot ends)

**Failure signals**:
- Chain-anchored commitments not honored more than verbal commitments would have been
- Group members report substrate creating friction rather than reducing it
- Substrate becomes "the thing we forget to update" rather than infrastructure

### Tier 3 — Household pilots (N=3-8)

Households — families or house-sharing groups — use substrate for household coordination. Household presence signaling, shared spatial ontology, chore/care/schedule commitment coordination, emergency response designations, mutual safety check-ins.

**Recruit from**: households with existing coordination overhead (multi-adult households, families with dependent-guardianship complexity, households with shared resources requiring coordination).

**What we learn**:
- Does HOUSEHOLD-COMPOSITION multi-party primitive reduce coordination overhead vs pairwise kinships?
- Where does household charter add value vs add process
- How does DEPENDENT-SOVEREIGNTY guardianship work in real family dynamics
- Household presence signaling: valuable coordination or surveillance-shaped?
- How household extensions (household energy management, shared calendars) compose with substrate discipline

**Pilot duration**: 90-180 days per household.

**Success metrics**:
- Household reports reduced "who's supposed to do what" friction
- Chain-anchored evidence of commitment coordination reducing missed responsibilities
- Household members express desire to continue substrate use post-pilot
- Charter (if declared) evolves through ceremony rather than becoming stale

**Failure signals**:
- Household presence signaling used as surveillance rather than coordination (KEEL III.23 violation in practice)
- Charter becomes dead letter (declared but not consulted)
- Household members split on substrate value (some find valuable, others resent)

### Tier 4 — Community pilots (N=20+)

Existing communities with coordination needs use substrate for community-scale coordination. Michigan Mesh on Signal, local maker collectives, regional preparedness groups, faith communities, cooperative organizations, professional associations.

**Recruit from**: communities with (a) existing coordination challenges, (b) technical adoption capacity, (c) mission alignment with substrate values (sovereignty, coordination, non-central-authority).

**What we learn**:
- Does substrate scale from N=8 (household) to N=20+ using same primitives?
- How do commons reputation dynamics work at community scale
- Where does seed federation add value at community-scale bootstrap
- How discovery layers work when substrate isn't universally adopted (mixed-adoption communities)
- What extensions communities need that solo/household operators don't
- How CONSEQUENCE-AND-FEDERATION-DISCIPLINE plays out at community scale

**Pilot duration**: 6-18 months.

**Success metrics**:
- Community reports substrate providing coordination that pre-substrate infrastructure couldn't
- Chain-anchored evidence of community-scale primitives (commons reputation flow, cross-household coordination, community ceremony)
- Community continues substrate adoption after pilot support
- Substrate handles at-least-one significant coordination event (planning, response, decision) meaningfully

**Failure signals**:
- Adoption stalls at core enthusiast subset; broader community doesn't take up
- Substrate becomes parallel coordination surface rather than primary (redundant with existing tools)
- Governance dynamics degrade rather than improve
- CONSEQUENCE-AND-FEDERATION discipline breaks down under community-scale disagreement

## Chain-anchored evidence discipline

Every pilot generates chain-anchored evidence — not survey responses, not developer anecdote, chain receipts. What gets chain-anchored during a pilot:

- Substrate installations and Genesis ceremonies per pilot participant
- Every substrate operation participants perform (with participant consent per pilot ceremony)
- Chain query patterns (what participants look up, when)
- Regent narration events and operator responses
- Commitment declarations and outcomes (honored, breached, renegotiated)
- Kinship declarations, scope grants, revocations
- Officer findings and operator dispositions
- Failure events (substrate crashes, transport outages, unexpected behavior)
- Pilot-specific ceremony receipts (pilot-start, pilot-check-in, pilot-end)

Post-pilot analysis operates on chain evidence via reproducibility ceremony discipline — anyone with pilot-shared chain access can independently analyze the same evidence and reach independent conclusions. This is empirical program discipline (per EMPIRICAL-PROGRAM) applied to pilot deployment.

## Ethical discipline for pilots involving real people

Pilot participants are real operators making real decisions with substrate infrastructure that may not yet be fully mature. Ethical discipline is specific:

### Informed consent

Every pilot participant receives clear disclosure:

- What substrate currently does vs what it's spec'd to do (be honest about spec-vs-implementation gap)
- What pilot data is chain-anchored and where (their own chain vs shared pilot chain)
- What analysis will be performed on their pilot data and who will see it
- What happens to their substrate at pilot end (they keep it, but pilot-specific features may cease)
- What happens to their chain data at pilot end (they retain full control per SUBSTRATE-EXIT-CEREMONY)
- Known bugs, missing features, and rough edges they'll encounter
- How to reach substrate developers for support during pilot

Consent is chain-anchored via `pilot:participant_consent:<pilot_id>:<participant_id>` receipt on both participant's chain and pilot coordinator's chain.

### Substrate primitives used in pilot must be substrate-defensible

Pilots test primitives that we're prepared to defend as substrate discipline. Not experimental scope grants that violate coordination-not-oversight (KEEL III.23), not observation surfaces that violate aligned blindness (KEEL III.24), not extension capabilities that we haven't spec'd. Pilots are testing implementation of spec'd primitives, not exploring whether-to-spec primitives.

If a pilot reveals a spec gap (participants need capability we didn't spec), gap goes back to design process; substrate doesn't ad-hoc extend during pilot.

### Exit paths must be smooth

Participants can withdraw from pilot at any time without losing anything critical. Chain evidence they've generated is theirs (per KEEL §II.5 — Genesis-derived signing means their receipts are theirs regardless of pilot participation). Substrate continues operating for them post-pilot even without pilot support. Coordination they've established with other pilot participants continues.

Withdrawal is chain-anchored via participant's own ceremony; no negotiation required with pilot coordinator.

### Failure handling

Substrate failures during pilot (crashes, data loss, unexpected behavior, security incidents) must be chain-anchored and disclosed to affected participants promptly. Post-hoc "we noticed a bug affecting you two months ago" is not acceptable.

If pilot substrate exhibits behavior violating aligned blindness or coordination-not-oversight, pilot pauses immediately; behavior investigated; participants notified; substrate corrected before pilot resumes.

### Compensation and reciprocity

Pilot participants are contributing valuable evidence to substrate design. Substrate community owes them reciprocity — not necessarily monetary, but real value in exchange:

- Direct developer access for questions and support
- Named contribution to spec refinements their pilot informed
- Priority access to substrate improvements
- Full sovereignty over their substrate post-pilot (they retain, they don't lose access)

## Minimum feature set per tier

Each tier requires a minimum substrate feature set to be "meaningfully load-bearing" at that scale. Attempting pilot at tier N with sub-tier-N feature set produces false-negative evidence (pilot fails not because primitive doesn't work but because primitive isn't yet built).

### Tier 1 (Solo) minimum feature set

- Genesis ceremony working end-to-end
- Chain-anchored decision receipt schema + dashboard flow
- Chain-anchored observation receipt schema + dashboard flow
- Chain query working (query own chain, filter by receipt class)
- Regent cognitive presence at basic level (respond to operator questions about their own chain content)
- Substrate self-observation via officer cadre
- Substrate exit ceremony working (participant can leave cleanly)

### Tier 2 (Small-group) minimum feature set

- Everything in Tier 1
- Discovery-and-bootstrap Layer 5 minimum (direct address exchange)
- Peer trust anchor grant ceremony working
- Kinship declaration ceremony working
- Commitment receipt schema + dashboard flow
- Cross-Regent narration under kinship scope
- Kinship revocation ceremony working

### Tier 3 (Household) minimum feature set

- Everything in Tier 2
- Household composition primitive working
- Household presence signaling
- Household-scope commitment coordination
- Dependent sovereignty primitives (if household includes dependents)
- Emergency notification scope working
- Household charter declaration + amendment ceremony

### Tier 4 (Community) minimum feature set

- Everything in Tier 3
- Discovery-and-bootstrap Layers 1-4 working (public directory, seed nodes, vouching, rendezvous)
- Commons reputation flow with basic aggregation
- Extension surface admission ceremony working for at least a few reference extensions
- Community coordination primitives (per COMMUNITY-COORDINATION spec)
- Circuit breaker + shadow-inference primitives functional (even if not exercised)

Pilots at higher tiers require lower-tier minimum sets. Attempting Tier 3 without Tier 2 minimums produces confused evidence.

## Feedback loop to spec refinement

Pilot findings feed spec work via structured process:

1. **Pilot-anchored finding chain-anchored**: `pilot:finding:<pilot_id>:<finding_id>` receipts document specific findings from pilots. Includes evidence class, implicated spec, proposed refinement.
2. **Spec-team review**: pilot findings routed to relevant spec maintainers. Findings can lead to spec refinements, empirical program investigations, or shadow-evaluation candidate proposals.
3. **Chain-anchored spec-change ceremony**: spec refinements per SUPERSESSION-FRAMEWORK; pilot findings cited as evidence.
4. **Post-refinement pilot verification**: refined spec deployed in subsequent pilot; chain-anchored evidence confirms refinement addressed original finding.

This feedback loop makes the substrate empirical-program-continuous (per SHADOW-EVALUATION-PRIMITIVE) rather than punctuated. Field testing feeds spec refinement; spec refinement feeds subsequent field testing; substrate improves through evidence-driven ceremony.

## Composition with existing specs

- **MINIMUM-VIABLE-INTERACTION-2026-07.md**: pilot tier ladder maps to MVI classes. Solo pilots test N=1 MVI; small-group pilots test N=2 MVI; household pilots test HOUSEHOLD-COMPOSITION; community pilots test community-scale primitives.
- **EMPIRICAL-PROGRAM-2026-07.md**: pilot evidence feeds continuous empirical program. Findings from pilots inform empirical program investigations.
- **SHADOW-EVALUATION-PRIMITIVE-2026-07.md**: pilot findings can propose candidate policy variants; shadow evaluation compares candidate vs current in subsequent pilots.
- **SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md**: pilot substrate honors blindness discipline; pilot data collection respects participant privacy per canonical blind classes.
- **TRANSPORT-ABSTRACTION-AND-CONSTRAINED-NETWORKS-2026-07.md**: pilots may specifically exercise constrained transports (Michigan Mesh over Signal, off-grid deployments). Transport evidence feeds transport spec refinement.
- **CONSEQUENCE-AND-FEDERATION-DISCIPLINE-2026-07.md**: pilot governance and dispute paths follow substrate consequence discipline. No pilot-specific enforcement mechanisms.
- **SUBSTRATE-EXIT-CEREMONY-2026-07.md**: pilot participants can exit substrate per canonical exit ceremony; pilot end does not trigger involuntary exit.

## Attack model

- **Attacker attempts to inject false findings into pilot evidence**: pilot findings are chain-anchored per participant's Genesis; attacker cannot inject findings claiming to be from participants without those participants' Genesis signatures.
- **Attacker exploits pilot to gain trust anchor from participants**: pilot participants use standard peer-trust-anchor discipline; pilot doesn't bypass trust anchor ceremony.
- **Attacker uses pilot recruitment to profile potential victims**: pilot recruitment discipline includes participant-safety considerations; recruitment communications reviewed for potential victim-targeting patterns.
- **Attacker infiltrates community-scale pilot to disrupt trust**: substrate discipline at community scale handles disruption per CONSEQUENCE-AND-FEDERATION-DISCIPLINE; pilot does not create special-case exposure.
- **Attacker exploits pilot's known-rough-edges to compromise participant substrates**: pilot participants informed about known bugs; unknown bugs pose real risk; substrate developer response to security incidents in pilot is priority.

## Failure modes

- **Pilot yields no clear signal**: participants use substrate briefly and abandon without clear reason. Post-pilot interview may surface reasons; sometimes pilots just don't produce definitive evidence.
- **Pilot yields negative signal on primitive we're committed to**: pilot evidence contradicts spec direction. Difficult case: either revise spec direction or refine pilot design; requires human judgment.
- **Pilot participants become disproportionately invested and can't accept pilot end**: pilot success can generate dependency; substrate should support graceful pilot-to-normal-use transition; exit ceremony supports withdrawal but participants may not want to exit.
- **Cross-tier pilot leakage**: participants in Tier 2 pilot start coordinating with participants in Tier 3 pilot; pilots don't remain cleanly separated. This is actually success in some ways (substrate composing across tiers) but complicates evidence analysis.
- **Pilot substrate exhibits behavior violating substrate discipline**: highest-severity failure; requires immediate pilot pause, participant notification, substrate correction, and post-hoc analysis of how the violation occurred despite spec discipline.

## Non-goals

- **Not universal substrate rollout**. Field testing is pilot-scale by design; broader rollout follows successful pilots and substrate readiness, not vice versa.
- **Not marketing evidence collection**. Pilot findings inform spec refinement, not marketing claims. Success stories are chain-anchored evidence, not curated testimonials.
- **Not participant-as-user-research**. Participants are pilot collaborators with sovereignty over their own participation, not research subjects.
- **Not competitive with existing tools**. Substrate provides distinctive value that doesn't require displacing operators' existing tools; pilots test substrate as addition to existing workflows, not replacement.
- **Not ethics-optional**. Pilots involving real people demand ethical discipline; substrate community holds itself accountable for participant well-being.

## Open positions

- **Pilot recruitment discipline**. Federation-level standards for identifying appropriate pilot candidates without exploiting existing power differentials or trust relationships.
- **Pilot coordinator role**. Who runs pilots? Substrate developers? Federation-level pilot coordinators? Community-embedded coordinators? Trade-offs on independence and integration.
- **Chain-shared pilot analysis surface**. Participants share subset of pilot chain data with substrate community for analysis; how much sharing under what scope?
- **Pilot compensation model**. Non-monetary reciprocity (contribution credit, priority access, developer time); calibration per pilot tier.
- **Failure-mode disclosure discipline**. What substrate failures during pilot require disclosure to which parties on what timeline? Federation working spec.
- **Post-pilot substrate continuity**. Participants continue substrate after pilot; substrate community's ongoing responsibility to those continuing operators.
- **Cross-pilot coordination**. Multiple pilots running concurrently; how to prevent unnecessary duplication vs preserve independent evidence collection.

## What composes from here

Immediate design work:

1. **Pilot participant consent receipt schema**
2. **Pilot finding chain-anchored receipt schema**
3. **Pilot coordinator ceremony flow**
4. **Chain-anchored pilot progression tracking** (participant-side + coordinator-side)
5. **Post-pilot analysis reproducibility protocol**

Near-term implementation:

1. **Pilot coordinator runtime** for chain-anchored pilot lifecycle management
2. **First pilot recruitment discipline** (probably Tier 1 solo pilots with pre-existing PKM-aware operators)
3. **Pilot dashboard** for coordinator visibility into ongoing pilots
4. **Participant-facing pilot onboarding UX**
5. **Post-pilot analysis tooling** for chain-anchored evidence review
6. **CLI verbs**: `zp pilot enroll|status|report|withdraw`, `zp pilot coordinator new-pilot|progress|analyze`

## Framing note

Field testing discipline is how the substrate moves from spec-only to empirically-validated without over-claiming or exposing pilot participants to poorly-designed early substrate. Same principle as chain-anchored discipline elsewhere: pilot evidence chain-anchored, participant consent chain-anchored, coordinator ceremony chain-anchored, ethical discipline explicit.

The load-bearing insight: **pilots at real-people scale produce evidence that spec design alone cannot generate — but pilots demand specific discipline that respects both substrate integrity and participant sovereignty.** Tier ladder from solo to community mirrors MVI classes; chain-anchored evidence is primary output; ethical discipline is non-negotiable; feedback loop to spec refinement makes substrate improvement continuous.

Combined with the substrate's structural discipline across every trust boundary, field testing closes the empirical-validation envelope. What was previously implicit — that substrate would eventually be tested somewhere — becomes structural: pilot tier ladder defined, minimum feature sets per tier specified, ethical discipline explicit, chain-anchored evidence feeding empirical program, participant sovereignty preserved throughout. Substrate is not just spec'd well; substrate is spec'd well and tested carefully. The path from design to deployment goes through pilots that respect both substrate integrity and the real people using it.
