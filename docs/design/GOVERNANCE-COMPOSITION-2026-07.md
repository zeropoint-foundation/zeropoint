# Governance Composition

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §III.1 (Decision D — collectives are compositional), §III.23 (coordination not oversight), Part VI (canonicalization ceremony), Part VIII (bounded operator sovereignty). Specifies how the substrate composes with governance-at-larger-scale primitives — proposal, deliberation, decision — for household, community, and federation contexts. Deliberately narrow scope; does not replace democratic institutions. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `HOUSEHOLD-COMPOSITION-2026-07.md` (household charter as governance primitive at household scale), `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (kinship-scope coordination as governance-adjacent), `COLLECTIVE-ADOPTION-ARCHITECTURE-2026-07.md` (collectives as compositional structure), `COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md` (community-scale coordination), `SUPERSESSION-FRAMEWORK-2026-07.md` (federation-level substrate change ceremony), `DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` (commons as governance-adjacent surface), `CONSEQUENCE-AND-FEDERATION-DISCIPLINE-2026-07.md` (governance and consequence discipline compose).

## Framing

Governance-at-larger-scale means proposal, deliberation, and decision primitives that operate across multiple sovereigns. Household charters, community coordination decisions, federation-scale substrate discipline changes — all require coordination beyond individual operator authority. The substrate needs governance primitives that compose these coordination needs while preserving operator sovereignty as invariant.

The substrate is deliberately not building democratic institutions. Voting systems, deliberative democracy, participatory budgeting, referenda, elected representation — these exist as civil-society institutions built over hundreds of years with substantial legitimacy, procedural discipline, and accountability mechanisms. Substrate does not attempt to replace them. What substrate provides is chain-anchored governance primitives that work well at scales existing democratic institutions handle poorly (household coordination, small community decisions, federation-level substrate discipline changes) and that compose with democratic institutions rather than competing with them.

The governance primitives are narrow: chain-anchored proposals, deliberation records, decision receipts, and operator dissent primitives. Not voting (which requires substantial machinery around eligibility, ballot secrecy, tally verification, dispute resolution). Not deliberation-shaping (which is human process substrate doesn't attempt to structure). Not consensus enforcement (which would violate operator sovereignty). Just the chain-anchored infrastructure that makes governance activity visible, auditable, and composable with substrate discipline.

Three properties frame the composition:

1. **Operator sovereignty is invariant.** Governance produces decisions that some operators disagree with. Substrate always preserves the operator's ability to disagree — dissent primitives, opt-out mechanisms, individual-scope sovereignty over shared decisions. Community consensus does not override individual operator authority in the operator's own substrate.
2. **Chain-anchored governance activity is auditable.** Proposals, deliberation records, decisions all chain-anchored. Future operators can walk the chain and see how governance decisions were made, what was considered, what alternatives were rejected, who dissented.
3. **Substrate does not implement decision-making rules.** Governance rules (voting thresholds, deliberation timelines, decision procedures) are declared per community, per charter, per specific decision. Substrate provides the primitives; communities specify the procedures.

## Scale tiers of governance composition

Governance composes differently at different scales. Substrate provides primitives that work across all scales.

### Household governance (N=2-8)

Governance at household scale composes with HOUSEHOLD-COMPOSITION-2026-07.md. Household charter is the primary governance artifact — declares shared values, coordination norms, dispute resolution protocol, amendment procedures. Chain-anchored per version; amendments per charter-declared amendment rules.

Household decisions:
- Weekly household coordination (chore rotation, meal planning) — informal, referenced against charter norms
- Household resource decisions (shared purchases, cost allocation) — decision ceremony varies per household charter
- Household composition decisions (new member invitation, member departure) — per charter membership rules
- Charter amendments — per charter's own amendment procedures

Substrate primitives at household scale:
- `household:proposal:<proposal_id>` — chain-anchored proposal for household consideration
- `household:deliberation:<deliberation_id>` — record of household discussion (member contributions chain-anchored per member's own chain)
- `household:decision:<decision_id>` — chain-anchored final decision with dissent recorded
- `household:dissent:<dissent_id>` — individual member's declared dissent from household decision

Small enough scale that informal process usually suffices; substrate provides chain-anchoring for consequential decisions (charter amendments, membership changes, significant resource allocations) without requiring formal process for every household coordination event.

### Community governance (N ≈ 20-500)

Community scale requires more explicit governance. Communities self-organize per their own governance model — mutual-aid networks, neighborhood associations, cooperative organizations, faith communities, professional collectives. Substrate does not prescribe community structure; substrate provides chain-anchored governance primitives that community-declared procedures compose with.

Community governance activities:
- Proposal submission (community member proposes action, resource allocation, policy)
- Deliberation (community members discuss proposal, chain-anchor their positions and considerations)
- Decision (community per its declared procedure reaches decision)
- Implementation (decision authorized, executed per community capacity)
- Review (post-decision evaluation, chain-anchored)

Substrate primitives at community scale:
- `community:proposal:<community_id>:<proposal_id>` — chain-anchored proposal with metadata (proposer, topic, requested action, timeline)
- `community:deliberation:<proposal_id>:<contribution_id>` — chain-anchored deliberation contributions
- `community:decision:<proposal_id>:<decision_id>` — chain-anchored decision with vote tallies (if voting) or consensus record (if consensus) or authorized-decision-maker-signature (if delegated)
- `community:dissent:<decision_id>:<dissent_id>` — chain-anchored individual member dissent
- `community:opt_out:<decision_id>:<member_id>` — chain-anchored individual opt-out from community decision effect

Community declares its governance procedure via `community:governance:procedure:<procedure_id>` chain-anchored declaration. Procedure specifies eligibility, deliberation duration, decision mechanism, amendment rules. Substrate honors declared procedure at ceremony time.

### Federation governance (N ≈ many communities)

Federation scale is the substrate community itself — cross-community coordination on substrate discipline. This is SUPERSESSION-FRAMEWORK-2026-07.md territory: substrate spec changes, canonical corpus refinements, federation-wide protocol updates.

Federation governance activities:
- Substrate discipline change proposals (ZEP — ZeroPoint Evolution Proposal per SUPERSESSION-FRAMEWORK)
- Cross-federation deliberation (substrate operators across communities weigh in)
- Consensus formation on discipline changes
- Adoption ceremony (substrate operators adopt new discipline per operator ceremony)

Substrate primitives at federation scale:
- Compose with SUPERSESSION-FRAMEWORK proposal, review, adoption ceremony
- Chain-anchored discipline changes with version references
- Reproducibility ceremony for federation-declared substrate implementations
- Peer-federation-scale reputation flow for federation-level discipline

Federation scale is where governance is most substrate-native — the substrate community coordinating on its own discipline. Existing democratic institutions do not handle this well because substrate discipline is technical and requires substrate-operator participation.

## The governance primitives

Six chain-anchored primitives that compose across scales:

### Proposal

Chain-anchored declaration that decision is needed:

```
governance:proposal:<scale>:<proposal_id>
  fields:
    proposer: <proposer_genesis_pubkey>
    scale: <household | community | federation>
    scope: <what decision is being proposed>
    topic: <human-readable topic identifier>
    proposed_action: <what would be done if proposal accepted>
    rationale: <proposer's reasoning>
    alternatives_considered: <optional list>
    decision_timeline: <deliberation period, decision date>
    procedure_reference: <which governance procedure applies>
    signature: <proposer's Genesis signature>
```

### Deliberation contribution

Chain-anchored addition to deliberation on a proposal:

```
governance:deliberation:<proposal_id>:<contribution_id>
  fields:
    contributor: <contributor_genesis_pubkey>
    contribution_type: <question | argument_for | argument_against | alternative_proposal | clarification>
    content: <contribution content>
    references: <optional references to other chain-anchored content>
    signature: <contributor's Genesis signature>
```

Contribution can be as small as "I support this" or as substantial as extended arguments. Substrate does not shape deliberation quality; substrate chain-anchors deliberation activity so process is auditable.

### Decision

Chain-anchored final decision on a proposal:

```
governance:decision:<proposal_id>:<decision_id>
  fields:
    decision_outcome: <accepted | rejected | modified | deferred>
    decision_procedure_used: <which procedure produced this decision>
    procedure_evidence: <vote tallies | consensus record | authorized-decision-maker-signature>
    modifications: <if outcome is modified, what changes were made>
    effective_date: <when decision takes effect>
    review_date: <optional scheduled review>
    signature: <procedure-authorized-signer(s) Genesis signature(s)>
```

### Dissent

Individual operator's chain-anchored declaration of dissent from decision:

```
governance:dissent:<decision_id>:<dissent_id>
  fields:
    dissenter: <dissenter_genesis_pubkey>
    dissent_content: <dissenter's reasoning>
    proposed_alternative: <optional>
    signature: <dissenter's Genesis signature>
```

Dissent does not overturn decision; it chain-anchors the dissent for future reference. Dissent is invariant sovereignty primitive — operator can always dissent regardless of decision procedure.

### Opt-out

Individual operator's chain-anchored declaration that decision does not apply to their substrate:

```
governance:opt_out:<decision_id>:<opt_out_id>
  fields:
    opter_out: <opter_out_genesis_pubkey>
    opt_out_scope: <full opt-out | scope-limited opt-out>
    opt_out_reason: <optional operator declaration>
    signature: <opter's Genesis signature>
```

Opt-out is per-operator sovereignty preservation. Operator can opt out of any community decision that would affect their substrate. Consequence: they may lose access to community-scope benefits contingent on decision compliance; they retain their own substrate sovereignty.

### Amendment

Chain-anchored proposal to change previously-decided decision:

```
governance:amendment:<original_decision_id>:<amendment_id>
  fields:
    proposer: <proposer_genesis_pubkey>
    amended_scope: <what part of original decision is being amended>
    proposed_change: <how it should change>
    rationale: <why amendment>
    procedure_reference: <which amendment procedure applies>
    signature: <proposer's Genesis signature>
```

Amendment goes through governance procedure declared for the original decision (or amendment-specific procedure if declared).

## Operator sovereignty invariants

Substrate preserves operator sovereignty as invariant across all governance scales:

- **Operator can dissent from any decision.** Dissent primitive is universal; no community decision procedure can prohibit dissent chain-anchoring.
- **Operator can opt out of decision effect on their substrate.** Opt-out primitive is universal; community-scope benefits may not apply to opting-out operator, but their substrate operates per their own authority.
- **Operator can leave community.** Any community membership is voluntary; operator can chain-anchor community exit per community's departure procedure (or unilaterally per operator ceremony if community procedure fails to provide exit).
- **Operator Genesis authority is invariant.** No community governance can override operator's Genesis-derived signing on their own substrate.
- **Operator can join alternative communities.** Substrate architecture supports multi-community membership; operator can participate in multiple communities with different governance procedures.

These invariants prevent community governance from becoming coercive at substrate layer. Community can adopt any governance procedure; operator retains individual sovereignty regardless.

## Composition with existing democratic institutions

Governance composition is designed to work alongside democratic institutions, not replace them. Specifically:

- **Substrate governance does not attempt legally-binding decisions.** Community decision that "we will fund public library" is chain-anchored coordination; it does not create legal obligation. If community wants legally-binding decision, they use civil-society institutions (nonprofit governance, formal cooperatives, government contract).
- **Substrate governance chain-anchors deliberation valuable for legitimacy.** Democratic institutions increasingly need transparent deliberation records; substrate chain-anchored governance provides high-integrity records that compose with democratic institution transparency requirements.
- **Substrate does not attempt to gate participation in democratic processes.** Voting for elected officials, referenda, jury duty — these are civil-society processes with their own eligibility rules; substrate does not participate.
- **Substrate composes with existing organizational governance.** Nonprofits, cooperatives, faith communities, professional associations have their own governance procedures; substrate provides chain-anchored infrastructure those procedures compose with.
- **Substrate does not substitute for professional decision-makers.** Boards, executives, elected officials have specific delegated authority; substrate chain-anchors their decisions per organizational discipline but does not replace their authority.

The philosophical position: democratic institutions face specific challenges (scalability, deliberation quality, transparent record-keeping); substrate provides chain-anchored infrastructure that composes with these institutions. Substrate is complementary infrastructure, not competing institution.

## Composition with existing specs

- **HOUSEHOLD-COMPOSITION-2026-07.md**: household charter is the household-scale governance primitive; this spec's household governance composes with household charter amendment procedures.
- **SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md**: kinship-scope coordination between kindred sovereigns is governance-adjacent; this spec extends coordination primitives with formal governance discipline at community scale.
- **COLLECTIVE-ADOPTION-ARCHITECTURE-2026-07.md**: collectives as compositional structure — households compose into communities compose into federations; this spec provides governance primitives at each level.
- **COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md**: community-scale coordination — this spec adds explicit governance primitives to coordination surfaces.
- **SUPERSESSION-FRAMEWORK-2026-07.md**: federation-level substrate change ceremony is one specific instance of federation-scale governance handled by this spec.
- **DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md**: commons hosts governance-adjacent surfaces (community-scale reputation, published proposals for cross-community consideration).
- **CONSEQUENCE-AND-FEDERATION-DISCIPLINE-2026-07.md**: governance decisions inform peer trust anchor decisions and consequence propagation; misbehaving governance participants face substrate consequence per federation discipline.
- **CRYPTOGRAPHIC-SOVEREIGNTY-AND-LEGAL-PROCESS-2026-07.md**: substrate governance decisions are not legally binding; when governance intersects with legal process, chain-anchored governance records support legal proceedings.
- **SUBSTRATE-EXIT-CEREMONY-2026-07.md**: operator can exit community per substrate exit ceremony analog; community can be exited without exiting substrate entirely.

## Attack model

- **Attacker attempts to force governance decision favorable to them via manipulation**: substrate does not shape deliberation quality; community's own governance procedure must handle manipulation resistance. Substrate provides chain-anchored evidence supporting later investigation.
- **Attacker floods deliberation with low-quality contributions**: deliberation contribution rate limits, community-declared moderation procedures (moderator role chain-anchored per community charter).
- **Attacker impersonates community members to sway decisions**: peer trust anchor discipline verifies member identity via Genesis signatures; impersonation would require Genesis compromise.
- **Attacker uses substrate governance to legitimize non-consensual coercion**: operator sovereignty invariants (dissent, opt-out, exit) prevent this at substrate layer; substrate does not enforce community decisions on individual operators.
- **Attacker exploits governance to concentrate resources in their control**: community governance procedure specifies decision authority; substrate does not prevent unequal outcomes but chain-anchors decisions for post-hoc analysis.
- **Attacker manipulates community membership to influence decisions**: community charter specifies membership rules; substrate composes with charter-declared procedures; charter changes require charter-amendment procedure.
- **Attacker uses federation-level governance to force discipline changes on individual operators**: SUPERSESSION-FRAMEWORK adoption is per-operator ceremony; individual operators can refuse to adopt federation-decided discipline changes (with substrate consequences per federation reputation flow).

## Failure modes

- **Governance procedure produces unimplementable decision**: community must revise procedure or amend decision.
- **Deliberation quality is low, decisions poorly considered**: substrate does not shape quality; community must develop deliberation practices.
- **Dissenting operators marginalized**: substrate protects dissent-chain-anchoring but cannot prevent social consequences; community norms around dissent-respect are cultural not substrate.
- **Governance procedure captured by minority**: community procedure design flaw; can be revised via procedure-amendment ceremony but capture may prevent revision.
- **Multi-community operator faces conflicting decisions**: operator navigates per their own judgment; can opt out of one community's decision without opting out of another's.
- **Federation-level governance stalls on substrate discipline change**: SUPERSESSION-FRAMEWORK handles; substrate discipline evolves slowly when consensus is hard.

## Non-goals

- **Not a voting system.** Substrate provides decision-recording primitives but does not implement voting machinery (eligibility verification, ballot secrecy, tally verification, dispute resolution).
- **Not deliberation quality shaping.** Substrate chain-anchors contributions; substrate does not moderate or shape deliberation.
- **Not consensus enforcement.** Operator sovereignty is invariant; substrate does not enforce community decisions on individual operators.
- **Not legally-binding decision creation.** Community decisions are chain-anchored coordination; legally-binding decisions use civil-society institutions.
- **Not replacement for democratic institutions.** Substrate complements democratic institutions; it does not attempt to replace representative government, courts, or regulatory bodies.
- **Not universal governance procedure.** Substrate provides primitives; communities declare procedures per their own values.
- **Not participation gate.** Substrate does not verify eligibility for civil-society democratic processes.

## Open positions

- **Community governance procedure canonical templates**. Reference templates for common community governance shapes (consensus, majority vote, delegated authority, sortition). Federation-published, adopter-modifiable.
- **Multi-community coordination protocols**. Two communities coordinate on cross-community decision; how does joint governance work?
- **Dissent-respect norms**. Cultural norms around chain-anchored dissent; substrate provides the primitive but community culture determines whether dissent gets respectful engagement or marginalization.
- **Federation-level governance participation**. Who participates in federation-scale substrate discipline decisions? All substrate operators? Delegated representatives? Rotating councils?
- **Governance-decision-tracking UX**. Dashboard for operator to see governance activity across communities they're part of, dissent options, opt-out mechanics.
- **Amendment cadence rate-limiting**. Communities may thrash if amendment procedures too permissive; substrate can support rate-limiting per community declaration.
- **Governance archive discipline**. Old governance decisions accumulate; how does community charter handle deprecated decisions?
- **Cross-community reputation for governance participants**. Operator's governance participation history composes with commons reputation; how weighted?

## What composes from here

Immediate design work:

1. **Chain-anchored governance receipt schemas** — proposal, deliberation, decision, dissent, opt-out, amendment
2. **Community governance procedure declaration schema**
3. **Multi-community operator UX for governance participation**
4. **Federation-scale governance composition with SUPERSESSION-FRAMEWORK**

Near-term implementation:

1. **Governance runtime** in `crates/zp-server/src/governance/`
2. **Community governance procedure registry**
3. **Dashboard governance panel**: active proposals in operator's communities, deliberation participation, decision history, personal dissent/opt-out record
4. **CLI verbs**: `zp governance proposal submit|list`, `zp governance deliberate <proposal>`, `zp governance decision list`, `zp governance dissent`, `zp governance opt-out`

## Framing note

Governance composition captures how substrate provides chain-anchored governance primitives for scales existing democratic institutions handle poorly, while preserving operator sovereignty as invariant and composing with — not replacing — civil-society democratic institutions. Same principle as chain-anchored discipline elsewhere: primitives declared, procedures community-authored, operator authority preserved, chain records auditable.

The load-bearing insight: **substrate provides governance primitives, not governance procedures — and preserves operator sovereignty as invariant across all governance scales.** Communities declare their own procedures; substrate honors declared procedures; operators can always dissent, opt out, or exit. Community consensus does not override individual operator authority in the operator's own substrate. Governance activity is chain-anchored for auditability without becoming coercive at substrate layer.

Combined with the substrate's structural discipline across every trust boundary, governance composition closes the "coordination at scale without becoming institution" gap. What was previously implicit — that substrate would need some governance mechanism to coordinate at community and federation scale — becomes structural: six chain-anchored governance primitives (proposal, deliberation, decision, dissent, opt-out, amendment), scale-appropriate composition (household charter → community procedure → federation SUPERSESSION-FRAMEWORK), operator sovereignty invariants preserved across all scales, composition with existing democratic institutions rather than replacement of them. Substrate is complementary infrastructure to civil society, not competing institution. Governance primitives exist to make substrate-native coordination work at scale; larger coordination needs continue to be handled by civil-society institutions substrate composes with.
