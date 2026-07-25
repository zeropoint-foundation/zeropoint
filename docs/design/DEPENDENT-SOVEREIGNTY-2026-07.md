# Dependent Sovereignty

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §III.9 (delegation narrowing), §III.23 (coordination not oversight), Part VII (Peer-Verification Contract). Specifies the substrate's discipline for sovereigns who cannot fully autonomously operate their own substrate — children being raised in sovereign households, elderly with cognitive decline, temporarily incapacitated adults, sovereigns with disabilities requiring assistive operation. Introduces scoped guardian-delegation as a primitive class distinct from peer-trust-anchor (adult-peer) and kinship (adult-mutual). Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (kinship is peer relationship between adult sovereigns; guardianship is asymmetric), `PEER-TRUST-ANCHOR-2026-07.md` (peer-level admission surfaces; dependent sovereigns require different trust model), `OPERATOR-DEATH-AND-LEGACY-2026-07.md` (guardian designation and death intersect), `CRISIS-RESPONSE-CEREMONY-2026-07.md` (dependent's crisis triggers may activate guardian rather than kindred), `COLLECTIVE-ADOPTION-ARCHITECTURE-2026-07.md` (households as collectives compose with dependent sovereignty).

## Framing

The substrate's default model — Genesis-derived signing, autonomous operator authority, chain-anchored consent for every decision — assumes an adult sovereign fully capable of exercising their sovereignty. Real households and communities include people who don't fit this model cleanly at all points in their life:

- Children being raised in sovereign households. Born into the substrate world. Cannot meaningfully consent to Genesis provisioning at birth; cannot autonomously operate substrate at three years old; developing capacity through childhood; approaching but not yet holding full sovereignty in adolescence.
- Elderly with progressive cognitive decline. Once fully sovereign adults; increasingly dependent on family or care community for decisions; may retain some capacities while losing others.
- Temporarily incapacitated adults. Post-surgery, medical crisis, mental health event, extended unconsciousness. Fully sovereign before and after; needs substrate coordination handled during the incapacity.
- Sovereigns with disabilities requiring assistive operation. May be fully autonomous in decision-making but require operational assistance to interact with substrate.

The failure modes without discipline: substrate discipline is designed for autonomous adults, so non-autonomous sovereigns are handled ad-hoc — perhaps by proxy under someone else's Genesis (violating identity separation), perhaps by shared Genesis (violating II.5 singularity), perhaps by leaving them outside substrate entirely (unable to inherit sovereign identity later). Each ad-hoc pattern erodes structural discipline.

Dependent Sovereignty introduces the missing primitive: **scoped guardian-delegation with graduated capacity model.** A dependent sovereign has their own Genesis and their own chain. A guardian holds narrow, chain-anchored delegated authority to act on their behalf within specific scope. As capacity develops (children) or declines (elderly cognitive decline), the guardianship scope adjusts through ceremony. The dependent's own authority is preserved even when they cannot exercise it fully; it grows or shrinks with their capacity, but it is always theirs.

Three properties frame the discipline:

1. **Every sovereign has their own Genesis and their own chain.** Even at birth. Even under deepest incapacity. No shared Genesis; no proxy identity; no substrate accounts held by others. Identity is the child's own from provisioning through adulthood and beyond.
2. **Guardianship is scoped delegation, not identity replacement.** Guardian holds narrow chain-anchored authorities delegated by the dependent (or by the dependent's community-recognized initial guardian for infants) to act within specific domains — medical decisions, education coordination, financial substrate operations, etc. Guardian does not "become" the sovereign; guardian acts on the sovereign's behalf within declared scope.
3. **Capacity is graduated and chain-anchored, not binary.** Capacity to exercise sovereignty develops (children) and can decline (elderly cognitive changes). Substrate models this as chain-anchored capacity attestations across specific domains, with graduated scope grants that adjust as capacity develops. Not "child until 18, adult forever after" — real capacity across specific domains.

## Genesis for dependent sovereigns

### Genesis at birth (or at earliest opportunity)

Children born into sovereign households receive Genesis provisioning at earliest appropriate opportunity. Ceremony:

1. **Initial guardian designation ceremony**: primary caregivers (parents or equivalent) are chain-anchored designated as initial guardians for the newborn under `guardian:designated_initial:<child_id>` receipts. This is a household ceremony — parents' own kinships and the household's collective adoption context per COLLECTIVE-ADOPTION-ARCHITECTURE inform the designation.

2. **Child Genesis provisioning**: Genesis material generated for the child. On Sovereign Form, this is a hardware token custody-held by initial guardians. On Appliance or Companion Form, custody arrangement per Substrate Form conventions.

3. **Genesis custody attestation**: initial guardians attest to holding Genesis material in trust for the child. Emit `guardian:genesis_custody:<child_id>` receipts. Custody is trust arrangement, not authority — guardians cannot use the child's Genesis for signing on their own behalf; only under specific delegated capabilities within guardianship scope.

4. **Foundational scope grants**: initial guardians grant themselves the minimal scoped capabilities needed for daily coordination — medical decisions per child's declared healthcare, extension admission for age-appropriate learning tools, kinship declaration on child's behalf for family relationships, participation in household commitments the child is party to.

5. **Chain begins**: child's chain is initialized. Every subsequent operation on child's behalf, by any guardian or by the child themselves as capacity develops, is chain-anchored.

The child's Genesis exists from the ceremony forward. It is theirs. Guardians hold custody and delegated capabilities; they do not own the identity.

### Genesis for incapacity emergence

Adults who lose capacity retain their Genesis. Guardians can gain scoped delegation authority via ceremony while the person retains identity ownership. If Genesis material becomes physically unavailable (person no longer able to touch hardware token per current Genesis custody arrangement), a Genesis rotation ceremony under M-of-N recovery quorum can establish new Genesis under guardian custody arrangement while preserving chain history and sovereign identity continuity.

## Guardian-delegation scope classes

Guardianship is not one authority; it's a set of scoped delegations across specific domains. Each domain grants narrow capability. Guardians rarely hold all classes; typically hold a subset appropriate to their relationship with the dependent.

Canonical scope classes:

- `guardian:scope:medical_decisions` — authority to make medical decisions on dependent's behalf, chain-anchored per each decision
- `guardian:scope:medical_information` — authority to receive medical information about dependent from healthcare systems
- `guardian:scope:financial_substrate` — authority for substrate-mediated financial operations on dependent's behalf (household expenses shared with dependent, education-related payments, medical payments, etc.)
- `guardian:scope:extension_admission` — authority to admit extensions to dependent's substrate (typically for age-appropriate tools for children; for necessary care tools for elderly)
- `guardian:scope:kinship_declaration` — authority to declare kinships on dependent's behalf (family relationships for children; care relationships for elderly)
- `guardian:scope:education_coordination` — authority to coordinate educational context for children — school communications, learning content, teacher relationships
- `guardian:scope:care_coordination` — authority to coordinate care providers for elderly or ill dependent
- `guardian:scope:crisis_response` — authority to activate crisis response ceremonies on dependent's behalf per CRISIS-RESPONSE-CEREMONY
- `guardian:scope:legacy_preservation` — authority to manage dependent's chain for preservation and appropriate future access
- `guardian:scope:transition_advocacy` — authority to advocate for dependent's transition toward greater autonomy as capacity develops

Each grant:
- Chain-anchored via `guardian:scope_granted:<dependent_id>:<guardian_id>:<scope_class>:<grant_id>`
- Time-bounded or capacity-bounded (many child scopes transition as child ages)
- Revocable — dependent (as capacity develops) can revoke; other guardians (M-of-N ceremony) can revoke a co-guardian's scope
- Auditable — every action taken under scope is chain-anchored with reference to the specific scope grant

Guardian does NOT get:
- Authority to sign anything as if they were the dependent (their signatures are guardian-under-scope, not dependent's Genesis)
- Authority to modify dependent's own chain history
- Authority to modify capacity attestations without ceremony
- Authority to obscure their own actions from the dependent's future review

## The capacity model

Capacity is graduated across specific domains, chain-anchored via capacity attestations, and evolves over time.

### Capacity attestation

`capacity:attested:<sovereign_id>:<domain>:<attestation_id>` receipts chain-anchor the sovereign's demonstrated capacity in specific domains at specific times. Attestations may be:

- **Self-attested**: sovereign declares their own capacity in a domain (adult sovereign asserting their capacity in matters they're competent to decide)
- **Guardian-attested**: guardian attests to dependent's capacity in specific domains (parent attesting a child's demonstrated capacity to make certain decisions)
- **Community-attested**: community-recognized authority attests (educational institution attesting a student's capacity in specific academic domains; medical professional attesting cognitive capacity in medical decision-making)
- **Multi-source attested**: for high-consequence capacity determinations, multiple attesting sources compose

Attestations have:
- Specific domain (medical decisions, financial decisions, kinship relationships, digital autonomy, specific technical capabilities)
- Confidence and evidence
- Time-bound applicability (attestations decay; must be re-attested if disputed)
- Revocability if attesting source's authority changes

### Capacity graduation for children

Children develop capacity across domains at different rates. Substrate models this without imposing a single "adult at 18" threshold.

Example graduation pattern (illustrative; operator/family declares actual thresholds):

- Age 0-6: guardian holds all scope classes; child holds identity ownership
- Age 6-10: child gains self-attestation in specific domains (age-appropriate learning tool selection); guardian retains most scopes
- Age 10-14: child gains partial autonomy in social/kinship domain (friendships with age-appropriate scope); guardian retains critical domains
- Age 14-18: child gains substantial autonomy in most domains; guardian retains legal-required scopes (typically medical/financial per jurisdiction)
- Age 18+: transition to full autonomous sovereignty via graduation ceremony; guardian scopes revoked; capacity attestations for adult domains

Actual thresholds are family-declared and can be per-capacity-domain rather than blanket age gates. A precocious 14-year-old may hold financial capacity for their own earnings while a 20-year-old may retain guardian coordination in medical decisions per family preference.

### Capacity graduation for elderly cognitive decline

Reverse trajectory. Sovereign's capacity in specific domains may decline while other capacities remain intact.

- Early stage: some capacities begin to require support; guardian gains narrow scope in specific domains via consent ceremony
- Progressive: additional scopes granted as capacity declines; sovereign retains identity ownership and self-attestation in preserved domains
- Advanced: guardian holds most scopes; sovereign retains identity; capacity attestations reflect current state
- End of life: composes with OPERATOR-DEATH-AND-LEGACY per operator's own or guardian-ceremony declarations

The pattern is symmetric to child graduation but with different time scale and different social dynamics. Sovereign's dignity and identity ownership preserved throughout.

### Temporary incapacity

Post-surgery, medical crisis, mental health event: capacity temporarily reduced. Sovereign designates specific guardians for temporary scopes in advance (medical proxy delegations), or family/community steps in via emergency ceremony.

Recovery: capacity attestations updated; guardian scopes revoked as sovereign resumes autonomous exercise; chain records the arc.

## Composition with kinship

Kinship (SOVEREIGN-KINSHIP-PRIMITIVES) is peer relationship between adult sovereigns. Guardianship is asymmetric — guardian and dependent are not peers in the sense of exchanging mutual scope grants.

But: guardianship often coexists with kinship. A parent and their adult child are kindred; while the child was young, the parent was guardian; kinship persists across the transition. A caring child of an elderly parent with declining cognitive capacity may be both kindred (adult peer relationship) and guardian (scoped decision authority).

Substrate distinguishes:
- Kinship declarations: mutual, adult-peer, per-scope grants for shared work
- Guardian declarations: asymmetric, guardian-holds-scope-on-dependent's-behalf, for decisions requiring capacity dependent lacks

The two can coexist for the same relationship pair. Chain records both distinctly. Cross-Regent narrations under kinship scopes remain adult-peer; guardian-scope actions are documented separately as decisions-on-behalf-of.

## Transition ceremony (dependent → autonomous)

For children reaching autonomy, or for temporarily incapacitated adults recovering, or for any dependent gaining capacity in specific domains: transition ceremony.

1. **Capacity attestation update**: dependent's capacity in specific domain attested at new level (self-attested + optionally community-attested for higher-stakes transitions)
2. **Guardian scope narrowing or revocation**: relevant guardian scope grants revoked or narrowed per new capacity
3. **Autonomy affirmation**: dependent emits self-authored receipts in the newly-autonomous domain, evidencing capacity in practice
4. **Transition receipt**: chain-anchors the transition — from date T forward, sovereign holds autonomous authority in domain D
5. **Guardian's ceremonial role recognition**: guardian's stewardship during dependency is chain-anchored as part of the transition receipt, honoring the guardianship as legitimate role

Transition can be graduated (one domain at a time) or comprehensive (single ceremony transitioning multiple domains together, e.g., legal adulthood transitions). Family and cultural context inform pacing.

## Composition with operator death

Guardian designation composes with executor designation (OPERATOR-DEATH-AND-LEGACY). Common cases:

- Adult sovereign designates their spouse as both executor (for post-death substrate handling) and, in scenarios of pre-death incapacity, guardian (for cognitive-decline management)
- Parents of a young child designate each other as co-guardians for the child AND as executors for each other, with contingent guardianship for the child if both die
- Multiple layers of contingency: primary co-guardians, secondary guardians, adopting-family guardians in event of primary guardian death

Substrate supports:
- **Guardian succession chains**: primary guardian(s), secondary, tertiary. If primary guardian dies or is unable to continue, ceremony transfers guardianship to next in chain per operator-declared or dependent-community-declared preferences
- **Contingent guardianship**: guardianship activates only on specific conditions (dependent's primary guardians die, dependent is orphaned, dependent is diagnosed with specific condition)
- **Community/family-declared vs individually-declared guardians**: young children's initial guardians are typically declared by broader family/community context; adults declare their own future-incapacity guardians

## Composition with peer-trust-anchor

Peers who deal with a dependent sovereign in substrate operations need to know: "is this signature authoritative for the dependent, or is it a guardian acting on their behalf?" Peer-trust-anchor discipline extends:

- Peer-trust-anchor for a dependent sovereign includes awareness of active guardians and their scoped capabilities
- Guardian's scope-authorized actions carry both guardian's Genesis signature AND reference to the scope grant that authorized them
- Peers verify: (a) guardian's Genesis is valid, (b) scope grant is chain-anchored and active, (c) action is within scope
- Peer's own trust anchor decisions may weight differently: some peers may trust the dependent's own signatures but require additional verification for guardian-signed actions; others may treat both equally

## Attack model

- **Attacker attempts to gain guardian scope over adult sovereign fraudulently**: guardian scope grants require the sovereign's Genesis signature (or M-of-N recovery for incapacitated sovereigns). Fraudulent guardian claims don't chain-verify.
- **Attacker holds custody of dependent's Genesis and abuses it**: Genesis custody is trust arrangement, not authority. Any signing action requires reference to an active scope grant. Custody-based abuse without scope grant is chain-visible violation. Multi-guardian arrangements (M-of-N) prevent single-custodian abuse.
- **Attacker acts as guardian without designated authority**: chain-anchored scope grants required; unauthorized guardian actions don't verify.
- **Guardian exceeds scope (acts under one scope grant in ways that touch other domains)**: Cognitive Self-Observer flags scope violations; chain-visible; other guardians can raise concern; capacity attestation can revoke or adjust scope.
- **Attacker manipulates capacity attestation to force premature autonomy or extended dependency**: attestations from multiple sources compose; single fraudulent attestation cannot override consensus. Community-recognized attesting authorities have their own trust anchor discipline.
- **Attacker abuses transition ceremony to strip sovereign of autonomy**: transition ceremony from autonomous to dependent requires strong verification (medical attestation, court order in some jurisdictions, or M-of-N family ceremony). Substrate cannot prevent all legal/social abuses but ceremony creates chain-anchored evidence.
- **Attacker exploits child during dependent phase**: guardians' scope actions are chain-anchored; the child's future adult self can review the record. This does not prevent abuse but creates accountability trail.
- **Attacker abuses elderly's declining capacity**: multi-guardian arrangements (M-of-N thresholds for significant decisions) prevent single-guardian abuse; community and family witness roles; standing corrections about handling capacity concerns.

## Failure modes

- **Guardian misjudges dependent's capacity**: too much scope granted may harm dependent; too little may over-restrict. Capacity attestations can be re-negotiated. Ombudsman-adjacent roles (community-attested capacity reviewers) can propose reassessment.
- **Guardian and dependent disagree about scope**: capable dependents can revoke guardian scopes unilaterally (if they still hold their Genesis and can sign). For dependents with capacity limitations, community ceremony can mediate.
- **Multiple guardians disagree**: M-of-N thresholds for significant decisions; community mediation for stalemate; escalation to legal/social mechanisms outside substrate.
- **Extended incapacity with unclear guardian designation**: family or community must convene emergency ceremony to designate provisional guardians; substrate supports but does not fully solve absent-designation cases.
- **Transition to autonomy contested**: capacity attestations from multiple perspectives compose. Substrate records the arc; ultimately dependent (as they gain autonomy) decides how to interpret their transition.
- **Guardian dies during ongoing guardianship**: guardian succession chain activates; if none declared, family/community emergency ceremony convenes.
- **Cross-jurisdiction guardianship (guardian and dependent in different legal systems)**: substrate chain-anchoring may not satisfy specific legal requirements in either jurisdiction; substrate is one component in a broader legal/social framework.

## Non-goals

- **Not a substitute for legal guardianship**. Substrate guardian-delegation handles substrate operations; legal guardianship handles legal decisions in courts, government interactions, and jurisdictional matters. Both compose but neither substitutes for the other.
- **Not universal maturity taxonomy**. Substrate does not enumerate what capacities children should have at what ages. Families and communities declare; substrate honors declarations.
- **Not automatic capacity assessment via observation**. Coordination-not-oversight applies. Substrate does not surveil dependent to assess their capacity; capacity attestations come from ceremony.
- **Not identity replacement**. Guardian never becomes the dependent. Guardian acts on dependent's behalf within scope; the dependent's identity is theirs.
- **Not enforcement of specific family structures**. Substrate primitives support diverse family compositions; ceremonies and scope grants are family-declared.
- **Not permanent dependency**. Even in progressive cognitive decline, dependent's identity is honored; guardian scopes exist to support decisions the dependent can no longer make autonomously, not to erase their sovereignty.

## Open positions

- **Initial guardian designation for newborn without established parental substrate**: how does a child born to non-substrate-adopting parents get Genesis provisioning if they later enter the sovereign world? Adoption ceremony? Late-onset provisioning via community ceremony?
- **Capacity attestation federation**: how do medical professionals, educational institutions, and other attesting authorities integrate with substrate? Federation working spec needed.
- **Cross-jurisdiction guardianship complexity**: legal guardianship varies substantially across jurisdictions. How does substrate primitive interact with specific legal frameworks?
- **Assistive technology as substrate composition**: sovereigns with disabilities requiring assistive interfaces — how does substrate compose with accessibility technology while preserving identity separation?
- **Age of substrate autonomy transition**: recommended defaults per jurisdiction? Community-defined thresholds? Family-declared with substrate defaults suggested by cultural context?
- **Retroactive review by adult of childhood guardian actions**: adults reviewing their own chain from childhood — what UX supports this reflection? Guardian's actions are chain-anchored; how does the adult navigate this in a way that's meaningful rather than overwhelming?
- **Emancipation ceremony**: young sovereigns seeking early autonomy (before family-declared threshold). Substrate primitive vs legal/social mechanism.
- **Group guardianship for foster and adoptive care**: children in state care, foster families, adoption transitions. Substrate primitives should accommodate but need concrete design work.
- **Dependent's kinship declarations**: can guardians declare kinships on dependent's behalf? Under what scope? Adult child reviewing family kinships declared during childhood.

## What composes from here

Immediate design work:

1. **Guardian designation receipt schemas** — with per-scope grant structures
2. **Capacity attestation schema** — multi-source composition rules
3. **Genesis custody attestation** — trust arrangement without authority conflation
4. **Transition ceremony flow** — dependent to autonomous, autonomous to dependent
5. **Guardian succession chain protocol** — contingent guardianship activation
6. **Composition rules with peer-trust-anchor** — how peers verify guardian-signed actions

Near-term implementation:

1. Guardian delegation runtime in `crates/zp-server/src/dependency/`
2. Capacity attestation registry and query
3. Genesis provisioning ceremony for newborns
4. Scope grant lifecycle management
5. Transition ceremony coordinator
6. Guardian succession chain state
7. Dashboard: guardianship panel (active guardianships, capacity attestations, scope grants, transition planning)
8. CLI verbs: `zp guardian designate|scope|attest|transition|succession`

## Framing note

Dependent Sovereignty introduces the primitive class that the substrate needed but hadn't yet articulated: guardianship as scoped delegation with graduated capacity model. Same principle as chain-anchored discipline elsewhere — narrow scopes, operator authorization at every step, ceremony for consequential transitions, chain records everything.

The load-bearing insight: **every sovereign has their own identity and their own chain, throughout their life, regardless of capacity to exercise sovereignty at any given moment.** Children have Genesis from earliest provisioning; elderly with cognitive decline retain their Genesis and identity; temporarily incapacitated adults' identities are preserved through their incapacity. Guardianship supports the exercise of sovereignty when the sovereign cannot fully do so themselves — never replaces sovereignty, never merges identity, never claims ownership of the dependent's chain.

Combined with the substrate's structural discipline across every trust boundary, dependent sovereignty completes the human-lifespan envelope. Sovereignty is not something granted at 18 and revoked at cognitive decline — it is something operators hold across their entire life, exercised fully when they can, exercised through scoped guardians when they cannot, and preserved as identity truth through every transition. Children grow into their sovereignty rather than being handed it; elderly retain their sovereignty rather than losing it. The substrate honors the full arc of a human life, and the guardians who steward parts of that arc do so under narrow chain-anchored scope that never eclipses the sovereign whose life they support.


---

## External-signal note (2026-07-21) — deepfake wire-fraud against dependents

Motivated by the open-model inflection signal (see `AI-LANDSCAPE-SIGNAL-2026-07.md` §4). Cognitively-declining elders — a named persona in this doc — are the disproportionate target of voice/likeness-clone social engineering (the "grandpa, it's me, wire the money" attack). The verified-kin challenge added to `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` composes with guardian scopes here: a guardian may hold challenge capability for a dependent who cannot reliably self-verify a purported kin contact. See that doc's note for the open primitive-vs-composition decision.
