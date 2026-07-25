# Household Composition

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), Part VII (Peer-Verification Contract), §III.23 (coordination not oversight), Part VIII (bounded operator sovereignty). Introduces the household as a chain-anchored multi-party primitive, avoiding N(N-1)/2 pairwise kinship declarations for family structures where four or more sovereigns share a residence and daily coordination. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (household is multi-party primitive built on kinship primitives; household members can also be pairwise kindred), `DEPENDENT-SOVEREIGNTY-2026-07.md` (households often include dependents), `OPERATOR-DEATH-AND-LEGACY-2026-07.md` (household continuity across member death), `COLLECTIVE-ADOPTION-ARCHITECTURE-2026-07.md` (households as one class of collective).

## Framing

SOVEREIGN-KINSHIP-PRIMITIVES treats kinship as pairwise: each mutual relationship between two sovereigns is its own declaration with its own scope grants. For pairs, dyads, and small friend groups, this shape is clean. For households — four adults sharing a residence, five family members across generations, six-person chosen-family — pairwise kinship generates N(N-1)/2 declarations. A four-person household needs 6 kinship declarations; a six-person household needs 15. Each with its own scope grants, its own labels, its own bundle applications.

Beyond the declaration overhead, pairwise kinship misses something structural about households: they share a residence, share physical space, share commitments (dog care, kids' pickup, groceries), share spatial ontology (naming of rooms and zones). These are household-level facts, not sums of pairwise kinships. If member A adopts a new spatial commitment ("the guest room is now the office"), it shouldn't require A to update six separate kinship declarations.

Household composition introduces the household as a multi-party chain-anchored primitive. Members belong to the household; household-level scope grants apply to all members; household-level commitments coordinate across all members; spatial ontology is household-wide. Pairwise kinships between members remain independently declarable for scopes that are pair-specific rather than household-wide.

Three properties frame the primitive:

1. **Household is a chain-anchored collective, not a merged identity.** Each member remains their own sovereign with their own Genesis, chain, and identity. Household is a shared context they all belong to and coordinate through — not a shared identity or shared authority.
2. **Household scopes are multi-party grants.** Members grant scopes to the household as a whole (all-current-members and all-future-members-per-membership-rules), not to specific pairwise partners. Household-level scopes apply to household-scope coordination; pairwise-specific sharing stays in pairwise kinship.
3. **Membership is chain-anchored and revocable.** Joining and leaving a household are ceremony receipts. Household continues as members join and leave; identity of the household persists (via household ID) while composition changes.

## The household primitive

### Household declaration

Households are established via founding ceremony. Founding members chain-anchor the household's existence.

Receipt: `household:founded:<household_id>` with:
- Household ID (content-hash of founding members' pubkeys + timestamp)
- Founding members' Genesis pubkeys
- Optional household name (member-chosen)
- Founding scope grants declared at establishment
- Optional household charter (member-declared shared values, coordination norms)

All founding members sign the founding receipt. Ceremony chain-anchors on each member's chain.

### Membership

Members belong to a household via `household:member:<household_id>:<member_id>` receipts. Membership is per-member per-household; a member can belong to multiple households (adults with residence and family-of-origin coordination; nomadic community members belonging to multiple community households; etc.).

Membership has:
- Member's Genesis pubkey
- Household ID
- Membership role (typically operator-declared: partner, child, elder, roommate, etc. — but no universal role taxonomy imposed)
- Membership scope grants (which household scopes this member participates in)
- Join timestamp
- Optional membership terms (revocable-anytime vs bounded-commitment)

### Household scopes

Household-level scope grants apply to all current members. Scope classes:

- `household:scope:presence` — mutual presence signaling among household members (composes with copresence beacon protocol per COPRESENCE-BEACON-PROTOCOL, using household_id in liveness heartbeat payload)
- `household:scope:spatial_ontology` — shared naming and shared understanding of physical zones ("kitchen," "guest room," "backyard"); shared spatial commitments (extension permissions per zone, sensing preferences per zone)
- `household:scope:commitment_coordination` — household-level shared commitments (grocery runs, chore rotation, pet care, kids' pickup schedule, guest hosting responsibilities)
- `household:scope:coordinated_calendar` — household-level calendar (shared events, meal planning, joint activities); more specific than individual pairwise calendar coordination
- `household:scope:emergency_response` — household-level crisis response coordination (household members are default care contacts for each other under crisis triggers)
- `household:scope:household_presence` — home-arrival/departure signals visible to all members
- `household:scope:extension_admission` — household-level extension admission decisions (some extensions are for-the-household, not per-member: household security, shared media library, household energy management)
- `household:scope:financial_coordination` — shared household expenses coordination (not individual financial autonomy — that stays per-sovereign)
- `household:scope:dependent_guardianship` — household members who share guardianship of dependent household members (composes with DEPENDENT-SOVEREIGNTY)

Each scope grant is bidirectionally consented at membership time and revocable per member. A household member can be present in the household but opt out of specific scopes (adult child living at home may participate in `presence` and `emergency_response` but not `financial_coordination`).

### Household charter

Optional but useful primitive: household charter declaring shared values, coordination norms, and dispute resolution protocols. Chain-anchored via `household:charter:<household_id>:<version>` receipts, member-signed.

Charter content is household-declared; substrate doesn't impose taxonomy. Common charter elements:

- Household values and shared commitments
- Coordination norms (weekly household meeting? shared meal cadence?)
- Dispute resolution protocol (who mediates disagreements)
- Membership change protocol (how new members join; how members leave)
- Physical space norms (guest hosting policy, sensing preferences)
- Financial coordination approach

Charter amendments require member consent per amendment rules declared in the charter itself.

## Composition with pairwise kinship

Household members can also be pairwise kindred. The two are complementary:

- **Household scopes**: things all members share equally (spatial ontology, household emergency response, household calendar for household-level events)
- **Pairwise kinship scopes**: things specific to a pair (romantic partners' `mutual_safety_check` grant; parent-child pairwise `commitment_coordination` for the child's activities; adult sibling pairwise `mood_signals`)

A four-person household with two romantic partners, an adult child, and an elder parent:
- One household declaration with four member receipts
- Household scopes granted to all four members equally
- Pairwise kinship between the two partners with pair-specific scopes (biometric sharing during copresence, mood signals, specific cross-Regent narration scope)
- Pairwise kinship between adult child and elder parent for elder care coordination
- Guardian scopes per DEPENDENT-SOVEREIGNTY if elder has begun to require guardianship

The household captures shared context; pairwise kinships capture pair-specific context. Neither can replace the other for its use case.

## Membership changes

### Joining

New member joins household via ceremony:

1. **Invitation**: existing members (per household charter rules, typically all-consent or M-of-N) sign `household:invitation:<household_id>:<invitee_id>` receipts
2. **Acceptance**: invitee signs `household:membership_accepted:<household_id>` receipt
3. **Scope grants**: initial scope grants declared (which household scopes the new member participates in)
4. **Chain sync**: new member gains access to household chain content per their scope grants (past household-scope receipts up to their join date)
5. **Membership receipt**: chain-anchored member receipt

### Leaving

Member leaves household via ceremony:

1. **Departure declaration**: leaving member emits `household:member_departing:<household_id>:<member_id>` receipt
2. **Charter observance**: any charter-declared departure protocols followed (waiting periods, transition planning)
3. **Scope grant revocation**: household scope grants for the departing member expire; forward household-scope activities no longer include them
4. **Historical record**: past household activities during their membership remain chain-anchored (household chain preserves history)
5. **Membership end receipt**: chain-anchored departure

Departing member can retain read access to their portion of the household chain history per operator preference (subject to remaining members' consent per household charter for anything requiring co-consent to share externally).

### Dissolution

Household dissolves when all members depart or via mutual dissolution ceremony:

1. **Dissolution declaration**: signed by all remaining members (or per charter dissolution rules)
2. **Historical preservation**: household chain remains as historical artifact; no forward household-scope activities
3. **Individual copies**: each former member retains their own chain with household-scope receipts marked as historical

Dissolution is distinct from all-members-leaving-serially: dissolution is a joint ceremony; sequential departures leave the household intact for remaining members until zero members remain.

## Composition with dependent sovereignty

Households often include dependent sovereigns — children being raised, elderly with cognitive decline, temporarily incapacitated adults. Household composition composes cleanly with dependent sovereignty:

- Dependent member has their own Genesis and chain (per DEPENDENT-SOVEREIGNTY)
- Dependent's household membership represented via member receipt
- Dependent's guardians (typically also household members) hold scoped guardianship per DEPENDENT-SOVEREIGNTY
- Household scope grants can be adapted for dependent's capacity — child may participate in `presence` and `spatial_ontology` fully, but not in `financial_coordination` until capacity graduates
- Guardian-authorized household actions (guardian granting scope on dependent's behalf) chain-anchored per DEPENDENT-SOVEREIGNTY

Children raised in a household grow into full household participation as capacity develops. Elderly members' scope grants may adjust as capacity declines. Household composition supports the full arc.

## Composition with operator death

Household continuity when a member dies:

- Deceased member's household membership transitions to memorial status via `household:member_deceased:<household_id>:<member_id>` receipt
- Deceased member's household scope grants deactivate for forward operations
- Remaining members continue household operation
- Household charter may declare specific transitions on member death (e.g., dependent guardianship succession)
- Deceased member's chain-anchored household participation remains as historical record

Household does not automatically dissolve on any member's death; it continues until member composition ceremonies dissolve it.

For household founding member death: household continues with surviving members. Founding-member status is chain-anchored history; forward household authority rests with all current members equally (or per charter rules).

## Cross-household relationships

Households can maintain relationships with other households (per COLLECTIVE-ADOPTION-ARCHITECTURE style):

- Two households may declare `household:relationship:<household_id>:<other_household_id>` receipts documenting recognized cross-household connection (grandparents' household + children's household; two households of chosen-family sharing occasional joint gatherings)
- Cross-household scope grants can enable specific shared activities without collapsing the households into one

Cross-household relationships preserve each household's distinct identity while enabling coordination between them.

## Attack model

- **Attacker forges household founding receipt**: founding requires all founding members' Genesis signatures. Forgery requires multiple Genesis compromises.
- **Attacker manipulates household to grant themselves membership**: invitation ceremony requires existing members' consent per charter; unauthorized invitation doesn't verify.
- **Attacker exploits household scope grants for surveillance of other members**: household scopes are coordination-shaped per KEEL III.23 — presence, spatial ontology, emergency response. No categorical review-of-other-members scopes exist regardless of authorization.
- **Attacker exploits departing member's history retention to leak household information**: departing member's history retention is per-operator-preference; charter can require member consent for external sharing of shared-household content.
- **Attacker manipulates charter amendments to consolidate authority**: charter amendments require consent per charter's own amendment rules; amendment attempts inconsistent with charter fail verification.
- **Attacker uses cross-household relationship to indirectly access another household's private context**: cross-household relationships have their own scope grants; indirect access is bounded by explicit cross-household scope declarations.
- **Attacker exploits dissolution to erase household evidence**: dissolution preserves chain history; erasure requires modifying chain history which is structurally impossible.

## Failure modes

- **Members disagree about household scope activation**: charter dispute resolution protocols; substrate does not force consensus.
- **Household charter conflicts with individual sovereignty**: member always retains right to depart; individual member sovereignty always takes precedence when in conflict with household coordination.
- **Departing member retains chain access, later leaks content**: household chain content shared with a departed member cannot be substrate-recovered; social/legal mechanisms outside substrate.
- **Household becomes single-member (all others depart)**: single-member household is degenerate; substrate treats as either dormant household (charter preserved, membership vacant) or as candidate for dissolution.
- **Charter version conflicts across member chains**: canonical version is the highest-numbered charter with valid amendment ceremony signatures; substrate resolves.
- **Household activity paused mid-member-transition**: household commitments may be in-flight during membership changes; transition ceremony includes commitment continuity planning.

## Non-goals

- **Not universal household taxonomy**. Substrate does not enumerate what households "should" look like or which roles members "should" hold. Households declare their own composition.
- **Not enforcement of shared living**. Household is a coordination primitive, not a legal residence declaration. Members may share physical residence or coordinate across residences.
- **Not merger of sovereignty**. Members remain distinct sovereigns; household is shared context, not shared identity.
- **Not automatic conflict resolution**. Substrate provides charter primitives for dispute resolution; actual resolution happens through human protocols.
- **Not replacement for legal household concepts**. Legal households (tax units, homeowner associations, tenant agreements) exist outside substrate. Substrate household composition may compose with legal concepts but doesn't replace them.

## Open positions

- **Charter template library**: reference charter templates for common household shapes (nuclear family, multi-generational, chosen family, roommates, co-parenting) as suggestions without imposing them.
- **Membership graduation**: children in household growing into full membership vs bounded-scope early membership. Age-graduated participation.
- **Cross-jurisdictional households**: members in different legal jurisdictions coordinate as household; substrate operations vs legal implications separate.
- **Household extensions**: extensions specifically designed for household operation (shared home automation, family calendar, household meal planning). Extension declarations for household-context.
- **Household-level Regent orchestration**: could household benefit from household-level Regent coordination that all member Regents consult, without merging their cognitive contexts? Composition patterns.
- **Household relationships composition depth**: how far do cross-household relationships extend? Grandparents-parents-children as chain of three related households vs single expanded household.
- **Household ceremonies for shared observances**: chain-anchored household ceremonies (anniversary, family gatherings, member birthdays) as commemorative artifacts.
- **Household identity vs member identity in peer interactions**: peer trust anchors for the household as a whole (some peers may deal with the household collectively) vs per-member trust anchors.

## What composes from here

Immediate design work:

1. **Household founding ceremony receipt schema**
2. **Membership lifecycle receipts** (invitation, acceptance, departure, dissolution)
3. **Household scope grant schema**
4. **Charter versioning and amendment protocol**
5. **Composition rules with pairwise kinship** (which primitives are household-level vs pairwise)

Near-term implementation:

1. Household state manager in `crates/zp-server/src/household/`
2. Ceremony coordinator for household lifecycle
3. Membership state tracking
4. Charter versioning and amendment logic
5. Household scope enforcement
6. Composition with kinship primitives runtime
7. Composition with dependent sovereignty runtime
8. Dashboard: household panel (members, scopes, charter, commitments)
9. CLI verbs: `zp household found|invite|accept|depart|dissolve|charter|scope`

## Framing note

Household composition extends the substrate's structural discipline to a specific class of coordination context: multi-party households sharing residence and daily coordination. Same principle as chain-anchored discipline elsewhere — chain-anchored ceremonies, scoped grants, operator-declared preferences, coordination not oversight.

The load-bearing insight: **household is a shared coordination context, not a shared identity.** Each member remains their own sovereign; household captures the coordination shape that would otherwise require N(N-1)/2 pairwise declarations. Household-level scopes serve household-level shared work; pairwise kinship remains available for pair-specific scopes. Members join and leave via ceremony; households persist as coordination artifacts across membership changes.

Combined with the substrate's structural discipline across every trust boundary — actions, admissions, observations, cognition, extensions, hardware, emergency response, Genesis rotation, peer trust, build lifecycle, reproducibility, recovery UX, standing corrections, hardware compromise evidence, WiFi sensing, sovereign kinship, crisis response, shared-space etiquette, operator death and legacy, dependent sovereignty, substrate migration, copresence beacon protocol — household composition completes the collective-coordination envelope. What was previously implicit — "we're a family; we coordinate on shared life" — becomes structural: household is chain-anchored; membership is documented; scopes are declared; charter captures shared norms; transitions are ceremony-based. The substrate honors households as coordination primitives without imposing what a household should be.
