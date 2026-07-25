# Collective Adoption Architecture — July 2026

**Document type:** Design note. Specifies how collectives — teams, organizations, communities, mutual aid networks, cooperatives, families, research groups — come to run on ZeroPoint together. Distinct from individual onboarding (covered in ONBOARDING-FLOW-2026-07.md) and from the ZP community's self-governance (covered in COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md). This note addresses the structural shape of the transition from vendor-mediated coordination to chain-anchored coordination among sovereign individuals.

**Status:** Design draft, updated July 2026 with the Decision D commitment made explicit.

**Framing per Decision D (July 2026 corpus audit):** The sovereign operator is the fundamental unit of the substrate. Collectives are not first-class substrate entities and do not receive their own Genesis, chain, or officers. A collective is a coordination pattern among sovereign operators, expressed through mandates, cross-references, commons emissions, peer discovery, and community surfaces. All state remains per-sovereign. Sovereignty is not delegated upward. Organizations, businesses, and other groups in ZP exist only as voluntary coordination between sovereign individuals. This document describes those coordination patterns; it does not describe a "collective entity" the substrate reifies.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-08.

---

## Part I — What This Is

A collective is any group whose members coordinate persistently: a startup, a nonprofit, a school district, a research collaboration, a mutual aid network, an extended family. Under vendor-mediated coordination — the dominant shape today — a central entity (the employer, the platform provider, the admin) holds the accounts, owns the data, and mediates trust between members. Members participate through credentials the vendor issued; the vendor can revoke, redirect, or surveil.

Collective adoption of ZeroPoint means something different. Each member holds their own Genesis-derived identity; coordination flows through chain-anchored mandates between sovereign participants; shared state is anchored on a distributed chain rather than in a vendor's database. No central authority holds credentials over members. The collective is a coordination pattern between sovereign individuals, not an entity with authority over them.

The adoption shape has to preserve this distinction structurally. If ZP gets adopted the way SaaS gets adopted — org signs contract, admin provisions member accounts, everyone logs in — the sovereignty thesis dies at the point of adoption. Making adoption feel familiar to a typical org's IT process is the wrong shape; the point of the substrate is that it isn't that shape.

---

## Part II — Threat Model

Five collective-adoption failure modes worth naming.

**Coerced adoption.** A leader mandates that members adopt. Members' sovereign identities become obligations rather than choices. Members can't cleanly exit without professional or social cost. The individual sovereignty the substrate promises is defeated at adoption time.

**Cargo-cult adoption.** The collective adopts the shape of ZP — provisions Genesis identities, spins up a chain — but continues to operate under vendor-mediated norms. Decisions still get made by one person and rubber-stamped as consensus. Chain receipts document things that weren't actually collectively decided. The substrate becomes theater.

**Fork-and-capture.** A collective adopts ZP, then forks the substrate for internal use with member sovereignty stripped out. The fork looks like ZP from outside, has ZP-like affordances, but the members are under vendor-shape authority again. The trademark and integrity clause address this legally; the adoption architecture needs to make it hard to arrive at fork-and-capture accidentally.

**Adoption-as-branding.** Organizations claim ZP compatibility to signal alignment with sovereignty rhetoric without actually running the substrate. The claim erodes what ZP means over time. This is a licensing and community-integrity issue as much as an adoption one, but the adoption architecture is where it starts.

**Vendor consolidation.** A single service provider — hosting, inference, mesh transport — becomes the de facto center for many collectives. The chain remains distributed, but the practical dependency graph re-centralizes. The Foundation is not a certification authority; the adoption architecture must not create a de facto one through vendor consolidation.

---

## Part III — What Adoption Actually Is

A collective adopts ZP when its members individually and severally decide to coordinate their shared work through ZP-native mechanisms — chain-anchored mandates, receipt-signed commitments, mutual delegation. The collective's shared state migrates onto the chain. The vendor tools that previously mediated coordination become optional legacy surfaces or get retired.

Adoption is not a single event. It is a transformation of how the collective coordinates, one member and one workflow at a time. There is no adoption date, no ceremony that marks "the collective is now on ZP." What exists after adoption is a coordination pattern in which each member holds their own Genesis-derived identity provisioned individually per the ONBOARDING-FLOW sequence; coordination happens through mandates that participants issue to each other, scoped to specific capabilities and time horizons; shared collective state — decisions members have committed to together, artifacts they have jointly produced, commitments they hold themselves to — is expressed as receipt cross-references distributed across each member's individual chain (per Decision D, there is no collective chain; members' chains hold the coordinated state via mutual reference); and exit is structurally cheap, so a member who leaves keeps their identity, keeps their history, and the coordination structure remains coherent without them because the other members' chains still carry the cross-references that constitute the shared state.

The word "adoption" is doing more work here than it usually does. Adopting a SaaS product is choosing a tool. Adopting ZP is changing the shape of how the collective holds itself together.

---

## Part IV — Preconditions

Four preconditions for a collective to be a candidate for ZP adoption:

Each participating member has their own Genesis or is willing to onboard to get one. Adoption cannot proceed with member identities held by the collective; that's not adoption, it's re-centralization.

Each member's substrate exists somewhere they control — their own device or a device provisioned for them under their own authority. Members whose substrate exists on infrastructure controlled by others are hosted users of someone else's substrate, not sovereign participants. This distinction matters and cannot be papered over.

The collective has decided, by whatever internal process it uses, that it actually wants chain-anchored coordination. Adoption isn't for every collective. If the collective's coordination model depends on central authority over members, ZP will fit poorly and force awkward compromises at every workflow. Better to acknowledge the mismatch than to adopt into it.

Some tolerance for a mixed period. Adoption is gradual; for a while some workflows still run on the legacy substrate. The collective must be prepared to operate in that mixed state without treating it as failure.

---

## Part V — The Transition Path

Typical shape of a collective's transition from vendor-mediated to chain-anchored coordination:

**Individual seeds.** One or two members adopt ZP for their own work first. They begin using it individually, developing intuition. They emit chain receipts about work that overlaps with the collective but isn't yet coordinated through ZP.

**Bilateral coordination.** Two seeded members start coordinating through mandates between them. A researcher and a collaborator share access to a specific dataset; a designer and a developer coordinate handoff of an artifact. The bilateral coordination surface produces its own chain receipts. The rest of the collective is still on vendor-mediated tools; the bilateral pair operates in both.

**Growing coordination surface.** More members onboard as they see value. Coordination surfaces expand: bilateral becomes trilateral, workflows migrate from vendor tools to chain-anchored mandates. The collective still operates in both modes; the mixed state is real, not transitional.

**Predominance.** Enough members and enough workflows are on ZP that new work naturally starts there. The vendor tools remain available for backward compatibility but they're the exception, not the norm. This is the state most collectives will settle in — not fully migrated, but predominantly.

**Full migration** (optional). Some collectives may reach a point where vendor tools genuinely aren't needed. Others won't. The architecture doesn't require full migration; predominance is a valid stable state.

There is no forced migration date. Members who prefer legacy tools for specific workflows continue using them. The chain doesn't judge; it just records what was coordinated through it.

---

## Part VI — Mixed-Adoption States

At any given time, most collectives adopting ZP will have some members on ZP and some not. The architecture must handle this without either forcing full-collective adoption or degrading into vendor-mediated coordination that just happens to have some chain receipts.

**Bridge patterns.** One adopted member acts as a gateway for a non-adopted member. The adopted member's substrate holds a mandate that captures the non-adopted member's intent — "I have discussed this with Alice; she has agreed to X." The chain records the agreement as delegated from Alice through the bridge; Alice's future onboarding lets her claim and re-sign her prior commitments if she chooses.

**Scoped participation.** Non-adopted members can be represented in ZP-coordinated workflows through scoped mandates issued by adopted members. This is a real gap in sovereignty — the non-adopted member isn't participating on their own authority — but the architecture surfaces the gap honestly rather than pretending it doesn't exist. The chain marks these participations as bridge-delegated so they can't be confused with direct participation.

**Parallel operation.** For workflows that touch both adopted and non-adopted members, coordination runs in both substrates. The vendor tool holds the current state for the non-adopted members; the chain holds the current state for the adopted members; a member operating in both keeps them in sync manually or through a Regent mandate. This is expensive but honest.

The wrong move is to pretend the collective is fully on ZP when it isn't. Chain receipts that claim collective consensus when non-adopted members weren't consulted are cargo-cult adoption. The architecture surfaces mixed-state honestly rather than papering it over.

---

## Part VII — Structural Safeguards

Four safeguards the collective-adoption architecture preserves.

**No collective can ban exit.** A member's Genesis is theirs. Their history is theirs. Their delegations to others can be revoked. The collective cannot vote to prevent a member from leaving; the substrate structurally does not allow it. Exit costs may be social or professional, but they cannot be technical.

**No collective can compel disclosure beyond mandate.** Members grant mandates to see specific things. The chain does not create a general "collective inspection" right over member substrates. If the collective wants broader inspection, it must ask each member for a broader mandate; each member decides individually.

**Per-member chain state survives collective dissolution.** If the collective dissolves, each member's chain remains — there was never a collective chain to lose. Each member keeps their own signed history including all the cross-references to former collaborators. Shared artifacts remain fetchable by their content-addressed chain references from any member who holds them. No entity takes anything from anyone else; there is no shared entity to dissolve.

**Officer attestations at collective scale emerge from composition.** Each member's officer cadre observes their own operator's participation in the collective. When one member's Regent is becoming a de facto center for others, that member's Aegis surfaces the coordinator-drift pattern locally; when concordant Aegis findings appear across multiple members' chains, the collective-level pattern becomes visible to any observer walking the cross-reference graph. There is no collective officer view; collective-level observation is the emergent intersection of N per-operator observations, verifiable by anyone with mandate-scoped access to the relevant chains. Same officer role at member scale, composed rather than aggregated.

---

## Part VIII — Failure Modes and Their Signals

Three specific failure modes the adoption architecture actively watches for.

**Coordinator drift.** One member's Regent becomes the operational center. Everyone else's chain participation reduces to signing what that Regent produces. The chain still looks distributed but the decision-making has re-centralized. Each other member's Aegis observes the pattern in their own operator's participation — sustained one-way flow of proposals from one substrate to their own, absent counter-proposals or independent artifact production. When multiple members' Aegises produce concordant findings, the collective-level pattern becomes visible via the cross-reference graph. Whether that's a problem is for each member and the collective to decide; the substrate's job is to make the pattern visible at the per-operator level so it can compose into collective visibility.

**Consensus theater.** Chain receipts document consensus that didn't actually happen. Members sign because they were asked to, not because they engaged. Sign-off times cluster suspiciously around a single request timestamp; sign-off order matches the requester's own order rather than a natural response order. Each member's own Aegis can observe their own sign-off pattern; when multiple members' observations align on the same suspicious pattern, the collective-scale finding emerges from composition. The operators themselves can also look for it directly if they're honest with themselves about what they're doing.

**Adoption without sovereignty.** Members were told to adopt by their employer; they went along without the underlying choice. Per-operator signal: no independent chain activity from those members outside collective workflows; their Regents are used only for what the collective needs, never for their own personal work. Not a technical failure — the substrate works — but the sovereignty thesis wasn't actually realized for those members. Each member's own Aegis observes their own operator's pattern of use; the aggregate view emerges from N per-member observations. The architecture cannot force sovereignty; it can only refuse to hide the absence.

---

## Part IX — What the Foundation's Role Is Not

The Foundation does not certify collectives as ZP-compatible. It does not maintain a directory of adopting collectives. It does not endorse specific adoption paths, service providers, or hosting arrangements. It does not adjudicate disputes between collective members. It does not hold collective identities on behalf of members.

The Foundation maintains the substrate, the trademark, and the integrity clause. Collectives adopt on their own authority under those terms; the Foundation's involvement stops at the substrate boundary. This is the same posture articulated in LICENSING-AND-INTEGRITY-2026-07.md applied to the adoption case: no gatekeeping, no certification, no central directory. If future adoption pressure ever produces a case for a certification body, it should be a separate entity, deliberately not controlled by the Foundation or by any single individual.

---

## Part X — Composition

- ONBOARDING-FLOW-2026-07.md — the individual onboarding this composes with; a collective can only adopt as fast as its members onboard.
- COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07.md — the ZP community's own instance of collective adoption; a specific case rather than the general pattern.
- MULTI-DEVICE-OPERATION-2026-07.md — per-device delegation that scales down inside individual member operations and up into collective coordination.
- LICENSING-AND-INTEGRITY-2026-07.md — the trademark and integrity clause that address fork-and-capture and adoption-as-branding at legal scale.
- SUPERSESSION-FRAMEWORK-2026-07.md — the mechanism by which the substrate itself changes in response to what collective adoption reveals about it.
- TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md — Aegis's role in observing per-operator patterns that compose into collective-level visibility across members' chains.
- REGENT-COMPARTMENTALIZATION-2026-07.md — the compartmentalization discipline that governs how each member's Regent participates in multiple collectives without confusing their contexts.
