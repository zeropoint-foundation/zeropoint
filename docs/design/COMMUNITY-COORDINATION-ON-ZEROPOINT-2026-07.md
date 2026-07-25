# Community Coordination on ZeroPoint — July 2026

**Document type:** Design note. Establishes the canonical answer to "how does the ZeroPoint community coordinate its own maintenance and evolution?" The answer is recursive: the ZeroPoint community coordinates through ZeroPoint. Every substrate primitive that lets an operator run their own instance also lets a community of operators coordinate their maintenance of the substrate together. Using a platform (GitHub, Discord, Matrix, mailing lists) contradicts the philosophy and forfeits properties the substrate exists to provide. This document specifies what each coordination need looks like when served by substrate primitives, names the bootstrap paradox and its resolution, and names structural undeplatformability as a first-order capability rather than a philosophical claim.

**Status:** Design note. Ready for iteration; open decisions marked.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — The Recursive Vision

ZeroPoint is designed such that a ZeroPoint community can run on ZeroPoint. This recursion is not a nice-to-have. It is the strongest available demonstration that the substrate does what it claims — the ecosystem that maintains it uses it. Any argument about whether ZeroPoint is ready for a community's serious use is settled inline: watch the ZeroPoint community coordinate through the substrate. If we can't, we're implicitly conceding that the substrate isn't ready for anyone else's serious use either.

Eating our own cooking isn't just discipline. It's the proof.

### 1.1 What the substrate already provides

Everything we designed for other reasons composes toward community coordination without contortion:

- **Peer discovery** distributes proposals and messages across a substrate-native mesh. No directory, no central relay.
- **The commons** circulates learned patterns, best practices, and reference material peer-to-peer.
- **Reputation** identifies whose work has held up over time, computed locally by each operator.
- **Constitutional rules** apply to community actions like any other action; the same governance the substrate provides to operators applies to the community coordinating on it.
- **Bounded identity** protects sensitive coordination — security disclosure, controversial proposals, dissenting positions.
- **Sovereignty** means no participant depends on the Foundation for continued access.
- **The receipt chain** makes every contribution provable and every governance decision auditable.

Community coordination on ZeroPoint is not a separate thing to build. It is what happens when operators start using the substrate for the kind of collective work that maintaining the substrate itself requires.

### 1.2 The alternative and why it's disqualified

The obvious alternative — GitHub as source-of-truth, Discord or Matrix for discussion, a mailing list for announcements, a website for documentation, cloud infrastructure for CI/CD — has been the default for open-source projects for a decade. It works well enough for projects whose values don't include the substrate's sovereignty commitments. It does not work for ZeroPoint.

Choosing platform-hosted coordination for a project whose whole thesis is that platform-hosted trust infrastructure is structurally inadequate would be an ideological failure of the most visible kind. It would also forfeit real properties the substrate exists to provide: undeplatformability, per-operator sovereignty over identity and history, no dependence on any specific corporate or governmental jurisdiction.

The rest of this document specifies what to do instead.

---

## Part II — What Each Coordination Need Becomes

Traditional software-community coordination has a well-established set of needs. Each of them has a substrate-native equivalent that composes with primitives we've already built.

### 2.1 Source code hosting

Code artifacts are content-addressed by their Blake3 hash. Release authorities (the Foundation for reference implementations; other authorities for community forks and alternative mechanisms) publish release receipts on the chain declaring "version X of implementation Y has content hash Z, signed by these parties." The bytes travel peer-to-peer via mesh. Any operator can verify what they've received matches the chain-attested hash.

There is no central server holding source. There are many operators holding copies, cryptographically verifiable against a chain-anchored declaration of what each release should be.

### 2.2 Version control

Append-only history is native to the chain. Commits are receipts. Branches are chain divergences. Forks are operators publishing their own chains that trace back to a shared ancestor. Merges are receipts referencing multiple parent commits. The "diff" between two versions is computable from their content-addressed representations.

There is no GitHub-style merge queue. There are operators who have accepted a change into their own reference and operators who haven't, and the chain makes the difference legible.

### 2.3 Proposals — the ZEP mechanism

**ZeroPoint Enhancement Proposals** are chain-anchored artifacts specified in `docs/design/SUPERSESSION-FRAMEWORK-2026-07.md`. Proposals are published via peer-discovery announces under `community:proposal:*` (or `foundation:proposal:*` for Foundation-authored proposals). Subscribers receive announcements as they happen. The proposal artifact itself is content-addressed; the announce carries a hash; the content lives on the author's chain and is fetchable peer-to-peer.

Discovery is via subscription. No central registry required, though the Foundation maintains a discoverable index as a convenience — indexed but not gated.

### 2.4 Discussion

The community-surface channels specified in `docs/design/COMMUNITY-SURFACE-ARCHITECTURE-2026-07.md` are where proposal discussion happens. `topic:zep-014-detection-alternative`, `topic:mesh-transport-improvements`, or whatever topic channels operators start. Chain-anchored messages, reputation-weighted, no platform moderation.

When a proposal generates interest, its discussion self-organizes into topic channels. When it doesn't, the announcement fades. Attention is emergent, not curated by a platform algorithm.

### 2.5 Pull requests and review

A proposal is a ZEP announcement. Reviewers publish attestation receipts: "I've reviewed ZEP-014; here's what I found." Attestations are chain-anchored, signed by the reviewer's operator identity, and reputation-weighted. When an operator considers adopting a proposed mechanism, their Regent surfaces the attestation history — "eight reviewers with strong reputation attested this; two flagged concerns; one attests the reference implementation is unsafe on ARM64."

Adoption is the operator's decision informed by peer review, not a merge-queue outcome imposed by a maintainer.

### 2.6 Issue tracking

Chain-anchored community messages tagged as issues. The Cartographer derives issue-trajectory ontology objects that group related messages into coherent threads. Some issues get picked up by operators who care; others don't.

There is no central maintainer triaging a queue. Distributed responsibility emerges from who's interested. Reputation for issue-resolution accumulates like any other contribution reputation.

### 2.7 CI/CD

Peer-run verification against declared invariants. The invariants themselves are a chain-anchored artifact (see `SUPERSESSION-FRAMEWORK-2026-07.md`). Any operator can run the invariant test suite against a proposed implementation on their own hardware and publish an attestation receipt: "I ran the invariant tests against ZEP-014's reference implementation on my hardware; here are the results, here's the environment fingerprint, here's the run duration."

Adopters see verification attestations from multiple independent peers. Broken implementations produce a chain of contradicting attestations that the community sees.

### 2.8 Releases

Release receipts are chain-anchored. The Foundation's release-signing ceremony produces a receipt: "here is version X of the reference implementation, its hash is Y, its declared capabilities are Z, it was built from source hash W with dependency hashes [...], signed by ceremony participants A, B, C."

Bytes travel peer-to-peer. Every operator who installs verifies the hash against the receipt. Compromised distribution channels (a mirror serving a modified binary) produce hash mismatches that operators' clients catch.

### 2.9 Contributor identity

Operator's ZP identity — Genesis-derived, portable, reputational. No GitHub account. No email address. When you propose a ZEP, you sign it with your operator identity; your history of prior proposals and their outcomes is visible on the chain via your identity's proposal history.

Anonymous or pseudonymous contribution works exactly the same way it works for any other operator activity: bounded identities for sensitive proposals, portable identities for open work, ceremonial linking for cases where an operator wants to associate a bounded contribution with their public identity.

### 2.10 Security disclosure

Chain-anchored announces under `foundation:security:advisory` for post-fix disclosure. Operators subscribed to that category receive advisories.

Coordinated pre-disclosure uses the substrate's bounded-identity primitives. A researcher discovers a vulnerability, contacts a Foundation-run security contact via a bounded-identity mandate exchange (per the peer-discovery outreach model and the bounded-space design), coordinates a fix with the reference-implementation maintainers, and public advisory follows fix propagation. The private-then-public workflow is exactly the pattern the community-surface architecture designed for sensitive-then-broadcast communication.

### 2.11 Documentation

Distributed content-addressed docs. The whitepaper, design notes, tutorials, API references — all chain-anchored artifacts distributed peer-to-peer. Discoverable via announces under `foundation:documentation:*`.

Cached at every operator who's read them. When the Foundation updates a doc, the update is a supersession receipt referencing the prior version; peers pick up the update via subscription. Operators can pin specific versions for reproducibility.

### 2.12 What ends up not being needed

- Central authentication service (Genesis-derived identity replaces it)
- Central authorization service (capability grants replace it)
- Central issue tracker (chain-anchored messages replace it)
- Central discussion forum (community channels replace it)
- Central release distribution (peer-to-peer with chain verification replaces it)
- Central docs site (distributed content-addressed docs replace it)
- Central voting mechanism (per-operator adoption replaces it)
- Central moderator role (reputation-first moderation replaces it)

Each of these central services has substantive costs — hosting, maintenance, single-point-of-failure exposure, jurisdictional dependency. Removing all of them is not just philosophical hygiene; it's operational simplification.

---

## Part III — The Bootstrap Paradox

The one place centralization would be unavoidable is the very first bootstrap: how does someone with no ZeroPoint installation discover the substrate for the first time? This is the chicken-and-egg problem every peer-to-peer system faces.

### 3.1 Options that don't collapse into permanent centralization

**Multi-source hash verification.** The initial release hash is published in many independent places — the Foundation's website, print media, conference talks, mirror sites, IPFS, physical media, community members' personal channels. New operators verify the hash matches across sources before running the first version. Compromising the hash across all sources is substantially harder than compromising any one.

**Web-of-trust bootstrapping.** New operators receive the substrate from operators they already trust via a pre-existing relationship. Bootstrap is a personal introduction, not a platform lookup. This is the strongest form: trust chains inherit from social relationships that exist prior to and independent of the substrate.

**Reticulum-style hardcoded seed destinations.** Every release ships with a small set of well-known destination hashes for Foundation-run seed peers. Operators connect once at install, receive the current state of the ecosystem, are then peer-connected for the rest of their operational life. The seed peers are a convenience, not a dependency — running seeds is something anyone can do.

**Cryptographic release signatures published in-band.** The Foundation's Genesis-derived release-signing key is baked into initial release packages. Operators verify future updates by walking the release chain from the baked-in root. Compromising future updates requires compromising the release-signing ceremony, which is designed to be multi-party.

**Print and physical media.** For the highest-assurance bootstrap, cryptographic hashes and release-signing keys can be published in printed materials, books, and physical distribution. This is the anchor that survives even complete network censorship.

### 3.2 Why the bootstrap phase is transitional

Once past bootstrap, the operator is a full participant. They can distribute to others. They can attest to what they've verified. They can host seed peers of their own. They can contribute to the substrate's continued distribution.

The bootstrap phase is expensive per-operator but cheap in aggregate: once a critical mass of operators has verified their installations and are peer-connected, further bootstrap happens via the peer network rather than through any central source. The Foundation's role in bootstrap is a courtesy to newcomers, not a requirement for continued function.

### 3.3 What survives Foundation disappearance

If the Foundation vanished tomorrow, the substrate would continue functioning. Every operator holds:

- Their own Genesis key and derived identity.
- Their own chain of receipts.
- Their local copy of the current reference implementation.
- Cached copies of the design documents.
- Peer connections to other operators.
- The invariants (which are a small artifact easily kept locally).

New operators would still need to bootstrap, and losing the Foundation as a bootstrap convenience would raise the friction. But existing operators could continue running, proposing, adopting, communicating. Another organization or informal collective could take up the Foundation's convenience role — seed peers, reference implementation maintenance, discoverable ZEP registry — because none of it requires special authority. It just requires someone doing the work.

The substrate is not dependent on the Foundation's continued existence for its own function. The Foundation is a convenience, not a load-bearing dependency.

---

## Part IV — Structural Undeplatformability

The recursive-community-on-substrate design has a load-bearing consequence: **the community is structurally impossible to shut down through any single point.** This is not a philosophical claim about resistance. It is an architectural property.

### 4.1 What structural undeplatformability defeats

- **Corporate takedown pressure.** No platform vendor to demand action from.
- **Regulatory undeplatforming.** No jurisdiction where the substrate is centrally hosted; no single hosting party to compel.
- **DDoS.** No central endpoint whose disruption disrupts the substrate.
- **DNS hijacking or DNS-level censorship.** The substrate does not depend on DNS for continued function.
- **Court-ordered seizure.** No central servers to seize.
- **Payment processor shutoff.** No central payment relationship that could be severed to disable coordination.
- **App store gatekeeping.** No app store as the sole distribution channel for the reference implementation.
- **Repository takedown.** No single repository holding the community's coordination substrate.

The community is reached only by reaching individual operators, which is the same as reaching individual sovereign entities. That is expensive, per-target, and legally bounded by whatever protections each operator's jurisdiction provides.

### 4.2 What structural undeplatformability does NOT defeat

- **Individual operator compromise.** A specific operator's device can still be compromised through vulnerability exploitation.
- **Legal action against known operators.** Specific individuals can still be pressured within their jurisdictions.
- **Network-level censorship.** ISPs can still block traffic patterns; nation-state firewalls can still degrade mesh function.
- **Physical seizure of the entire community.** Extreme case; still requires knowing who all the operators are and having jurisdiction over each.
- **Reputation-destruction campaigns.** The community can still be discredited socially through non-technical attacks.
- **Substrate-level cryptographic attacks.** If Ed25519, Blake3, or X25519 are broken, the substrate would need to rekey. This is a research-timeline risk, not an operational one.

The property claimed is bounded and specific. It defeats the platform-shutdown attack vector. It does not defeat every possible attack.

### 4.3 Historical precedent

The property is achievable and has been demonstrated. Bitcoin has resisted platform shutdown for over a decade despite significant institutional and governmental pressure — because there is no Bitcoin platform to shut down. Tor's onion services can't be centrally undeplatformed because there is no central point to attack. Reticulum was designed for network-independent operation and functions with or without conventional internet infrastructure. IPFS content survives despite takedown requests when it's genuinely distributed.

None of these systems survived because someone chose not to shut them down. They survived because there was nothing to shut down. ZeroPoint inherits that property by construction.

### 4.4 The asymmetry that makes it a categorical position

Sovereign coordination is a load-bearing property of the architecture from day one, or it is not achievable at all. It cannot be added later.

Every platform-hosted competitor would have to rebuild their coordination substrate from the ground up to match this property. That is not something projects do mid-flight. They either had sovereignty as a design commitment from the start or they didn't.

Meanwhile, adopting the property costs almost nothing on the ZeroPoint side: the substrate is already built to support it. The community just starts coordinating through what's already here. The recursive proof is inhabited from that moment on.

---

## Part V — Who This Serves

Naming structural undeplatformability isn't just clarifying a technical property. It defines who ZeroPoint can plausibly serve.

A community that runs on a shutdownable platform implicitly excludes anyone who couldn't afford to lose the platform mid-project. That's a substantial exclusion. Groups who currently either don't participate in platform-hosted communities or participate under constant precarity:

- **Journalists in authoritarian regimes** whose sources need to remain safe and whose coordination needs to survive state pressure on major platforms.
- **Researchers whose work touches politically inconvenient topics** — climate research in jurisdictions that punish it, epidemiology under governments that suppress it, historical research that certain regimes call subversive.
- **Coordinators of things governments would prefer weren't coordinated** — humanitarian aid in sanctioned regions, cross-border educational exchanges under restrictive regimes, civil society organizations under authoritarianism.
- **Financial cooperation that regulators want to suppress** — not necessarily illegal, but often inconvenient to state or corporate interests that can bring platform pressure.
- **Health information communities that get moderated off major platforms** — mental health, harm reduction, chronic illness peer support, reproductive health information.
- **Vulnerable minority communities** whose safe communication has been repeatedly disrupted by moderation decisions on centralized platforms.
- **Whistleblowers coordinating disclosures** who cannot use platforms whose Terms of Service or legal jurisdiction expose them.

None of these groups can safely use platform-hosted communities for their real work. They can safely use ZeroPoint communities because the platform-shutdown attack vector doesn't apply.

The design choice isn't just philosophically consistent. It's a real capability that expands who the substrate can serve. Adopters looking for undeplatformability have exactly one substrate that structurally provides it. That is a specific market position, and it exists because the architecture was built for it from day one.

---

## Part VI — The Foundation's Role in a Centerless Community

The Foundation is a peer in the ecosystem it seeded. Its role is bounded and specific.

### 6.1 What the Foundation does

- **Publishes the invariants precisely.** The invariants are a small chain-anchored artifact operators can verify their implementations against.
- **Maintains the reference implementation.** The Foundation's release receipts are one adoption target among possible sets; operators can prefer alternatives.
- **Runs seed peers for bootstrap discovery.** New operators install the reference package and connect to Foundation seeds for their first ecosystem view. Seeds are a convenience, not a dependency.
- **Contributes proposals like any other participant.** Foundation-authored ZEPs go through the same lifecycle as anyone else's.
- **Participates in review.** Foundation-signed attestation receipts weigh the same as any operator's attestations, weighted by the receiving operator's trust in the Foundation.
- **Curates a discoverable registry of proposals.** The registry is one index; anyone can host their own; the Foundation's registry does not gatekeep.
- **Sponsors security work.** Coordinated disclosure workflows terminate at Foundation-run security contacts by convention, not by requirement.
- **Publishes documentation.** The whitepaper, design notes, tutorials are Foundation-authored contributions to the ecosystem's shared understanding.

### 6.2 What the Foundation does not do

- **Does not gatekeep proposals.** Anyone can publish a ZEP; publication requires no Foundation approval.
- **Does not control adoption decisions.** Which mechanisms an operator runs is the operator's choice.
- **Does not require accounts.** There is no Foundation-issued identity credential.
- **Does not moderate community discussion.** Community channels moderate themselves via the reputation-first mechanisms specified in the community-surface architecture.
- **Does not host the substrate.** Foundation servers are seed peers, not authoritative sources.
- **Does not require Foundation continuity for continued substrate function.** If the Foundation vanished, operators would continue running.

### 6.3 The Foundation's authority is bounded to two things

- **Preserving the invariants in its own reference implementation.** A Foundation-signed release that violates an invariant is a bug the Foundation fixes.
- **The quality of its own contributions.** Foundation-authored proposals, attestations, and documentation are judged like any other operator's contributions — weighted by adopters' assessment of quality.

That is the entire scope of Foundation authority. Nothing else about the substrate depends on Foundation power.

---

## Part VII — The Migration Path

The bootstrap phase is real. Some conventional tooling is temporarily necessary during it. The design goal is to migrate off conventional tooling as ZeroPoint capabilities come online, and to structure the community's early coordination such that the transition happens naturally.

### 7.1 What conventional tooling is temporarily necessary

At the earliest bootstrap, before the substrate is running in enough places to be self-sustaining:

- **A website** publishing the initial release hash and release-signing key. This is the anchor for multi-source hash verification.
- **A method for first-contact operators to reach each other.** Could be conference talks, print publications, personal networks, existing forums where sovereignty-oriented people already gather.
- **A minimal conventional communication channel** for the first small number of operators to coordinate initial bring-up. Could be encrypted email, could be an existing secure messenger, could be in-person.

Each of these is expected to fade as the substrate takes over its function. The website's hash-publication role becomes redundant when peer-verified distribution is running at scale. First-contact channels become redundant when introduction ceremonies work over the mesh. Coordination channels become redundant when community channels are running on the substrate.

### 7.2 The order of substitution

**Phase 1: Bootstrap infrastructure exists.**
- Reference implementation ships with baked-in Foundation identity for verification.
- Seed peers are running.
- The invariants are a chain-anchored artifact operators can verify against.
- The initial release hash is published in multiple independent locations.

**Phase 2: First community channels on the substrate.**
- `community:general`, `community:governance`, `community:proposals` are running.
- The first several dozen operators are participating.
- Website's discussion function migrates to substrate channels.

**Phase 3: Proposal mechanism live.**
- ZEP-000 (the meta-proposal defining ZEPs) is published as the first substrate-native ZEP.
- Foundation begins publishing its own proposals as ZEPs.
- Registry becomes discoverable via peer-discovery announces.

**Phase 4: Distribution migrates.**
- Release receipts are the primary distribution mechanism.
- Peer-to-peer distribution handles most installations.
- The website's role reduces to first-bootstrap hash publication.

**Phase 5: Documentation migrates.**
- All design notes, whitepaper, and reference documentation exist as chain-anchored artifacts.
- Discoverable via announces.
- The website's role reduces further, or the site itself becomes a substrate-hosted deliverable.

**Phase 6: The community is fully substrate-hosted.**
- Every coordination need is served by substrate primitives.
- Conventional tooling remains only for the specific bootstrap-anchor role.
- The community is structurally undeplatformable.

### 7.3 Success criteria

Migration is complete when:

- A new operator can bootstrap end-to-end without depending on any single-source platform except for the initial hash verification (which itself is verified against multiple independent sources).
- All active community coordination — proposals, discussion, review, releases, documentation — happens through substrate channels.
- The Foundation's role could be adopted by an alternative organization without breaking any operational function.
- Foundation shutdown would inconvenience new-operator bootstrap but not disrupt continuing operator function.

### 7.4 What does not migrate

Some things stay conventional forever, and that's fine:

- **Bootstrap anchors** — website(s), print media, physical distribution. These exist for the "very first install" case that peer-to-peer cannot solve.
- **Cross-jurisdictional legal presence** — the Foundation as a legal entity in some jurisdiction, for signing contracts, holding trademarks, handling regulatory interfaces. This is administrative overhead, not substrate function.
- **Emergency communication channels** — for scenarios where the substrate itself is under attack or a critical vulnerability requires broad coordination faster than substrate propagation would provide.

These are bounded exceptions, not the primary coordination surface.

---

## Part VIII — Open Design Decisions

Extracted throughout:

1. **Release-signing ceremony structure.** Multi-party thresholds, hardware-key management, transition protocol for key rotation.
2. **Seed peer count and geographic distribution.** How many, where, how they're maintained.
3. **Registry hosting.** Foundation registry format, alternative-registry discovery mechanism.
4. **Print and physical media strategy.** What specifically is published where for bootstrap anchoring.
5. **ZEP-000 specification.** The meta-proposal defining ZEPs; needs to be drafted and published as the first substrate-native ZEP.
6. **First-community-channels bootstrap.** Which channels launch first, how the initial operator cohort is seeded.
7. **Legacy platform sunset timeline.** How and when the Foundation announces migration completion for each conventional-tooling function.
8. **Foundation succession plan.** What happens if the Foundation needs to hand off its convenience role to another organization or informal collective.
9. **Alternative-authority ecosystem.** How other release-signing authorities beyond the Foundation become possible (community forks with their own release chains).

---

## Part IX — Companion Documents

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture record; the "there is no center" property (Part I §1) is the foundational commitment this document operationalizes for community coordination.
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — the transport substrate; every announcement, proposal, and discussion in this document flows through peer discovery.
- `docs/design/DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` — the pattern-sharing model that circulates review attestations, best practices, and reference material.
- `docs/design/COMMUNITY-SURFACE-ARCHITECTURE-2026-07.md` — the channels, sessions, moderation, and identity model on which community discussion runs.
- `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` — introduced the supersession framework as an affordance; this document specifies how that affordance is exercised for community coordination.
- `docs/design/SUPERSESSION-FRAMEWORK-2026-07.md` — the ZEP mechanism specification that formalizes proposals.
- `docs/design/BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` — the recovery models that let operators participate in the community without single-point-of-failure risks.
- `docs/design/ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md` — the encryption architecture that keeps community state private per operator.
- `docs/design/PHONE-AND-IDENTITY-2026-07.md` — introduction ceremonies for first-contact between operators.
- `docs/design/MEDIA-PROVENANCE-2026-07.md` — provenance for content shared in community channels.
- `docs/whitepaper-v9.md` — public thesis; §12 (Threat Model) should name undeplatformability explicitly and cite this document for the mechanism.

---

*ZeroPoint's community coordinates through ZeroPoint. Every substrate primitive that lets an operator run their own instance also lets a community of operators coordinate their maintenance of the substrate together. Using a platform forfeits properties the substrate exists to provide, including the structural undeplatformability that expands who ZeroPoint can plausibly serve. Eating our own cooking is not just discipline; it is the strongest available proof that the substrate does what it claims. The Foundation is a peer that provides bootstrap convenience and reference maintenance; nothing else about the substrate depends on Foundation authority. When the Foundation vanishes, the substrate continues.*
