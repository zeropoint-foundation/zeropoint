# Community Surface Architecture — July 2026

**Document type:** Design note. Establishes the canonical architecture for how operators gather and communicate through ZeroPoint — the "actual surface to do that effectively out of the box." Consolidates design work from the extended community-surface design session: channels and spaces, bounded vs. portable identity per space, session-level locked-door meetings, reputation-first moderation, presence, notifications, content lifecycle, discovery, and contacts. Sits under `ARCHITECTURE-2026-07.md` Part V (the presentation layer) and composes with the identity, discovery, encryption, and Regent design notes.

**Status:** Design note. Ready for iteration; many open decisions marked.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — What the Community Surface Actually Is

The substrate provides primitives — chain, gate, mandate, peer discovery, Cartographer, Regent. These primitives are inert without a functional gathering surface. Communities can't form on top of transport primitives alone. What ZP needs to ship is a first-class communication layer that composes with everything the substrate provides, works out of the box, and doesn't require a Foundation server to function.

The design intent, from the session that produced this note:

> "I want to create the means for our future community to gather and communicate at will. An actual surface to do that effectively out of the box."

"At will" is doing important work. Any group of operators can create a space, announce it, invite others — no Foundation approval, no gatekeeper. The Foundation runs reference channels but they're not privileged in the substrate. If the community decides tomorrow that `community:general` is over-moderated and forks to `topic:general-community-alt`, that's a valid move the architecture supports.

### 1.1 Reference points

Two existing designs approximate what ZP wants:

- **Nostr** — cryptographic identity per user, signed events published to dumb-pipe relays, clients aggregate from multiple relays, no lock-in, anyone can run a relay. The right structural shape, but with weak identity (just a key, no chain-of-authority), unclear relay economics, and no governance primitives worth speaking of.
- **Reticulum's LXMF (Lightweight Extensible Messaging Format)** — store-and-forward messaging designed for mesh networks. Direct peer messaging, relay through intermediate nodes, store-and-forward for offline recipients, works over any transport. Native to the mesh model ZP already uses.

ZP has more infrastructure than either — chain, gate, mandate model, Cartographer, Regent — so it can build a gathering layer that's structurally stronger than either.

> **Posture revision, 2026-08-14 — scoped to transport, not to this document's conclusion.** The assessment of Nostr in §1.1 stands unchanged and is quoted verbatim in `NOSTR-TRANSPORT-CONFORMANCE-2026-08.md` §1. What that document reverses is the *response* to it, in the transport domain only: rather than building a structurally stronger equivalent, Nostr is targeted as a compatible transport and discovery backend — one implementation among several behind the existing `zp-mesh` traits, never the only path — with the substrate supplying from above the two things §1.1 diagnoses as missing (chain-of-authority and governance primitives). The reasoning is that the diagnosed weakness is precisely what the substrate already has, which makes supplying it cheaper than reproducing relays.
>
> **This does not settle the community surface.** That is a product question and the transport document explicitly declines to resolve it here (`NOSTR-TRANSPORT-CONFORMANCE-2026-08.md` §10, "Alternatives considered"). Whether the gathering layer described below is built on the same carrier, on LXMF, or on something else remains open. Operator ruling 2026-08-14 covers transport admission only.

### 1.2 What differentiates ZP's community surface

- **Chain-anchored provenance for every message.** Every post is a signed receipt with cryptographic history.
- **Reputation from commons participation composes into community standing.** No siloed reputation.
- **Mandate-governed moderation with disputes reviewable on-chain.** Not opaque moderator decisions.
- **Cognitively augmented via the Regent.** Not a passive UI.
- **No dedicated relay economics problem.** The mesh substrate handles transport without relay operators being a distinct role.

---

## Part II — Channel and Space Taxonomy

Four categories of channel, distinguished by scope and purpose:

- **Foundation-reserved channels** — `community:general` (open discussion), `community:governance` (Foundation announcements, protocol discussion), `community:security` (advisories, threat coordination), `community:research` (studies, findings, participation invitations). Foundation-operated but not Foundation-controlled — the Foundation is a channel host, not a moderator with special powers.
- **Topic channels** — self-organized by operators. `topic:mesh-networking`, `topic:onboarding-help`, `topic:threat-intel`, `topic:whatever-operators-care-about`. Anyone can create; discovery is via announces.
- **Working groups** — invitation-scoped, mandate-gated. Small groups collaborating on specific work. Membership is bounded to the working group.
- **Direct messages** — one-to-one via LXMF-style store-and-forward. Encrypted end-to-end using the recipient's key.

Each channel category composes with the same underlying primitives — channel is a peer-discovery destination hash, messages are chain-anchored receipts, encryption uses the CEK-per-context model from the encrypted storage architecture. What differs across categories is default policy: visibility, entry, moderation.

---

## Part III — Bounded vs. Portable Spaces

A first-class property of every space, declared at space founding: whether reputation is **portable** or **bounded**.

- **Portable spaces.** Operators participate as their persistent identity. Reputation earned in the space carries forward into other portable contexts. Suitable for public communities, professional discussion, technical channels where cross-context reputation is a feature.
- **Bounded spaces.** Operators participate as a space-scoped identity derived via the pattern-sharing key ceremony (per `DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md`). Reputation stays within the space. External observers see only the space-specific key. Suitable for support groups, sensitive personal discussion, subcultures with distinct norms, roleplay contexts, dissent networks.

### 3.1 Entry mechanisms for bounded spaces

Bounded spaces choose an entry model:

- **Sponsorship-required** — an existing member vouches; sponsor's space-reputation degrades if sponsee misbehaves.
- **Application-based** — space founder or governance mechanism approves entry.
- **Proof-of-work** — computational cost to derive a space-specific identity, raising the cost of Sybil attacks.
- **Time-locked open** — anyone joins but must wait N days of presence before participating.
- **Fully open** — anyone with a bounded identity can join freely.

Each mechanism is appropriate for different space types. Support groups probably want sponsorship or application. Roleplay spaces might be fully open. Whistleblower spaces might use proof-of-work.

### 3.2 What changes in bounded spaces

- **Fork-as-exit means leaving the space entirely.** Bounded identity cannot migrate with reputation intact to a new space; abandoning the bounded identity abandons the reputation.
- **Sponsorship works differently.** A sponsor is vouching for a bounded identity, not for the operator's persistent identity.
- **Emergency signals stay local.** Acute incidents in bounded spaces are handled within the space; they don't broadcast to the wider ecosystem.
- **Ceremonial linking as opt-in unlock.** A participant can choose to publish a chain-anchored receipt linking their bounded identity to their persistent identity. One-way, one-time-visible; not retractable retrospectively. Useful for e.g. researchers who published under bounded identity who later want to claim credit.

### 3.3 Statistical de-anonymization limits

Bounded reputation is structurally isolated at the identity layer. But bounded identities can still be linked through writing style, timing patterns, topic interests, response cadence, vocabulary. Real defenses (see `REGENT-COMPARTMENTALIZATION-2026-07.md`) require Regent-side style perturbation, timing quantization, topic-interest awareness. Cryptographic separation gives structural bounded identity; statistical separation is a Regent-mediated ongoing service.

### 3.4 Founder authority in bounded spaces

Bounded spaces have more concentrated founder authority than portable spaces because forking loses reputation. Limits on founder power that still hold:

- Constitutional floor still applies (`HarmPrincipleRule` at the gate).
- Space-level reputation is chain-anchored and observable to prospective entrants.
- Founder mandate can be revocable at founding.
- Coordinated departure retains member relationships even if reputation is lost.

Bounded spaces genuinely concentrate founder authority. That's a trade-off, not a bug — bounded spaces have legitimate reasons to exist even at that cost.

---

## Part IV — Sessions and Locked-Door Meetings

Sessions are time-scoped interactions within a space. A space exists persistently; a session within it is temporary, bounded, with a defined start and end. Session-level properties compose with space-level properties.

### 4.1 What "locked" mechanically means

Layered:

- **Membership lock.** No new joiners once the door closes. Peers routing session-join announces stop propagating new-join attempts to the session's destination after the lock receipt.
- **Observer lock (optional).** Even subscribers who were previously receiving session activity are cut off if they weren't in the door at lock time.
- **Cryptographic content lock.** Session content encrypted only to the manifest participants. Non-manifest peers cannot decrypt session receipts even if they see the raw wire traffic.
- **Invitation lock.** Participants cannot bring in delegates or advisors mid-session unless the session was declared to allow this at creation.

Each is a separate switch. Conveners choose which apply per meeting.

### 4.2 The attendance manifest

At lock time, the convener signs a manifest receipt listing every participant's identity (the space-scoped identity if bounded, the persistent identity if portable). Every participant countersigns to attest presence. The signed manifest is a chain receipt establishing exactly who was in the session at lock time. Post-session, the manifest is what makes attendance provable — participants can prove they were there; non-participants can prove they weren't asked to be.

The manifest anchors the group cryptography — the session's ephemeral encryption key is derived from a group Diffie-Hellman ceremony over the manifest participants, giving forward secrecy.

### 4.3 Ephemeral vs. persistent sessions

- **Ephemeral sessions.** Content is not persisted anywhere except in participant memory during the session. When the session ends, encryption keys are destroyed. Only the attendance manifest survives as a chain receipt. Session content is unrecoverable, ever, by anyone. Appropriate for support groups, sensitive personal discussion, ephemeral coordination.
- **Persistent sessions.** Content stays encrypted to manifest participants. Each participant retains the session receipts on their own chain. Any participant can decrypt and revisit later. Non-participants can never access. Appropriate for working-group decisions, governance deliberations, historical record.

Both modes are supported. The choice is declared at session convening. Post-session, no changing.

### 4.4 Time-boxing vs. convener-controlled

- **Time-boxed.** Meeting has declared start and end. Door locks at start; session receipts sealed at end. Automatic.
- **Convener-controlled.** Meeting starts when convener issues open receipt; door locks when convener issues lock receipt; session ends when convener issues close receipt. Manual.

Grace periods for late arrivals are configurable.

### 4.5 Non-recording attestation composes

Locked-door sessions typically require non-recording attestation from participants (per `SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md`). Each participant's node attests at join, continuously re-attests during the session, and attests non-violation at session close. Combined with cryptographic content protection and manifest-scoped encryption, this gets close to the "words spoken in a room, gone when the room disperses" property that trust-based systems can only promise.

Explicit exceptions: session-level recording flags for meetings that are meant to be recorded; participant-level recording capability grants for transcriptionists or compliance officers.

---

## Part V — Reputation-First Moderation

The moderation model: **reputation-first with minimal explicit affordances.** Traditional moderation as a formal role is genuinely unnecessary if the reputation system is designed well. The stack:

### 5.1 The layers

- **Personal filters** — always available, per-operator, no coordination required. Mute individuals, block sources, subscribe/unsubscribe from channels, filter by category or reputation floor.
- **Reputation weighting** — primary defense. Bad-faith sources become progressively invisible. Reputation is chain-anchored, contextual (per-category), portable (with the operator's identity), and computed locally by each peer using their own graph of trust.
- **Constitutional floor** — HarmPrincipleRule at the gate. Some content isn't signable at all.
- **Regent as personal advocate** — proactively surfaces concerning patterns, suggests filters, deploys defensive filters autonomously under operator-scoped delegation.
- **Fork with portable identity** — the structural threat that disciplines everyone, including channel creators. Bad moderation just makes people leave, and that pressure disciplines moderators without any explicit oversight mechanism.

### 5.2 What reputation can handle vs. can't

**Can handle:**
- Chronic low-quality content (gradually invisible)
- Chronic spam (source reputation degrades to nothing)
- Chronic bad-faith participation (same)
- Attention distribution (higher-reputation content surfaces first)

**Struggles with:**
- Acute incidents (active harassment, doxxing, threats)
- New-participant onboarding (they have no reputation yet)
- Contextual violations (someone great in one context bad in another)
- Attention monopolization (high-rep + high-volume floods the channel)
- Adversarial reputation building (long-game attacks)
- Time-sensitive coordination (crisis response)

### 5.3 Handling what reputation misses, without adding moderators

- **Bootstrap.** Sponsorship (existing operator vouches, transferring partial reputation); Foundation-seeded baseline (small baseline reputation granted to new operators, decaying over time); time-based presence accumulation.
- **Acute incidents.** The Regent flags patterns immediately and deploys filters autonomously; emergency-signal category lets affected operators broadcast a request for community response — a coordinated reputation-degradation boost, not a moderator ruling.
- **Coordinated attacks.** Chain lineage makes coordination visible; Cartographer cluster-detection identifies patterns; reputation-degradation propagates across clusters.
- **Attention monopolization.** Per-source rate limiting at receivers' substrates; Cartographer downweighting monopolization patterns; diversity-weighted attention in Regent presentation.
- **Contextual violation** — handled by contextual reputation; global rep doesn't exist.
- **Norm evolution.** Community-negotiated through what the community chooses to attest positively vs. negatively.

### 5.4 Minimum practical moderation-like affordances

Some genuinely useful additions without formal moderator roles:

- **Channel-scoped off-topic flagging.** Any member with reputation above threshold X in a specific channel can indicate that content is off-topic *for this channel*. The community negotiates what threshold X is per space.
- **Channel-founder rule declaration.** Founders declare channel-specific rules attested at creation. Not enforcement power — just declaration. New participants see rules; can decide whether to join. Reputation dynamics enforce compliance emergently.

Neither is "moderation" as a role. Both are affordances the community can use if it chooses.

### 5.5 Requirements for "genuinely good reputation"

For reputation-first to work, reputation must be:

- Chain-anchored attestations
- Computed locally, not globally (Web-of-Trust style, but Cartographer-automated)
- Portable across the operator's identity
- Contextual (per-category)
- Cryptographically expensive to Sybil
- Time-weighted (sustained behavior weighs more than recent bursts)

Designing reputation this well is hard. The reputation-first posture bets on getting it right; layered moderation is a backward-compatible fallback if reputation design proves insufficient.

---

## Part VI — Presence and Availability

Awareness of who's around is useful ("is Ken available to talk?"), but the surveillance implications are real. Design instinct: presence signaling is opt-in per contact, revocable, scope-limited, and never precise beyond what the operator wants.

- **Manual status** — available / busy / do-not-disturb. Operator sets.
- **Contextual presence** — appear online to close contacts, invisible to broader community, in a way that respects bounded/portable identity separation.
- **No-presence-at-all** as a valid choice.
- **Presence bound to specific contexts** — I can appear online to my working group but not to the broader community.

Defaults matter. Privacy-preserving default: presence is off; operator opts in per context.

---

## Part VII — Notifications and Attention Management

The mesh delivers announces; the operator's substrate decides what breaks through to conscious attention. This is largely the Regent's job — filtering signal from noise based on operator preferences, urgency, source reputation, category, current context.

Design questions:
- How urgent signals cut through DND
- How the Regent learns operator attention patterns
- How urgency claims are verified (someone claiming urgency to get through when they don't actually have any is an attack)
- Cross-context attention budget

The Regent handles the presentation:

- Threaded conversation summarized during operator's absence
- Notifications filtered by learned attention patterns
- Meeting invitations surfaced with context
- Community-discovery results ranked by fit
- Drafts of messages proposed for review
- Autonomous minor engagements (RSVPing yes to a meeting the operator would obviously say yes to) within scoped delegation

---

## Part VIII — Content Lifecycle

### 8.1 Rich content beyond text

Communities need images, audio, video, files, structured data. Chain-anchored messaging cannot be text-only.

- **Content-addressed storage for binary blobs** (they don't fit in single-packet mesh announces).
- **Attachments referenced from chain receipts by content hash.**
- **Peer-to-peer distribution for large files.**
- **Encryption for bounded-context media.**
- **Thumbnails and previews for low-bandwidth clients.**

Media provenance (per `MEDIA-PROVENANCE-2026-07.md`) applies to shared content.

### 8.2 Threading and reply semantics

Without conversation structure, community discussion becomes chaos.

- Flat vs. nested vs. tree threading — probably tree with configurable depth.
- Reply-to-specific-message via receipt reference.
- Mentions across bounded/portable contexts (respect scope; a mention in a bounded space doesn't create a portable-context notification).
- Regent presents thread structure at different fidelity levels — minimal terminal linearizes; standard browser renders tree; secure mode server-side renders.

### 8.3 Message correction under signing-is-gravity

Messages on the chain can't be deleted or edited in place. Correction primitive: **supersession receipts.**

- "Receipt R2 supersedes R1" with the original visible for provenance but the superseded version marked.
- Client shows the corrected version by default with UI affordance to see the original.
- Different from deletion — the original stays chain-visible.

### 8.4 Reactions

Lightweight expressive signals distinct from full messages. Emoji reactions, endorse, dispute. Each reaction is a small chain receipt; volume is manageable if implementation is efficient.

### 8.5 Search

Full-text search across accessible content requires local indexing. Encrypted index that only the operator can query. Search respects context boundaries — a search in bounded-space X doesn't return results from portable contexts.

---

## Part IX — Community Discovery for New Operators

Peer-discovery announces let communities broadcast their existence. But the operator needs a browsable, searchable, filterable way to find communities matching their interests.

This is a Cartographer-driven surface: the operator's Regent knows what they're interested in and surfaces community options. The community discovery layer needs a taxonomy or shape that lets communities self-describe:

- **Community declarations.** Community founders publish a self-describing profile: purpose, topic areas, size, entry mechanism, portable vs. bounded, general norms.
- **Reputation of community itself.** Communities have reputation as coherent entities: healthy discussion, active moderation-via-reputation, good faith.
- **Regent-mediated fit assessment.** The Regent evaluates candidate communities against the operator's interests and needs.
- **Warm introductions.** If the operator has peers who are already in a community, those peers can introduce them.

No centralized directory. Communities discover interested operators via announces; operators discover communities via their Regent's filtering of the announce stream.

---

## Part X — Contacts and Social Graph

People you know across contexts. Address book equivalent — but where's the state kept? On the operator's chain, per the substrate philosophy.

- **Bounded-context aliases.** I know Ken as "Ken" in one community and by a bounded-space handle in another; my contact record links these under my control, respecting the compartmentalization.
- **Relationship types.** Colleague, friend, mentor, working-group-member.
- **Context-scoped visibility.** Which of my contacts can see which parts of my profile.
- **No cross-operator contact sharing.** My address book is mine.

The Regent surfaces contact-context awareness — reminds the operator which identity is appropriate for interacting with a specific contact.

---

## Part XI — Real-Time Communication

Voice and video calls are fundamentally different from async messaging. Store-and-forward doesn't help; you need direct peer-to-peer connection with low latency.

- **Session establishment via chain-anchored capability grants.** Convening a call is a chain event.
- **Ephemeral encryption keys** — session key derived per call, destroyed at end.
- **Group ratcheting for long calls** — periodic key rotation for forward secrecy within the call.
- **Mesh vs. direct routing** — direct if reachable, mesh-relayed if not.
- **Degradation for constrained transports.** LoRa can't carry voice; the session degrades to text-based coordination.

Realtime composes with locked-door sessions naturally. Both are session-bounded; both use non-recording attestation; the wire protocol differs but the surrounding structure is the same.

---

## Part XII — Coordination and Calendaring

Even minimal calendaring is essential. Especially given locked-door sessions need scheduling.

- **Chain-anchored event receipts.**
- **Time-zone-aware presentation via the Regent.**
- **RSVPs as capability-scoped attendance intent.**
- **Recurring events.**
- **Integration with the operator's existing calendar** (probably CalDAV bridge).

Smaller than the substrate work but essential for community coordination.

---

## Part XIII — Cross-Cutting Concerns

### 13.1 Accessibility

Not just ethical — a design constraint. Screen readers, high-contrast rendering, alt text for images (fed by media provenance if available), cognitive accessibility patterns, motor accessibility. Woven throughout, not deferred.

### 13.2 Multi-device operation

Operators use multiple devices. Community surface must handle this gracefully — same identity across devices, session state that follows the operator, presence indicators that respect device availability. Detailed multi-device design is a separate note; the community surface's role is to compose gracefully with whatever multi-device architecture is chosen.

### 13.3 Crisis and safety escalation

Someone in a community shows signs of mental health crisis, or credible threats emerge. Deserving of careful design. Options: constitutional-layer response for extreme cases, community-defined trusted-responder roles, opt-in emergency-signal categories, Foundation-supported resource pointers. Worth naming as a v1.1 concern rather than shipping under-thought.

### 13.4 Onboarding flow

The first fifteen minutes determine adoption. Substrate concern, not just UX. Genesis ceremony, community discovery for fresh install, first mandate approval, Regent introduction, initial subscription filter setup, first interactions. Every decision made during onboarding anchors downstream behavior. Deserves its own design work.

---

## Part XIV — Open Design Decisions

Extracted from throughout the document:

1. **Wire format for community messages** — the specific receipt structure, encoding, and mesh envelope format for community-channel messages.
2. **Threading depth defaults** — how deep tree threading nests before flattening. Configurable per space.
3. **Rate limiting parameters** — per-source rate limits at receivers' substrates. Sensible defaults; per-context configurability.
4. **Reputation contextual granularity** — per-space? Per-category? Per-topic? Design decision affects reputation-computation cost.
5. **Emergency-signal category design** — how urgency signals cut through DND; how urgency claims are verified.
6. **Reactions volume** — reactions produce chain receipts. Volume management: how many reactions per message, how to prevent reaction floods.
7. **Search index format** — encrypted local index; specific data structure choice.
8. **Community declaration schema** — what fields communities publish for discovery. Taxonomy design.
9. **Cross-community reputation semantics** — how portable-space reputation propagates across communities. Some communities may want to weight external reputation lightly; others may treat it as strong signal.
10. **Real-time call protocol** — specific transport, codec choices, key ratcheting cadence. Substantial engineering decision.
11. **Calendar wire format** — event receipts, RSVP receipts, recurrence expression. Standardize on iCal-compatible or invent?
12. **Presence privacy defaults** — off by default, or on-with-limited-scope by default. Trade-off between usability and privacy.

---

## Part XV — Companion Documents

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture record; the presentation layer (Part V) is the substrate this document extends.
- `docs/whitepaper-v9.md` — public thesis; Part V describes the presentation primitives at a high level.
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — mesh transport for community discovery and announces.
- `docs/design/DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` — pattern-sharing key derivation for bounded-space identities; reputation composition.
- `docs/design/ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md` — CEK-per-context model applies to community content; capability-scoped peer sharing.
- `docs/design/SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md` — non-recording attestation for locked-door sessions.
- `docs/design/REGENT-COMPARTMENTALIZATION-2026-07.md` — the Regent's role in identity separation across community contexts.
- `docs/design/MEDIA-PROVENANCE-2026-07.md` — provenance for media shared in communities.
- `docs/design/PHONE-AND-IDENTITY-2026-07.md` — introduction ceremonies for cross-community bootstrapping.
- `docs/design/BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` — the operator's community state must be recoverable.

---

*The community surface is not a feature; it's the substrate expressed as a place where operators gather and communicate. Every design decision preserves the sovereignty properties the substrate provides — no centers, no lock-in, no gatekeepers, cryptographic identity throughout. Communities form when the participants decide; disband when the participants decide; fork when the participants decide. Foundation-reserved channels exist as convenience, not as authority. The measure of the design is whether operators can gather at will, communicate honestly, and maintain sovereignty over what they say, who they say it to, and how long it persists.*
