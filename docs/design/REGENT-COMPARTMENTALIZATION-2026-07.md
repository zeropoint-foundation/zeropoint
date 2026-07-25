# The Regent's Role in Sovereign Identity Compartmentalization — July 2026

**Document type:** Design note. Establishes the canonical answer to "how does an operator maintain identity compartmentalization across contexts when they cannot reasonably be expected to remember which identity to use in each moment?" Sits under `ARCHITECTURE-2026-07.md` Part IV (the cognitive layer) and composes with the pattern-sharing key derivation established in `DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md`, the bounded-reputation model in the community-surface work, and the phone/identity considerations that surfaced during the community-surface design session.

**Status:** Design note. Ready for iteration; open decisions marked explicitly.

**Multi-device operation note (per Decision C, July 2026):** The Regent's home is the operator, not any specific device. Regent state (identity, memory, ontology view, compartmentalization state) is chain-anchored and replicated across all authorized devices in the sovereign's fleet. Active Regent presence is on the device the operator is currently using; only one active instance at a time; explicit chain-anchored handoff transitions between devices. This document's compartmentalization work applies at the operator level (persistent across devices) rather than per-device — style profiles, linkage assessments, and warning history follow the operator, not the device. The "Multi-device Regent visibility" open decision named in Part XII is resolved by C: state replicates, single active instance moves with the operator via explicit handoff.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Part I — The Compartmentalization Problem

The substrate gives every operator a rich set of identity contexts. Their Genesis-derived signing key. Their pattern-sharing keys for the commons. Their bounded-space identities per space. Their purpose-scoped keys per context. Optional phone attestations. Optional real-name attestations. Optional professional-credential attestations. Optional locations, working groups, personas.

Each of these exists for a reason: sovereignty, privacy, boundedness, or interoperability with the non-ZP world. The substrate makes the compartmentalization *possible*. It does not make it *natural*.

Left to their own devices, operators will:

- **Use their portable identity in a bounded space** because they didn't notice the space was bounded. The bounded identity's whole point is defeated by a single slip.
- **Publish content in a bounded space that reveals their portable identity through style, references, or explicit self-mention.** No cryptographic separation defends against this.
- **Reuse a pattern-sharing key across contexts where triangulation could de-anonymize them.** The Cartographer can detect this, but only if something is watching.
- **Attest a phone number in a context where the attestation defeats the compartmentalization they thought they had.**
- **Cross-post between contexts,** publishing content in a bounded space that they then share to a portable space, effectively linking the two.
- **Forget which identity they're using** when switching between contexts within a single session, particularly when the presentation surface doesn't remind them.

Every one of these is a failure of the operator, not of the substrate. But it is a failure the operator will make repeatedly and predictably, because compartmentalization is not the default of how human beings communicate.

The substrate is not enough. **Compartmentalization requires an active surface that watches, warns, suggests, and remembers on the operator's behalf.** That surface is the Regent.

---

## Part II — The Regent's Structural Position

The Regent is uniquely positioned for this work because it sits at the intersection of three properties no other component has:

**Full local visibility across all the operator's contexts.** The Regent sees the operator's chain, ontology, active identity contexts, and current session state. It knows what identity is currently active, what identities exist, and what each has been used for previously. No other component has this cross-context view — and no external party should.

**Advocacy for the operator, not for the ecosystem.** The Regent's job is to serve the operator's sovereignty, not to optimize for community engagement or Foundation objectives. When compartmentalization protects the operator, the Regent should recommend it even if it makes participation slower or friction-heavier.

**Presentation-layer control.** The Regent controls the operator's presentation surface. It decides what to surface, when, with what framing. This is the layer where compartmentalization warnings can be inserted at the moment they matter — before a publish, before a context switch, before an identity binding.

The Regent is not a policy engine — the gate handles that. The Regent is not a chain of receipts — the substrate handles that. The Regent is the operator's cognitive advocate, and compartmentalization is one of the load-bearing things a cognitive advocate should do.

---

## Part III — What the Regent Knows

To help with compartmentalization, the Regent maintains active awareness of several categories of state:

**Identity contexts.** Every identity the operator has: their Genesis-derived signing identity, pattern-sharing keys, per-bounded-space identities, purpose-scoped keys, attestation bindings (phone, professional credentials, etc.). The Regent knows what each identity was created for, when it was created, and what it has been used for.

**Context associations.** Which contexts each identity has been used in. The Regent tracks: "the operator's portable identity has been used in `community:general` and `community:governance`; their bounded identity in `support-group:tuesday` has only been used there; their pattern-sharing key for the commons has emitted patterns in three categories."

**Content-level style fingerprint per identity.** The Regent maintains a rough style profile per identity — vocabulary, cadence, characteristic phrasings, topic patterns — for the purpose of detecting when the operator's style would leak identity across contexts. This is not for external use; the Regent uses it internally to warn the operator about statistical de-anonymization risks.

**Cross-context linkage risk assessments.** The Regent maintains an ongoing model of which of the operator's identities are at risk of being linked to which others, and via which vector (explicit mention, style pattern, timing correlation, topic overlap, attestation overlap). This assessment is refreshed as new receipts are emitted.

**Historical warnings and operator overrides.** When the Regent has warned about a compartmentalization risk and the operator has overridden the warning ("I understand the risk, publish anyway"), that decision is remembered. Future warnings can reference the pattern: "you overrode a similar warning three weeks ago; here's what changed since then."

All of this state lives on the operator's own chain and derived storage, encrypted per the storage architecture. No other party — including the Foundation — has access.

---

## Part IV — Active Protections

The Regent's compartmentalization work is not passive. It actively intervenes at specific moments in the operator's engagement flow.

### 4.1 Pre-publish review

Before any content is emitted to a chain receipt with a specific identity, the Regent runs a pre-publish review:

1. **Confirm the active identity.** Explicitly surface "you are about to publish as [identity name/description] in [context]."
2. **Check for cross-identity references.** Scan the draft content for mentions or implications that could link this identity to another of the operator's identities. Flag: "the draft mentions 'my whitepaper' — this could link this bounded identity to your public work."
3. **Style-fingerprint mismatch check.** Compare the draft's style against the identity's established style profile. Flag drift: "the phrasing here is more consistent with your portable identity than with this bounded identity."
4. **Topic-overlap check.** If the draft's topic is one that's been prominent in another of the operator's contexts, warn: "you've discussed this topic recently in your portable identity — publishing here could allow topic-correlation triangulation."
5. **Attestation exposure check.** If the current context includes an attestation (phone, real name) that the target space doesn't need to know, flag: "this context has a phone attestation attached; the space you're publishing to would gain visibility to it. Continue?"
6. **Explicit confirmation.** For high-risk cases, require explicit override from the operator, not just quiet dismissal.

The review is fast in the common case and cheap when nothing is flagged. It becomes surfacing when the operator is about to do something that would defeat their own compartmentalization.

### 4.2 Context-switch surfacing

Every time the operator switches between contexts — moving from a bounded space to a portable one, from personal DMs to community engagement, from one bounded space to another — the Regent surfaces the switch explicitly:

- **Header change.** The presentation surface visually marks that the identity context has changed. Different color band, different framing text, different presence indicators.
- **Fresh-context prompt.** "You are now in [context] as [identity]. This is different from where you just were. Content here will not be linked to your previous context." Not a modal to dismiss; an ambient signal that persists.
- **Return-context reminder.** When the operator switches back, "You are now back in [prior context]. Your recent activity in [other context] is not visible here."

Ambient surfacing keeps compartmentalization present in the operator's awareness without requiring active mental effort each time.

### 4.3 Statistical de-anonymization defense

For high-privacy contexts (bounded identities, particularly sensitive spaces), the Regent can actively work to defeat statistical de-anonymization:

- **Style perturbation.** Suggest alternative phrasings that would break style-fingerprint matches with other identities. "Try 'agree' instead of 'concur' — that phrasing pattern shows up in your portable-identity posts." This is a suggestion the operator can accept or reject; not automatic editing.
- **Timing quantization.** For scheduled publishes, delay by random intervals to defeat activity-timing correlation with the operator's other identities. Configurable.
- **Topic diversification suggestions.** If the operator is about to post about the same topic they've been discussing in another identity, suggest waiting or rephrasing to reduce topic-overlap signal.
- **Response-cadence normalization.** If the operator is responding to messages in one identity at their typical cadence for another identity, note the pattern.

These are affordances the operator can enable per context. In casual contexts they're overhead; in genuinely sensitive contexts (support groups, whistleblower spaces, sensitive research) they're substantive protection.

### 4.4 Association-attempt detection

When another party — a peer, a service, an inference from public data — attempts to associate the operator's identities, the Regent detects the pattern and flags it:

- **Direct probing.** A peer asks about the operator in ways that suggest they're trying to correlate identities ("do you also participate in X community?").
- **Attestation-driven linkage.** A peer publishes an attestation that would link two of the operator's identities.
- **Public-data correlation.** External information (a data breach, an accidental cross-post by an associate) creates a linkage vector.

The Regent surfaces these to the operator with proposed responses: revoke a shared attestation, request the peer stop the probing, publish a counter-attestation, migrate to a fresh bounded identity.

---

## Part V — Presentation and Consent

Compartmentalization only works if the operator can see it. The Regent's presentation surface makes it visible.

### 5.1 The persistent context indicator

The presentation surface at all times displays:

- **Which identity is currently active.**
- **What context (community, space, DM) is being engaged.**
- **What visibility this identity has in this context** (portable? bounded? attested?).
- **What has been shared from this identity in this context** so far in this session.

Not buried in a settings screen — ambient in the operator's field of view. The Regent may render this differently in different fidelity modes (minimal terminal shows a header; standard browser shows a persistent side badge; secure mode shows a pixel-embedded indicator), but the information is always present.

### 5.2 Explicit identity switching

When the operator moves to engage in a context where a different identity would be appropriate, the Regent proposes the switch rather than making it silently:

- **Suggestion:** "You're about to engage in [space], where you typically use [identity]. Switch to that identity?"
- **Options:** Accept switch / use current identity anyway (with warning) / cancel engagement / create new identity for this context.
- **Learning:** The Regent remembers the operator's choice pattern per space, so future suggestions become more accurate.

### 5.3 The identity review surface

The operator can, at any time, query the Regent for a full compartmentalization review:

- **All identities.** What identities the operator has, when they were created, what for.
- **Per-identity usage.** What each identity has been used for, in what contexts, at what times.
- **Cross-identity linkage assessment.** Where the Regent sees risk of linkage, with confidence levels.
- **Attestation exposure map.** Which attestations are visible in which contexts.
- **Historical warnings and overrides.** What the Regent has flagged and what the operator has decided.

This is the operator's dashboard for their own compartmentalization posture. It should be findable, not hidden. The Regent should surface it proactively when the operator's compartmentalization posture is changing (adding a new attestation, entering a new sensitive context, receiving a linkage-attempt).

### 5.4 Consent for identity creation and binding

Every new identity, every new attestation, every new binding is a decision that requires explicit operator consent. The Regent surfaces these decisions clearly:

- **Creating a new bounded identity.** "This will be a new identity specifically for [space]. It will not be linkable to your other identities unless you explicitly link them. Attestations attached: none. Create?"
- **Attaching a phone attestation.** "This will publish a receipt attesting that this identity controls phone number [X]. Visibility: [scope]. Revocable at any time. Attach?"
- **Ceremonial linking.** "This will publish a chain-anchored linkage between [identity A] and [identity B]. Linkage is one-way and one-time-visible — once linked, the linkage is provable and cannot be retracted retrospectively. This is a serious commitment. Proceed?"

Consent is informed, not implied. The Regent's job is to make the operator's decisions visible to themselves.

---

## Part VI — Onboarding and Initial Choices

The compartmentalization problem is at its worst for new operators, who don't yet understand what compartmentalization means or why it matters. The Regent handles this with staged onboarding.

### 6.1 Initial Genesis ceremony

At Genesis, the Regent explains — in language accessible to non-cryptographic users — what identity means in ZP:

- "This Genesis key is the root of your identity in ZP. It's not the only identity you'll have — it's the origin from which other identities can be derived."
- "You can create separate identities for different contexts. Support groups where you want privacy. Communities where you want to be publicly you. Research studies where you want to participate anonymously. Each is derived from your Genesis, and only you can prove they're all yours if you choose to."
- "I will help you decide which identity to use in each context. When you're not sure, ask me."

Initial Genesis creates only the portable identity. Other identities are created on demand as the operator enters contexts that would benefit from them.

### 6.2 First community entry

When the operator enters their first community, the Regent surfaces the identity choice:

- "This community is [portable / bounded]. If portable, your Genesis-derived identity will be used — anyone in this community can potentially see your other public activity. If bounded, we'll create a new identity specifically for this community — nothing from your other identities will follow you here."
- "For [community type X], operators typically choose [portable / bounded]. What would you like?"

The Regent's suggestions are informed by the community's declared type and the operator's own history in similar contexts. Suggestions are defaults, not decisions — the operator chooses.

### 6.3 First bounded-space experience

When the operator first enters a bounded space, the Regent explains what "bounded" means concretely:

- "Your identity here is separate from your other identities. What you say here stays here — other communities cannot see it. What you say elsewhere is not visible here."
- "I recommend using a different name here than your public name, if you have one. The cryptographic separation is real, but style patterns can still link you if you're not careful."
- "I'll help watch for cross-context leakage as you engage. If you're about to say something that could link this identity to your others, I'll ask before it publishes."

The Regent frames bounded identity not as a rule to follow but as a service being offered — help maintaining the separation the operator asked for.

### 6.4 Progressive complexity

As the operator engages with more contexts, the Regent progressively surfaces more compartmentalization detail:

- **First month:** Basic context switching, portable vs. bounded distinction.
- **After a few bounded spaces:** Attestation options (phone, real name), why each has trade-offs.
- **After pattern-sharing key use:** Cross-context style considerations.
- **After identity review interactions:** Deeper controls (rotation, ceremonial linking, purpose-scoped keys).

Not overwhelming operators with all decisions upfront. The Regent teaches by presenting the next-relevant decision at the moment it becomes relevant.

---

## Part VII — Cross-Regent Interactions

When Regents from different operators interact — coordinating meetings, exchanging introductions, negotiating on behalf of their operators — the operator's compartmentalization must be preserved.

### 7.1 The visibility asymmetry

The operator's own Regent sees all of the operator's identity contexts. Peer operators' Regents do not. When the operator's Regent represents them to a peer's Regent, it presents only the identity active in the current context.

- If the operator is in `community:general` as their portable identity and their Regent responds to a message, the response comes from the portable identity.
- If the operator is in `bounded-support-group:X` and their Regent responds, the response comes from the bounded identity, and no information about the operator's other identities is exposed.
- If the operator's Regent is asked "what other communities is your operator part of?" by a peer's Regent, the answer is "not information I share" or the answer scoped to the current context only.

### 7.2 Cross-Regent mandate model

Regent-to-Regent interaction happens under a mandate. When the operator authorizes their Regent to represent them in a specific context (e.g., "please negotiate a meeting time with @carlie for the working group"), the mandate is scoped to that context. The Regent cannot use information from other contexts to answer questions the peer's Regent asks, even if the answer would be helpful.

This is a real design constraint. The operator's Regent might know that the operator prefers late-morning meetings across all contexts, but if the mandate is scoped to a specific working-group context, only late-morning-preference information from that context is available for the negotiation. Cross-context information leakage is a compartmentalization failure even when the operator would benefit from it.

The Regent should flag to the operator when a cross-context information source would be useful for a task and ask whether to widen the mandate. Not silently use cross-context info; not silently refuse to help.

### 7.3 Peer-Regent attestation model

When a peer's Regent presents itself as representing peer P, the operator's Regent verifies the mandate the peer's Regent holds. This is the same mandate-scoped delegation model that applies to all substrate action. No implicit trust of any Regent; every claim is chain-anchored.

---

## Part VIII — Audit and Introspection

The operator can, at any time, ask the Regent for a full compartmentalization audit.

### 8.1 The identity map

The Regent produces a visual map of the operator's identities and their contexts:

- **Nodes:** each identity the operator holds.
- **Edges:** contexts each identity has been used in.
- **Attestations:** which attestations are attached to which identities.
- **Linkages:** which identities are cryptographically linked (via ceremonial linking or via detected style/topic correlation).
- **Risk hotspots:** contexts where the Regent assesses linkage risk as elevated.

This is the operator's mental model of their own identity structure, made explicit.

### 8.2 The linkage assessment

For each pair of identities the operator holds, the Regent maintains an ongoing linkage-risk assessment: how likely is it that a determined observer with access to public information from both identities could correlate them?

Factors: shared attestations, style-pattern similarity, topic overlap, timing-correlation susceptibility, shared associates (people who've interacted with both), context overlap (both identities have engaged in adjacent spaces).

The operator can query "how linkable are identities A and B currently?" and get a specific answer with the underlying factors. This is not for adversaries to see — it's for the operator's own strategic decision-making.

### 8.3 The compartmentalization posture score

Aggregate: the Regent maintains a rough posture score for the operator's overall compartmentalization: high, medium, low. This is a single-glance summary that surfaces when it's changed significantly (adding a new attestation, entering a new sensitive context, receiving a linkage-attempt).

Posture score is presented with context: "your posture is medium because your bounded identity in [X] and your portable identity have topic overlap on [Y]. This is fine for casual observers but could be resolved by a determined analyst. Would you like to reduce the overlap?"

---

## Part IX — Compromise Response

When a context leaks — through operator error, adversarial attack, or exposure by a peer — the Regent helps the operator understand and respond.

### 9.1 Detection

The Regent flags likely compromises:

- **Direct linkage attestation:** someone publishes an attestation linking two of the operator's identities.
- **Public correlation:** external information becomes available that correlates identities (a data breach, an accidental cross-post).
- **Suspicious inquiry pattern:** peers or bots asking questions that suggest they're trying to correlate.
- **Style-fingerprint match:** the operator's own posts inadvertently reveal cross-identity patterns (through their own analysis or through Cartographer-side detection).

### 9.2 Blast radius assessment

When a compromise is detected, the Regent produces a blast radius report:

- **What identity is compromised.**
- **What contexts is that identity engaged in.**
- **What content has been posted from that identity.**
- **What attestations are attached.**
- **What linkages to other identities may now be visible.**
- **Estimated observer sophistication required to exploit** (casual observer, determined analyst, well-resourced attacker).

### 9.3 Response options

The Regent presents options ranked by severity:

- **Revoke attestations** that increase the linkage.
- **Migrate to a fresh identity** for the affected context.
- **Publish a counter-attestation** that reframes the exposure.
- **Withdraw from the affected context** entirely.
- **Ceremonial disclosure** — if the linkage is going to be obvious anyway, sometimes proactive disclosure on the operator's terms is better than being outed.

The operator chooses; the Regent executes.

### 9.4 Post-compromise learning

After a compromise, the Regent updates its model of the operator's threat environment. Future warnings are tuned to the specific patterns that led to this compromise. The compromise itself becomes a Friction receipt in the operator's ontology that informs subsequent compartmentalization decisions.

---

## Part X — Design Principles

The load-bearing principles that shape this document:

**The operator is the sovereign; the Regent serves.** Every compartmentalization decision is ultimately the operator's. The Regent surfaces, suggests, warns — never decides against operator will.

**Compartmentalization is a service, not a rule.** The operator asked for compartmentalization when they created a bounded identity. The Regent's job is to help them maintain what they asked for, not to enforce a rule against their preferences.

**Presence over prompts.** Ambient signaling about context and identity is better than modal prompts that get dismissed. Compartmentalization awareness lives in the presentation surface at all times, not just at decision moments.

**Informed consent over hidden optimization.** Every identity binding, every attestation, every linkage is surfaced clearly. No silent optimizations of the operator's identity posture without their awareness.

**Progressive disclosure over front-loaded complexity.** New operators don't need to understand every compartmentalization option upfront. The Regent teaches by presenting the next-relevant decision at the moment it becomes relevant.

**Local knowledge, private analysis.** The Regent's analysis of the operator's identity structure lives on the operator's own chain and derived state. No other party sees it. Compartmentalization defense doesn't require exposing the compartmentalization structure to anyone.

**Style and pattern matter as much as cryptography.** Cryptographic identity separation is defeated by style-fingerprint linkage. The Regent takes both seriously; neither alone is sufficient.

---

## Part XI — Composition with Other Work

- `docs/ARCHITECTURE-2026-07.md` Part IV — the cognitive layer specification this document extends.
- `docs/design/DISTRIBUTED-KNOWLEDGE-COMMONS-2026-07.md` — pattern-sharing key derivation; the Regent helps the operator manage which pattern-sharing key is used in which commons context.
- `docs/design/PEER-DISCOVERY-AS-OUTREACH-2026-07.md` — subscription filters; the Regent maintains awareness of which identities are subscribed to which categories.
- `docs/design/ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md` — key hierarchy; the Regent operates within the key hierarchy but is not itself part of it.
- `docs/design/BACKUP-AND-RECOVERY-LANDSCAPE-2026-07.md` — during recovery, the Regent's compartmentalization state must be re-derivable from the chain. Recovery re-establishes the operator's identity contexts but the Regent's warning history is derived state that rebuilds over time.
- Community-surface design (in progress) — bounded vs. portable spaces, locked-door sessions, session-based identity — the Regent is the surface where these interact with the operator's day-to-day flow.
- The phone-and-identity considerations that surfaced during community-surface design — the Regent is the surface that helps the operator navigate phone attestation, contact-book bridging, and introduction ceremonies without compromising sovereignty.

---

## Part XII — Open Design Decisions

Deliberate scope-open questions:

1. **Style-fingerprint model.** How the Regent computes and maintains style profiles per identity is unspecified here. Options range from simple lexical statistics to learned embeddings. Trade-offs on accuracy, storage, computational cost, and the risk of the fingerprint model itself being exploitable if compromised.

2. **Cross-context information use with operator override.** When the operator explicitly authorizes cross-context information use for a specific task, what's the mechanism? A per-task cross-context mandate? A blanket "advisor" mode? The default should be strict separation; the affordance for widening is worth deliberate design.

3. **Regent's role in ceremonial linking.** When the operator wants to link identities publicly (revealing a bounded identity), the Regent should help — but the design of that ceremony (warnings, cooling-off periods, staged disclosure) is worth its own note.

4. **How Regent's compartmentalization state survives Regent-instance changes.** If the operator changes clients, upgrades ZP, migrates devices — the compartmentalization state must survive. Some derives cleanly from chain; some (style profiles, learned warnings) requires derived-state migration.

5. **Adversarial Regent auditing.** Could a compromised Regent leak the operator's compartmentalization structure? Yes, if compromised sufficiently. This is a Part II §2.6 threat (malicious software on device) that the Regent-layer defense doesn't fully solve. Composition with software integrity attestation is the mitigation, but worth deeper design.

6. **Multi-device Regent visibility.** When the operator has Regent instances on multiple devices, does each Regent see all identities? Or is per-device identity scope possible? Composes with multi-device operation questions.

---

## Part XIII — Closing

The substrate provides identity primitives with strong cryptographic properties. But primitives are not skills, and skills are not what most operators are practiced at. The Regent's role in compartmentalization is to close the gap: to make it possible for an operator to have the identity posture they wanted without becoming a full-time identity architect.

Every operator will make compartmentalization mistakes. The measure of the design is not whether the mistakes happen, but whether the operator understands the mistakes when they happen, learns from them, and retains sovereignty over the response. The Regent is what makes that possible — the cognitive advocate whose visibility is complete, whose incentives align with the operator's, and whose presentation surface is always at hand to help.

Sovereignty is not just cryptographic. It is also cognitive. The Regent is the layer where the two meet.

---

*The substrate makes compartmentalization possible; the Regent makes it practical; the operator remains the sovereign of both. Every warning is surfaced, every decision is theirs, every history is theirs to review. The Regent works for one person only — and that person owns everything the Regent knows about them.*
