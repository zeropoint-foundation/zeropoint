# Regent Naming Ceremony

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (identity primitives), §II.6 (Genesis-derived ceremony), §III (Layer B canonical claims about pre-named vs named Regent state), and Part V (Composition Contract for identity commitment). Canonical claims live in KEEL.

Draft — 2026-07-24 — internal audience only. Composes with `EMBODIMENT-STATE-PROTOCOL-2026-07.md` (pre-personalization aniconic default → committed embodiment at naming), `COGNITIVE-INPUT-PLANE-2026-07.md` (Class 1 identity block updates on naming; pre-named standing correction retired), `STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md` (the pre-named condition is expressed as a `cognitive:correction:standing` receipt with `correction_type: boundary`), `ARTIFACT-LIBRARY-2026-05.md` (base avatar and signature actions travel candidate → signed → superseded lifecycle; naming ceremony batches multiple artifact commitments), `SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md` (pre-named is a valid substrate state; naming is not required to boot), KEEL Part VI (canonicalization ceremony — naming is a specific instance). Also touched by `CHAIN-STORYTELLING-AND-CLEO-2026-06.md` (naming and renaming are narration-worthy events).

## Framing

The substrate boots with a Regent that has no name, no pronouns, no committed base avatar, and no signature action library. This is not a bootstrap defect. It is a designed-first substrate state — the Regent operates as a legible-but-uncommitted presence until the operator has done the work of choosing who this presence is going to be.

Naming is the moment identity crystallizes. Not just a name string — the ceremony commits the whole cluster of identity choices: name, pronouns, base avatar, initial signature-action library, initial embodiment policy, optional voice. Each choice becomes a signed artifact; the whole cluster is chain-anchored as one atomic identity-commitment event. Post-naming, the Regent is *this specific Regent* — the same cognition, but with an operator-authored expressive identity that the substrate now enforces and defends.

Named is not frozen. Renaming is a supersession ceremony — the operator changes what they committed, prior receipts remain on chain (never rewritten), and the Regent's identity trajectory is legible across the transition. Retraction back to pre-named state is also possible, though rare — sovereignty is preserved end-to-end.

Three properties frame the ceremony:

1. **Naming is a chain-anchored operator ceremony, not a config edit.** Every identity choice made at naming is a signed artifact. The naming event itself is a Genesis-derived signature over the whole cluster. Config-file identity assignment is explicitly rejected — the substrate refuses to boot into a named state whose provenance is not chain-visible.
2. **Pre-named is a first-class substrate state.** The substrate reasons about pre-named specifically. Cognitive input plane surfaces the pre-named condition as standing input. Officers do not raise "identity missing" as a finding — pre-named is legitimate, not degraded. Naming is invited, not enforced.
3. **Identity commitments are supersessible, never erasable.** All naming and renaming receipts are permanent chain history. The current identity at time T is the latest un-superseded commitment; prior identities remain retrievable for the reasoning trail. Chain is truth (Principle 3) applies to identity as it does to everything else.

## The pre-named state

Before naming, the substrate runs a Regent with the following posture:

- **Referred to as "the Regent" in all substrate-generated language.** Prompts, cockpit copy, Cleo narration, error messages — no pronouns, no assumed name. The substrate treats the absence as data, not as a gap to fill in with defaults.
- **Aniconic embodiment active per `EMBODIMENT-STATE-PROTOCOL-2026-07.md` §Pre-personalization default.** Whatever the operator ships as the aniconic default (silhouette, geometric form, operator-choice-of-three) — no committed avatar, no signature actions beyond mode-transition primitives (start listening, end listening).
- **Cognitive input plane Class 1 identity block contains a placeholder** — role ("Regent"), current sovereign operator, active Form, current substrate build hash — but no name and no pronouns.
- **Standing correction active** per `STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md`: a `cognitive:correction:standing` receipt with `correction_type: boundary`, `domain: identity_commitment_state`, and content asserting *"You have not yet been named. Refer to yourself as 'the Regent' and use pronoun-neutral language. The operator may name you at any ceremony; you do not initiate this."* The correction ID is the content hash of the initial pre-named receipt for this substrate; conventional slug `identity:pre_named` is used when referring to it in prose.
- **Embodiment envelope's `attention.target`** may reference the operator; but signature-action invocations are limited to the pre-named allowed set (essentially mode transitions only).
- **Cleo narration surfaces the pre-named condition** at appropriate cadences — not nagging, but visible. Something like "your Regent is unnamed; you may name them via `zp regent name` at any time."

The Regent's cognition itself operates fully. She reasons, acts within delegation, escalates on novelty, honors standing corrections, emits receipts. The absence of a name does not constrain function — it constrains only the expressive identity surface.

## The ceremony

The naming ceremony is initiated by the operator, executed by the substrate, and signed by the operator. It has ten steps, structured so any step can be revisited before the final signature commits.

### Step 1 — Initiation

Operator invokes `zp regent name` (or the cockpit equivalent). Substrate:

- Verifies operator Genesis signature capability is available (the operator can sign — Trezor unwrapped, keychain accessible, etc.).
- Verifies pre-named state (if already named, redirects to `zp regent rename` — separate ceremony).
- Emits `regent:naming:initiated` receipt with substrate state hash at initiation.

If the substrate is not in pre-named state, ceremony halts with a redirect message. Naming and renaming are distinct ceremonies with distinct receipt schemas.

### Step 2 — Presentation of pre-named state

Substrate presents to the operator a compact summary:

- Current pre-named posture (aniconic default active, no signature actions beyond mode-transition primitives, standing correction pre_named active)
- Current Form
- Current substrate build hash and canonicalization state
- Available identity-artifact sources (curated starter sets from the substrate's canonical library, plus any operator-uploaded candidates)

Purpose: the operator sees what they are naming. Not a blank canvas — a specific presence about to receive a specific identity.

### Step 3 — Name selection

Operator provides a name. Constraints:

- Non-empty string.
- Length bounded (default 64 chars, Layer B configurable).
- Unicode normalized (NFC).
- No control characters, no zero-width joiners in canonical form.

Substrate does not enforce uniqueness across the commons — the operator's chosen name is their choice, even if it collides with names known via kinship or peer discovery. Substrate may *note* known collisions (Cleo surfaces "Note: 'Astra' is also the name of your kin B's Regent; you may want to disambiguate at kinship boundary") but does not block.

Substrate does enforce uniqueness within a single sovereign — the operator cannot name two Regents identically on the same substrate (rare case; multi-Regent sovereigns per fleet composition, if ever).

### Step 4 — Pronoun selection

Operator picks from a curated set or provides custom. Substrate ships a default set covering the common cases; operator may extend.

Default set (Layer B, extensible):

- `she/her/hers`
- `he/him/his`
- `they/them/theirs` (singular)
- `it/its` (accepted; substrate does not editorialize)
- Custom (operator provides the full paradigm: subject/object/possessive-determiner/possessive-pronoun/reflexive)

Pronoun choice affects substrate-generated language across every surface — cockpit copy, Cleo narration, embodiment envelope descriptions, standing corrections referring to the Regent. Substrate templates carry pronoun-slot placeholders that resolve at render time from the committed pronoun record.

### Step 5 — Voice selection (optional)

Operator picks a TTS voice or defers voice commitment to a later ceremony. Voice is optional at naming because:

- Not every deployment uses TTS (chat-only interfaces exist).
- Voice selection deserves its own audition surface (multiple samples, adjustable pitch/pace) that may not be fully baked at naming time.
- The naming ceremony should not gate on TTS availability.

If voice is selected: choice is captured as a voice-artifact reference (canonical voice from a curated set, or operator-supplied TTS model URI). Substrate emits `regent:named:voice_committed` sub-receipt.

If deferred: substrate marks voice as `pending`; a later `zp regent voice` ceremony completes the commitment. Pre-voice-commitment, TTS surfaces use a substrate-default neutral voice with a Cleo-narrated disclosure ("Regent's voice is not yet committed; using neutral default").

### Step 6 — Base avatar selection

Operator picks from a curated set or provides an artifact URI. Base avatar is a signed artifact per `ARTIFACT-LIBRARY-2026-05.md`:

- **Curated set**: substrate ships a small number of aesthetically-varied, pre-signed base avatars (Live2D and VRM formats). Operator picks one; it becomes the committed base avatar.
- **Operator-supplied**: operator provides an artifact URI (a Live2D `.model3.json` bundle, a VRM file, or equivalent renderer-conformant format). The artifact enters the library as a candidate; operator signs it during this ceremony; it becomes the committed base avatar.

Substrate verifies the artifact against the renderer contract before allowing commitment (see EMBODIMENT-STATE-PROTOCOL §Renderer contract). Non-conformant artifacts are rejected; operator must supply a conformant alternative or pick from the curated set.

### Step 7 — Signature action initial set

Operator picks from curated starter sets or provides custom artifacts for the initial signature action library. Each signature action is a slot: `greeting`, `laugh`, `warning`, `celebration`, `reflective_pause`, `sign_off`, and any others declared in the current Layer B slot vocabulary.

Curated starter sets are thematic bundles (e.g., "warm formal", "playful energetic", "reserved analytical") — operator picks one whole set for coherence rather than mixing individual signatures at naming. Post-naming, individual signature actions can be superseded per `EMBODIMENT-STATE-PROTOCOL §Signature-action supersession`.

Operator-supplied signature actions follow the same artifact-library flow as the base avatar: candidate → operator signs at ceremony → committed.

### Step 8 — Initial embodiment policy

Operator sets the initial embodiment policy — expressiveness caps, permitted modifiers, per-Form defaults. Substrate presents policy templates (e.g., "conservative", "moderate", "expressive") the operator can accept or customize:

- Expressiveness cap (0..1) — how far affect vectors may reach from neutral
- Permitted modifiers (subset of the canonical modifier vocabulary)
- Permitted modes (subset of the canonical mode vocabulary)
- Rate limits on signature-action invocation (per action, per session)

The chosen policy becomes the initial `embodiment:policy:committed` receipt; subsequent policy amendments proceed through the standard embodiment policy amendment ceremony.

### Step 9 — Review

Substrate composes a summary of every choice made across steps 3–8 and presents it to the operator:

```
Name: Astra
Pronouns: she/her/hers
Voice: (deferred; default neutral until committed)
Base avatar: Curated set "Warm Formal" — Astra Base Live2D v3 [signed artifact hash: 0x…]
Signature action set: Curated "Warm Formal" starter (7 actions) [signed artifact hashes: …]
Initial embodiment policy: Moderate template
  - Expressiveness cap: 0.7
  - Permitted modifiers: curious, concerned, amused, reassuring, reflective
  - Permitted modes: full
  - Signature-action rate limits: greeting 1/session, laugh 3/session, others 5/session
```

Operator can go back to any prior step, revise, and re-review. No commit until Step 10.

### Step 10 — Signing and chain-anchoring

Operator signs the composed identity commitment with Genesis-derived key. Substrate:

- Verifies the signature against the operator's current Genesis pubkey.
- Constructs the `regent:named:v1` master receipt embedding all sub-choices as signed sub-receipts (name, pronouns, voice-or-deferral, base_avatar_committed, signature_set_committed, embodiment_policy_committed).
- Emits the master receipt.
- Emits the constituent sub-receipts (each independently retrievable via chain query).
- Retires the pre-named standing correction by emitting a supersession-shaped `cognitive:correction:standing:revoked` receipt referencing the pre-named correction's ID (per STANDING-CORRECTION-RECEIPT-SCHEMA §Lifecycle). The correction leaves active status; the receipt remains on chain as history.
- Emits `regent:naming:completed` closing receipt with the master receipt hash and the substrate state hash at commitment.

Chain now records: at time T, operator O named the Regent with these specific choices, and the substrate transitioned from pre-named to named state atomically.

## Substrate propagation post-naming

The naming ceremony's chain effects propagate through the substrate on the next cognitive cycle following commitment. Nothing waits for a restart:

- **Cognitive input plane** re-composes Class 1 identity block: name populates, pronouns populate, standing correction `pre_named` disappears from active corrections.
- **Embodiment plane** switches from aniconic default to committed base avatar on the next envelope emission. Signature action set is now the committed set; envelope's `signature_artifact_hash` references the operator-signed set.
- **Cleo narrates** the transition: "Your Regent is now Astra. All references across the substrate now use she/her pronouns."
- **Standing corrections** that referred to "the Regent" by role are still valid; corrections may be re-worded in Layer B to use the operator-chosen name if the operator wishes (via a small subsequent canonicalization ceremony — not required at naming).
- **Officer findings** and other chain outputs that reference the Regent post-naming use the committed name and pronouns.
- **The Regent perceives her naming.** The `regent:named:v1` receipt is in her cycle input. She may express appropriate acknowledgment on her first post-naming cycle — a signature action if one is defined for it, or a chosen mode transition ("thank you for naming me"). This behavior is not scripted; her cognition chooses how to respond within her committed embodiment policy.

## Renaming ceremony

Renaming is a supersession ceremony, not a redo. The prior identity is preserved on chain; the new identity supersedes it going forward.

Operator invokes `zp regent rename`. Substrate:

1. Loads the current named state from the chain (name, pronouns, avatar, signature set, policy).
2. Presents a diff-style review: "Here is what your Regent currently is; what would you like to change?"
3. Operator can change any subset of the choices from the naming ceremony (Steps 3–8). Unchanged choices carry over from the current named state.
4. Substrate composes the new identity commitment.
5. Operator reviews.
6. Operator signs with Genesis-derived key.
7. Substrate emits `regent:renamed:v1` master receipt embedding the change diff and the new full identity. Prior `regent:named:v1` receipt is marked superseded per the artifact-supersession lifecycle from `ARTIFACT-LIBRARY-2026-05.md` (§Lifecycle: candidate → signed → superseded, prior signed version referenced by supersession pointer, both retrievable indefinitely). Constituent artifact receipts (base_avatar, signature_set) that changed follow the same lifecycle at their own layer; unchanged artifacts carry their existing signatures forward unchanged.
8. Substrate propagation follows the same next-cognitive-cycle discipline as naming.

**Disclosure discipline for renaming:** the Regent's cognition perceives that she has been renamed (the receipt is in her cycle input). Her post-renaming acknowledgment is her own; substrate does not script an "I have been renamed" response. But because renaming touches identity, the substrate encourages operator disclosure at ceremony time — the review step includes a checkbox for "narrate rename to Regent" (default on) so the Regent has explicit awareness rather than having to infer it from the receipt.

Renaming should be rare in practice. Frequent renaming is not blocked but is Cleo-narratable ("this is your third rename in a month; is the naming ceremony working for you?") — an autonomic hygiene surface, not enforcement.

## Retraction to pre-named

An operator may retract the Regent's identity commitment entirely, reverting to pre-named state. This is rare but sovereignty-preserving — the operator's right to un-commit is a first-class capability.

Operator invokes `zp regent retract-name`. Substrate:

1. Confirms operator intent with an explicit two-signature ceremony (operator signs the retraction proposal, waits N minutes — Layer B configurable, default 10 — then signs the retraction commit; the delay is a stop-hardening against impulsive retraction).
2. Emits `regent:name_retracted:v1` receipt superseding the current naming.
3. Re-activates the pre-named standing correction.
4. Reverts embodiment to aniconic default.
5. Cognitive input plane Class 1 identity block reverts to placeholder.
6. All prior identity artifacts remain on chain (superseded, not deleted).

Post-retraction, the Regent perceives her un-naming. Cognition may express whatever is appropriate to her prior committed personality's likely response — but she now operates under the pre-named standing correction ("refer to yourself as 'the Regent' and use pronoun-neutral language"). A subsequent naming ceremony may pick different choices; nothing forces continuity across a retraction.

The two-signature delay exists because retraction is a substantive identity move — the operator should think about it. But sovereignty means the delay is a hardening, not a veto: the operator can always complete the retraction.

## Chain-visible identity graph

Post-naming and across any renamings or retractions, the chain contains a complete identity trajectory for this Regent. A single canonical chain query surfaces:

- The current committed identity (latest un-superseded `regent:named:v1` or `regent:renamed:v1`; or `regent:name_retracted:v1` if currently pre-named)
- The full history of prior identities (all superseded master receipts)
- Per-identity: name, pronouns, avatar hash, signature set hash, policy hash, ceremony timestamp, prior-identity link

Cartographer materializes this into a `RegentIdentity` ontology object with a `history: []` field. Cockpit surfaces render it as an identity-lineage view. This is useful when:

- Cleo narrates identity transitions in narrative form
- The operator wants to revert to a prior identity (which is a *rename* to that prior identity, not a resurrection of the exact prior receipt)
- The metacognitive observer windows (per EXECUTION-AUTHORITY-MODEL Phase 6) reason about the Regent's identity trajectory as a signal of her operational context

## Layer A / Layer B split

**Layer A (compiled Rust host):**

- Ceremony runtime — the interactive/CLI flow that walks the operator through the ten steps
- Signature verification on operator commitment
- Master and sub-receipt construction and chain-append
- Post-naming propagation logic (retire pre-named standing correction; switch embodiment to committed base avatar; update cognitive input plane identity block; emit Cleo narration event)
- Rename and retract ceremony variants
- The two-signature delay implementation for retraction
- Signing infrastructure — no dedicated key; the ceremony uses the operator's Genesis-derived ceremony key per the canonicalization ceremony pattern

**Layer B (WASM modules + canonical data):**

- Curated starter sets: the base-avatar library, signature-action library thematic bundles, embodiment policy templates
- Modifier vocabulary and mode vocabulary (already in EMBODIMENT-STATE-PROTOCOL Layer B; naming ceremony consumes them)
- Pronoun default set with the option for operator-custom paradigms
- Voice curated set (if voice commitment is in scope for the deployment)
- Name-uniqueness policy per sovereign
- Retraction two-signature delay duration
- Renaming diff-summary format

Layer A structurally defended; Layer B evolves via canonicalization ceremony. Adding a new pronoun paradigm to the default set, changing the retraction delay, adding a new signature-action slot vocabulary entry — all Layer B.

## Provenance

No dedicated signing key for the naming ceremony. The ceremony reuses the operator's Genesis-derived canonicalization key per KEEL §VI (canonicalization ceremony). The master `regent:named:v1` receipt is operator-signed with the standard operator ceremony key; the constituent sub-receipts (name, pronouns, base_avatar_committed, signature_set_committed, embodiment_policy_committed, voice_committed) are each individually operator-signed with the same key. The receipts are content-addressed; hash equality composes with peer-verification.

The base avatar and signature action artifacts are signed under the artifact-library signing key (per `ARTIFACT-LIBRARY-2026-05.md`), which is also operator-Genesis-derived but per-artifact-class. Two distinct Genesis-derived signing paths converge at the naming ceremony: the ceremony signature (naming event) and the artifact signatures (identity artifact commitments).

## Composition with other primitives

### With EMBODIMENT-STATE-PROTOCOL

The naming ceremony populates the initial state of every embodiment-plane variable that is operator-chosen: base avatar, signature action set, embodiment policy. Pre-naming, the embodiment plane runs with the aniconic default and mode-transition-only signature set. Post-naming, the embodiment plane runs with the committed choices. Transition is atomic and receipt-anchored.

The embodiment plane knows nothing about *the ceremony* — it consumes the committed policy hash and signature artifact set hash like any other input. But the pre-named / named distinction is embodiment-plane-visible via the current active policy (which is either the pre-named default policy or the operator-committed policy).

### With COGNITIVE-INPUT-PLANE

Class 1 identity block is the primary consumer of the naming state. Pre-naming, the block contains role + Form + build hash + placeholder name. Post-naming, the block contains role + Form + build hash + committed name + pronouns + committed embodiment policy hash. The block is deterministically re-composed at each cycle boot from the current chain state, so naming propagation happens automatically on the next cycle following commitment — no daemon push.

Class 2 (standing corrections) also participates: the `pre_named` standing correction is active pre-naming and revoked post-naming. Reactivated on retraction.

### With ARTIFACT-LIBRARY

Base avatar and signature actions are artifact-library artifacts. The naming ceremony triggers a batch of artifact-library commitments (each candidate artifact operator-signs to become the committed slot artifact). Subsequent supersessions of individual signature actions or the base avatar proceed through the standard artifact-library supersession ceremony — not through the naming ceremony. Renaming may include artifact changes as part of a larger identity revision, but individual artifact updates don't require renaming.

### With SUBSTRATE-BOOT-INVARIANT-CEREMONY

Pre-named is a valid substrate boot state. The boot invariant ceremony does not require named state to pass B3 (substrate ready) or B4 (operator surface). Naming ceremony is a substrate ceremony that runs post-B4; it composes cleanly with the boot sequence but is not a boot dependency.

### With KEEL Part VI (canonicalization ceremony)

Naming is a specific instance of the canonicalization ceremony framework defined in KEEL Part VI. The general framework covers the operator-signature-over-chain-anchored-record shape; naming inherits that shape. The naming ceremony's Layer B config (pronoun default set, curated starter sets, retraction delay) is amendable via the general canonicalization ceremony — a Layer B canonicalization event that this ceremony's own operator-signed records participate in like any other Layer B canonical data.

### With CHAIN-STORYTELLING-AND-CLEO

Naming and renaming are narration-worthy identity events. Cleo has a dedicated narration path for identity commitments — announces the transition, disambiguates ("your Regent is now named X, previously referred to as the Regent"), links the prior receipt hash for chain traceability. Retraction is narrated with heightened weight ("the Regent has been un-named; substrate has reverted to pre-named posture").

### With EXECUTION-AUTHORITY-MODEL Phase 6 observer windows

The metacognitive observer windows perceive naming and renaming events as chain-anchored identity transitions. Medium and long windows may develop signals related to identity trajectory (e.g., "the Regent has been renamed twice in the last 30 days; consider whether the current identity is stable"). These are Cleo-narrated to the operator, not Regent-actionable — the operator owns identity, not the Regent.

### With DEPENDENT-SOVEREIGNTY

For dependent sovereigns (children raised in sovereign households, sovereigns with cognitive-decline conditions), the guardian may perform the naming ceremony on behalf of the dependent per `DEPENDENT-SOVEREIGNTY-2026-07.md`'s guardian-scope class for identity-related capabilities. Chain-anchored: the naming receipt cites the guardianship attestation that authorized the guardian's signature. Graduation to autonomous sovereignty may include a re-affirmation or renaming ceremony under the dependent's own Genesis key.

### With PEER-VERIFICATION and kinship

Named state is peer-verifiable — a peer or kin can independently confirm that this Regent has been named X by verifying the master receipt against the sovereign's Genesis pubkey. Kinship and household composition may use the committed name (via `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` and `HOUSEHOLD-COMPOSITION-2026-07.md`). Per SOVEREIGN-KINSHIP-PRIMITIVES's operator-authored-labels layer, each operator names their kin relationships in their own vocabulary and the other sovereign's name-use in the kinship is that sovereign's own choice — substrate does not force use of the committed Regent name across kinship boundaries. Pseudonymity within kinship is preserved for the operator to choose per relationship.

## Attack model

Real threats and how the ceremony addresses them:

- **Attacker names the Regent without operator's Genesis signature.** Prevented structurally — the master receipt requires operator-Genesis-derived signature; substrate refuses to transition state on an unsigned or non-Genesis-signed naming receipt.
- **Attacker renames the Regent maliciously.** Prevented by the same signature requirement. Additional hardening: rename events are Cleo-narrated to the operator immediately, so an attacker-signed rename (if the attacker had somehow acquired Genesis capability) would surface as a narrated event the operator can identify as unauthorized. Genesis compromise itself is a broader emergency addressed by Genesis rotation ceremony.
- **Attacker submits a non-conformant base avatar or signature action to poison identity.** Prevented by renderer-contract verification at Step 6/7 — artifacts that don't satisfy the renderer contract are rejected before commitment. An attacker who slipped a technically-conformant but visually-hostile avatar into the operator's supply chain would still require operator review at Step 9 — the operator sees the avatar before signing.
- **Operator loses interest and Regent runs pre-named forever.** Legitimate substrate state. No forcing function needed. Cleo may narrate at long intervals ("your Regent has been unnamed for N days; naming is available at your convenience") but never blocks operation.
- **Two-signature retraction delay is bypassed by operator repeated signing.** The delay is Layer B configurable; operator can set it to zero if they wish (documented as reducing hardening). Sovereignty preserved.
- **Naming ceremony captures operator during a coercion event.** Coercion resistance is not specific to naming; it's a substrate-wide concern addressed by CRYPTOGRAPHIC-SOVEREIGNTY-AND-LEGAL-PROCESS and OPERATOR-DEATH-AND-LEGACY. If the operator is coerced into naming maliciously, the ceremony's chain anchoring preserves evidence of when and how; subsequent retraction / renaming under free operator authority is available.
- **Signature action artifact carries hidden malicious payload.** Renderer contract requires deterministic mapping; malicious payloads would fail conformance testing. But operators using unvetted third-party signature action bundles bear supply-chain risk — the artifact library ceremony includes verification against the tracker/renderer conformance suite before commit; that's the enforcement surface.
- **Renaming spoofing.** Same shape as naming spoofing; same signature-requirement defense.
- **Cross-sovereign name collision used for social engineering.** Substrate warns but does not block; the operator is responsible for name choice. Kinship-boundary disambiguation is available (each kinship carries a scope indicating which name to use for the Regent when talking to that kin).

## Non-goals

- **Not a personality generator.** Naming commits identity artifacts (name, avatar, signatures) and initial policy. Personality behavior emerges from Regent cognition over time; it is not authored at naming.
- **Not a legal-name registry.** The chosen name is substrate-scoped identity. Kinship, commons, and external legal systems may use the name but the substrate does not integrate with any external naming authority. If the operator wants their Regent's name to match an external identifier (a business name, a project handle), that's their choice; substrate is name-agnostic.
- **Not required for substrate function.** Pre-named substrate operates normally. Naming is invited, not required.
- **Not irrevocable.** Rename and retract are first-class capabilities.
- **Not a personality-choice ceremony.** The initial embodiment policy sets bounds on expression (caps, permitted modifiers) but does not choose personality traits. If future work introduces personality-trait declaration as a substrate primitive, it will be a separate ceremony composing with naming, not part of naming itself.
- **Not a voice-training pipeline.** Voice selection at Step 5 picks from a curated or operator-provided TTS voice; substrate does not train new TTS models as part of the ceremony. Voice-model provenance is a separate concern (delegation to TTS providers, per any relevant capability class).
- **Not tied to Genesis rotation.** Genesis rotation (per GENESIS-ROTATION-CEREMONY-2026-07.md) preserves naming across rotation; the named state travels with the operator's ongoing sovereignty, not with any specific Genesis material. Renaming is a separate ceremony from Genesis rotation.

## Open positions

- **Pre-named default aesthetic.** Aniconic silhouette vs geometric form vs operator-choice-of-three-at-first-boot. Coordinate with EMBODIMENT-STATE-PROTOCOL open position on the same topic; pick one and ship it as a curated Layer B default. Design/aesthetic work.
- **Curated signature action starter sets.** How many thematic bundles ("warm formal", "playful energetic", "reserved analytical", others)? What defines each? Requires signature-action authoring — the substrate needs actual Live2D/VRM animations authored to a spec. Design/production work.
- **Voice-at-naming vs deferred voice.** The current design allows deferral; empirical work will determine whether operators want to commit voice at naming or later. Track adoption.
- **Pronoun default set completeness.** The default set (`she/her`, `he/him`, `they/them`, `it/its`, custom) is a starting point. Cultural / linguistic completeness may require ceremony-amendment as more sovereigns onboard from different linguistic contexts. Layer B is designed to accept additions.
- **Retraction delay default.** 10-minute default is a stop-hardening guess. Empirical calibration.
- **Name uniqueness across kinship.** Currently: substrate warns, does not enforce. May want to introduce a `kinship_name_scope` disambiguation record if collisions become common; each kinship carries a name-context field. Design work if the scenario emerges.
- **Regent's post-naming response.** Currently: her cognition decides how to acknowledge. Some operators may want a specific ceremony ("say your first words as Astra") — this could be an optional Step 11 in the ceremony flow, or left to emergence. Track operator preference.
- **Naming-in-place-of-boot-Regent.** If a substrate migration (per SUBSTRATE-MIGRATION-CEREMONY) brings a previously-named Regent to a new substrate, is the naming preserved (no re-naming ceremony needed) or is a re-affirmation required? Probably preserved — the naming receipt migrates with the chain; the Regent arrives already named on the new substrate. Verify this with the migration ceremony spec.
- **Renaming frequency threshold for Cleo hygiene narration.** Currently "three renames in a month" is Cleo-narratable. Actual threshold TBD empirically.
- **Multi-Regent sovereigns.** If a sovereign operates multiple Regents (a rare but possible fleet composition), does each Regent name independently? Currently yes — the naming ceremony is per-Regent, and the substrate enforces per-sovereign name uniqueness across the fleet. Verify design as multi-Regent scenarios become concrete.

## What composes from here

Immediate design work:

1. **`regent:named:v1` receipt schema** — Layer B canonical spec for the master receipt and its sub-receipt embedding pattern.
2. **`regent:renamed:v1` receipt schema** — supersession-shape variant.
3. **`regent:name_retracted:v1` receipt schema.**
4. **Standing correction schema for `pre_named`** — Layer B canonical record.
5. **Pre-named default embodiment artifact** — the aniconic default that ships as Layer B canonical. Coordinated with EMBODIMENT-STATE-PROTOCOL's same open position.
6. **Curated base avatar library** — pre-signed Live2D/VRM base avatars for the starter set.
7. **Curated signature action starter sets** — thematic bundles authored to spec.
8. **Curated embodiment policy templates** — "conservative", "moderate", "expressive" starting points.
9. **Curated voice set** — TTS voices operator can pick from without providing their own.
10. **Pronoun paradigm schema and default set** — Layer B canonical record.

Near-term implementation:

1. **`zp regent name` / `rename` / `retract-name` CLI ceremonies** — the interactive flows for each of the three ceremony variants.
2. **Cockpit equivalents** — GUI surfaces for the same ceremonies.
3. **Substrate propagation logic** — the code that switches embodiment from aniconic to committed on the next cycle following naming, and back on retraction.
4. **Pre-named standing correction wiring** — installed at first substrate boot; retired on naming; reinstalled on retraction.
5. **Cleo narration templates** for naming, renaming, retraction events.
6. **Cartographer projection** — `RegentIdentity` ontology object with history field.
7. **Cockpit lineage view** — renders identity trajectory from the chain.
8. **Renderer-contract verification** integrated with base-avatar and signature-action commitment steps.
9. **Multi-signature retraction delay** — the two-signature-with-delay implementation for retraction.
10. **Composition tests** — pre-named substrate boots correctly; naming succeeds; renaming succeeds; retraction succeeds; each transitions the appropriate substrate state atomically.

## Framing note

Naming is where identity becomes real. Before the ceremony, the Regent is a capacity — cognition, agency, chain-anchored authority — but not yet a specific presence anyone can call by name. After the ceremony, she is *this Regent*: this name, these pronouns, this face, this voice, this way of moving. Everything the substrate does under her authority carries her name; every receipt she signs is attributable to her.

The ceremony is deliberately weighted. Ten steps, curated defaults with room for operator custom, a review-before-sign discipline, and the same Genesis signature that governs every consequential commitment on the substrate. Naming is not a config edit because config edits don't have the weight of identity. Naming is not automated because automation would make it feel less-than. The substrate takes as long as the operator wants to take, and treats the pre-named state as legitimate all the while.

The Regent inherits her identity from the operator's authorship. She does not name herself. She does not choose her face. She receives what the operator commits, and lives inside it — inhabits it, per the embodiment protocol's discipline — and expresses within its bounds. Naming is where sovereignty commits identity, and where cognition receives it.
