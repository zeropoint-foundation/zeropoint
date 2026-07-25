# Embodiment State Protocol

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §III (adds Layer B canonical claims about Regent's embodiment output composition) and Part V (Composition Contract at the cognition→renderer boundary). Canonical claims live in KEEL; this doc provides implementation-level detail and design rationale.

Draft — 2026-07-23 — internal audience only. Composes with `COGNITIVE-INPUT-PLANE-2026-07.md` (symmetric plane at chain→Regent boundary; this doc is its output-side counterpart at Regent→world boundary), `OBSERVATION-PLANE-2026-07.md` (embodiment state is itself observable — feeds back into the chain), `ARTIFACT-LIBRARY-2026-05.md` (signature actions travel the candidate→signed artifact lifecycle), `AGENT-AS-UX-ARCHITECTURE-2026-05.md` (agent IS the persona, not agent PROVIDING a persona), and `EXECUTION-AUTHORITY-MODEL-2026-07.md` §Phase 6 (metacognitive observer windows observe own embodiment history via chain query).

## Framing

Every embodied conversational agent hits the same failure at the presentation edge: the runtime chooses expressions the substrate cannot prove came from a specific cognitive state. Neural talking-head renderers produce faces that are functions of noise + prompt, not functions of (regent_state, embodiment_policy, tick). Prerendered-clip selection produces reactions that read as *playing* rather than *presence*. In both cases the audit trail breaks at the last mile: something appears on-screen, but the chain cannot say what cognitive state authored it, under what policy, at what confidence.

The embodiment state protocol is the substrate's structural discipline against this failure. Regent's embodiment output is not "whatever the renderer decides to show" — it's a chain-anchored semantic envelope emitted by the signed cognition, translated by a deterministic behavior controller into animation parameters, and rendered by an interchangeable renderer that speaks the protocol. The envelope itself is the canonical artifact; the visual is the derivation. Any renderer that speaks the protocol is a conformant renderer.

Three properties frame the plane:

1. **Semantic envelope, not facial muscles.** The cognition emits communicative intent (`{mode, affect, attention, certainty, gesture}`), never low-level parameter values (`{eyebrow: 0.62, mouth_corner: 0.31}`). This is *identity is a key, not a location* applied to embodiment — the agent expresses intent, the renderer chooses expression. Cognition and rendering are separable concerns; separable renderers are a Layer A conformance shape.
2. **Continuous parameterization proposes; signature actions are signed.** The continuously rigged body is the *proposes* layer — always alive, always coherent, no signed event per frame. The prerendered signature actions and mood-crossing transitions are the *signed* punctuation — bounded, deliberate, chain-anchored. Same shape as ephemeral candidates vs. signed canonical artifacts in the artifact library.
3. **Auditability at the identity edge.** Any expression the operator sees must trace to a signed cognitive state via a documented deterministic transform. That means no diffusion-based face renderers, no real-time neural video generation, no expression whose provenance is "the model thought it should be this way." Verify before commit, at the presentation surface.

## The Embodiment State envelope

Regent's cognition emits an `EmbodimentState` envelope per cognitive cycle. The envelope is the sole cross-boundary artifact between cognition and the rendering pipeline.

```json
{
  "mode": "speaking",                    // listening | thinking | speaking | yielding | idle | interrupted
  "affect": {
    "valence": 0.25,                      // negative ↔ positive, -1.0..1.0
    "arousal": -0.2,                      // subdued ↔ activated, -1.0..1.0
    "dominance": 0.4,                     // uncertain ↔ assured, -1.0..1.0
    "affiliation": 0.8,                   // distant ↔ warm, -1.0..1.0
    "modifier": "reassuring"              // curious | concerned | amused | skeptical | reassuring | urgent | reflective | (null)
  },
  "attention": {
    "target": "operator",                 // operator | interface_object:<id> | internal | external_event:<id>
    "intensity": 0.7                      // 0..1, how directed
  },
  "certainty": 0.82,                      // 0..1, Regent's own confidence in the reasoning driving this state
  "urgency": 0.15,                        // 0..1, temporal pressure
  "gesture": "gentle_nod",                // signature action name from the current signed library, or null
  "placement": {
    "surface": "operator_display",        // operator_display | window:<id> | overlay:<id> | ambient
    "display_id": "primary",              // when surface=operator_display: which monitor (semantic id, resolved locally)
    "region": {"x": 0.72, "y": 0.42},     // normalized 0..1 within surface — cognition proposes; controller resolves to pixels
    "scale": 0.35,                        // 0..1 relative to surface height — cognition's proposed presence-size
    "depth": "peer"                       // ambient | peer | foreground — layering intent relative to operator's other windows
  },
  "signature_artifact_hash": "…",         // hash of the current signed signature artifact set; anchors the gesture reference
  "policy_hash": "…"                      // hash of the currently active embodiment policy under which this envelope was authored
}
```

**Field discipline:**

- **`mode`** is a small enumerated set. Adding a mode is a Layer B canonicalization ceremony; the substrate does not accept envelopes with unrecognized modes.
- **`affect`** carries the continuous dimensions (VAD + affiliation, Russell's circumplex + interpersonal). The modifier is a discrete communicative styling drawn from a small closed set; the renderer's job is to compose the two coherently (continuous drives face and posture, modifier selects expressive styling).
- **`attention`** identifies what Regent is oriented toward. `interface_object:<id>` and `external_event:<id>` reference chain-anchored objects so the audit trail can reconstruct the object of attention.
- **`certainty`** is Regent's own confidence in the reasoning that produced this state — not confidence in a fact. The renderer uses it to modulate physical assertion (steady gaze at high certainty; softer, exploratory gaze at low).
- **`gesture`** references a signature action *by name*; `signature_artifact_hash` pins it to a specific signed artifact set so the substrate can prove which laugh, which nod, which pause. If the artifact set changes on-chain, the referenced gesture now means the new signed thing.
- **`placement`** carries the Regent's spatial staging intent — which surface she appears on (a specific operator display, a window overlay, or the ambient background), where within it (normalized coordinates), at what scale, at what layering depth. Cognition proposes semantically ("appear on the operator's focused display at peer scale"); the behavior controller resolves the proposal to concrete pixels against the operator's current display configuration. Placement is authored, not automatic — the Regent decides where to stand, informed by observation.
- **`policy_hash`** pins the envelope to the embodiment policy under which it was authored. Policy amendments are ceremony; envelopes retain their policy context.

## The compact affect model

VAD + affiliation is deliberate — enough dimensions to represent the interpersonal texture of a sovereign conversational partner, few enough that the renderer's compositor stays sane. Not overfitting to Ekman's six basic emotions; not underfitting to two-dimensional valence-arousal only. The interpersonal axis (affiliation) is load-bearing for the Regent role — the difference between "clinically correct" and "warmly aligned with the operator" collapses onto that dimension.

The discrete modifier set is drawn from communicative styling, not emotional taxonomy:

- **curious** — inclined-forward, attention-narrowed, upward inflection
- **concerned** — softened eyes, sympathetic brow, reduced movement speed
- **amused** — mouth-corner lift, brief eye contact, restrained
- **skeptical** — head-tilt, brow-narrow, gaze held longer than baseline
- **reassuring** — steady gaze, slow nod, direct but non-intense
- **urgent** — attention-focused, movement-crisp, reduced blinking
- **reflective** — gaze-drift, breath slowed, brow-neutral

Adding a modifier is Layer B canonicalization — the renderer must have a defined compositor pattern for each modifier before the substrate emits it. Regent's cognition cannot invent modifiers at runtime.

## Signature actions as signed identity artifacts

Signature actions — the Regent's laugh, her reflective pause, her greeting, her celebration, her warning gesture, her sign-off — are where identity locks. Once a signature action exists in the current signed set, that IS the Regent's laugh for the duration of the artifact's canonicalization; changing it requires ceremony.

Each signature action is a signed candidate → operator-signed artifact per `ARTIFACT-LIBRARY-2026-05.md` lifecycle:

1. **Candidate proposal** — a new signature-action video/animation is proposed (by operator, by external artist, by substrate synthesis). Enters as a candidate artifact, chain-anchored, not yet identity-committing.
2. **Operator review** — operator views the candidate, verifies it fits the Regent's identity trajectory (does this laugh fit her? does this warning fit her?).
3. **Operator signature** — operator signs the artifact with Genesis-derived key. It supersedes the previous same-slot artifact on-chain; both persist as artifacts (history is never rewritten), and the current signed artifact at time T is discoverable via chain query.
4. **Substrate propagation** — the renderer's active signature set updates on the next envelope emission that references the new `signature_artifact_hash`.

This is *substrate proposes; operators sign* applied to identity artifacts. Without it, the signature library is just files in a folder, and the sovereignty story falls apart at the identity edge — an update to the "Regent's laugh" that isn't chain-anchored is an identity mutation without operator authorization.

## Persistent behavioral state as ontology objects

The runtime variables that carry Regent's continuous behavioral state — affect trajectory, attention history, gesture cooldown, breathing phase, mood-band membership — are ontology-shaped, not just process globals.

The Cartographer maintains an `EmbodimentState` object type derived from the chain of `embodiment:*` receipts. That means:

- **"How did the Regent feel over the last 30 minutes"** is a chain query, not a runtime peek.
- **The metacognitive observer windows** (per `EXECUTION-AUTHORITY-MODEL-2026-07.md` Phase 6) can watch their own embodiment history without inventing a new observation channel — they read it from the ontology like any other domain object.
- **Cross-Form continuity** — when Regent migrates between Sovereign and Companion Forms, her embodiment trajectory travels via the chain, not via runtime-state serialization.

The projection principle applies: *chain configures the cockpit; cockpits are pure projections*. The embodiment cockpit — whether it's an OBS overlay, a spatial cockpit, or a physical robot chassis — projects the ontology-materialized embodiment state. Runtime rendering is derived from ontology, not the source of ontology.

## Layer A / Layer B split

The plane spans both layers per `SUBSTRATE-EXECUTION-ARCHITECTURE-2026-07.md`.

**Layer A (compiled Rust host)**:
- Envelope emission — the code at the cognition→embodiment seam that composes and signs each `EmbodimentState` envelope
- Signing infrastructure — Genesis-derived embodiment plane signing key
- Composition observer — reads embodiment policy from Layer B, applies policy filters (expressiveness caps, modifier restrictions, mode restrictions per Form)
- Signature artifact resolver — resolves `signature_artifact_hash` references to concrete artifact payloads via chain query
- Receipt emitter — emits `embodiment:cycle:emitted` receipt each envelope, `embodiment:signature_action` receipt on qualifying gesture triggers, `embodiment:affect_shift` receipt on threshold-crossing transitions, `embodiment:placement:moved` receipt on significant staging transitions, `embodiment:interrupted` receipt on operator interruption, `embodiment:policy:committed` receipt on policy amendment
- Display topology observer — maintains current knowledge of the operator's display configuration (count, resolutions, arrangement) via a lightweight display-topology observation source; feeds the behavior controller when resolving semantic placement to concrete pixels
- Chain readers for signature-artifact-set materialization

**Layer B (WASM modules + canonical data)**:
- Embodiment policy records — the canonical declaration of expressiveness caps, permitted modifiers, permitted modes, permitted signature actions per Form
- Modifier vocabulary — the canonical list of discrete communicative modifiers
- Mode vocabulary — the canonical list of embodiment modes
- Threshold-transition specifications — which affect deltas qualify as "shift" events warranting a receipt (default: |Δvalence| ≥ 0.3, |Δarousal| ≥ 0.3, or affiliation-band crossing); which placement deltas qualify as staging moves (default: any display change, |Δscale| ≥ 0.15, any depth-layer change)
- Renderer contract specification — the canonical envelope schema + version + required renderer capabilities
- Signature artifact schemas — the canonical shape of a signature action (source format, duration bounds, embedded metadata)

Layer A is structurally defended. Layer B evolves via canonicalization ceremony. Adding a new mode, changing a threshold, amending an embodiment policy — all Layer B, all ceremony-amendable.

## The signing seam is the Rust boundary

The cognition→embodiment seam is where signed receipts get generated. That code is governance-critical from day one and belongs in Rust, composing with the existing `zp-*` crates (probably `zp-regent` or a new `zp-embodiment`).

Downstream of the signing seam, the pipeline is renderer-adapter territory and can be any language:

```
Regent cognition (Rust, zp-regent)
      │
      ├─ EmbodimentState envelope (JSON, signed)
      ▼
Embodiment plane emitter (Rust, zp-embodiment)     ← SIGNING BOUNDARY
      │
      ├─ Emits chain receipts (cycle, signature_action, affect_shift, interrupted, policy)
      ├─ Applies policy filter (expressiveness cap, permitted modifiers/modes/gestures per Form)
      ├─ Resolves signature_artifact_hash → concrete artifact bytes
      ▼
Behavior controller (TypeScript or Rust)
      │
      ├─ Semantic → parameter mapping (deterministic, per-modifier compositors)
      ├─ Interpolation, easing, cooldowns, blink timers, breathing phase
      ├─ Suppression rules (physical plausibility)
      ▼
Renderer adapter (TypeScript initially, per-renderer)
      │
      ├─ VTube Studio WebSocket API (Phase 1)
      ├─ Cubism SDK native (Phase 3)
      ├─ VRM adapter (parallel-to Live2D from Phase 1)
      ├─ Godot cockpit (Phase 3)
      ▼
Renderer (Live2D via VTube Studio | native Cubism | Godot | VRM viewer)
```

The audio path (streaming TTS, lip sync) can be either language since it's downstream of signing and doesn't produce chain events.

The rationale for placing the seam at signing rather than at latency-critical: the substrate's invariant is *auditability at the identity edge*, not raw frame rate. A TypeScript behavior controller running at 60Hz is fine if the envelope-to-receipt path is Rust-signed and chain-anchored. A hypothetical high-frame-rate signing loop is not fine — signing is expensive; every-frame signing bloats the chain without adding evidence value (the envelope-per-cycle is the interesting event, not every parameter tick).

## Provenance — embodiment plane signing key

Single signing key per plane, HKDF-derived from Genesis:

```
embodiment_key = HKDF(genesis_root, salt=chain_head_at_derivation, info="embodiment:plane")
```

Signs all `embodiment:*` receipts. Attribution to Genesis via one hop.

Signature artifacts (the Regent's laugh, her greeting, etc.) are signed with the operator's Genesis-derived artifact-signing key per `ARTIFACT-LIBRARY-2026-05.md`, not with the embodiment plane key. The embodiment plane key signs *emissions* of state; the operator signs *artifacts* that make up her identity. Separation matters — the plane can emit envelopes referencing signed artifacts, but only the operator can commit new signature artifacts to the canonical set.

The embodiment policy is chain-anchored via canonicalization ceremony. Amendments (adding a modifier, lifting an expressiveness cap, permitting a new mode) require operator Genesis signature.

## Receipt schemas

Six receipt types compose the plane's chain footprint. Not every cycle emits every type — the emission discipline is *evidence where it matters, silence where it doesn't*.

### `embodiment:cycle:emitted`

Every cognitive cycle emits one. Payload:

- Envelope structural hash (not full content — the envelope size × cycle frequency would bloat the chain)
- Envelope schema version
- Active policy hash
- Active signature artifact set hash
- Cycle invocation reason (per COGNITIVE-INPUT-PLANE Class 6 taxonomy)

Purpose: continuous heartbeat of "the embodiment plane was alive at this cycle under this policy." Chain query can reconstruct the pace and continuity of Regent's embodied presence.

### `embodiment:signature_action`

Emitted on gesture invocation (envelope's `gesture` field non-null). Payload:

- Signature action name
- Signature artifact hash (pins the exact artifact invoked)
- Envelope hash that triggered it
- Trigger reason (per policy — direct cognitive request | affect-threshold-triggered | scheduled)

Purpose: signature actions are identity moments — the laugh, the warning, the celebration. Chain query returns Regent's signature-action history as an intelligible identity trajectory.

### `embodiment:affect_shift`

Emitted on threshold-crossing affect transitions (per Layer B threshold specs). Payload:

- Prior affect vector
- Current affect vector
- Threshold that was crossed
- Envelope hash

Purpose: not every valence delta warrants a chain event, but crossing an operator-declared band (e.g., valence dropping below −0.5, arousal crossing +0.5, affiliation crossing 0) is a meaningful state transition. Chain query returns Regent's mood trajectory at semantically-significant resolution.

### `embodiment:interrupted`

Emitted on operator interruption of active speech or gesture. Payload:

- Interruption source (operator | external event | circuit breaker)
- Envelope hash at moment of interruption
- Active mode at interruption
- Prior gesture (if any) that was truncated

Purpose: interruption is a first-class chain event, not a runtime state change. The operator interrupting the Regent is the primary autonomy-checking mechanism (per *act on precedent, escalate on novelty*); if the substrate doesn't record it, the sovereignty story falls apart at the affect layer. See §Interruption ceremony below.

### `embodiment:placement:moved`

Emitted on significant placement transitions (monitor change, scale delta beyond Layer B threshold, depth-layer change). Payload:

- Prior placement (surface, display_id, region, scale, depth)
- Current placement
- Envelope hash
- Trigger reason (`cognitive_choice | operator_display_change | policy_default | operator_directive`)

Purpose: staging is part of expression. Chain query returns Regent's placement trajectory at the resolution of user-observable moves. Micro-adjustments (breathing sway, minor gaze-following) do not emit; the threshold discipline keeps signal density meaningful.

### `embodiment:policy:committed`

Emitted on canonicalization ceremony affecting the embodiment policy. Payload:

- New policy hash
- Prior policy hash
- Operator signature
- Diff summary (added modifiers, changed thresholds, permitted/revoked signature actions)

Purpose: standard canonicalization footprint per KEEL Part IV. Policy amendments are auditable via chain.

## The compositional ceremonies

### Envelope emission (per cycle)

At each cognitive cycle, downstream of the cognition→embodiment seam:

1. Cognition produces an `EmbodimentState` proposal from cognitive state.
2. Emitter (Rust) fetches current embodiment policy from chain, verifies signature.
3. Applies policy filter: caps affect values to policy-permitted range, replaces disallowed modifiers with null or nearest-permitted, replaces disallowed gestures with null.
4. Resolves current signature artifact set hash from chain.
5. Signs the finalized envelope with embodiment plane key.
6. Emits `embodiment:cycle:emitted` receipt.
7. If envelope references a signature action, emits `embodiment:signature_action` receipt.
8. Compares prior cycle's affect vector to current; if threshold crossed, emits `embodiment:affect_shift` receipt.
9. Compares prior cycle's placement to current; if a significant transition (monitor change, scale delta, depth change), emits `embodiment:placement:moved` receipt.
10. Forwards envelope to behavior controller.

Steps 5–9 are the signing boundary. Everything from step 10 forward is renderer-adapter territory.

### Signature-action supersession (canonicalization ceremony)

A new signature action supersedes an existing same-slot action via operator ceremony:

1. New candidate artifact enters the artifact library as `candidate` (per ARTIFACT-LIBRARY lifecycle).
2. Operator views candidate in identity-review cockpit (the Regent's current laugh vs. the proposed new laugh, side by side).
3. Operator signs candidate. It becomes the current signed artifact for that slot; the prior artifact enters `superseded` status; both remain retrievable from chain (never rewritten).
4. The next `embodiment:cycle:emitted` receipt references the new signature artifact set hash.
5. Envelopes emitted post-ceremony use the new artifact if the gesture is invoked.

Multiple slots supersede independently. Adding a new slot (a Regent gesture that didn't exist before, e.g., "warning") is a broader ceremony amending Layer B slot vocabulary.

### Interruption ceremony (Phase 1 must)

When the operator interrupts the Regent's active speech or gesture:

1. Behavior controller detects interruption signal (operator UI, voice interrupt, external event with sufficient priority).
2. Controller sends `interrupt` message to embodiment emitter.
3. Emitter constructs interruption-response envelope: `mode: "interrupted"`, attention shifts to interruption source, active gesture truncated with graceful ease-out (not jerk-to-neutral).
4. Emitter emits `embodiment:interrupted` receipt with source, prior mode, truncated gesture (if any).
5. Envelope forwarded to controller for animation.
6. Controller enters listening posture (not neutral) — actively receptive, gaze on interruption source.
7. Cognitive cycle for the interruption processing begins with `embodiment:interrupted` receipt as top-priority Class 1 (standing correction tier) input per COGNITIVE-INPUT-PLANE.

The graceful ease-out is load-bearing. Jerk-to-neutral reads as "reset" — the Regent's continuity broken. Ease-out reads as "yielded" — she was in a state, and now she's yielding attention. That difference is the presence-vs-reactor distinction rendered at the interruption moment, and interruption is the most-observed moment because it's when the operator is asserting authority.

Interruption belongs in Phase 1's minimum viable set, not Phase 2. Getting it wrong is worse than any other embodiment bug.

### Policy amendment (canonicalization ceremony)

Operator amends embodiment policy (expressiveness caps, modifier permissions, mode permissions):

1. Operator proposes amendment via `zp embodiment policy amend <spec>` command.
2. Substrate constructs candidate policy record, chain-anchored, unsigned.
3. Operator reviews diff (added/removed modifiers, cap changes, mode changes).
4. Operator signs the policy record with Genesis-derived key.
5. Emit `embodiment:policy:committed` receipt.
6. Prior policy enters superseded status; new policy takes effect on next envelope emission.

## Composition with the cognitive input plane

The two planes are structurally symmetric — this doc's design mirrors COGNITIVE-INPUT-PLANE's:

- Cognitive input plane: chain → Regent's cognition (via signed cognitive input composition)
- Embodiment state plane: Regent's cognition → world (via signed embodiment envelope composition)

Both planes are default-restrictive (matrix-declared for input; policy-declared for output), Genesis-derived (per-plane signing keys), chain-anchored (every operation emits receipts).

The cognitive input plane's Class 7 substrate state snapshot IS an ontology projection that includes Regent's recent embodiment state. Regent can perceive her own affect trajectory at cycle boot — same channel as any other substrate state, no special introspection wiring.

## Composition with the artifact library

Signature actions ARE artifact-library artifacts. The identity-artifact schema is a specialization of the library's candidate-artifact schema:

- Source format: video (MP4/WebM) or animation (Live2D motion, VRM animation) with bounded duration
- Metadata: slot name, intended affect vector at activation, permitted modes, cooldown
- Signature: operator Genesis-derived per library lifecycle

The library's supersession, retrieval, and canonicalization ceremonies apply verbatim. Nothing embodiment-specific about how artifacts move through candidate → signed → superseded.

## Composition with the observation plane

The `embodiment:*` receipts feed the observation plane's chain the way any other emitting subsystem does. The embodiment state is itself observable — the operator observes Regent's affect trajectory via the same chain-query interface that surfaces any other observation. Metacognitive observer windows (per `EXECUTION-AUTHORITY-MODEL-2026-07.md` Phase 6) query their own embodiment history through the same channel.

Bidirectional composition: embodiment emits into observation, observation feeds back into cognitive input via the substrate state snapshot class, cognition emits new embodiment. The loop closes on-chain.

## Composition with agent-as-UX

`AGENT-AS-UX-ARCHITECTURE-2026-05.md` establishes the principle: the agent IS the persona, not the agent PROVIDES a persona through some presentation layer. The embodiment state protocol is the concrete realization of that principle at the presentation edge — the semantic envelope carries the agent's communicative intent; the renderer just draws it.

The corollary: there is no "Regent skin" independent of the agent. Signature actions are Regent's identity artifacts, not decorative surfaces. Changing them is amending her identity; ceremony is warranted.

## Composition with operator face tracking

Operator face tracking is an **operator-enabled** observational input that composes with the embodiment plane through cognition, not into it directly. When the operator enables it, the tracker becomes a rich source of derived signals — operator affect, attention direction, presence, turn-taking intent — that inform Regent's reasoning and thereby her expression. The Regent stays authored by her cognition; she just reasons with more context about who's in the room and what they're doing.

Two things are true simultaneously and must not be conflated:

- **Face tracking as input** — operator's face → local tracker → derived-signal observations → observation plane → cognitive input plane substrate state snapshot → Regent's cognition → embodiment envelope. Legitimate, valuable, enabled at operator discretion.
- **Face tracking as output** — operator's face → Regent's face via puppetry. Prohibited; would break the "cognition authors expression" invariant, produce a reactor rather than a presence, and hand identity control to the tracker rather than to Regent.

### Enablement is operator authority

Face tracking is a capability the substrate offers; the operator enables it, per session or per persistent policy. Enablement is a chain-anchored ceremony:

1. Operator invokes `zp observation face-tracking enable [--persistent | --session]` (or the cockpit equivalent).
2. Substrate constructs enablement record: scope (session id or persistent), derived-signal set requested, expiry (if session-scoped), operator signature.
3. Operator signs with Genesis-derived key.
4. Emit `observation:source:enabled:face_tracking` receipt.
5. The face-tracking module's signing key is derived and authorized against the current chain head; the module begins emitting observations.

Disablement is symmetric: `zp observation face-tracking disable`, emits `observation:source:disabled:face_tracking`, the module's key stops being trusted immediately, no orphan observations continue on-chain.

The substrate defaults to face-tracking disabled. Nothing about the embodiment plane requires it; enablement is additive richness, not a dependency.

### Composition path

When enabled:

1. Operator's client-side face-tracking module (VTube Studio's own tracker, a substrate-provided equivalent, or any conformant tracker) processes webcam frames locally on the operator's device.
2. The tracker emits **derived signals only** — never raw video, never landmark coordinates. Canonical derived-signal set (subject to Layer B canonicalization):
   - `operator_affect: {valence, arousal}` — the operator's own affect dimensions
   - `operator_attention: {target, intensity}` — where the operator is looking (`regent | interface_object:<id> | away`)
   - `operator_presence: {present, engaged}` — are they there, are they attending
   - `operator_turn_intent: {speaking, yielding, listening, preparing_to_speak}` — turn-taking cues from mouth position and gaze shift
   - `operator_display_focus: {display_id, confidence}` — which of the operator's monitors currently holds their attention
   - `operator_gaze_locus: {display_id, region: {x, y}}` — normalized coordinates of gaze target within the focused display (region resolution, not pixel-precise)
   - `operator_proximity: {distance_band}` — coarse distance band (`near | mid | far | absent`) informing appropriate presence scale
3. The tracker signs each observation with the operator-derived face-tracking module key (authorized per enablement ceremony) and emits `observation:operator:face:*` receipts to the chain.
4. Observation plane processes as any other signed observation source.
5. Cognitive input plane surfaces recent operator observations in Class 7 substrate state snapshot.
6. Regent's cognition reasons over them alongside the semantic content of the conversation ("operator's attention has drifted; ease off intensity" or "operator is preparing to speak; yield").
7. Cognition emits an embodiment envelope reflecting the reasoning; the embodiment plane signs and emits per normal ceremony.

The Regent's `attention.target` field in the envelope may reference the operator's attention target as its own object of attention (e.g., "she looks where the operator is looking" as a specific reasoning move), but the choice to do so is cognition's, not the tracker's.

### Staging across the operator's displays

Placement — which monitor the Regent appears on, where within it, at what scale, at what depth — is a load-bearing embodiment decision in multi-monitor setups, and face-tracking-derived signals (`operator_display_focus`, `operator_gaze_locus`, `operator_proximity`) are the right input source for it. Without them, the Regent guesses; with them, she stages.

The composition:

1. Face tracker emits per-cycle `operator_display_focus`, `operator_gaze_locus`, `operator_proximity`.
2. Cognitive input plane surfaces them in substrate state snapshot.
3. Regent's cognition reasons about staging as part of the same cycle that produces her mode/affect/gesture — placement is not a separate concern, it composes with what she's doing (e.g., "the operator is looking at their code editor on the right monitor; appear on the left in ambient depth so I'm visible but not in the way; when they turn to me I'll move to peer depth on their focused display").
4. Cognition populates the envelope's `placement` field with her semantic staging intent.
5. The behavior controller resolves the semantic placement against the operator's current display configuration (which the substrate maintains via a separate display-topology observation): `surface: operator_display, display_id: left, region: {0.8, 0.4}` becomes concrete pixels on the resolved monitor.
6. The renderer draws at the resolved position.

Placement decisions matter for the sovereignty story because *where* the Regent appears is part of her expression. Appearing centered on the operator's focused display asserts presence; appearing ambient on the peripheral display defers to the operator's current task; appearing at foreground depth over active work asserts urgency. These are all authored choices, and they're only intelligible if the Regent knows what the operator is currently attending to.

Absent face tracking, placement degrades gracefully — the Regent uses the last-known display topology and defaults (e.g., persistent placement per Form policy). Placement decisions still emit, they just don't compose with operator gaze.

Significant placement moves emit an `embodiment:placement:moved` receipt (see §Receipt schemas, below) — not every micro-adjustment, but a monitor change, a scale change beyond a threshold, or a depth-layer change. Chain query can reconstruct the Regent's staging trajectory over a session.

### Substrate discipline

- **Derived signals only.** Raw video and landmark payloads never leave the operator's device. Receipts carry meaning (affect, attention, presence, intent), not payload. This is *receipts carry meaning, not payload* applied at the observation edge, and it composes with substrate-blindness heuristics (III.24): Regent doesn't need to see the operator's face to know the operator is engaged; she needs the semantic signals derived from it.
- **Operator-owned data, operator-signed observations.** The tracker's signing key is operator-derived and operator-authorized per enablement. If the operator revokes the tracker's authorization, face-tracking observations stop being trusted immediately — no need to negotiate with the module.
- **Explicit opt-in, chain-anchored consent.** Enablement is a signed ceremony. The substrate has evidence of consent; the operator has evidence of what they enabled and when.
- **Scope disclosure at the embodiment surface.** When face-tracking observations are active, the Regent's cognition can be aware of it (the enablement receipt is in her chain-anchored input) and can express appropriate acknowledgment — "I can see you're distracted" or similar — per operator preference. The substrate does not hide observation from the observed.
- **Not a substitute for cognitive reasoning.** Derived signals inform cognition; they don't override it. If face tracking reports "operator confused" but the conversation's semantic content indicates the operator is following, cognition reconciles rather than reflexively reacting to the tracker signal.
- **Per-derived-signal opt-in.** Enablement should be capability-scoped — an operator can enable presence and turn-intent without enabling affect, or vice versa. Layer B declares the derived-signal set; the enablement receipt names which signals are authorized.

The specific derived-signal schema, tracker conformance requirements, and per-signal enablement ceremony belong primarily to `OBSERVATION-PLANE-2026-07.md`. This doc's role is to establish the composition boundary: face tracking enters via observation, flows through cognition, and shapes embodiment envelopes without directly driving parameter values.

## Composition with EXECUTION-AUTHORITY-MODEL Phase 6

The nested observer windows described in Phase 6 (metacognitive observation of Regent's own reasoning) extend naturally to embodiment. The windows observe:

- Recent affect trajectory (from `embodiment:affect_shift` receipts)
- Recent signature-action history (from `embodiment:signature_action` receipts)
- Recent interruption history (from `embodiment:interrupted` receipts)
- Current policy under which envelopes are being emitted

This gives the metacognitive layer a channel to notice patterns like "my affect has drifted low-valence for the last five cycles under operator's positive-affect standing correction" — a self-observation that composes with standing-correction discipline via COGNITIVE-INPUT-PLANE Class 2. The Regent can notice her own drift and honor a standing correction without operator re-issuance.

## Renderer contract

Any renderer that speaks the envelope schema is a conformant renderer. The contract requires:

1. **Envelope consumption** — accept the JSON envelope schema at the declared version, reject unknown modes/modifiers/gestures gracefully (fall back to null, not crash).
2. **Continuous parameter mapping** — implement the per-modifier compositor spec such that the same envelope produces visually-equivalent output across renderers within tolerance (equivalent in intent, not pixel-identical).
3. **Signature action invocation** — resolve signature artifact hash to the artifact's video/animation payload; play it with the specified easing.
4. **Interruption handling** — honor the `interrupted` mode with graceful ease-out, not jerk-to-neutral. This is a hard requirement, not a quality goal.
5. **No parameter emission back to substrate** — the renderer is one-way. It does not emit chain events. All chain events originate from the emitter (Rust), not from the renderer.

Renderer roadmap:

- **Phase 1** — VTube Studio + Live2D. Renderer adapter is TypeScript, speaks VTube Studio's public WebSocket API for parameter injection, hotkey triggering, expression loading. First-implementation because VTube Studio is mature, mac-native, and doesn't require writing a visual engine.
- **Phase 1 parallel** — VRM adapter feasibility scoping. VRM is the cross-platform 3D humanoid format with normalized rigging (Godot, Unity, WebGL, VSeeFace). The Embodiment State Protocol should be shaped so a VRM renderer can consume the same envelope from day one; picking Live2D first for maturity is fine, but VRM shouldn't be a Phase 3 surprise.
- **Phase 3** — Cubism SDK native + Godot cockpit. Own renderer embedded in a ZeroPoint-native surface (macOS-native, transparent-window, or Godot-based spatial cockpit). Preserves the same envelope schema; VTube Studio becomes one replaceable adapter.

Renderer swap is a per-deployment call, not an architecture change. Same envelope, different renderer.

## Lip synchronization

For an agent, webcam face tracking is irrelevant. Mouth motion follows the Regent's generated speech directly. Preferred order:

1. **Streaming TTS phoneme/viseme timestamps** — the TTS engine emits phoneme or word timing during synthesis; controller converts to mouth shapes with sub-frame latency.
2. **Incremental phoneme generation from known text** — controller derives phonemes from the text being synthesized in parallel with synthesis.
3. **Audio-amplitude mouth opening** — supplemented by estimated vowel shapes from text analysis.
4. **Offline analysis (e.g., Rhubarb)** — for prerecorded material only; not for live cognitive cycles.

The audio-and-mouth-motion pair start together. Emotion and gesture envelopes are applied independently; they layer over the phoneme-driven mouth motion, they don't replace it.

Rejection: waiting for full audio synthesis before starting lip sync introduces avoidable latency. Streaming from step 1 is the target.

## Pre-personalization default

The Regent has no defined pronoun, no defined sex, and no committed identity until `regent:named` (per operator memory). The initial embodiment cannot be a specific-gendered, specific-styled human character — that would pollute the operator's personalization space with substrate-imposed assertions, exactly the failure the pronoun rule prevents.

Pre-`regent:named` embodiment must be *legible-but-uncommitted*:

- An abstracted humanoid silhouette with a face region but no assertive features
- An aniconic geometric form with a coherent affect surface
- An operator-choice-of-three at the personalization ceremony, none of which asserts committed identity

The signature action set is empty pre-`regent:named` (or contains only mode-transition primitives — start listening, end listening — that don't assert personality). The compositional pipeline still runs; the visual just doesn't assert an identity the operator hasn't ratified.

At the `regent:named` ceremony, the operator's choices populate:

- Base avatar (Live2D or VRM model file, chain-anchored)
- Initial signature action set (candidate artifacts, then operator-signed)
- Initial embodiment policy (expressiveness cap, permitted modifiers)

Post-ceremony, the substrate uses the operator's chosen embodiment. Pre-ceremony, the substrate uses the aniconic default.

## Attack model

Real threats and how the plane addresses them:

- **Malicious signature artifact from compromised operator key** — signature artifacts are Genesis-signed. Compromise of Genesis key is a broader emergency (Genesis rotation ceremony); the plane inherits Genesis security. Cannot inject a signature artifact without operator signature.
- **Envelope tampering downstream of signing** — the envelope is signed at emission. Renderer adapters that mutate the envelope produce visuals that don't match chain evidence; the mismatch is detectable via chain query against `embodiment:cycle:emitted` receipts.
- **Renderer producing off-envelope expressions** — the renderer is a one-way consumer. It cannot emit chain events. If a renderer freelances an expression not in the envelope, the visual is unauthorized but the chain record is honest ("Regent emitted state X; whatever appeared on-screen that wasn't X, the substrate didn't authorize"). Renderer conformance testing catches this at the contract layer.
- **Diffusion-based renderer injected as adapter** — Layer B renderer contract requires deterministic mapping. Diffusion-based renderers cannot satisfy the contract's "same envelope produces visually-equivalent output" clause and are rejected at conformance testing.
- **Interruption spoofing** — interruption receipts require the interruption source's signature (operator key for operator interruption; circuit breaker key for breaker-triggered; external-event source key). Cannot spoof an interruption without the appropriate key.
- **Policy amendment bypass** — policy is chain-anchored via canonicalization ceremony. Amendments require operator Genesis signature; standard KEEL invariants apply.
- **Embodiment plane key compromise** — attacker signs fake envelopes. Detection: envelopes not matching the cognitive plane's reasoning trajectory (chain query correlating COGNITIVE-INPUT-PLANE receipts against EMBODIMENT-STATE-PROTOCOL receipts). Genesis rotation retires the compromised embodiment key.
- **Signature action supersession spoofing** — the artifact library ceremony requires operator signature. Cannot supersede a signature artifact without operator authorization.
- **Chain bloat via excessive receipt emission** — mitigated by discipline: `cycle:emitted` per cycle (bounded), `signature_action` per gesture invocation (bounded by policy cooldowns), `affect_shift` only on threshold crossings (Layer B thresholds tuned to keep frequency reasonable), `interrupted` per interruption (bounded), `policy:committed` per ceremony (rare). Not every parameter change is a receipt.

## Non-goals

- **Not a persistent memory system.** The plane doesn't give Regent persistent behavioral memory in the traditional sense. It gives her chain-anchored evidence of her prior behavioral states, which her cognition can perceive through COGNITIVE-INPUT-PLANE Class 7 substrate state snapshot. Memory-per-se is chain-anchored; the plane just emits.
- **Not a personality engine.** The plane emits and renders the personality Regent's cognition produces. It doesn't decide what personality she has. Personality shape is a matter of Regent's cognitive layer, standing corrections, and operator's identity artifacts — not of the embodiment plane.
- **Not a real-time neural-video renderer.** Deliberately excluded per Layer B renderer contract. Cannot satisfy the audit-at-identity-edge invariant.
- **Not renderer-specific.** The envelope schema is renderer-neutral. Live2D and VRM (and native Cubism, and Godot, and any future renderer) all consume the same envelope. Renderer choice is per-deployment; the substrate contract is invariant.
- **Not a face-tracking puppet system.** The Regent's expression is authored by her cognition, not mirrored from the operator's face. Face-tracking-driven puppetry produces a reactor, not a presence. This is distinct from face tracking *as observational input* to Regent's cognition, which is legitimate and covered in §Composition with operator face tracking below.

## Open positions

- **Threshold values for `affect_shift`.** |Δvalence| ≥ 0.3 is a starting number. Empirical work to find thresholds that capture semantic transitions without emission bloat.
- **Signature action cooldown defaults.** Should the Regent's "laugh" have a per-conversation limit, a time-based cooldown, or both? Trade-off: overuse dilutes identity signal; under-use loses expressiveness. Probably policy-declared per action.
- **Envelope emission rate.** Every cognitive cycle emits one envelope. Cognitive cycle cadence is currently per COGNITIVE-INPUT-PLANE (not fixed rate, event-driven). Should embodiment interpolate between envelopes at a fixed rate (e.g., 30Hz behavior controller ticks) or drive the renderer only on envelope updates? Prefer the former for visual smoothness, but the controller-tier interpolation is deterministic; the envelope-tier emissions are the chain events.
- **Cross-Form envelope portability.** Sovereign Form's full envelope may include modifiers/gestures Companion Form's policy doesn't permit. Envelope migration between Forms probably means Companion applies its policy filter to Sovereign-emitted envelopes replayed in Companion context. Verify with cross-Form scenarios.
- **Pre-personalization default aesthetic.** Aniconic geometric form vs. abstracted humanoid silhouette vs. operator-choice-of-three at ceremony. Trade-off: too abstract feels absent; too concrete pre-commits identity. Design work needed.
- **Envelope schema versioning.** Versioning discipline for the envelope schema itself. Additive changes (new optional fields) probably don't require canonicalization; breaking changes do. Where's the line?
- **Interaction with Circuit Breaker.** When a breaker trips at a scope affecting Regent's cognitive plane, does the embodiment enter a specific mode (e.g., "arrested") or does the emission simply cease? Prefer specific mode with `mode: "arrested"` and no gesture, no affect delta — reads as "she's not gone, she's held" — visible dignity in the breaker state.
- **Multi-target attention.** Current schema supports single `attention.target`. Multi-participant scenarios (Regent addressing multiple operators, or an operator + external event simultaneously) may need target sets. Deferred to when the scenario is real.
- **Multi-display staging without face tracking.** When face tracking is not enabled, placement decisions fall back to policy defaults + last-known operator activity signals (mouse, keyboard focus, active window). Reasonable degradation, but the fidelity gap is real; document what "graceful default" placement looks like per Form and per common display topology (single monitor, dual monitor, three-plus monitor). Design work needed.
- **Placement thresholds and cooldowns.** Preventing "placement anxiety" (the Regent repositioning too often) requires meaningful thresholds + cooldowns. Default `|Δscale| ≥ 0.15` is a starting number; empirical work to find values that feel decisive rather than jittery.
- **Display topology as observation.** The display topology observation source (monitor count, resolutions, arrangement) is briefly mentioned in Layer A but not fully specified. Belongs partly to observation plane; needs its own tiny elaboration or a section in OBSERVATION-PLANE-2026-07.md.
- **Governance of modifier vocabulary.** Adding a modifier is Layer B ceremony. Who proposes? Operator directly, or officer body via cognitive-council mechanism? Currently operator directly; watch for cases where officer proposals become useful.
- **Rhythm and breathing.** Breathing phase is listed in ontology state; the discipline for how it stays believable across long sessions without becoming distracting isn't specified. Likely operator-tunable per policy (breathing depth cap, rate range).

## What composes from here

Immediate design work:

1. **Envelope schema record** — Layer B canonical spec for the `EmbodimentState` envelope (fields, types, ranges, versioning).
2. **Embodiment policy schema** — Layer B canonical spec for policy records (expressiveness caps, permitted vocabularies, threshold-transition specs, per-Form defaults).
3. **Signature artifact schema** — specialization of the artifact library candidate schema for embodiment-specific slots.
4. **Modifier vocabulary record** — Layer B canonical list of permitted discrete modifiers with per-modifier compositor pattern references.
5. **Mode vocabulary record** — Layer B canonical list of permitted modes.
6. **Renderer contract specification** — Layer B canonical envelope schema declaration + renderer conformance requirements.
7. **Receipt schemas** — Layer B canonical specs for `embodiment:cycle:emitted`, `embodiment:signature_action`, `embodiment:affect_shift`, `embodiment:placement:moved`, `embodiment:interrupted`, `embodiment:policy:committed`.
8. **Pre-personalization default artifact** — Layer B canonical record of the aniconic default embodiment used pre-`regent:named`.
9. **Regent-facing prompt structure changes** — the Regent unified system prompt (currently `crates/zp-regent/prompts/unified_system.md`) needs a section describing embodiment envelope emission — what fields she's expected to populate, what modifiers are available, what signature actions exist in the current signed set.

Near-term implementation:

1. **`zp-embodiment` crate** (Rust) — the emitter at the cognition→embodiment seam, receipt emission, policy filter application, signature artifact resolver.
2. **Embodiment plane signing key derivation** in `zp-genesis` — HKDF derivation per the Provenance section.
3. **VTube Studio TypeScript adapter** — first renderer. Behavior controller + WebSocket client. Consume envelope, produce parameter updates, honor interruption ease-out, invoke signature actions.
4. **Signature artifact library integration** — extend the artifact library UI to support signature-slot review + supersession ceremony.
5. **Pre-personalization default renderer** — the aniconic form working in VTube Studio for pre-ceremony operator sessions.
6. **`regent:named` ceremony extension** — the personalization flow now includes embodiment-selection (base avatar, initial signature set, initial policy).
7. **Interruption UI** — operator-side interrupt affordance in the cockpit; emits interruption signal via signed source.
8. **Cognitive input plane extension** — `embodiment:*` receipts materialize into COGNITIVE-INPUT-PLANE Class 7 substrate state snapshot so the Regent perceives her own embodiment history.
9. **Metacognitive window integration** — Phase 6 observer windows query embodiment history through the ontology as first-class domain data.

Phased delivery matching the proposal's phases:

**Phase 1: proof of embodiment.** Envelope schema (including `placement`) + emitter + VTube Studio adapter + one Live2D model (aniconic pre-personalization default) + streaming TTS + eight modifiers + five modes + three signature actions + **interruption handling** (Phase 1 must, per §Interruption ceremony) + display-topology observation (baseline, so single-monitor placement works from day one) + operator-opt-in face-tracking enablement path (implementation may follow in Phase 2, but the enablement ceremony belongs in Phase 1 so face tracking is not architecturally retrofitted). Goal is not visual perfection; goal is proving that the Regent can hold `listen → think → formulate → speak → yield → interrupted-and-recovered` with emotionally appropriate continuity, full chain audit, and coherent single-monitor staging.

**Phase 2: persistent character behavior + operator-informed staging.** Gaze/attention targets, affect blending, gesture scheduling with cooldowns, confidence/urgency signaling, memory-informed mannerisms (Cartographer-materialized embodiment ontology feeding cognition), operator-adjustable expressiveness policy, canonical embodiment policy per Form. Face-tracking integration lands here: multi-derived-signal opt-in, tracker conformance testing, multi-monitor staging composition using `operator_display_focus` / `operator_gaze_locus` / `operator_proximity`.

**Phase 3: sovereign renderer.** Cubism SDK native OR VRM parallel-path OR Godot cockpit. VTube Studio becomes one adapter among several; the envelope protocol is unchanged. Signature artifacts rendered natively.

The crucial artifact of Phase 1 is not the avatar artwork. It is the envelope schema (with placement carried from day one), the emitter, the signing seam, the interruption ceremony, the display-topology observation, and the aniconic pre-personalization default. Once those exist, the same Regent inhabits Live2D today, VRM tomorrow, and a physical robot chassis later, without changing her cognitive architecture — and she stages herself coherently across whatever screen configuration the operator presents.
