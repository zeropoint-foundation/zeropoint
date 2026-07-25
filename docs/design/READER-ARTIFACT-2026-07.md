# READER-ARTIFACT-2026-07

**Status:** draft. Candidate for ontology.
**Predecessor:** none — new artifact class.
**Depends on:** ONTOLOGY-AND-CARTOGRAPHER, SUPERSESSION-FRAMEWORK, MEDIA-PROVENANCE, LICENSING-AND-INTEGRITY, DISTRIBUTED-KNOWLEDGE-COMMONS, COMMUNITY-SURFACE-ARCHITECTURE, TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT.

---

## 1. Purpose

Establish the read-along reader as a **Regent-invocable presentation artifact** — the surface by which the Regent renders substantial written material to the operator with synchronized narration, and the **receipt shape** that turns such presentations from ephemeral UI into chain-provable events.

Two things happen at once and both must be true:

1. **Presentation as embodiment.** When the Regent has substantial written material to convey — a section of ARCHITECTURE, a rationale for a policy transition, a peer's proposed pattern under review — the material should be *heard-and-read*, not skimmed. A voice with pacing creates presence. The operator experiences the material.
2. **Presentation as governance event.** The fact that the operator was shown material M in voice V at rate R, whether they completed it, where they paused, is *governance-relevant*. Retention and attention are not private matters when the material is a constitutional rule or a commons pattern. The reader emits receipts.

The reader is therefore neither a UI convenience nor a media player. It is a first-class artifact with a pinned surface, a receipt shape, and a bounded relationship to identity, voice, and the commons.

---

## 2. The surface contract

The Regent may invoke:

```
Reader.present(doc, {
  voice_binding,         // see §5 voice-as-identity
  rate?,                 // default 1.0
  resume_from?,          // {sentence_idx, word_idx}
  receipt_scope,         // determines chain destination for read events
  context_scope,         // bounded-space identity to attribute reading under
  presentation_reason,   // free-text: why the Regent is presenting this
})
```

The Regent may enqueue multiple docs as a **narrated playlist**. The operator retains full control at all times: pause, resume, jump to any sentence, change voice, cancel. Regent invocation is a *proposal for the operator's attention*, not a compulsion. Every operator-side transition emits its own receipt (see §6).

The Regent's `presentation_reason` is important: it accompanies the receipt so the operator can later see, in their own read history, *why* the Regent handed them each doc. "Because you're transitioning into governance context and this is the current constitutional rule." "Because Alex published a pattern and you flagged patterns from Alex for review." Without a stated reason, presentations become opaque and the surface loses trust posture.

---

## 3. Rendering pipeline (pinned)

The doc is broken into **sentences** and each sentence into **words**. Both are addressable structures that receipts reference. Both must be deterministic and versioned.

**Sentence splitter (SPLITTER-V1):** documented separately, but its core commitments:

- Splits at `.`, `!`, `?` followed by whitespace or line break
- Protects: decimals (`v9.0`), URLs (`zeropoint.global`), abbreviations from a bounded list (`etc.`, `e.g.`, `Mr.`, etc.), ellipses, single-letter initials (`U.S.`), section dividers (`---`)
- Splits on blank line regardless
- Caps sentence length at 500 chars, dividing overflow at commas/semicolons
- Preserves each sentence's `startChar` position in the source doc

**Word tokenizer:** `/\S+/g` on sentence text; each word's absolute position in the doc is `sentence.startChar + match.index`.

**Why this is a governance surface, not an implementation detail:**

Receipts reference `(doc_hash, sentence_idx, word_idx)`. If the splitter changes semantics — treats a new construct as a sentence boundary, merges what it used to split, or vice versa — then every prior receipt refers to *different* chunks of text than it did when written. A receipt asserting "operator read sentence 4.7 of ARCHITECTURE" becomes ambiguous.

Therefore the splitter is **version-pinned in the ontology** and updates go through SUPERSESSION-FRAMEWORK. When SPLITTER-V2 arrives, either it is behaviorally identical to V1 for all existing docs (and the ontology asserts this equivalence, verifiably), or existing receipts remain bound to V1 by explicit version tag and only new receipts use V2.

---

## 4. Audio: content-addressed, reproducible

Audio blobs for a rendered sentence are content-addressable and reproducible.

**Content address:**
```
audio_key = sha256(doc_hash || voice_id || sentence_idx || model_pin)
```

Where `model_pin` locks the inference substrate:

```
model_pin = {
  model: "onnx-community/Kokoro-82M-v1.0-ONNX",
  quantization: "fp16" | "q8" | "fp32",
  device_class: "webgpu" | "wasm",   // see below
  splitter_version: "v1",
}
```

**Reproducibility claim:** two operators, given the same `(doc, voice_id, model_pin)`, produce byte-identical audio for each sentence.

This claim needs verification per `device_class`. Kokoro should be deterministic across WebGPU and WASM given the same weights and quantization, but this must be *asserted and periodically verified* by the artifact's stewards. If it turns out to drift, `device_class` becomes part of `audio_key` for real and reproducibility is scoped per class.

**Why it matters:** if audio is reproducible and content-addressed, it can be shared. A community can publish "here is the doc, here is Nicole reading it" and any operator can verify locally. Audio provenance follows the same trust posture as everything else in ZeroPoint — verifiable rather than trusted.

---

## 5. Voice-as-identity

Voices are not aesthetic choices. They are **identity bindings** the operator makes deliberately, receipt-emitting, Genesis-authenticated.

### 5.1 The binding structure

The operator may bind voices to contexts. Recommended baseline bindings:

| Context | Voice binding purpose |
| --- | --- |
| `governance` | Everything policy-relevant: constitutional rules, supersession events, authority transitions |
| `community` | Commons material — patterns, peer proposals, community briefings |
| `working` | Everyday cognition — the Regent's routine communication |
| `whisper` | Intimate, sensitive, low-stakes, or emotionally-loaded material |
| `provenance` | Read-backs of the operator's own past activity from the receipt chain |

Bindings are not mandatory. An operator who wants a single voice throughout is fine. But when bindings exist, the operator *hears* what mode they're in without having to check UI chrome. Presentation carries context implicitly.

### 5.2 Voice identity across model versions

Kokoro voices (`nicole`, `bella`, `michael`, `emma`, etc.) are stable identifiers within a model version. If Kokoro publishes a v2, voice `nicole` in v1 and `nicole` in v2 are **not the same voice** for governance purposes even if they sound similar.

Voice bindings therefore include model version:

```
voice_binding = {
  context: "governance",
  voice_id: "af_nicole",
  model: "Kokoro-82M-v1.0",
  bound_at: <timestamp>,
  bound_by: <genesis_signature>,
}
```

When the model upgrades, existing bindings enter a **re-affirmation window**: the operator is prompted to either (a) explicitly rebind (choose a v2 voice to succeed the v1 binding), (b) assert equivalence (v2's voice is close enough), or (c) let the binding expire.

### 5.3 Cross-operator voice interoperability

A pattern shared in the commons that includes narration inherits the pattern-author's voice binding. When the operator plays back a peer's shared narrated pattern, they hear it in *the peer's* chosen voice — a subtle but important signal that this material is *from someone else*.

The operator's own presentations always use the operator's own bindings; there's no confusion about whose voice is whose.

---

## 6. Receipt shape for read-along events

Every meaningful state transition during a presentation emits a receipt.

### 6.1 Event vocabulary

- `READ_STARTED` — `{doc_hash, voice_id, rate, resumed_from?, presentation_reason, at, ctx}`
- `READ_SENTENCE_COMPLETED` — `{doc_hash, voice_id, sentence_idx, at}`
- `READ_PAUSED_BY_OPERATOR` — `{doc_hash, sentence_idx, word_idx, at}`
- `READ_RESUMED` — `{doc_hash, sentence_idx, word_idx, at}`
- `READ_JUMPED` — `{doc_hash, from_sentence, to_sentence, mechanism: "click"|"seek"|"next", at}`
- `READ_VOICE_CHANGED` — `{doc_hash, from_voice, to_voice, at}` (mid-doc voice change)
- `READ_RATE_CHANGED` — `{doc_hash, from_rate, to_rate, at}`
- `READ_BUFFER_UNDERRUN` — `{doc_hash, sentence_idx, at, duration_ms}`
- `READ_COMPLETED` — `{doc_hash, voice_id, duration_wall_clock_ms, effective_rate_avg, sentences_read, sentences_skipped, at}`
- `READ_ABANDONED` — `{doc_hash, last_sentence_reached, fraction_complete, at}`

### 6.2 Chain destination

Receipts chain into whichever scope the Regent specified in `receipt_scope`:

- **Personal chain** for private reading — everyday material, working-voice presentations
- **Governance chain** for anything under a governance voice binding
- **Community chain** for commons material — the operator opts in per-community whether their read receipts of that community's patterns are visible to the community

The choice is not the Regent's alone. Bounded-space identity (`context_scope`) determines what's *permitted* to be chained where. Presenting governance material under a `whisper` binding to the personal chain is a configuration error and the reader refuses it.

### 6.3 What receipts enable

Aggregated read receipts answer questions the operator (and, where consented, the community) can ask:

- What fraction of ARCHITECTURE has the operator actually read?
- Which sections have they re-read? Which have they never opened?
- What's their effective reading rate for governance material vs. community material?
- Are there docs the Regent has proposed multiple times that the operator has repeatedly abandoned? *(This is not a shame signal. It might mean the doc is poorly written, or presented at the wrong moment, or the Regent is being tone-deaf about what warrants the operator's attention.)*

The Regent uses this to modulate future presentations. Receipts also feed COMMUNITY-COORDINATION when an operator is participating in commons work — "yes, I've read the proposal, in full, in governance voice."

---

## 7. Commons pattern: shared narrated docs

A community may publish a **narrated pattern**: a doc plus its full rendering.

### 7.1 Shape

```
pattern:narrated-doc/${doc_hash}
{
  doc_hash,
  doc_text,                       // or fetch pointer if large
  splitter_version,
  sentences: [{startChar, text, wordStarts}],
  voice_binding: {
    voice_id, model, quantization
  },
  audio_manifest: [
    {sentence_idx, audio_key, size_bytes}
  ],
  audio_blobs: <fetch pointers or inlined for small docs>,
  published_by: <peer_identity>,
  published_at,
  attestations: [<peer signatures>]
}
```

### 7.2 Verification

Any operator can verify a narrated pattern locally:

1. Fetch or re-derive the doc from `doc_hash`
2. Run the pinned splitter — sentence structure must match
3. Re-render each sentence with local Kokoro against the same `voice_binding` and `model_pin`
4. Compare audio blob hashes

If everything matches, the operator now has a verified rendering they can trust — same voice, same pacing, same content — and can play it locally without regenerating.

### 7.3 Why this composes

- **A book club as commons pattern.** A community reads and narrates a rotating set of texts. The narrations are content-addressable, the readings receipt-chained. Members can catch up asynchronously by playing the group's rendering, and their own read receipts flow back into community coordination.

- **Onboarding as narration.** A community's welcome material is a narrated pattern in the community's shared voice. New members hear it before they read it. The community can track completeness of onboarding through the receipt chain.

- **Proposals with rationale.** A peer proposing a new pattern can include an audio narration of the rationale in their own bound voice. Reviewers hear the peer's voice explain, then read the pattern. The connection between *the person* and *the proposal* is embodied rather than abstract.

---

## 8. Persistence

The reader's own state (playlist, settings, current position, audio cache) persists across the operator's session via:

- **IndexedDB** for doc text and audio blobs (no practical size limit)
- **localStorage** for settings and pointers
- **Genesis-scoped backup** via BACKUP-AND-RECOVERY-LANDSCAPE for cross-device continuity

Backup export/import is user-facing — the reader offers explicit "download my state" and "restore from file" surfaces so the operator can always take their reading history with them, independent of any recovery mechanism.

---

## 9. Buffer honesty as trust posture

The reader shows its own generation state to the operator in real time. When Kokoro can't keep up with playback, the reader **pauses and displays "Rebuffering — generation is slower than playback"** rather than stuttering.

This is not a UX polish. It is the ZeroPoint trust posture applied to a presentation surface: **the system narrates its own state rather than hiding it**. Operators are given the truth of what's happening, always, and can make informed decisions (switch to WebGPU, switch to a system voice, wait, or continue reading in silence).

`READ_BUFFER_UNDERRUN` receipts feed governance visibility: if a governance-context reading routinely stalls, the community learns that the reader's substrate isn't up to the material and can react.

---

## 10. Trajectory-aware presentation

Certain doc classes carry presentation constraints in the ontology. TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT may declare, for example:

- Constitutional rules **must** be presented under the operator's governance voice binding, at rate ≤ 1.2×
- Recovery-flow material **must** be presented at rate 1.0 with no skip permitted
- Consent forms **must** be read in full (`READ_COMPLETED` receipt required) before any downstream authority can be exercised

The Regent honors these constraints when invoking `Reader.present`. Attempting to present constitutional material at 2.0× returns a policy error, not silent compliance. The operator can still choose to skip or abandon (their own agency); the *presentation itself* can't be tuned to defeat its purpose.

---

## 11. Open questions

The following require resolution before this artifact moves from draft to committed:

1. **Splitter correction.** When SPLITTER-V1 is discovered to have a bug (as it did with the micro-fragment merger this month), how do we reconcile existing receipts that reference buggy indices? Are they re-mapped, deprecated, or simply frozen as V1-scoped?

2. **Voice model versioning cliff.** When Kokoro publishes a materially new model, does the ecosystem migrate together on a coordinated cliff, or does each operator manage the re-affirmation window independently? What happens to commons patterns pinned to the old model?

3. **Presentation vs. operator-invoked reading.** The operator may open a doc and start reading on their own initiative. Should those receipts have a different type from Regent-invoked presentations, or is `presentation_reason: "operator_initiated"` sufficient?

4. **Cross-bounded-space voice isolation.** How does the reader integrate with per-bounded-space identity, so a governance briefing in `bounded-space:work` isn't audible when the operator is in `bounded-space:home`? Is this an audio-output-channel concern or a state-scoping concern?

5. **Read speed as fatigue signal.** Should the Regent adjust presentation based on the operator's historical reading pace and completion rate? Is that healthful attention to operator state, or is it manipulative modulation dressed as care? This deserves its own consideration; provisionally, *no automatic modulation without operator consent to that specific behavior*.

6. **Sensitive material in shared spaces.** A whisper-voice presentation in a public setting (phone speaker on a bus) is a privacy leak. The reader has no ambient awareness. Should it require the operator to affirm privacy context before playing whisper-bound content? Should whisper-bound content be text-only by default?

---

## 12. What this artifact does not attempt

- **Voice cloning or operator-voice synthesis.** Kokoro voices are the substrate. Bringing the operator's own voice into the system opens identity and provenance surface we're not prepared to steward here.
- **Video-integrated presentation.** Later, if ever. Out of scope.
- **Non-audio reading modes** (silent read tracking, gaze-based highlighting, ambient prompts). These are legitimate presentation surfaces but are different artifacts.
- **Real-time generation for streaming Regent output.** The reader is for authored artifacts (docs), not for the Regent's live chat. That surface has different constraints and lives elsewhere.

---

## 13. Change log

- **2026-07:** initial draft. Sketches surface contract, receipt shape, voice-as-identity binding, commons pattern, and reproducibility claim. Twelve open questions logged for resolution before commit.
