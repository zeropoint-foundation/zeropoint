# Media Provenance — July 2026

**Document type:** Design note. Establishes ZeroPoint's approach to provenance for shared media (photos, video, audio, files), the ZP-secured camera app that provides capture-time provenance on phones, and integration with the C2PA industry standard. In an era of deepfakes, AI-generated content, and manipulation, being able to prove where a piece of media came from is a first-order concern for any communication surface.

**Status:** Design note. Ready for iteration; open decisions marked.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Date:** 2026-07-05.

---

## Formal lens declaration

Per `LENS-DISCIPLINE-2026-07.md`, this document declares the following lens as its first-class canonical form. The problem-and-design prose below elaborates the declaration. Composes with `MEDIA-PROVENANCE-INTEROP-2026-07.md`, which declares the complementary interoperability lens (`media_provenance_interop`) targeting the C2PA-ecosystem-composition surface.

- **`lens_id`**: `media_provenance`
- **`focus`**: how C2PA-shaped signing patterns and capture-time provenance compose with per-operator sovereign roots (rather than vendor-anchored PKI)
- **`dimensions`**: capture-time signing, deepfake detection surface, manipulation resistance, miscontextualization resistance, false-attribution resistance, author impersonation resistance, time forgery resistance, location forgery resistance, edit-chain preservation, downstream verification, cross-vendor federation, per-operator vs per-vendor blast radius
- **`keyword_composition`**: [provenance, C2PA, signing, certificate, attribution, camera, deepfake, chain of custody, capture time, manipulation, miscontextualization, false attribution, author impersonation, time forgery, location forgery, edit chain, downstream verification, media integrity, content provenance, capture receipt, sensor attestation, Ed25519, ES256, KMS, sovereign root, vendor PKI]
- **`transformation_question`**: *"how does this substrate primitive move media-provenance blast radius one architectural step further — from ecosystem-wide (unmitigated) to per-vendor (C2PA today) to per-operator (ZP)?"*
- **`cross_references`**: `MEDIA-PROVENANCE-INTEROP-2026-07.md`, `KEEL-2026-07.md` §II.5 (sovereign identity), §II.8 (chain-anchored evidence), §III.19 (detectability), Part VII (peer verification), `PEER-TRUST-ANCHOR-2026-07.md`, `PORTABLE-CHAIN-EXPORT-CEREMONY-2026-07.md`, `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md`, `AI-LANDSCAPE-SIGNAL-2026-07.md` (deepfake / voice-cloning attack surface)

When chain-anchored as a `lens:declared:media_provenance` receipt, invocation semantics follow the lens discipline: any work context matching the keyword composition triggers a `lens:applied:media_provenance:<invocation_id>` receipt. Silent-media-provenance-lens over a long observer window is a signal that substrate work is drifting from a use-case class that motivates specific primitive shapes (capture-time signing, per-operator PKI, edit-chain preservation). Directional: outside-in (external ecosystem standard + real vendor-failure case → substrate composition).

---

## Part I — The Problem

Shared media without provenance is a source of chaos in modern communication. Deepfakes, AI-generated images, manipulated photos, miscontextualized content, false attribution — all of these degrade the epistemic value of what appears in a community surface. Existing platforms handle this poorly: they rely on downstream detection (adversarial arms race), reverse-image search (only shows where else content has appeared, not source), or forensic analysis (post-hoc, expensive, doesn't scale).

The categories of provenance failure worth designing against:

- **Deepfakes and AI-generated content** presented as real.
- **Manipulation** — real image but photoshopped or edited to mislead.
- **Miscontextualization** — real unmodified content presented in wrong context (old photo claimed as new event, image from one place claimed as another).
- **False attribution** — content really is from where claimed, but the attribution to a specific person or moment is false.
- **Author impersonation** — someone shares another operator's content claiming they created it.
- **Time forgery** — real content but claimed to be from a different time than actual.
- **Location forgery** — real content but claimed to be from a different place than actual.

ZP needs to make shared media verifiable at the source, in a way that composes with the sovereign identity substrate and doesn't require operators to trust any centralized authority.

---

## Part II — C2PA as Reference Standard

**Leverage rather than replace.** The Content Provenance and Authenticity coalition (C2PA — Adobe, Microsoft, camera manufacturers, others) has been building a standard for content provenance chains. Cryptographic signing at capture, edit history as signed manifests, verification against publisher identity. Growing adoption: Nikon and Sony ship C2PA-supporting cameras; Adobe integrates provenance signing in Photoshop, Lightroom, and Firefly; browsers and content platforms increasingly display provenance information.

ZP should wrap C2PA rather than replace it. C2PA claims become one input to a ZP provenance receipt. ZP adds what C2PA lacks:

- **Chain-anchored publication** tied to sovereign operator identity
- **Community-context claims** appropriate to bounded or portable spaces
- **Cartographer typing** as an Artifact in the operator's ontology
- **Reputation-integrated provenance** — signatures come from operators whose reputation for honest attestation is chain-visible

C2PA provides the capture-time cryptography; ZP provides the sovereign accountability.

---

## Part III — What a ZP Media Provenance Receipt Carries

A media provenance receipt has several load-bearing fields:

- **Content hash** (`ch`). Blake3 of the raw media bytes. The receipt binds to specific content, not to "an image."
- **Capture claims** (`cap`). Device identity, capture timestamp, capture location if authorized to include. Signed by the capture device or verified via C2PA manifest when available.
- **Chain of custody** (`custody`). Every hop the media has taken between capture and publication, each hop signed by the party that transmitted or held it. Ownership provenance.
- **Edit history** (`edits`). Any modifications since capture, each signed by the editor with the specific change described (crop, color correction, redaction, composite, etc.).
- **Publication claim** (`pub`). The operator publishing the media, the community context, and any framing claims ("this is my photo from Tuesday" vs. "this is a screenshot I found online").
- **Attestations of veracity** (`attest`). Explicit attestations by the publisher about the nature of the content — e.g., "this is AI-generated," "this is authentic capture," "this is a screen recording of external content."

The receipt is signed by the publisher's chain signing key and anchored to the publisher's chain like any other action.

---

## Part IV — Verification Workflow

When operator A shares media in community C:

1. **A's node emits a publication receipt** with the content hash, provenance chain, and A's identity signature.
2. **Recipients verify locally.** Content hash matches actual bytes; provenance chain walks back to a claimed origin without gaps; each hop is properly signed; signatures verify against expected keys.
3. **Chain termination check.** If the chain terminates at a C2PA-supporting camera, that's strong provenance — the media was captured by that specific hardware at that time. If the chain terminates at a chain of ZP operators, the trust bottoms out at whoever originated it and their reputation. If the chain has gaps or terminates at an unverifiable source ("I found this on a public website"), that's honest partial provenance — attested to be unverified.
4. **Presentation to the operator.** The Regent surfaces the verification result with confidence indicators.

Verification is offline — no network call to any central authority. The receipts contain everything needed to verify.

---

## Part V — Categories of Provenance

The presentation layer surfaces provenance categorically, not just as "verified" or "unverified":

- **Native captured with hardware attestation.** C2PA-signed at capture, unbroken chain to publication. Highest confidence. Presented as "verified capture."
- **Captured, no hardware attestation.** Operator attests to capture but on a device without C2PA support. Moderate confidence — bounded by operator's reputation for honesty. Presented as "operator-attested capture."
- **Received from another operator with provenance.** Chain traces to an earlier operator's provenance receipt. Confidence inherited from the source chain. Presented as "received from [source] with their provenance."
- **External source, transparently unverified.** Operator attests they found this at a public URL or received from anonymous source. Provenance chain stops early; confidence is low but the transparency is honest. Presented as "unverified external source."
- **AI-generated (attested).** Sharer explicitly attests this was generated by an AI model, including model identity if available. Watermarking from participating models (Anthropic, OpenAI, others with cryptographic watermarks) can corroborate the claim. Presented as "AI-generated, disclosed."
- **Provenance-absent.** No provenance chain at all. Suspicious by default. Presented as "no provenance available — treat with caution."

The design principle: **absence of provenance is signal.** In a world where forgery is cheap, the default posture should be "unverified until proven otherwise."

---

## Part VI — The Regent's Presentation of Provenance

The Regent presents provenance prominently for all media. Not as small metadata — as first-class UX. Examples:

- **High provenance:** *"Photo, C2PA-verified capture by Nikon Z8 at 2026-07-04 14:23:15, published by @kenrom. Provenance strong."*
- **Operator-attested:** *"Image, no capture attestation. Shared by @user with claim of external source. Provenance limited to sharer's honesty. Sharer's reputation: high."*
- **Concerning:** *"Image with no provenance chain. Cannot verify authenticity or origin. Present in this context requires trust in sharer alone."*
- **AI-disclosed:** *"AI-generated image, disclosed by @user. Generated by model [ModelName]. Not a photograph."*

The Regent may present these differently across fidelity modes (minimal shows text descriptors; standard shows visual badges; secure shows pixel-embedded indicators), but the information is always available.

The operator can request detailed provenance inspection at any time — the Regent surfaces the full chain of custody, edit history, and attestations.

---

## Part VII — Edit Workflow

Media can be legitimately edited. Every edit is a signed receipt describing the specific change. The design principle: **transparency without alarmism.** Most edits are legitimate; the design should make them attested but not scary.

Types of edits by severity:

- **Preserving edits** — crop, rotate, color correction, format conversion. Metadata-tagged as low-severity. Reader sees "edited for framing/color."
- **Redactive edits** — blur faces, remove background elements for privacy, redact sensitive text. Metadata-tagged with reason. Reader sees "redacted for privacy: faces blurred."
- **Substantive edits** — composite, add/remove meaningful content, replace elements. Metadata-tagged as high-severity. Reader sees "substantive edit: content composited/removed."
- **Deceptive edits** — modifying to change meaning while claiming the original. Constitutional violation. Publisher's reputation destroyed if caught; chain-visible violation receipt.

Each edit receipt includes:
- Edit type category
- Description of the change (structured or human-readable)
- New content hash
- Reference to prior content hash (edit chain links)
- Editor's signature

The final published version carries the full edit chain. Viewers can walk back to original capture. The Regent presents edit history unobtrusively for benign edits and prominently for substantive ones.

---

## Part VIII — The ZP Camera App

C2PA is showing up in high-end camera hardware, but capture at scale happens on phones. A ZP-secured camera app ships alongside the substrate and gives operators immediate access to strong provenance without waiting for hardware ecosystems to catch up.

### 8.1 What the app does at minimum

- **Capture with immediate signing.** Photo captured → image bytes → phone's secure enclave (Secure Enclave on iOS, StrongBox/TrustZone on Android) → signed capture receipt with timestamp, location if authorized, device attestation, camera settings. Receipt written to the operator's local chain, encrypted, not yet published.
- **C2PA manifest generation.** Write standard C2PA claims alongside ZP-native provenance receipts. This gives interoperability — a photo shared outside the ZP ecosystem still carries C2PA provenance that C2PA-aware tools can verify.
- **Edit workflow integration.** Crop, adjust, redact — each edit produces a signed edit receipt linked to the prior content hash. The final published version carries the full edit chain.
- **Publication with community-context awareness.** Choose the community, choose bounded vs. portable identity, publication receipt anchors to the operator's chain, respects the community's context rules.

### 8.2 Sensor attestation — realistic tiers

The fundamental question: how do we prove image bytes came from the actual sensor and not from another source (the photo library, an injected external image, a screen being photographed)?

- **Software-only signing via secure enclave** (v1 target). The app produces cryptographically-signed capture receipts using the phone's secure enclave. Doesn't prove the source is the sensor, but proves the app signed at time of capture with the operator's identity. Provides device identity, verified timestamp, location claim, immediate signing before manipulation is possible.
- **Hardware-attested capture** (v2+). iOS increasingly supports TEE-mediated camera pipelines. Android has similar capabilities on some devices via StrongBox and the DICE architecture. Where the platform supports it, image bytes traverse sensor → TEE → signature without leaving the trusted boundary. Genuinely proves source-is-sensor.
- **Sensor-authenticated capture** (v3, aspirational). Some newer camera sensors are experimenting with continuous authentication at the silicon level — the sensor itself signs data as it's produced. Not widely available yet but the direction the industry is heading.

For v1, be honest: software-only capture attestation is much better than nothing, but doesn't prevent sophisticated sensor-injection attacks. The value proposition is "this media was signed by this operator's device at this time with claim of camera capture." The reputation and constitutional layers handle residual attack surface.

### 8.3 Time attestation

Phone clocks can be manipulated. Multi-signal approach:

- Device-claimed time (from phone clock)
- Secure enclave monotonic counter (can't roll back)
- Trusted timestamp service via chain anchor (if phone is online at capture, immediately submit to a chain-anchored timestamp; the chain block time bounds when the receipt existed by)
- Cell tower / GPS time cross-check when available

The composite gives strong temporal evidence — you can't claim you captured media yesterday when the chain proves the receipt landed today.

### 8.4 Location attestation

GPS can be spoofed on rooted devices. Best available approach: include GPS as-provided with clear attestation ("device-reported location, not independently verified"), corroborate with cell tower fingerprint and WiFi network fingerprint when available, allow operator opt-out of location entirely. Honest limits on what location proves.

### 8.5 Privacy considerations for the camera app

- **Location is opt-in per capture, not global.**
- **Face and subject redaction happens locally on device before publication.** The operator can redact before anything leaves their device.
- **Publication decisions are per-media, per-context.** Nothing auto-publishes. The operator's Regent proposes; the operator approves.
- **SIM identity is not touched by the app.** No phone number extraction; no carrier information in provenance.
- **The camera app runs against the operator's ZP identity, not the phone's OS identity.** No Apple ID or Google account queries.

### 8.6 Integration with the ZP substrate

- Captured media becomes an Artifact in the operator's Cartographer ontology.
- The Cartographer types media and enables ontology-level queries ("images from my home in the last month," "photos I've shared with community X").
- Publication receipts respect the bounded/portable context of the destination.
- The commons contribution model applies — provenance-verified media shared to the commons builds the operator's reputation for authenticity contributions.

### 8.7 Cross-platform considerations

- **iOS.** Use Secure Enclave for signing, PhotoKit/AVFoundation for capture. Leverage App Attest and DeviceCheck for device attestation. C2PA support via Content Credentials SDK where available.
- **Android.** StrongBox where available, TrustZone otherwise, Camera2 API. Use Play Integrity for device attestation. Manufacturer fragmentation is real; test matrix will be substantial.
- **Desktop.** macOS AVFoundation with Secure Enclave; Windows with TPM 2.0; Linux with TPM where available. Desktop is lower priority since most operator-side capture will be phone-based.

### 8.8 Roadmap shape

- **v1** — Software-signing camera app on iOS and Android. C2PA manifest generation. Time and location attestation via multi-signal approach. Edit workflow. Chain-anchored publication. Ships with the community surface.
- **v2** — Hardware-attested capture where platform supports it. Deeper C2PA integration. Multi-camera corroboration (if two ZP camera users capture the same scene, their receipts cross-attest each other).
- **v3** — Sensor-authenticated capture as sensor manufacturers adopt it. Live-stream provenance for video calls (extending capture attestation to realtime).

---

## Part IX — Live Streaming Has Built-In Legitimacy

Live streaming has a property that recorded media does not: **it's inherently harder to fake**. A live stream can be verified in real time by multiple witnesses; latency-sensitive manipulation is technically difficult; the flow of the stream carries continuous provenance signals that a static image doesn't.

For ZP:

- **Live-stream provenance receipts.** The camera signs the stream in chunks; each chunk is a chain-anchored receipt with a hash of the chunk's content.
- **Continuous attestation.** Software integrity attestation (per `SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md`) applies — the streaming node continuously attests that its output is unmodified sensor content.
- **Peer witnesses.** Peers viewing the stream can attest that they saw specific content at specific times, corroborating the streamer's provenance.
- **Deepfake detection is harder in real time.** Real-time deepfake generation is bandwidth-heavy and latency-sensitive; caught deepfakes in live streams are more attributable.

Live streaming is a first-class capability of the community surface for reasons of both operator experience (real-time engagement) and epistemic quality (harder to fake than post-hoc media).

---

## Part X — Adversarial Dynamics

### 10.1 Forged provenance receipts

**Attack:** Attacker fabricates a capture receipt for AI-generated content.

**Defense:** Signatures must trace to real device or operator keys. Forging requires either compromising a real device's signing key (increasingly hard with TPM-backed signing) or forging a signature (cryptographically infeasible).

### 10.2 Laundering via re-photographing

**Attack:** Attacker photographs a screen displaying AI-generated content, producing "real" capture attestation for fake content.

**Defense:** Partial. Corroboration across multiple sources helps (if only one place shows this specific image, be suspicious). The capture attestation only proves "these photons hit this sensor at this time," not "the subject is real." Honest presentation of what capture attestation actually proves is important; overselling it creates false confidence.

### 10.3 Metadata manipulation post-capture

**Attack:** Attacker modifies timestamp or location claims after capture.

**Defense:** The capture signature covers metadata; modification invalidates the signature.

### 10.4 Publisher impersonation

**Attack:** Attacker shares media claiming to be from another operator.

**Defense:** Publication signature must be from the claimed operator's key; forging requires their private key.

### 10.5 Compromised capture device

**Attack:** Camera with stolen signing keys produces false attestations.

**Defense:** Revocation infrastructure for compromised device keys; device reputation degradation when compromises surface.

### 10.6 AI generation that evades watermarking

**Attack:** AI content from models without cryptographic watermarks.

**Defense:** Absence of positive provenance combined with active AI-generated attestation being a constitutional requirement — publishers who share AI-generated content must attest so, and false attestation is a constitutional violation.

### 10.7 Screen photography (rephotographing an image)

**Attack:** Attacker photographs another image displayed on a screen.

**Defense:** Hardest attack. Some signals possible (moiré patterns, sensor characteristics, focus artifacts) but not reliable. Fundamentally handled by reputation and community dynamics rather than at capture-time.

### 10.8 Sensor injection on unrooted device

**Attack:** Software-only signing is vulnerable to image data injection into the camera pipeline.

**Defense:** v1 accepts this risk; hardware-attested capture (v2+) closes it on supported platforms.

---

## Part XI — The Broader Pattern

Media provenance is one instance of provenance-as-a-substrate-primitive. The same design generalizes to:

- **Document provenance** (authorship chain, edit history, source of quoted material)
- **Data provenance** (source of dataset, transformation history, aggregation lineage)
- **Code provenance** (build chain, source repository, dependency signing — this is closely related to software integrity attestation)
- **Claim provenance** (assertions of fact, source of the assertion, chain of transmission)

The media case is the most visible and most needed given current threat landscape. But the primitive scales. What we design for images works for audio, video, documents, datasets, and factual claims.

Provenance is also a public-goods primitive. Every operator who signs honest provenance receipts strengthens the ecosystem's collective ability to trust content. Every operator who signs false receipts weakens it. Reputation dynamics reward the former and punish the latter. Over time, the ecosystem develops a culture of provenance that other platforms can't easily replicate because they lack the sovereign identity substrate.

---

## Part XII — Open Design Decisions

1. **Wire format for provenance receipts.** Concrete field structure, encoding, signature scheme.
2. **C2PA manifest embedding.** How ZP provenance receipts co-exist with C2PA manifests in shared media files. Some duplication is inevitable; how much is worth it for interoperability?
3. **Edit granularity.** How fine-grained are edit receipts? Every pixel change? Every commit-worthy change? Trade-off between provenance completeness and receipt volume.
4. **Live-stream chunk size.** For live-stream provenance, how big are the signed chunks? Latency vs. verification granularity trade-off.
5. **Watermark cooperation with AI model providers.** Which AI models integrate their watermarks with ZP's provenance? Requires collaboration or standardization; scope of effort worth deciding.
6. **Retroactive provenance for existing media.** Operators have existing photo libraries with no provenance. Do we offer a retroactive "I attest this is mine" flow, and how do we clearly label such attestations as weaker than capture-time provenance?
7. **Cross-operator corroboration receipts.** When two ZP operators capture the same scene, how do they cross-attest? Format, discovery, verification.

---

## Part XIII — Companion Documents

- `docs/ARCHITECTURE-2026-07.md` — canonical architecture record; media as Artifacts in the Cartographer ontology (Part II §6.3) is the substrate this document extends.
- `docs/design/SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md` — the camera app's capture attestation is an application of the software integrity attestation pattern.
- `docs/design/REGENT-COMPARTMENTALIZATION-2026-07.md` — the Regent's role in presenting provenance and helping operators maintain identity separation when publishing media across contexts.
- `docs/design/COMMUNITY-SURFACE-ARCHITECTURE-2026-07.md` — media flows through community channels per the community surface design.
- `docs/design/PHONE-AND-IDENTITY-2026-07.md` — the camera app runs on phones; the composition rules that prevent phone identity from leaking into provenance receipts.
- `docs/design/ENCRYPTED-STORAGE-ARCHITECTURE-2026-07.md` — media at rest per §IX of that document; encryption architecture applies to captured media.

---

*Media without provenance is epistemic noise. Media with cryptographically anchored provenance — capture attestation, edit history, publisher signature, sovereign identity — is verifiable evidence. ZP wraps C2PA to leverage existing camera adoption, ships a ZP camera app so phone capture doesn't wait for hardware ecosystems, and treats provenance as first-class UX rather than metadata footnote. Absence of provenance is signal; the substrate rewards operators who provide provenance and imposes real cost on those who don't.*
